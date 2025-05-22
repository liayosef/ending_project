import http.server
import socketserver
import json
import socket
import threading
import os
import time
import webbrowser
import hashlib
from urllib.parse import parse_qs, urlparse, quote, unquote
from protocol import Protocol, COMMUNICATION_PORT

HTTP_PORT = 8000

# נתונים עבור ילדים
children_data = {}
data_lock = threading.Lock()
active_connections = {}


class UserManager:
    """מחלקה לניהול משתמשים - הרשמה, התחברות ושמירת נתונים"""

    def __init__(self, data_file='users_data.json'):
        self.data_file = data_file
        self.users = {}
        self.load_users()

    def load_users(self):
        """טעינת נתוני משתמשים מקובץ"""
        try:
            with open(self.data_file, 'r', encoding='utf-8') as f:
                self.users = json.load(f)
                print(f"[*] נטענו נתונים עבור {len(self.users)} משתמשים")
        except FileNotFoundError:
            # יצירת משתמש דמו
            self.users = {
                'admin@example.com': {
                    'fullname': 'מנהל המערכת',
                    'password_hash': self._hash_password('admin123')
                }
            }
            self.save_users()
            print("[*] נוצר קובץ משתמשים חדש עם משתמש דמו")
        except Exception as e:
            print(f"[!] שגיאה בטעינת נתוני משתמשים: {e}")
            self.users = {}

    def save_users(self):
        """שמירת נתוני משתמשים לקובץ"""
        try:
            with open(self.data_file, 'w', encoding='utf-8') as f:
                json.dump(self.users, f, ensure_ascii=False, indent=2)
            print("[*] נתוני משתמשים נשמרו בהצלחה")
        except Exception as e:
            print(f"[!] שגיאה בשמירת נתוני משתמשים: {e}")

    def _hash_password(self, password):
        """הצפנת סיסמה"""
        return hashlib.sha256(password.encode('utf-8')).hexdigest()

    def register_user(self, email, fullname, password):
        """רישום משתמש חדש"""
        if not email or not fullname or not password:
            return False, "יש למלא את כל השדות"

        if email in self.users:
            return False, "כתובת האימייל כבר קיימת במערכת"

        if len(password) < 6:
            return False, "הסיסמה חייבת להכיל לפחות 6 תווים"

        # הוספת המשתמש
        self.users[email] = {
            'fullname': fullname,
            'password_hash': self._hash_password(password)
        }

        self.save_users()
        print(f"[+] משתמש חדש נרשם: {email}")
        return True, "המשתמש נרשם בהצלחה"

    def validate_login(self, email, password):
        """אימות כניסת משתמש"""
        if email not in self.users:
            return False

        password_hash = self._hash_password(password)
        return self.users[email]['password_hash'] == password_hash

    def get_user_fullname(self, email):
        """קבלת שם מלא של משתמש"""
        if email in self.users:
            return self.users[email]['fullname']
        return None


# תבנית דף הרשמה
REGISTER_TEMPLATE = """<!DOCTYPE html>
<html lang="he" dir="rtl">
<head>
    <meta charset="UTF-8">
    <title>בקרת הורים - הרשמה</title>
    <style>
        body { 
            font-family: 'Segoe UI', Tahoma, Arial, sans-serif;
            background: linear-gradient(135deg, #f5f7fa 0%, #c3cfe2 100%);
            min-height: 100vh;
            display: flex;
            justify-content: center;
            align-items: center;
            padding: 20px;
            margin: 0;
        }
        .form-container {
            background: white;
            padding: 50px;
            border-radius: 15px;
            max-width: 450px;
            width: 100%;
            box-shadow: 0 10px 20px rgba(0,0,0,0.1);
        }
        .logo-circle {
            background-color: #4a6fa5;
            width: 50px;
            height: 50px;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 24px;
            color: white;
            margin: 0 auto 20px;
        }
        h1 {
            color: #4a6fa5;
            font-size: 24px;
            margin: 0 0 30px;
            text-align: center;
        }
        .form-group {
            margin-bottom: 20px;
        }
        label {
            display: block;
            font-weight: bold;
            margin-bottom: 5px;
            color: #555;
        }
        input {
            width: 100%;
            padding: 12px 15px;
            border: 2px solid #e1e8ed;
            border-radius: 8px;
            font-size: 16px;
            box-sizing: border-box;
        }
        button {
            background: #4a6fa5;
            color: white;
            border: none;
            padding: 12px 20px;
            border-radius: 8px;
            cursor: pointer;
            width: 100%;
            font-size: 16px;
            font-weight: bold;
            margin-bottom: 15px;
        }
        .login-link {
            text-align: center;
            margin-top: 20px;
        }
        .login-link a {
            color: #4a6fa5;
            text-decoration: none;
        }
        .login-link a:hover {
            text-decoration: underline;
        }
        .message {
            padding: 10px;
            border-radius: 8px;
            margin-bottom: 20px;
            text-align: center;
        }
        .error-message {
            background-color: #f8d7da;
            color: #721c24;
        }
        .success-message {
            background-color: #d4edda;
            color: #155724;
        }
    </style>
</head>
<body>
    <div class="form-container">
        <div class="logo-circle">🛡️</div>
        <h1>בקרת הורים - הרשמה</h1>
        ${message}
        <form method="post" action="/register">
            <div class="form-group">
                <label for="fullname">שם מלא</label>
                <input type="text" id="fullname" name="fullname" placeholder="הכנס שם מלא" required>
            </div>
            <div class="form-group">
                <label for="email">כתובת אימייל</label>
                <input type="email" id="email" name="email" placeholder="הכנס כתובת אימייל" required>
            </div>
            <div class="form-group">
                <label for="password">סיסמה</label>
                <input type="password" id="password" name="password" placeholder="הכנס סיסמה (לפחות 6 תווים)" required>
            </div>
            <div class="form-group">
                <label for="confirm_password">אימות סיסמה</label>
                <input type="password" id="confirm_password" name="confirm_password" placeholder="הכנס סיסמה שוב" required>
            </div>
            <button type="submit">הרשם</button>
        </form>
        <div class="login-link">
            כבר יש לך חשבון? <a href="/login">התחבר כאן</a>
        </div>
    </div>
</body>
</html>"""

LOGIN_TEMPLATE = """<!DOCTYPE html>
<html lang="he" dir="rtl">
<head>
    <meta charset="UTF-8">
    <title>בקרת הורים - כניסה</title>
    <style>
        body { 
            font-family: 'Segoe UI', Tahoma, Arial, sans-serif;
            background: linear-gradient(135deg, #f5f7fa 0%, #c3cfe2 100%);
            min-height: 100vh;
            display: flex;
            justify-content: center;
            align-items: center;
            padding: 20px;
            margin: 0;
        }
        .form-container {
            background: white;
            padding: 50px;
            border-radius: 15px;
            max-width: 450px;
            width: 100%;
            box-shadow: 0 10px 20px rgba(0,0,0,0.1);
        }
        .logo-circle {
            background-color: #4a6fa5;
            width: 50px;
            height: 50px;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 24px;
            color: white;
            margin: 0 auto 20px;
        }
        h1 {
            color: #4a6fa5;
            font-size: 24px;
            margin: 0 0 30px;
            text-align: center;
        }
        .form-group {
            margin-bottom: 20px;
        }
        label {
            display: block;
            font-weight: bold;
            margin-bottom: 5px;
            color: #555;
        }
        input {
            width: 100%;
            padding: 12px 15px;
            border: 2px solid #e1e8ed;
            border-radius: 8px;
            font-size: 16px;
            box-sizing: border-box;
        }
        button {
            background: #4a6fa5;
            color: white;
            border: none;
            padding: 12px 20px;
            border-radius: 8px;
            cursor: pointer;
            width: 100%;
            font-size: 16px;
            font-weight: bold;
            margin-bottom: 15px;
        }
        .register-link {
            text-align: center;
            margin-top: 20px;
        }
        .register-link a {
            color: #4a6fa5;
            text-decoration: none;
        }
        .register-link a:hover {
            text-decoration: underline;
        }
        .message {
            padding: 10px;
            border-radius: 8px;
            margin-bottom: 20px;
            text-align: center;
        }
        .error-message {
            background-color: #f8d7da;
            color: #721c24;
        }
        .success-message {
            background-color: #d4edda;
            color: #155724;
        }
    </style>
</head>
<body>
    <div class="form-container">
        <div class="logo-circle">🛡️</div>
        <h1>בקרת הורים</h1>
        ${message}
        <form method="post" action="/login">
            <div class="form-group">
                <label for="email">כתובת אימייל</label>
                <input type="email" id="email" name="email" placeholder="הכנס כתובת אימייל" required>
            </div>
            <div class="form-group">
                <label for="password">סיסמה</label>
                <input type="password" id="password" name="password" placeholder="הכנס סיסמה" required>
            </div>
            <button type="submit">התחבר</button>
        </form>
        <div class="register-link">
            אין לך חשבון? <a href="/register">הרשם כאן</a>
        </div>
    </div>
</body>
</html>"""

DASHBOARD_TEMPLATE = """<!DOCTYPE html>
<html lang="he" dir="rtl">
<head>
    <meta charset="UTF-8">
    <title>לוח בקרה - בקרת הורים</title>
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Arial, sans-serif;
            background: #f5f7fa;
            margin: 0;
            padding: 0;
        }
        .header {
            background: linear-gradient(90deg, #4a6fa5 0%, #3a5a8a 100%);
            color: white;
            padding: 20px;
            box-shadow: 0 2px 5px rgba(0,0,0,0.1);
        }
        .header-content {
            max-width: 1200px;
            margin: 0 auto;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .logo-container {
            display: flex;
            align-items: center;
            gap: 15px;
        }
        .logo-circle {
            background-color: white;
            width: 40px;
            height: 40px;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            color: #4a6fa5;
            font-size: 20px;
        }
        .user-info {
            display: flex;
            align-items: center;
            gap: 15px;
        }
        .logout-btn {
            background: rgba(255, 255, 255, 0.2);
            color: white;
            padding: 8px 15px;
            border-radius: 5px;
            text-decoration: none;
            font-size: 14px;
        }
        .main-content {
            max-width: 1200px;
            margin: 40px auto;
            padding: 0 20px;
        }
        .welcome-message {
            margin-bottom: 30px;
            font-size: 18px;
            color: #555;
        }
        .children-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 20px;
            margin-top: 30px;
        }
        .child-card {
            background: white;
            border-radius: 15px;
            padding: 30px;
            box-shadow: 0 5px 15px rgba(0,0,0,0.05);
            cursor: pointer;
            transition: transform 0.2s, box-shadow 0.2s;
        }
        .child-card:hover {
            transform: translateY(-5px);
            box-shadow: 0 8px 25px rgba(0,0,0,0.1);
        }
        .child-icon {
            width: 80px;
            height: 80px;
            background-color: #4a6fa5;
            border-radius: 15px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 40px;
            color: white;
            margin: 0 auto 15px;
        }
        .child-name {
            font-size: 24px;
            font-weight: bold;
            text-align: center;
            margin-bottom: 10px;
        }
        .child-status {
            text-align: center;
            padding: 5px 10px;
            border-radius: 15px;
            display: inline-block;
            font-size: 14px;
        }
        .status-online {
            background-color: #d4edda;
            color: #155724;
        }
        .status-offline {
            background-color: #f8d7da;
            color: #721c24;
        }
        .domain-controls {
            background: white;
            padding: 30px;
            border-radius: 15px;
            margin: 20px 0;
            box-shadow: 0 5px 15px rgba(0,0,0,0.05);
        }
        .domain-form {
            display: flex;
            gap: 15px;
            margin-bottom: 30px;
        }
        .domain-input {
            flex: 1;
            padding: 12px 15px;
            border: 2px solid #e1e8ed;
            border-radius: 8px;
            font-size: 16px;
        }
        .primary-btn {
            background: #4a6fa5;
            color: white;
            border: none;
            padding: 12px 30px;
            border-radius: 8px;
            cursor: pointer;
            font-weight: bold;
        }
        .domain-list {
            margin-top: 30px;
            border: 2px solid #e1e8ed;
            border-radius: 10px;
            max-height: 400px;
            overflow-y: auto;
            background: #f9f9f9;
        }
        .domain-item {
            padding: 15px 20px;
            border-bottom: 1px solid #e1e8ed;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .remove-btn {
            background: #e74c3c;
            color: white;
            border: none;
            padding: 8px 15px;
            border-radius: 6px;
            cursor: pointer;
        }
        .back-btn {
            background: #95a5a6;
            color: white;
            border: none;
            padding: 10px 20px;
            border-radius: 8px;
            cursor: pointer;
            text-decoration: none;
            display: inline-block;
        }
        .empty-message {
            padding: 20px;
            text-align: center;
            color: #666;
            font-style: italic;
        }
    </style>
</head>
<body>
    <div class="header">
        <div class="header-content">
            <div class="logo-container">
                <div class="logo-circle">🛡️</div>
                <h1>בקרת הורים</h1>
            </div>
            <div class="user-info">
                <span>שלום ${user_name}</span>
                <a href="/logout" class="logout-btn">התנתק</a>
            </div>
        </div>
    </div>

    <div class="main-content">
        <div class="welcome-message">
            ברוך הבא למערכת בקרת ההורים!
        </div>
        <div style="text-align: center; margin: 20px 0;">
            <a href="/manage_children" style="background: #17a2b8; color: white; padding: 12px 25px; border-radius: 8px; text-decoration: none; font-weight: bold;">ניהול ילדים</a>
        </div>
        <div class="children-grid">
            ${children_cards}
        </div>

        <div class="domain-controls" style="display: ${display_child_controls}">
            <h3>ניהול דומיינים חסומים עבור: ${current_child}</h3>
            <form method="post" action="/add_domain" class="domain-form">
                <input type="hidden" name="child" value="${current_child}">
                <input type="text" name="domain" class="domain-input" placeholder="הכנס דומיין לחסימה">
                <button type="submit" class="primary-btn">הוסף דומיין</button>
            </form>

            <h3>דומיינים חסומים כרגע</h3>
            <div class="domain-list">
                ${blocked_domains_html}
            </div>

            <div style="text-align: center; margin-top: 30px;">
                <a href="/dashboard" class="back-btn">חזור לרשימת הילדים</a>
            </div>
        </div>
    </div>
</body>
</html>"""

MANAGE_CHILDREN_TEMPLATE = """<!DOCTYPE html>
<html lang="he" dir="rtl">
<head>
    <meta charset="UTF-8">
    <title>ניהול ילדים - בקרת הורים</title>
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Arial, sans-serif;
            background: #f5f7fa;
            margin: 0;
            padding: 0;
        }
        .header {
            background: linear-gradient(90deg, #4a6fa5 0%, #3a5a8a 100%);
            color: white;
            padding: 20px;
            box-shadow: 0 2px 5px rgba(0,0,0,0.1);
        }
        .header-content {
            max-width: 1200px;
            margin: 0 auto;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .logo-container {
            display: flex;
            align-items: center;
            gap: 15px;
        }
        .logo-circle {
            background-color: white;
            width: 40px;
            height: 40px;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            color: #4a6fa5;
            font-size: 20px;
        }
        .user-info {
            display: flex;
            align-items: center;
            gap: 15px;
        }
        .logout-btn, .back-btn {
            background: rgba(255, 255, 255, 0.2);
            color: white;
            padding: 8px 15px;
            border-radius: 5px;
            text-decoration: none;
            font-size: 14px;
        }
        .main-content {
            max-width: 1200px;
            margin: 40px auto;
            padding: 0 20px;
        }
        .management-container {
            background: white;
            padding: 30px;
            border-radius: 15px;
            margin: 20px 0;
            box-shadow: 0 5px 15px rgba(0,0,0,0.05);
        }
        .add-child-form {
            display: flex;
            gap: 15px;
            margin-bottom: 30px;
            padding: 20px;
            background: #f8f9fa;
            border-radius: 10px;
        }
        .child-input {
            flex: 1;
            padding: 12px 15px;
            border: 2px solid #e1e8ed;
            border-radius: 8px;
            font-size: 16px;
        }
        .primary-btn {
            background: #4a6fa5;
            color: white;
            border: none;
            padding: 12px 30px;
            border-radius: 8px;
            cursor: pointer;
            font-weight: bold;
        }
        .danger-btn {
            background: #e74c3c;
            color: white;
            border: none;
            padding: 8px 15px;
            border-radius: 6px;
            cursor: pointer;
            font-size: 14px;
        }
        .children-list {
            border: 2px solid #e1e8ed;
            border-radius: 10px;
            background: #f9f9f9;
        }
        .child-item {
            padding: 20px;
            border-bottom: 1px solid #e1e8ed;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .child-info {
            display: flex;
            align-items: center;
            gap: 15px;
        }
        .child-icon {
            width: 50px;
            height: 50px;
            background-color: #4a6fa5;
            border-radius: 10px;
            display: flex;
            align-items: center;
            justify-content: center;
            color: white;
            font-size: 20px;
        }
        .child-details h3 {
            margin: 0 0 5px 0;
            font-size: 18px;
        }
        .child-details p {
            margin: 0;
            color: #666;
            font-size: 14px;
        }
        .status-online {
            color: #28a745;
            font-weight: bold;
        }
        .status-offline {
            color: #dc3545;
            font-weight: bold;
        }
        .child-actions {
            display: flex;
            gap: 10px;
        }
        .manage-btn {
            background: #17a2b8;
            color: white;
            padding: 8px 15px;
            border-radius: 6px;
            text-decoration: none;
            font-size: 14px;
        }
        .message {
            padding: 15px;
            border-radius: 8px;
            margin-bottom: 20px;
            text-align: center;
        }
        .success-message {
            background-color: #d4edda;
            color: #155724;
        }
        .error-message {
            background-color: #f8d7da;
            color: #721c24;
        }
    </style>
</head>
<body>
    <div class="header">
        <div class="header-content">
            <div class="logo-container">
                <div class="logo-circle">🛡️</div>
                <h1>ניהול ילדים</h1>
            </div>
            <div class="user-info">
                <span>שלום ${user_name}</span>
                <a href="/dashboard" class="back-btn">חזור לדשבורד</a>
                <a href="/logout" class="logout-btn">התנתק</a>
            </div>
        </div>
    </div>

    <div class="main-content">
        ${message}

        <div class="management-container">
            <h2>הוספת ילד חדש</h2>
            <form method="post" action="/add_child" class="add-child-form">
                <input type="text" name="child_name" class="child-input" placeholder="הכנס שם הילד" required>
                <button type="submit" class="primary-btn">הוסף ילד</button>
            </form>
        </div>

        <div class="management-container">
            <h2>רשימת הילדים</h2>
            <div class="children-list">
                ${children_list}
            </div>
        </div>
    </div>
</body>
</html>"""


class ParentServer:
    def __init__(self):
        self.running = True
        self.server_socket = None
        self.connection_threads = []
        self.load_children_data()

    def load_children_data(self):
        try:
            with open('children_data.json', 'r', encoding='utf-8') as f:
                data = json.load(f)
                for child, info in data.items():
                    info['blocked_domains'] = set(info['blocked_domains'])
                    info.setdefault('client_address', None)
                    info.setdefault('last_seen', None)
                children_data.update(data)
                print(f"[*] נטענו נתונים עבור {len(children_data)} ילדים")
        except FileNotFoundError:
            children_data['ילד 1'] = {"blocked_domains": {"facebook.com", "youtube.com"}, "client_address": None,
                                      "last_seen": None}
            children_data['ילד 2'] = {"blocked_domains": {"instagram.com", "tiktok.com"}, "client_address": None,
                                      "last_seen": None}
            children_data['ילד 3'] = {"blocked_domains": {"twitter.com"}, "client_address": None,
                                      "last_seen": None}
            self.save_children_data()
            print(f"[*] נוצרו נתוני ברירת מחדל עבור {len(children_data)} ילדים")

    def add_child(self, child_name):
        """הוספת ילד חדש"""
        print(f"[DEBUG] 🔹 מנסה להוסיף ילד: '{child_name}'")

        if not child_name or not child_name.strip():
            print("[DEBUG] ❌ שם ילד ריק")
            return False

        child_name = child_name.strip()

        with data_lock:
            if child_name in children_data:
                print(f"[DEBUG] ❌ ילד '{child_name}' כבר קיים")
                return False

            # הוספת הילד עם נתונים בסיסיים
            children_data[child_name] = {
                "blocked_domains": set(),  # רשימה ריקה של דומיינים חסומים
                "client_address": None,
                "last_seen": None
            }

            print(f"[DEBUG] ✅ ילד '{child_name}' נוסף למילון")
            print(f"[DEBUG] כעת יש {len(children_data)} ילדים")

            try:
                self.save_children_data()
                print(f"[+] ✅ ילד '{child_name}' נוסף בהצלחה ונשמר")
                return True
            except Exception as e:
                print(f"[!] ❌ שגיאה בשמירת ילד חדש: {e}")
                # הסרת הילד מהזיכרון אם השמירה נכשלה
                del children_data[child_name]
                return False

    def save_children_data(self):
        """שמירת נתוני ילדים - גרסה בטוחה"""
        try:
            data_to_save = {}
            for child, info in children_data.items():
                # המרה של set ל-list אם צריך
                blocked_domains = info["blocked_domains"]
                if isinstance(blocked_domains, set):
                    blocked_domains = list(blocked_domains)

                data_to_save[child] = {
                    "blocked_domains": blocked_domains,
                    "last_seen": info.get("last_seen")
                }

            with open('children_data.json', 'w', encoding='utf-8') as f:
                json.dump(data_to_save, f, ensure_ascii=False, indent=2)

            print("[DEBUG] ✅ נתונים נשמרו בהצלחה")

        except Exception as e:
            print(f"[!] ❌ שגיאה בשמירת נתונים: {e}")
            import traceback
            traceback.print_exc()
            raise  # העלאת השגיאה כדי שהקורא יוכל לטפל בה

    def remove_child(self, child_name):
        """הסרת ילד עם דיבוג"""
        print(f"[DEBUG] מנסה למחוק ילד: {child_name}")
        print(f"[DEBUG] ילדים לפני מחיקה: {list(children_data.keys())}")

        with data_lock:
            if child_name in children_data:
                # נתק את הילד אם הוא מחובר
                if child_name in active_connections:
                    try:
                        active_connections[child_name]["socket"].close()
                        print(f"[DEBUG] ניתקתי את החיבור של {child_name}")
                    except Exception as e:
                        print(f"[DEBUG] שגיאה בניתוק חיבור: {e}")
                    del active_connections[child_name]

                del children_data[child_name]
                try:
                    self.save_children_data()
                    print(f"[+] ✅ ילד נמחק בהצלחה: {child_name}")
                    print(f"[DEBUG] ילדים אחרי מחיקה: {list(children_data.keys())}")
                    return True
                except Exception as e:
                    print(f"[!] ❌ שגיאה בשמירת נתונים: {e}")
                    return False
            else:
                print(f"[!] ❌ ילד לא נמצא: {child_name}")
                return False

    def handle_child_connection(self, client_socket, address):
        print(f"[*] חיבור חדש מ-{address}")
        child_name = None

        try:
            msg_type, data = Protocol.receive_message(client_socket)

            if msg_type == Protocol.REGISTER_CHILD:
                child_name = data.get('name')
                if child_name and child_name in children_data:
                    with data_lock:
                        children_data[child_name]['client_address'] = address
                        children_data[child_name]['last_seen'] = time.time()

                    Protocol.send_message(client_socket, Protocol.ACK, {"status": "registered"})
                    print(f"[+] {child_name} נרשם בהצלחה")

                    active_connections[child_name] = {"socket": client_socket, "address": address}

                    self.handle_child_communication(client_socket, child_name)

                else:
                    Protocol.send_message(client_socket, Protocol.ERROR, {"message": "Invalid child name"})
                    print(f"[!] שם ילד לא תקין: {child_name}")

        except Exception as e:
            print(f"[!] שגיאה בחיבור {child_name}: {e}")
        finally:
            client_socket.close()
            if child_name:
                with data_lock:
                    if child_name in children_data:
                        children_data[child_name]['client_address'] = None
                    if child_name in active_connections:
                        del active_connections[child_name]
                print(f"[-] {child_name} התנתק")

    def handle_child_communication(self, client_socket, child_name):
        while self.running:
            try:
                msg_type, data = Protocol.receive_message(client_socket)

                if msg_type == Protocol.GET_DOMAINS:
                    with data_lock:
                        domains = list(children_data[child_name]['blocked_domains'])
                    Protocol.send_message(client_socket, Protocol.UPDATE_DOMAINS, {"domains": domains})
                    print(f"[+] נשלחו דומיינים ל-{child_name}: {domains}")

                elif msg_type == Protocol.CHILD_STATUS:
                    with data_lock:
                        children_data[child_name]['last_seen'] = time.time()
                    Protocol.send_message(client_socket, Protocol.ACK)

                elif msg_type == Protocol.ERROR:
                    print(f"[!] Error from child {child_name}: {data}")
                    break

            except Exception as e:
                print(f"[!] שגיאה בתקשורת עם {child_name}: {e}")
                break

    def start_communication_server(self):
        def run_server():
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.bind(('', COMMUNICATION_PORT))
            self.server_socket.listen(5)
            print(f"[*] שרת תקשורת מאזין על פורט {COMMUNICATION_PORT}")

            while self.running:
                try:
                    client_socket, address = self.server_socket.accept()
                    client_thread = threading.Thread(
                        target=self.handle_child_connection,
                        args=(client_socket, address)
                    )
                    client_thread.daemon = True
                    client_thread.start()
                    self.connection_threads.append(client_thread)
                except Exception as e:
                    if self.running:
                        print(f"[!] שגיאה בקבלת חיבור: {e}")

        comm_thread = threading.Thread(target=run_server)
        comm_thread.daemon = True
        comm_thread.start()

    def shutdown(self):
        self.running = False
        if self.server_socket:
            self.server_socket.close()


print("[*] ParentServer אותחל עם פונקציות ניהול ילדים")

# יצירת אובייקט ניהול משתמשים
user_manager = UserManager()
parent_server = ParentServer()


class ParentHandler(http.server.SimpleHTTPRequestHandler):

    def get_cookies(self):
        """קבלת עוגיות מהבקשה"""
        cookies = {}
        if "Cookie" in self.headers:
            raw_cookies = self.headers["Cookie"].split(";")
            for cookie in raw_cookies:
                if "=" in cookie:
                    name, value = cookie.strip().split("=", 1)
                    cookies[name] = unquote(value)
        return cookies

    def is_logged_in(self):
        """בדיקת מצב התחברות"""
        cookies = self.get_cookies()
        email = cookies.get("user_email")
        if email and user_manager.get_user_fullname(email):
            return email
        return None

    def notify_child_immediate(self, child_name):
        """עדכון מיידי לילד"""
        with data_lock:
            if child_name in active_connections:
                conn_info = active_connections[child_name]
                if conn_info and conn_info.get("socket"):
                    try:
                        socket = conn_info["socket"]
                        domains = list(children_data[child_name]['blocked_domains'])
                        Protocol.send_message(socket, Protocol.UPDATE_DOMAINS, {"domains": domains})
                        print(f"[*] נשלח עדכון מיידי ל-{child_name}")
                    except Exception as e:
                        print(f"[!] שגיאה בעדכון {child_name}: {e}")

    def do_GET(self):
        path = unquote(self.path)
        parsed_path = urlparse(path)
        query_params = parse_qs(parsed_path.query)

        if parsed_path.path == '/register':
            self.send_response(200)
            self.send_header('Content-type', 'text/html; charset=utf-8')
            self.end_headers()
            register_html = REGISTER_TEMPLATE.replace('${message}', '')
            self.wfile.write(register_html.encode('utf-8'))

        elif parsed_path.path in ['/', '/login']:
            # בדיקה אם המשתמש כבר מחובר
            logged_in_user = self.is_logged_in()
            if logged_in_user:
                self.send_response(302)
                self.send_header('Location', '/dashboard')
                self.end_headers()
                return

            self.send_response(200)
            self.send_header('Content-type', 'text/html; charset=utf-8')
            self.end_headers()
            login_html = LOGIN_TEMPLATE.replace('${message}', '')
            self.wfile.write(login_html.encode('utf-8'))

        elif parsed_path.path == '/logout':
            # ניתוק המשתמש
            self.send_response(302)
            self.send_header('Set-Cookie', 'user_email=; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT')
            self.send_header('Location', '/login')
            self.end_headers()

        elif parsed_path.path == '/dashboard':
            # בדיקה אם המשתמש מחובר
            logged_in_user = self.is_logged_in()
            if not logged_in_user:
                self.send_response(302)
                self.send_header('Location', '/login')
                self.end_headers()
                return

            user_name = user_manager.get_user_fullname(logged_in_user)
            selected_child = query_params.get('child', [None])[0]

            if selected_child and selected_child in children_data:
                domains_html = []
                with data_lock:
                    child_domains = children_data[selected_child]['blocked_domains']
                    for domain in child_domains:
                        domains_html.append(f"""
                            <div class="domain-item">
                                <div>{domain}</div>
                                <form method="post" action="/remove_domain" style="display:inline;">
                                    <input type="hidden" name="child" value="{selected_child}">
                                    <input type="hidden" name="domain" value="{domain}">
                                    <button type="submit" class="remove-btn">הסר</button>
                                </form>
                            </div>
                        """)

                dashboard_html = DASHBOARD_TEMPLATE.replace('${children_cards}', '')
                dashboard_html = dashboard_html.replace('${display_child_controls}', 'block')
                dashboard_html = dashboard_html.replace('${current_child}', selected_child)
                dashboard_html = dashboard_html.replace('${user_name}', user_name)
                dashboard_html = dashboard_html.replace('${blocked_domains_html}',
                                                        ''.join(
                                                            domains_html) if domains_html else '<div class="empty-message">אין דומיינים חסומים</div>')
            else:
                children_cards = []
                with data_lock:
                    for child_name, child_info in children_data.items():
                        is_connected = child_info.get('client_address') is not None
                        status_class = "status-online" if is_connected else "status-offline"
                        status_text = "מחובר" if is_connected else "לא מחובר"
                        encoded_child_name = quote(child_name)

                        children_cards.append(f"""
                            <div class="child-card" onclick="window.location='/dashboard?child={encoded_child_name}'">
                                <div class="child-icon">👶</div>
                                <div class="child-name">{child_name}</div>
                                <div class="child-status {status_class}">{status_text}</div>
                                <p style="text-align: center; margin-top: 10px;">
                                    {len(child_info['blocked_domains'])} אתרים חסומים
                                </p>
                            </div>
                        """)

                dashboard_html = DASHBOARD_TEMPLATE.replace('${children_cards}', ''.join(children_cards))
                dashboard_html = dashboard_html.replace('${display_child_controls}', 'none')
                dashboard_html = dashboard_html.replace('${current_child}', '')
                dashboard_html = dashboard_html.replace('${user_name}', user_name)
                dashboard_html = dashboard_html.replace('${blocked_domains_html}', '')

            self.send_response(200)
            self.send_header('Content-type', 'text/html; charset=utf-8')
            self.end_headers()
            self.wfile.write(dashboard_html.encode('utf-8'))

        elif parsed_path.path == '/manage_children':
            # בדיקה אם המשתמש מחובר
            logged_in_user = self.is_logged_in()
            if not logged_in_user:
                self.send_response(302)
                self.send_header('Location', '/login')
                self.end_headers()
                return

            user_name = user_manager.get_user_fullname(logged_in_user)

            # בניית רשימת הילדים
            children_list = []
            with data_lock:
                for child_name, child_info in children_data.items():
                    is_connected = child_info.get('client_address') is not None
                    status_class = "status-online" if is_connected else "status-offline"
                    status_text = "מחובר" if is_connected else "לא מחובר"
                    encoded_child_name = quote(child_name)

                    children_list.append(f"""
                               <div class="child-item">
                                   <div class="child-info">
                                       <div class="child-icon">👶</div>
                                       <div class="child-details">
                                           <h3>{child_name}</h3>
                                           <p class="{status_class}">{status_text}</p>
                                           <p>{len(child_info['blocked_domains'])} אתרים חסומים</p>
                                       </div>
                                   </div>
                                   <div class="child-actions">
                                       <a href="/dashboard?child={encoded_child_name}" class="manage-btn">נהל חסימות</a>
                                       <form method="post" action="/remove_child" style="display:inline;">
                                           <input type="hidden" name="child_name" value="{child_name}">
                                           <button type="submit" class="danger-btn" onclick="return confirm('האם אתה בטוח שברצונך למחוק את {child_name}?')">מחק</button>
                                       </form>
                                   </div>
                               </div>
                           """)

            manage_html = MANAGE_CHILDREN_TEMPLATE.replace('${user_name}', user_name)
            manage_html = manage_html.replace('${children_list}', ''.join(
                children_list) if children_list else '<div style="padding: 20px; text-align: center; color: #666;">אין ילדים רשומים</div>')
            manage_html = manage_html.replace('${message}', '')

            self.send_response(200)
            self.send_header('Content-type', 'text/html; charset=utf-8')
            self.end_headers()
            self.wfile.write(manage_html.encode('utf-8'))
        else:
            self.send_error(404)

    def do_POST(self):
        print(f"[DEBUG] POST request לכתובת: {self.path}")

        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length)
        post_params = parse_qs(post_data.decode('utf-8'))

        print(f"[DEBUG] פרמטרים שהתקבלו: {post_params}")

        if self.path == '/register':
            # קבלת נתוני הטופס
            fullname = post_params.get('fullname', [''])[0].strip()
            email = post_params.get('email', [''])[0].strip()
            password = post_params.get('password', [''])[0]
            confirm_password = post_params.get('confirm_password', [''])[0]

            # בדיקת התאמת סיסמאות
            if password != confirm_password:
                error_message = '<div class="message error-message">הסיסמאות אינן תואמות</div>'
                register_html = REGISTER_TEMPLATE.replace('${message}', error_message)
                self.send_response(200)
                self.send_header('Content-type', 'text/html; charset=utf-8')
                self.end_headers()
                self.wfile.write(register_html.encode('utf-8'))
                return

            # ניסיון רישום המשתמש
            success, message = user_manager.register_user(email, fullname, password)

            if success:
                # הצלחה - הפנייה לדף התחברות עם הודעה
                success_message = '<div class="message success-message">ההרשמה הושלמה בהצלחה! כעת תוכל להתחבר</div>'
                login_html = LOGIN_TEMPLATE.replace('${message}', success_message)
                self.send_response(200)
                self.send_header('Content-type', 'text/html; charset=utf-8')
                self.end_headers()
                self.wfile.write(login_html.encode('utf-8'))
            else:
                # כישלון - חזרה לדף הרשמה עם הודעת שגיאה
                error_message = f'<div class="message error-message">{message}</div>'
                register_html = REGISTER_TEMPLATE.replace('${message}', error_message)
                self.send_response(200)
                self.send_header('Content-type', 'text/html; charset=utf-8')
                self.end_headers()
                self.wfile.write(register_html.encode('utf-8'))

        elif self.path == '/login':
            email = post_params.get('email', [''])[0].strip()
            password = post_params.get('password', [''])[0]

            if not email or not password:
                error_message = '<div class="message error-message">יש למלא את כל השדות</div>'
                login_html = LOGIN_TEMPLATE.replace('${message}', error_message)
                self.send_response(200)
                self.send_header('Content-type', 'text/html; charset=utf-8')
                self.end_headers()
                self.wfile.write(login_html.encode('utf-8'))
                return

            # בדיקת תקינות הכניסה
            if user_manager.validate_login(email, password):
                # התחברות מוצלחת - שמירת המשתמש בעוגייה
                self.send_response(302)
                self.send_header('Set-Cookie', f'user_email={quote(email)}; Path=/')
                self.send_header('Location', '/dashboard')
                self.end_headers()
                print(f"[+] משתמש התחבר: {email}")
            else:
                # כניסה נכשלה
                error_message = '<div class="message error-message">שם משתמש או סיסמה שגויים</div>'
                login_html = LOGIN_TEMPLATE.replace('${message}', error_message)
                self.send_response(200)
                self.send_header('Content-type', 'text/html; charset=utf-8')
                self.end_headers()
                self.wfile.write(login_html.encode('utf-8'))

        elif self.path == '/add_domain':
            # בדיקה אם המשתמש מחובר
            logged_in_user = self.is_logged_in()
            if not logged_in_user:
                self.send_response(302)
                self.send_header('Location', '/login')
                self.end_headers()
                return

            child_name = post_params.get('child', [''])[0]
            domain = post_params.get('domain', [''])[0].strip()

            if child_name and domain and child_name in children_data:
                with data_lock:
                    children_data[child_name]['blocked_domains'].add(domain)
                parent_server.save_children_data()
                print(f"[+] נוסף דומיין {domain} עבור {child_name}")

                # עדכון מיידי לילד!
                self.notify_child_immediate(child_name)

            encoded_child_name = quote(child_name)
            self.send_response(302)
            self.send_header('Location', f'/dashboard?child={encoded_child_name}')
            self.end_headers()

        elif self.path == '/remove_domain':
            # בדיקה אם המשתמש מחובר
            logged_in_user = self.is_logged_in()
            if not logged_in_user:
                self.send_response(302)
                self.send_header('Location', '/login')
                self.end_headers()
                return

            child_name = post_params.get('child', [''])[0]
            domain = post_params.get('domain', [''])[0].strip()

            if child_name and domain and child_name in children_data:
                with data_lock:
                    if domain in children_data[child_name]['blocked_domains']:
                        children_data[child_name]['blocked_domains'].remove(domain)
                parent_server.save_children_data()
                print(f"[-] הוסר דומיין {domain} מ-{child_name}")

                # עדכון מיידי לילד!
                self.notify_child_immediate(child_name)

            encoded_child_name = quote(child_name)
            self.send_response(302)
            self.send_header('Location', f'/dashboard?child={encoded_child_name}')
            self.end_headers()

        elif self.path == '/add_child':
            print("[DEBUG] 🔹 נכנסתי לטיפול בהוספת ילד")

            try:
                logged_in_user = self.is_logged_in()
                if not logged_in_user:
                    print("[DEBUG] ❌ משתמש לא מחובר")
                    self.send_response(302)
                    self.send_header('Location', '/login')
                    self.end_headers()
                    return

                child_name = post_params.get('child_name', [''])[0].strip()
                print(f"[DEBUG] שם הילד שהתקבל: '{child_name}'")

                if child_name:
                    success = parent_server.add_child(child_name)
                    print(f"[DEBUG] תוצאת הוספה: {success}")

                    if success:
                        print(f"[✅] ילד '{child_name}' נוסף בהצלחה!")
                    else:
                        print(f"[❌] כישלון בהוספת ילד '{child_name}'")
                else:
                    print("[❌] שם ילד ריק")

                # חזרה לדף ניהול ילדים
                print("[DEBUG] שולח redirect ל-manage_children")
                self.send_response(302)
                self.send_header('Location', '/manage_children')
                self.end_headers()
                print("[DEBUG] ✅ תגובה נשלחה בהצלחה")

            except Exception as e:
                print(f"[!] שגיאה ב-add_child: {e}")
                import traceback
                traceback.print_exc()

                # שליחת תגובת שגיאה
                self.send_response(500)
                self.send_header('Content-type', 'text/html')
                self.end_headers()
                self.wfile.write(b'<h1>Server Error</h1>')

        elif self.path == '/remove_child':
            print("[DEBUG] 🔹 נכנסתי לטיפול במחיקת ילד")

            try:
                logged_in_user = self.is_logged_in()
                if not logged_in_user:
                    print("[DEBUG] ❌ משתמש לא מחובר")
                    self.send_response(302)
                    self.send_header('Location', '/login')
                    self.end_headers()
                    return

                child_name = post_params.get('child_name', [''])[0].strip()
                print(f"[DEBUG] שם הילד למחיקה: '{child_name}'")

                if child_name:
                    success = parent_server.remove_child(child_name)
                    print(f"[DEBUG] תוצאת מחיקה: {success}")

                    if success:
                        print(f"[✅] ילד '{child_name}' נמחק בהצלחה!")
                    else:
                        print(f"[❌] כישלון במחיקת ילד '{child_name}'")
                else:
                    print("[❌] שם ילד ריק")

                # חזרה לדף ניהול ילדים
                print("[DEBUG] שולח redirect ל-manage_children")
                self.send_response(302)
                self.send_header('Location', '/manage_children')
                self.end_headers()
                print("[DEBUG] ✅ תגובה נשלחה בהצלחה")

            except Exception as e:
                print(f"[!] שגיאה ב-remove_child: {e}")
                import traceback
                traceback.print_exc()

                # שליחת תגובת שגיאה
                self.send_response(500)
                self.send_header('Content-type', 'text/html')
                self.end_headers()
                self.wfile.write(b'<h1>Server Error</h1>')
        else:
            self.send_response(404)
            self.end_headers()


if __name__ == "__main__":
    try:
        print("[*] מתחיל את שרת בקרת ההורים...")
        print(f"[*] מנהל משתמשים: {len(user_manager.users)} משתמשים רשומים")

        parent_server.start_communication_server()

        with socketserver.TCPServer(("", HTTP_PORT), ParentHandler) as httpd:
            print(f"[*] שרת HTTP פועל על http://localhost:{HTTP_PORT}")
            print(f"[*] שרת תקשורת פועל על פורט {COMMUNICATION_PORT}")
            print(f"[*] מוכן לקבל חיבורים מילדים")
            server_url = f"http://localhost:{HTTP_PORT}"
            print(f"[*] פותח דפדפן אוטומטית: {server_url}")
            webbrowser.open(server_url)

            print("[*] לחץ Ctrl+C לעצירת השרת")
            try:
                httpd.serve_forever()
            except KeyboardInterrupt:
                print("\n[*] עצירת השרת...")
                parent_server.shutdown()
                httpd.shutdown()


    except Exception as e:
        print(f"[!] שגיאה בהפעלת השרת: {e}")