import socket
from scapy.all import *
from scapy.layers.dns import DNS, DNSQR, DNSRR
import json
import threading
import time
from urllib.parse import parse_qs
import subprocess
from collections import defaultdict
import platform
import os
import ctypes
import ssl
import ipaddress
from protocol import Protocol, COMMUNICATION_PORT
import http.server
import socketserver
from datetime import datetime, timedelta
import sys
import webbrowser

# עיצוב מחדש שמתאים לקונספט של שאר האתר

REGISTRATION_HTML_TEMPLATE = '''<!DOCTYPE html>
<html lang="he" dir="rtl">
<head>
    <meta charset="UTF-8">
    <title>רישום - בקרת הורים</title>
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
            max-width: 500px;
            width: 100%;
            box-shadow: 0 10px 20px rgba(0,0,0,0.1);
            text-align: center;
        }
        .logo-circle {
            background-color: #4a6fa5;
            width: 80px;
            height: 80px;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 40px;
            color: white;
            margin: 0 auto 30px;
        }
        h1 {
            color: #4a6fa5;
            font-size: 28px;
            margin: 0 0 20px;
        }
        .subtitle {
            color: #666;
            font-size: 16px;
            margin-bottom: 30px;
        }
        .form-group {
            margin-bottom: 25px;
            text-align: right;
        }
        label {
            display: block;
            font-weight: bold;
            margin-bottom: 8px;
            color: #555;
            font-size: 16px;
        }
        input[type="text"] {
            width: 100%;
            padding: 15px;
            border: 2px solid #e1e8ed;
            border-radius: 8px;
            font-size: 16px;
            box-sizing: border-box;
            text-align: right;
        }
        input[type="text"]:focus {
            outline: none;
            border-color: #4a6fa5;
            box-shadow: 0 0 0 3px rgba(74, 111, 165, 0.1);
        }
        .submit-btn {
            background: #4a6fa5;
            color: white;
            padding: 15px 40px;
            border: none;
            border-radius: 8px;
            font-size: 16px;
            font-weight: bold;
            cursor: pointer;
            width: 100%;
            margin-top: 20px;
        }
        .submit-btn:hover {
            background: #3a5a8a;
        }
        .info-text {
            background: #f8f9fa;
            padding: 15px;
            border-radius: 8px;
            border-left: 4px solid #4a6fa5;
            margin-top: 20px;
            font-size: 14px;
            color: #666;
        }
        .message {
            padding: 15px;
            border-radius: 8px;
            margin-bottom: 20px;
            text-align: center;
        }
        .error-message {
            background-color: #f8d7da;
            color: #721c24;
            border: 1px solid #f5c6cb;
        }
        .success-message {
            background-color: #d4edda;
            color: #155724;
            border: 1px solid #c3e6cb;
        }
        .warning-message {
            background-color: #fff3cd;
            color: #856404;
            border: 1px solid #ffeaa7;
        }
    </style>
</head>
<body>
    <div class="form-container">
        <div class="logo-circle">🛡️</div>
        <h1>מערכת בקרת הורים</h1>
        <div class="subtitle">האינטרנט מוגבל עד לרישום במערכת</div>

        {message}

        <form method="post" action="/register">
            <div class="form-group">
                <label for="child_name">👶 השם שלך:</label>
                <input type="text" id="child_name" name="child_name" placeholder="הכנס את השם שלך..." required>
            </div>
            <button type="submit" class="submit-btn">🔐 היכנס למערכת</button>
        </form>

        <div class="info-text">
            💡 אם השם שלך לא רשום במערכת, בקש מההורים להוסיף אותך דרך לוח הבקרה
        </div>
    </div>
</body>
</html>'''

BLOCK_HTML_TEMPLATE = '''<!DOCTYPE html>
<html lang="he" dir="rtl">
<head>
    <meta charset="UTF-8">
    <title>אתר חסום - {child_name}</title>
    <style>
        body { 
            font-family: 'Segoe UI', Tahoma, Arial, sans-serif;
            background: linear-gradient(135deg, #ff4757, #ff6b6b);
            min-height: 100vh;
            display: flex;
            justify-content: center;
            align-items: center;
            padding: 20px;
            margin: 0;
            color: white;
        }
        .child-name-tag {
            position: fixed;
            top: 20px;
            right: 20px;
            background: rgba(0,0,0,0.8);
            padding: 10px 20px;
            border-radius: 25px;
            font-size: 14px;
            font-weight: bold;
        }
        .block-container {
            background: rgba(255,255,255,0.1);
            backdrop-filter: blur(10px);
            padding: 50px;
            border-radius: 20px;
            max-width: 600px;
            width: 100%;
            box-shadow: 0 15px 35px rgba(0,0,0,0.3);
            border: 1px solid rgba(255,255,255,0.2);
            text-align: center;
        }
        .block-icon {
            background: rgba(255,255,255,0.2);
            width: 100px;
            height: 100px;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 50px;
            margin: 0 auto 30px;
        }
        h1 {
            font-size: 36px;
            margin: 0 0 20px;
            font-weight: bold;
        }
        .warning-box {
            background: rgba(255,255,255,0.15);
            border: 2px solid rgba(255,255,255,0.3);
            border-radius: 15px;
            padding: 25px;
            margin: 30px 0;
        }
        .warning-box p {
            margin: 10px 0;
            font-size: 18px;
        }
        .warning-box strong {
            font-weight: bold;
            color: #fff;
        }
        .description {
            font-size: 18px;
            line-height: 1.6;
            margin: 20px 0;
            opacity: 0.9;
        }
        .advice {
            background: rgba(255,255,255,0.1);
            padding: 20px;
            border-radius: 10px;
            margin-top: 30px;
            font-size: 16px;
        }
    </style>
</head>
<body>
    <div class="child-name-tag">{child_name}</div>
    <div class="block-container">
        <div class="block-icon">🚫</div>
        <h1>אתר חסום!</h1>

        <div class="warning-box">
            <p><strong>אתר:</strong> {host}</p>
            <p><strong>זמן:</strong> {current_time}</p>
            <p><strong>ילד:</strong> {child_name}</p>
        </div>

        <div class="description">
            הגישה לאתר זה נחסמה על ידי מערכת בקרת ההורים
        </div>

        <div class="advice">
            💡 אם אתה חושב שזו טעות או שאתה צריך גישה לאתר זה ללימודים, פנה להורים שלך
        </div>
    </div>
</body>
</html>'''


# הודעות שגיאה והצלחה מעוצבות:
def create_error_page(title, message, back_button=True, retry_button=False):
    buttons_html = ""

    if retry_button:
        buttons_html += '''<button onclick="tryAgain()" class="submit-btn" style="background: #4a6fa5; margin-left: 10px;">נסה שוב</button>'''

    if back_button:
        buttons_html += '''<button onclick="goBack()" class="submit-btn" style="background: #95a5a6;">חזור</button>'''

    return f'''<!DOCTYPE html>
<html lang="he" dir="rtl">
<head>
    <meta charset="UTF-8">
    <title>{title}</title>
    <style>
        body {{ 
            font-family: 'Segoe UI', Tahoma, Arial, sans-serif;
            background: linear-gradient(135deg, #f5f7fa 0%, #c3cfe2 100%);
            min-height: 100vh;
            display: flex;
            justify-content: center;
            align-items: center;
            padding: 20px;
            margin: 0;
        }}
        .container {{
            background: white;
            padding: 50px;
            border-radius: 15px;
            max-width: 500px;
            width: 100%;
            box-shadow: 0 10px 20px rgba(0,0,0,0.1);
            text-align: center;
        }}
        .icon {{ 
            font-size: 60px; 
            margin-bottom: 20px; 
        }}
        h1 {{ 
            color: #e74c3c; 
            font-size: 24px; 
            margin-bottom: 20px; 
        }}
        p {{ 
            color: #666; 
            font-size: 16px; 
            line-height: 1.6; 
        }}
        .submit-btn {{
            background: #4a6fa5;
            color: white;
            padding: 12px 30px;
            border: none;
            border-radius: 8px;
            font-size: 16px;
            font-weight: bold;
            cursor: pointer;
            margin: 10px 5px;
            display: inline-block;
        }}
        .submit-btn:hover {{
            opacity: 0.9;
        }}
        .button-container {{
            margin-top: 30px;
        }}
    </style>
    <script>
        function goBack() {{
            if (window.history.length > 1) {{
                window.history.back();
            }} else {{
                window.location.href = '/';
            }}
        }}

        function tryAgain() {{
            window.location.reload();
        }}

        // אם אין היסטוריה, הסתר כפתור חזור
        window.addEventListener('load', function() {{
            if (window.history.length <= 1) {{
                var backButtons = document.querySelectorAll('button[onclick*="goBack"]');
                backButtons.forEach(function(btn) {{
                    btn.style.display = 'none';
                }});
            }}
        }});
    </script>
</head>
<body>
    <div class="container">
        <div class="icon">❌</div>
        <h1>{title}</h1>
        <p>{message}</p>
        <div class="button-container">
            {buttons_html}
        </div>
    </div>
</body>
</html>'''


def create_success_page(title, message):
    return f'''<!DOCTYPE html>
<html lang="he" dir="rtl">
<head>
    <meta charset="UTF-8">
    <title>{title}</title>
    <style>
        body {{ 
            font-family: 'Segoe UI', Tahoma, Arial, sans-serif;
            background: linear-gradient(135deg, #f5f7fa 0%, #c3cfe2 100%);
            min-height: 100vh;
            display: flex;
            justify-content: center;
            align-items: center;
            padding: 20px;
            margin: 0;
        }}
        .container {{
            background: white;
            padding: 50px;
            border-radius: 15px;
            max-width: 500px;
            width: 100%;
            box-shadow: 0 10px 20px rgba(0,0,0,0.1);
            text-align: center;
        }}
        .icon {{ font-size: 60px; margin-bottom: 20px; }}
        h1 {{ color: #28a745; font-size: 24px; margin-bottom: 20px; }}
        p {{ color: #666; font-size: 16px; line-height: 1.6; }}
        .highlight {{ background: #d4edda; padding: 15px; border-radius: 8px; margin: 20px 0; border-left: 4px solid #28a745; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="icon">🎉</div>
        <h1>{title}</h1>
        <div class="highlight">{message}</div>
        <p>תוכל לסגור את הדף הזה ולהתחיל לגלוש באינטרנט</p>
    </div>
</body>
</html>'''


# הודעות שגיאה והצלחה מעוצבות:
def create_error_page(title, message, back_button=True, retry_button=False):
    buttons = ""

    if retry_button:
        buttons += '''
        <button onclick="tryAgain()" class="submit-btn" style="background: #4a6fa5; margin-left: 10px;">נסה שוב</button>
        '''

    if back_button:
        buttons += '''
        <button onclick="goBack()" class="submit-btn" style="background: #95a5a6;">חזור</button>
        '''

    script = '''
    <script>
        function goBack() {
            if (window.history.length > 1) {
                window.history.back();
            } else {
                window.location.href = '/';
            }
        }

        function tryAgain() {
            window.location.reload();
        }

        // אם אין היסטוריה, הסתר כפתור חזור
        window.onload = function() {
            if (window.history.length <= 1) {
                var backButtons = document.querySelectorAll('button[onclick*="goBack"]');
                backButtons.forEach(function(btn) {
                    btn.style.display = 'none';
                });
            }
        }
    </script>
    '''

    return f'''<!DOCTYPE html>
<html lang="he" dir="rtl">
<head>
    <meta charset="UTF-8">
    <title>{title}</title>
    <style>
        body {{ 
            font-family: 'Segoe UI', Tahoma, Arial, sans-serif;
            background: linear-gradient(135deg, #f5f7fa 0%, #c3cfe2 100%);
            min-height: 100vh;
            display: flex;
            justify-content: center;
            align-items: center;
            padding: 20px;
            margin: 0;
        }}
        .container {{
            background: white;
            padding: 50px;
            border-radius: 15px;
            max-width: 500px;
            width: 100%;
            box-shadow: 0 10px 20px rgba(0,0,0,0.1);
            text-align: center;
        }}
        .icon {{ font-size: 60px; margin-bottom: 20px; }}
        h1 {{ color: #e74c3c; font-size: 24px; margin-bottom: 20px; }}
        p {{ color: #666; font-size: 16px; line-height: 1.6; }}
        .submit-btn {{
            background: #4a6fa5;
            color: white;
            padding: 12px 30px;
            border: none;
            border-radius: 8px;
            font-size: 16px;
            font-weight: bold;
            cursor: pointer;
            margin: 10px 5px;
            display: inline-block;
        }}
        .submit-btn:hover {{
            opacity: 0.9;
        }}
        .button-container {{
            margin-top: 30px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="icon">❌</div>
        <h1>{title}</h1>
        <p>{message}</p>
        <div class="button-container">
            {buttons}
        </div>
    </div>
    {script}
</body>
</html>'''


def create_success_page(title, message):
    return f'''<!DOCTYPE html>
<html lang="he" dir="rtl">
<head>
    <meta charset="UTF-8">
    <title>{title}</title>
    <style>
        body {{ 
            font-family: 'Segoe UI', Tahoma, Arial, sans-serif;
            background: linear-gradient(135deg, #f5f7fa 0%, #c3cfe2 100%);
            min-height: 100vh;
            display: flex;
            justify-content: center;
            align-items: center;
            padding: 20px;
            margin: 0;
        }}
        .container {{
            background: white;
            padding: 50px;
            border-radius: 15px;
            max-width: 500px;
            width: 100%;
            box-shadow: 0 10px 20px rgba(0,0,0,0.1);
            text-align: center;
        }}
        .icon {{ font-size: 60px; margin-bottom: 20px; }}
        h1 {{ color: #28a745; font-size: 24px; margin-bottom: 20px; }}
        p {{ color: #666; font-size: 16px; line-height: 1.6; }}
        .highlight {{ background: #d4edda; padding: 15px; border-radius: 8px; margin: 20px 0; border-left: 4px solid #28a745; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="icon">🎉</div>
        <h1>{title}</h1>
        <div class="highlight">{message}</div>
        <p>תוכל לסגור את הדף הזה ולהתחיל לגלוש באינטרנט</p>
    </div>
</body>
</html>'''


REGISTRATION_FILE = "child_registration.json"
REGISTRATION_CHECK_INTERVAL = 30
CHILD_NAME = None
REAL_DNS_SERVER = "8.8.8.8"
LISTEN_IP = "0.0.0.0"
LISTEN_PORT = 53
BLOCK_PAGE_IP = "127.0.0.1"
PARENT_SERVER_IP = "127.0.0.1"
BLOCKED_DOMAINS = set()
ORIGINAL_DNS = None

BLOCK_SERVER_PORT = None

browsing_history = []
history_lock = threading.Lock()
MAX_HISTORY_ENTRIES = 1000

# מעקב אחר ביקורים בחלון זמן
domain_visits = defaultdict(list)
domain_visits_lock = threading.Lock()
MAIN_SITE_WINDOW_SECONDS = 30

OBVIOUS_TECHNICAL_PATTERNS = [
    'analytics', 'tracking', 'ads', 'doubleclick', 'googletagmanager',
    'cdn', 'cache', 'static', 'assets', 'edge', 'akamai', 'cloudflare',
    'api', 'ws', 'websocket', 'ajax', 'xhr', 'heartbeat', 'status',
]


# פונקציות לניהול רישום הילד
def load_registration():
    try:
        with open(REGISTRATION_FILE, 'r', encoding='utf-8') as f:
            data = json.load(f)
            return data.get('child_name'), data.get('is_registered', False)
    except FileNotFoundError:
        return None, False
    except Exception as e:
        print(f"[!] שגיאה בטעינת רישום: {e}")
        return None, False


def save_registration(child_name, is_registered=True):
    try:
        data = {
            'child_name': child_name,
            'is_registered': is_registered,
            'registration_time': datetime.now().isoformat()
        }
        with open(REGISTRATION_FILE, 'w', encoding='utf-8') as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        print(f"[+] ✅ רישום נשמר: {child_name}")
        return True
    except Exception as e:
        print(f"[!] שגיאה בשמירת רישום: {e}")
        return False


def check_child_registration():
    global CHILD_NAME
    saved_name, is_registered = load_registration()

    if saved_name and is_registered:
        if verify_child_with_parent(saved_name):
            CHILD_NAME = saved_name
            print(f"[+] ✅ ילד רשום: {CHILD_NAME}")
            return True
        else:
            print(f"[!] ⚠️ רישום של '{saved_name}' לא תקף יותר")
            try:
                os.remove(REGISTRATION_FILE)
            except:
                pass
    return False


def verify_child_with_parent(child_name):
    try:
        print(f"[DEBUG] מנסה לאמת ילד: {child_name}")
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)  # הגדלת timeout
        sock.connect((PARENT_SERVER_IP, COMMUNICATION_PORT))

        verify_data = {"child_name": child_name}
        print(f"[DEBUG] שולח בקשת אימות: {verify_data}")
        Protocol.send_message(sock, Protocol.VERIFY_CHILD, verify_data)

        print("[DEBUG] ממתין לתגובה...")
        msg_type, data = Protocol.receive_message(sock)
        print(f"[DEBUG] התקבלה תגובה: {msg_type}, נתונים: {data}")

        if msg_type == Protocol.VERIFY_RESPONSE:
            is_valid = data.get("is_valid", False)
            print(f"[DEBUG] תוצאת אימות: {is_valid}")

            # ⚠️ חשוב! לא לסגור את החיבור כאן אם הילד תקף
            # השרת ימשיך להשתמש בחיבור הזה
            if not is_valid:
                sock.close()
            # אם הילד תקף, השרת ימשיך להשתמש בחיבור

            return is_valid
        else:
            print(f"[DEBUG] סוג הודעה לא צפוי: {msg_type}")
            sock.close()
            return False

    except Exception as e:
        print(f"[!] שגיאה באימות עם השרת: {e}")
        import traceback
        traceback.print_exc()
        return False


def prompt_for_child_name():
    # פונקציה זו לא נדרשת יותר - הכל עובר דרך HTML
    pass


def wait_for_registration():
    print("\n" + "🔐 פותח דף רישום...")
    print("🌐 דפדפן יפתח אוטומטי עם דף הרישום")

    # ממתין שהשרת יתחיל לרוץ ויגדיר את הפורט
    time.sleep(3)

    # פתיחת דפדפן עם הפורט הנכון
    try:
        if BLOCK_SERVER_PORT:
            if BLOCK_SERVER_PORT == 80:
                registration_url = "http://127.0.0.1"
            else:
                registration_url = f"http://127.0.0.1:{BLOCK_SERVER_PORT}"

            print(f"🌐 פותח דפדפן: {registration_url}")
            webbrowser.open(registration_url)
            time.sleep(2)
        else:
            print("[!] שרת לא הצליח להתחיל")
            return False
    except Exception as e:
        print(f"[!] שגיאה בפתיחת דפדפן: {e}")

    print("💡 הזן את השם שלך בטופס שמופיע בדפדפן")
    print("🔄 אם הדף לא נטען, רענן את הדפדפן")

    # ממתין עד שהילד יירשם דרך הדפדפן
    max_wait = 300  # 5 דקות
    waited = 0

    while not CHILD_NAME and waited < max_wait:
        time.sleep(5)
        waited += 5

        if waited % 30 == 0:  # הודעה כל 30 שניות
            print(f"[*] ממתין לרישום... ({waited}/{max_wait} שניות)")
            if BLOCK_SERVER_PORT:
                if BLOCK_SERVER_PORT == 80:
                    print(f"[*] 💡 נסה לגשת ל: http://127.0.0.1")
                else:
                    print(f"[*] 💡 נסה לגשת ל: http://127.0.0.1:{BLOCK_SERVER_PORT}")

    if CHILD_NAME:
        print(f"\n🎉 רישום הושלם דרך הדפדפן!")
        print(f"👶 שם: {CHILD_NAME}")
        return True
    else:
        print("\n❌ תם הזמן לרישום")
        return False


def periodic_registration_check():
    global CHILD_NAME
    while True:
        try:
            time.sleep(REGISTRATION_CHECK_INTERVAL)
            if CHILD_NAME:
                if not verify_child_with_parent(CHILD_NAME):
                    print(f"[!] ⚠️ הילד '{CHILD_NAME}' לא רשום יותר במערכת!")
                    print("[!] 🔒 חוזר למצב חסימה מלאה...")
                    try:
                        os.remove(REGISTRATION_FILE)
                    except:
                        pass
                    CHILD_NAME = None
                    block_all_internet()
        except Exception as e:
            print(f"[!] שגיאה בבדיקה תקופתית: {e}")


def block_all_internet():
    global BLOCKED_DOMAINS
    common_domains = {
        "google.com", "youtube.com", "facebook.com", "instagram.com",
        "twitter.com", "tiktok.com", "netflix.com", "amazon.com",
        "microsoft.com", "apple.com", "yahoo.com", "bing.com"
    }
    BLOCKED_DOMAINS.update(common_domains)
    print("[!] 🔒 אינטרנט חסום - ילד לא רשום!")


def is_obviously_technical(domain):
    domain_lower = domain.lower()
    for pattern in OBVIOUS_TECHNICAL_PATTERNS:
        if pattern in domain_lower:
            return True
    return False


def add_to_history(domain, timestamp, was_blocked=False):
    if is_obviously_technical(domain):
        return

    with history_lock:
        entry = {
            "domain": domain,
            "timestamp": timestamp,
            "was_blocked": was_blocked,
            "child_name": CHILD_NAME
        }
        browsing_history.append(entry)
        if len(browsing_history) > MAX_HISTORY_ENTRIES:
            browsing_history.pop(0)
        print(f"[HISTORY] ✅ נוסף: {domain} ({'חסום' if was_blocked else 'מותר'})")


def send_history_update():
    if hasattr(child_client, 'connected') and child_client.connected and browsing_history:
        try:
            with history_lock:
                recent_history = browsing_history.copy()
            data = {"child_name": CHILD_NAME, "history": recent_history}
            Protocol.send_message(child_client.sock, Protocol.BROWSING_HISTORY, data)
            print(f"[HISTORY] נשלח עדכון לשרת: {len(recent_history)} רשומות")
        except Exception as e:
            print(f"[!] שגיאה בשליחת היסטוריה: {e}")


class BlockHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        try:
            self.send_response(200)
            self.send_header('Content-type', 'text/html; charset=utf-8')
            self.end_headers()

            # אם הילד לא רשום - הצג דף רישום
            if not CHILD_NAME:
                registration_html = REGISTRATION_HTML_TEMPLATE.replace('{message}', '')
                self.wfile.write(registration_html.encode('utf-8'))
                return

            # אם הילד רשום - הצג דף חסימה מעוצב
            current_time = time.strftime('%H:%M:%S')
            host = self.headers.get('Host', 'לא ידוע')

            block_html = BLOCK_HTML_TEMPLATE.format(
                child_name=CHILD_NAME,
                host=host,
                current_time=current_time
            )
            self.wfile.write(block_html.encode('utf-8'))

        except Exception as e:
            print(f"[!] שגיאה בטיפול בבקשת HTTP: {e}")
            # דף שגיאה פשוט
            error_html = create_error_page("שגיאה במערכת", "נסה לרענן את הדף", False)
            try:
                self.wfile.write(error_html.encode('utf-8'))
            except:
                pass

    def do_POST(self):
        if self.path == '/register':
            try:
                content_length = int(self.headers['Content-Length'])
                post_data = self.rfile.read(content_length)

                from urllib.parse import parse_qs
                form_data = parse_qs(post_data.decode('utf-8'))
                child_name = form_data.get('child_name', [''])[0].strip()

                print(f"[*] בקשת רישום מהדפדפן: '{child_name}'")

                if not child_name:
                    error_html = create_error_page("שגיאה", "השם לא יכול להיות ריק!", back_button=True, retry_button=True)
                    self.send_response(200)
                    self.send_header('Content-type', 'text/html; charset=utf-8')
                    self.end_headers()
                    self.wfile.write(error_html.encode('utf-8'))
                    return

                if len(child_name) < 2:
                    error_html = create_error_page("שגיאה", "השם חייב להכיל לפחות 2 תווים!", back_button=True, retry_button=True)
                    self.send_response(200)
                    self.send_header('Content-type', 'text/html; charset=utf-8')
                    self.end_headers()
                    self.wfile.write(error_html.encode('utf-8'))
                    return

                # בדיקה אם הילד רשום במערכת
                if verify_child_with_parent(child_name):
                    # הילד רשום! שמירה והצלחה
                    save_registration(child_name)
                    global CHILD_NAME
                    CHILD_NAME = child_name

                    # עדכון שם הילד בclient
                    child_client.child_name = CHILD_NAME

                    # דף הצלחה מעוצב
                    success_html = create_success_page(
                        f"ברוך הבא {child_name}!",
                        "✅ נרשמת בהצלחה במערכת בקרת ההורים<br>🌐 כעת תוכל לגלוש באינטרנט בבטחה"
                    )

                    self.send_response(200)
                    self.send_header('Content-type', 'text/html; charset=utf-8')
                    self.end_headers()
                    self.wfile.write(success_html.encode('utf-8'))

                    print(f"[+] ✅ ילד נרשם בהצלחה דרך הדפדפן: {child_name}")
                    return

                else:
                    # הילד לא רשום במערכת
                    error_html = create_error_page(
                        "לא רשום במערכת",
                        f"השם '{child_name}' לא רשום במערכת בקרת ההורים.<br>💡 בקש מההורים להוסיף אותך דרך לוח הבקרה.",
                        back_button=True,
                        retry_button=True
                    )
                    self.send_response(200)
                    self.send_header('Content-type', 'text/html; charset=utf-8')
                    self.end_headers()
                    self.wfile.write(error_html.encode('utf-8'))
                    return

            except Exception as e:
                print(f"[!] שגיאה בטיפול בטופס רישום: {e}")
                error_html = create_error_page(
                    "שגיאה במערכת",
                    "אירעה שגיאה בעת עיבוד הבקשה.<br>נסה שוב או פנה לתמיכה טכנית."
                )
                self.send_response(200)
                self.send_header('Content-type', 'text/html; charset=utf-8')
                self.end_headers()
                self.wfile.write(error_html.encode('utf-8'))
        else:
            # בקשת POST אחרת - הפנייה לדף הרישום
            self.do_GET()

    def log_message(self, format, *args):
        # השתק הודעות לוג של HTTP
        return

def clear_dns_cache():
    print("[*] מנקה DNS cache...")
    try:
        result = subprocess.run(['ipconfig', '/flushdns'], capture_output=True, text=True, encoding='utf-8')
        if result.returncode == 0:
            print("[+] Windows DNS cache נוקה")
        else:
            print(f"[!] בעיה בניקוי cache: {result.stderr}")
    except Exception as e:
        print(f"[!] שגיאה בניקוי cache: {e}")


def start_block_server():
    def start_http_server():
        global BLOCK_SERVER_PORT
        # נסה קודם פורט 80, ואם לא אז 8080
        try:
            with socketserver.TCPServer(("127.0.0.1", 80), BlockHandler) as httpd:
                BLOCK_SERVER_PORT = 80
                print("[+] שרת חסימה HTTP פועל על פורט 80")
                httpd.serve_forever()
        except PermissionError:
            try:
                with socketserver.TCPServer(("127.0.0.1", 8080), BlockHandler) as httpd:
                    BLOCK_SERVER_PORT = 8080
                    print("[+] שרת חסימה HTTP פועל על פורט 8080")
                    httpd.serve_forever()
            except Exception as e:
                print(f"[!] שגיאה בשרת HTTP: {e}")
                BLOCK_SERVER_PORT = None

    print("[*] מפעיל שרת חסימה...")
    global BLOCK_SERVER_PORT
    BLOCK_SERVER_PORT = None

    http_thread = threading.Thread(target=start_http_server, daemon=True)
    http_thread.start()

    # ממתין עד שהשרת יתחיל ויגדיר את הפורט
    for i in range(10):  # ממתין עד 5 שניות
        time.sleep(0.5)
        if BLOCK_SERVER_PORT is not None:
            break

    return BLOCK_SERVER_PORT


class DNSManager:
    def __init__(self):
        self.system = platform.system()
        self.original_dns = None
        self.interface_name = None

    def is_admin(self):
        try:
            if self.system == "Windows":
                return ctypes.windll.shell32.IsUserAnAdmin()
            else:
                return os.geteuid() == 0
        except:
            return False

    def get_current_dns(self, interface_name):
        """שמירת הגדרות DNS הנוכחיות"""
        try:
            cmd = ['powershell', '-Command',
                   f'Get-DnsClientServerAddress -InterfaceAlias "{interface_name}" | Select-Object -ExpandProperty ServerAddresses']
            result = subprocess.run(cmd, capture_output=True, text=True, encoding='utf-8')
            if result.returncode == 0 and result.stdout.strip():
                dns_servers = [line.strip() for line in result.stdout.strip().split('\n') if line.strip()]
                print(f"[*] DNS נוכחי: {dns_servers}")
                return dns_servers
            else:
                print("[*] אין DNS ספציפי מוגדר (אוטומטי)")
                return []
        except Exception as e:
            print(f"[!] שגיאה בקריאת DNS נוכחי: {e}")
            return []

    def get_active_interface(self):
        try:
            cmd = ['powershell', '-Command',
                   'Get-NetAdapter | Where-Object {$_.Status -eq "Up"} | Select-Object -First 1 -ExpandProperty Name']
            result = subprocess.run(cmd, capture_output=True, text=True, encoding='utf-8')
            if result.returncode == 0 and result.stdout.strip():
                interface_name = result.stdout.strip()
                print(f"[*] נמצא ממשק: {interface_name}")
                return interface_name
        except Exception as e:
            print(f"[!] שגיאה בחיפוש ממשק: {e}")

        # גיבוי - נסה שמות נפוצים
        common_names = ['Wi-Fi', 'Ethernet', 'Local Area Connection']
        for name in common_names:
            try:
                result = subprocess.run(['netsh', 'interface', 'ip', 'show', 'config', f'name={name}'],
                                        capture_output=True, text=True, encoding='utf-8')
                if result.returncode == 0:
                    print(f"[*] נמצא ממשק: {name}")
                    return name
            except:
                continue
        return None

    def set_dns_windows(self, interface_name, dns_server):
        try:
            print(f"[*] מנסה להגדיר DNS ל-{dns_server} בממשק '{interface_name}'")

            cmd = ['powershell', '-Command',
                   f'Set-DnsClientServerAddress -InterfaceAlias "{interface_name}" -ServerAddresses "{dns_server}"']
            result = subprocess.run(cmd, capture_output=True, text=True, encoding='utf-8')

            if result.returncode == 0:
                print(f"[+] DNS הוגדר בהצלחה ל-{dns_server}")
                return True
            else:
                print(f"[!] שגיאה ב-PowerShell: {result.stderr}")
                return False
        except Exception as e:
            print(f"[!] שגיאה בהגדרת DNS: {e}")
            return False

    def setup_dns_redirect(self):
        if not self.is_admin():
            print("[!] נדרשות הרשאות מנהל לשינוי הגדרות DNS")
            print("[!] אנא הפעל את התוכנית כמנהל (Run as Administrator)")
            return False

        if self.system == "Windows":
            interface_name = self.get_active_interface()
            if interface_name:
                self.interface_name = interface_name

                # ⚠️ חשוב! שמירת הגדרות DNS הנוכחיות לפני השינוי
                current_dns = self.get_current_dns(interface_name)
                self.original_dns = current_dns

                print(f"[*] שומר DNS מקורי: {current_dns}")

                if self.set_dns_windows(interface_name, "127.0.0.1"):
                    print("[+] DNS הוגדר בהצלחה למחשב המקומי")
                    return True
            else:
                print("[!] לא נמצא ממשק רשת פעיל")
        else:
            print("[!] מערכת הפעלה לא נתמכת כרגע (נתמך רק Windows)")
        return False

    def restore_original_dns(self):
        """שחזור הגדרות DNS מקוריות"""
        if not self.interface_name:
            print("[!] אין מידע על ממשק הרשת")
            return False

        if self.system == "Windows":
            try:
                if self.original_dns and len(self.original_dns) > 0:
                    # החזרת DNS ספציפי שהיה קיים
                    dns_list = ','.join(f'"{dns}"' for dns in self.original_dns)
                    cmd = ['powershell', '-Command',
                           f'Set-DnsClientServerAddress -InterfaceAlias "{self.interface_name}" -ServerAddresses {dns_list}']
                    print(f"[*] מחזיר DNS ל: {self.original_dns}")
                else:
                    # החזרה להגדרות אוטומטיות
                    cmd = ['powershell', '-Command',
                           f'Set-DnsClientServerAddress -InterfaceAlias "{self.interface_name}" -ResetServerAddresses']
                    print(f"[*] מחזיר DNS להגדרות אוטומטיות")

                result = subprocess.run(cmd, capture_output=True, text=True, encoding='utf-8')
                if result.returncode == 0:
                    print(f"[+] ✅ DNS שוחזר בהצלחה בממשק {self.interface_name}")

                    # נקה cache של DNS
                    clear_dns_cache()
                    return True
                else:
                    print(f"[!] שגיאה בשחזור DNS: {result.stderr}")
                    return False
            except Exception as e:
                print(f"[!] שגיאה בשחזור DNS: {e}")
                return False
        return False


# שיפור פונקציית הסגירה:
def graceful_shutdown():
    print("\n" + "=" * 60)
    print("🔄 מתחיל סגירה נקייה של המערכת...")
    print("=" * 60)

    try:
        # עצירת client
        if hasattr(child_client, 'keep_running'):
            child_client.keep_running = False
            print("[*] עוצר client...")

        # שחזור DNS
        print("[*] משחזר הגדרות DNS מקוריות...")
        if dns_manager.restore_original_dns():
            print("[+] ✅ DNS שוחזר בהצלחה")
        else:
            print("[!] ⚠️ יתכן שצריך לשחזר DNS ידנית")
            print("💡 במקרה בעיה: הגדרות רשת → שנה מתאם → מאפיינים → TCP/IPv4 → קבל DNS אוטומטית")

        print("[+] ✅ מערכת נסגרה בהצלחה")
        print("=" * 60)

    except Exception as e:
        print(f"[!] ❌ שגיאה בסגירה: {e}")
        print("💡 יתכן שתצטרך לשחזר הגדרות DNS ידנית")


class ChildClient:
    def __init__(self):
            self.sock = None
            self.child_name = CHILD_NAME
            self.connected = False
            self.keep_running = True
            self.connection_event = threading.Event()

    def connect_to_parent(self):
            # אם כבר יש חיבור מהאימות, לא צריך ליצור חדש
            if self.sock and self.connected:
                print("[DEBUG] כבר מחובר מאימות קודם")
                return

            retry_count = 0
            max_retries = 5

            while self.keep_running and retry_count < max_retries:
                try:
                    print(f"[*] מנסה להתחבר לשרת הורים (ניסיון {retry_count + 1}/{max_retries})...")
                    self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    self.sock.settimeout(3)
                    self.sock.connect((PARENT_SERVER_IP, COMMUNICATION_PORT))

                    register_data = {"name": self.child_name}
                    Protocol.send_message(self.sock, Protocol.REGISTER_CHILD, register_data)

                    self.sock.settimeout(5)
                    msg_type, _ = Protocol.receive_message(self.sock)

                    if msg_type == Protocol.ACK:
                        self.connected = True
                        self.connection_event.set()
                        print(f"[+] מחובר לשרת הורים כ-{self.child_name}")
                        self.request_domains_update()
                        time.sleep(1)
                        self.listen_for_updates()
                        return

                except socket.timeout:
                    print(f"[!] timeout בחיבור לשרת הורים")
                    retry_count += 1
                except Exception as e:
                    print(f"[!] שגיאת חיבור: {e}")
                    retry_count += 1

                self.connected = False
                if self.sock:
                    try:
                        self.sock.close()
                    except:
                        pass

                if retry_count < max_retries:
                    print(f"[*] ממתין {2} שניות לפני ניסיון חוזר...")
                    time.sleep(2)

            print(f"[!] נכשל בחיבור לשרת הורים אחרי {max_retries} ניסיונות")
            print("[*] ממשיך בפעולה ללא שרת הורים")
            self.connection_event.set()

    def wait_for_connection(self, timeout=10):
        print(f"[*] ממתין לחיבור לשרת הורים (עד {timeout} שניות)...")
        if self.connection_event.wait(timeout):
            if self.connected:
                print("[+] חיבור לשרת הורים הושלם בהצלחה")
                return True
            else:
                print("[!] חיבור נכשל, ממשיך בפעולה עצמאית")
                return False
        else:
            print("[!] timeout בחיבור לשרת הורים")
            return False

    def request_domains_update(self):
        if self.connected:
            try:
                Protocol.send_message(self.sock, Protocol.GET_DOMAINS)
                print("[*] בקשה לעדכון דומיינים נשלחה")
            except Exception as e:
                print(f"[!] שגיאה בבקשת עדכון דומיינים: {e}")
                self.connected = False

    def listen_for_updates(self):
        print(f"[*] מתחיל להאזין לעדכונים מהשרת...")
        while self.connected and self.keep_running:
            try:
                self.sock.settimeout(30)
                msg_type, data = Protocol.receive_message(self.sock)

                if msg_type == Protocol.UPDATE_DOMAINS:
                    domains = data.get('domains', [])
                    global BLOCKED_DOMAINS
                    old_domains = BLOCKED_DOMAINS.copy()
                    BLOCKED_DOMAINS = set(domains)

                    print(f"[+] עודכנו דומיינים חסומים: {len(BLOCKED_DOMAINS)} דומיינים")
                    if len(BLOCKED_DOMAINS) <= 10:
                        print(f"[DEBUG] דומיינים: {list(BLOCKED_DOMAINS)}")

                    if old_domains != BLOCKED_DOMAINS:
                        print("[*] מנקה DNS cache...")
                        clear_dns_cache()

                elif msg_type == Protocol.CHILD_STATUS:
                    Protocol.send_message(self.sock, Protocol.ACK)

                elif msg_type == Protocol.GET_HISTORY:
                    send_history_update()

                elif msg_type == Protocol.ERROR:
                    print(f"[!] שגיאה מהשרת: {data}")
                    self.connected = False
                    break

            except socket.timeout:
                continue
            except Exception as e:
                print(f"[!] שגיאה בקבלת עדכון: {e}")
                self.connected = False
                break

        print("[*] הפסקת האזנה לשרת הורים")

    def send_status_update(self):
        while self.keep_running:
            if self.connected:
                try:
                    Protocol.send_message(self.sock, Protocol.CHILD_STATUS)
                except:
                    self.connected = False
            time.sleep(30)


child_client = ChildClient()
dns_manager = DNSManager()


def is_blocked_domain(query_name):
    # אם הילד לא רשום - חוסמים הכל!
    if not CHILD_NAME:
        print(f"[BLOCK] ילד לא רשום - חוסם הכל: {query_name}")
        return True

    # אם הילד רשום - רק דומיינים ספציפיים חסומים
    original_query = query_name
    query_name = query_name.lower().strip('.')

    print(f"[DEBUG] בודק דומיין: '{original_query}' -> '{query_name}' (ילד רשום: {CHILD_NAME})")

    if query_name in BLOCKED_DOMAINS:
        print(f"[DEBUG] התאמה ישירה: {query_name}")
        return True

    for blocked_domain in BLOCKED_DOMAINS:
        blocked_domain = blocked_domain.lower().strip('.')
        if query_name == blocked_domain:
            print(f"[DEBUG] התאמה מדויקת: {query_name} == {blocked_domain}")
            return True
        if query_name.endswith('.' + blocked_domain):
            print(f"[DEBUG] תת-דומיין: {query_name} סיומת של .{blocked_domain}")
            return True

    print(f"[DEBUG] {query_name} מותר")
    return False


def handle_dns_request(data, addr, sock):
    try:
        packet_response = DNS(data)
    except Exception as e:
        print(f"[!] שגיאה בניתוח בקשת DNS: {e}")
        return

    if packet_response.opcode == 0 and packet_response.qr == 0:
        try:
            query_name = packet_response[DNSQR].qname.decode().strip(".")
        except Exception as e:
            print(f"[!] שגיאה בקריאת שם הדומיין: {e}")
            return

        print(f"[+] בקשת DNS מ-{addr[0]} ל: {query_name}")
        current_time = datetime.now().isoformat()

        if is_blocked_domain(query_name):
            print(f"[-] חוסם את {query_name}, מפנה ל-{BLOCK_PAGE_IP}")
            add_to_history(query_name, current_time, was_blocked=True)

            response = DNS(
                id=packet_response.id,
                qr=1,
                aa=1,
                qd=packet_response.qd,
                an=DNSRR(rrname=packet_response.qd.qname, ttl=0, rdata=BLOCK_PAGE_IP)
            )
            sock.sendto(bytes(response), addr)
            print(f"[+] נשלחה תשובה לחסימת {query_name} ל-{addr[0]}")

        else:
            print(f"[+] מעביר את הבקשה ל-DNS האמיתי ({REAL_DNS_SERVER})")
            add_to_history(query_name, current_time, was_blocked=False)

            try:
                proxy_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                proxy_sock.settimeout(5)
                proxy_sock.sendto(data, (REAL_DNS_SERVER, 53))
                response_data, _ = proxy_sock.recvfrom(4096)
                proxy_sock.close()

                try:
                    response_dns = DNS(response_data)
                    for answer in response_dns.an:
                        answer.ttl = 0
                    sock.sendto(bytes(response_dns), addr)
                    print(f"[+] התקבלה והועברה תשובת DNS עבור {query_name} ל-{addr[0]}")
                except:
                    sock.sendto(response_data, addr)
                    print(f"[+] התקבלה והועברה תשובת DNS עבור {query_name} ל-{addr[0]}")

            except socket.timeout:
                print(f"[!] תם הזמן בהמתנה לתשובה מ-DNS האמיתי")
                error_response = DNS(id=packet_response.id, qr=1, aa=1, rcode=2, qd=packet_response.qd)
                sock.sendto(bytes(error_response), addr)
            except Exception as e:
                print(f"[!] שגיאה בהעברת הבקשה ל-DNS האמיתי: {e}")
                error_response = DNS(id=packet_response.id, qr=1, aa=1, rcode=2, qd=packet_response.qd)
                sock.sendto(bytes(error_response), addr)


def start_dns_proxy():
    print(f"[*] מפעיל Proxy DNS ל-{CHILD_NAME} על {LISTEN_IP}:{LISTEN_PORT}...")
    print(f"[*] דומיינים חסומים: {', '.join(BLOCKED_DOMAINS) if BLOCKED_DOMAINS else 'ממתין לעדכון מהשרת'}")
    print(f"[*] דף חסימה יוצג מכתובת: {BLOCK_PAGE_IP}")

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind((LISTEN_IP, LISTEN_PORT))
    except PermissionError:
        print("[!] שגיאת הרשאות: לא ניתן להאזין לפורט 53. נסה להריץ את התוכנית כמנהל.")
        return
    except socket.error as e:
        print(f"[!] שגיאת סוקט: {e}")
        return

    print("[*] DNS Proxy פועל. לחץ Ctrl+C כדי לעצור.")

    try:
        while True:
            try:
                data, addr = sock.recvfrom(512)
                threading.Thread(target=handle_dns_request, args=(data, addr, sock), daemon=True).start()
            except Exception as e:
                print(f"[!] שגיאה בטיפול בבקשה: {e}")
    except KeyboardInterrupt:
        print("\n[*] עצירת השרת על ידי המשתמש.")
    finally:
        sock.close()
        print("[*] משחזר הגדרות DNS מקוריות...")
        dns_manager.restore_original_dns()
        print("[*] השרת נסגר.")


def graceful_shutdown():
    print("\n" + "=" * 60)
    print("🔄 מתחיל סגירה נקייה של המערכת...")
    print("=" * 60)

    try:
        if hasattr(child_client, 'keep_running'):
            child_client.keep_running = False

        print("[*] משחזר הגדרות DNS מקוריות...")
        dns_manager.restore_original_dns()

        print("[+] ✅ מערכת נסגרה בהצלחה")
        print("=" * 60)

    except Exception as e:
        print(f"[!] ❌ שגיאה בסגירה: {e}")


def display_startup_messages():
    print("\n" + "=" * 70)
    print("🛡️  מערכת בקרת הורים - ילד")
    print("=" * 70)
    print(f"👶 ילד: {CHILD_NAME}")
    print(f"🔒 מצב: {'רשום במערכת' if CHILD_NAME else 'לא רשום - אינטרנט חסום'}")
    print(f"🌐 DNS: 127.0.0.1 (מקומי)")
    print(f"📡 שרת הורים: {PARENT_SERVER_IP}:{COMMUNICATION_PORT}")
    print("=" * 70)
    if CHILD_NAME:
        print("✅ המערכת פועלת - אינטרנט זמין עם חסימות")
    else:
        print("❌ נדרש רישום - אינטרנט חסום לחלוטין")
    print("=" * 70)


if __name__ == "__main__":
    try:
        print("\n🚀 מתחיל מערכת בקרת הורים...")

        print("[*] בודק רישום קיים...")
        if check_child_registration():
            print(f"[+] ✅ נמצא רישום: {CHILD_NAME}")
        else:
            print("[!] ⚠️ לא נמצא רישום תקף")
            print("[*] 🌐 מכין דף רישום...")

            # הפעלת שרת החסימה לפני הרישום
            print("[*] מפעיל שרת דף רישום...")
            server_port = start_block_server()

            if not server_port:
                print("[!] ❌ שרת לא הצליח להתחיל - בדוק הרשאות")
                sys.exit(1)

            # וגם מגדיר DNS כדי שהדף יעבוד
            print("[*] מגדיר הפניית DNS...")
            if dns_manager.setup_dns_redirect():
                print("[+] ✅ הגדרות DNS עודכנו בהצלחה")
            else:
                print("[!] ⚠️ נדרשות הרשאות מנהל - הפעל כמנהל")
                sys.exit(1)

            time.sleep(3)  # נותן זמן לשרת להתחיל

            if not wait_for_registration():
                print("\n❌ יציאה ללא רישום")
                sys.exit(1)

        display_startup_messages()

        # אם עדיין לא הגדרנו DNS (במקרה שהילד כבר היה רשום)
        if not dns_manager.original_dns:
            print("[*] מגדיר הפניית DNS...")
            if dns_manager.setup_dns_redirect():
                print("[+] ✅ הגדרות DNS עודכנו בהצלחה")
            else:
                print("[!] ⚠️ לא ניתן להגדיר DNS אוטומטית")
                print("\n--- הגדרה ידנית ---")
                print("1. פתח 'הגדרות רשת' או 'Network Settings'")
                print("2. לחץ על 'שנה אפשרויות מתאם' או 'Change adapter options'")
                print("3. לחץ ימני על הרשת שלך ובחר 'מאפיינים' או 'Properties'")
                print("4. בחר 'Internet Protocol Version 4 (TCP/IPv4)' ולחץ 'מאפיינים'")
                print("5. בחר 'השתמש בכתובות DNS הבאות' ובשדה הראשון הכנס: 127.0.0.1")
                print("6. לחץ OK לשמירה")
                print("-------------------------\n")
                input("לחץ Enter אחרי שהגדרת את ה-DNS...")

        # רק אם השרת לא רץ כבר (במקרה שהילד כבר היה רשום)
        if BLOCK_SERVER_PORT is None:
            print("[*] מפעיל שרת דף חסימה...")
            start_block_server()

        print("[*] מתחיל חיבור לשרת הורים...")
        child_client.child_name = CHILD_NAME
        connection_thread = threading.Thread(target=child_client.connect_to_parent, daemon=True)
        connection_thread.start()

        child_client.wait_for_connection(timeout=8)

        registration_check_thread = threading.Thread(target=periodic_registration_check, daemon=True)
        registration_check_thread.start()

        status_thread = threading.Thread(target=child_client.send_status_update, daemon=True)
        status_thread.start()

        if not child_client.connected:
            print("[*] פועל ללא שרת הורים - רק דומיינים שיתקבלו מאוחר יותר יחסמו")

        print("=" * 70)
        print(f"🎉 מערכת בקרת הורים פעילה עבור {CHILD_NAME}")
        print(f"🔒 דומיינים חסומים: {len(BLOCKED_DOMAINS)}")
        print("[*] מפעיל DNS Proxy...")
        print("🛑 לחץ Ctrl+C לעצירת המערכת")
        print("=" * 70)

        start_dns_proxy()

    except KeyboardInterrupt:
        print("\n🛑 התקבלה בקשת עצירה...")
        graceful_shutdown()
    except Exception as e:
        print(f"\n[!] ❌ שגיאה קריטית: {e}")
        graceful_shutdown()
        sys.exit(1)