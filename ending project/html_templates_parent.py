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
        .nav-buttons {
            text-align: center;
            margin: 20px 0;
        }
        .nav-btn {
            background: #17a2b8;
            color: white;
            padding: 12px 25px;
            border-radius: 8px;
            text-decoration: none;
            font-weight: bold;
            margin: 0 10px;
        }
        .nav-btn:hover {
            background: #138496;
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
        <div class="nav-buttons">
            <a href="/manage_children" class="nav-btn">ניהול ילדים</a>
            <a href="/browsing_history" class="nav-btn">היסטוריית גלישה</a>
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

BROWSING_HISTORY_TEMPLATE = """<!DOCTYPE html>
<html lang="he" dir="rtl">
<head>
    <meta charset="UTF-8">
    <title>היסטוריית גלישה - בקרת הורים</title>
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
        .filter-container {
            background: white;
            padding: 20px;
            border-radius: 15px;
            margin-bottom: 20px;
            box-shadow: 0 5px 15px rgba(0,0,0,0.05);
        }
        .filter-form {
            display: flex;
            gap: 15px;
            align-items: center;
            flex-wrap: wrap;
        }
        .filter-input {
            padding: 10px 15px;
            border: 2px solid #e1e8ed;
            border-radius: 8px;
            font-size: 14px;
        }
        .filter-btn {
            background: #4a6fa5;
            color: white;
            border: none;
            padding: 10px 20px;
            border-radius: 8px;
            cursor: pointer;
            font-weight: bold;
        }
        .history-container {
            background: white;
            border-radius: 15px;
            margin: 20px 0;
            box-shadow: 0 5px 15px rgba(0,0,0,0.05);
        }
        .history-header {
            padding: 20px;
            border-bottom: 1px solid #e1e8ed;
            background: #f8f9fa;
            border-radius: 15px 15px 0 0;
        }
        .history-list {
            max-height: 600px;
            overflow-y: auto;
        }
        .history-item {
            padding: 15px 20px;
            border-bottom: 1px solid #e1e8ed;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .history-item:hover {
            background: #f8f9fa;
        }
        .domain-info {
            flex: 1;
        }
        .domain-name {
            font-weight: bold;
            font-size: 16px;
            margin-bottom: 5px;
        }
        .domain-time {
            color: #666;
            font-size: 14px;
        }
        .status-badge {
            padding: 5px 12px;
            border-radius: 15px;
            font-size: 12px;
            font-weight: bold;
        }
        .status-blocked {
            background: #f8d7da;
            color: #721c24;
        }
        .status-allowed {
            background: #d4edda;
            color: #155724;
        }
        .empty-message {
            padding: 40px;
            text-align: center;
            color: #666;
            font-style: italic;
        }
        .stats-container {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        .stat-card {
            background: white;
            padding: 20px;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.05);
            text-align: center;
        }
        .stat-number {
            font-size: 2em;
            font-weight: bold;
            color: #4a6fa5;
        }
        .stat-label {
            color: #666;
            font-size: 14px;
        }
        .danger-btn {
           background: #e74c3c !important;
        }
        .danger-btn:hover {
           background: #c0392b !important;
        }

        /* CSS לקיבוץ היסטוריה */
        .grouped-item {
            background: #f8f9fa;
            border-left: 4px solid #4a6fa5;
        }

        .activity-badge {
            background: #17a2b8;
            color: white;
            padding: 2px 6px;
            border-radius: 10px;
            font-size: 11px;
            font-weight: bold;
        }

        .grouped-item .status-badge {
            min-width: 120px;
            font-size: 11px;
        }

        .site-name {
            font-weight: bold;
            font-size: 16px;
            color: #333;
        }

        .main-domain {
            color: #666;
            font-style: italic;
            font-size: 12px;
        }

        .domain-name {
            line-height: 1.4;
        }

        .history-item:hover .site-name {
            color: #4a6fa5;
        }
    </style>
</head>
<body>
    <!-- שאר ה-HTML ללא שינוי -->
    <div class="header">
        <div class="header-content">
            <div class="logo-container">
                <div class="logo-circle">🛡️</div>
                <h1>היסטוריית גלישה</h1>
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

        <div class="stats-container">
            ${stats_cards}
        </div>

        <div class="filter-container">
            <h3>סינון היסטוריה</h3>
            <form method="get" action="/browsing_history" class="filter-form">
                <select name="child" class="filter-input">
                    <option value="">כל הילדים</option>
                    ${children_options}
                </select>
                <select name="status" class="filter-input">
                    <option value="">כל הסטטוסים</option>
                    <option value="blocked">חסום</option>
                    <option value="allowed">מותר</option>
                </select>
                <input type="text" name="domain" class="filter-input" placeholder="חפש דומיין..." value="${domain_filter}">
                <button type="submit" class="filter-btn">סנן</button>
                <a href="/browsing_history" class="filter-btn" style="background: #95a5a6; text-decoration: none;">נקה סינון</a>
            </form>
        </div>
        <form method="post" action="/clear_history" style="display: inline-block; margin-right: 15px;">
            <select name="child" class="filter-input" required>
                <option value="">בחר ילד למחיקת היסטוריה</option>
                ${children_options}
            </select>
            <button type="submit" class="filter-btn" style="background: #e74c3c;" 
                    onclick="return confirm('האם אתה בטוח שברצונך למחוק את כל ההיסטוריה של הילד הנבחר?')">
                🗑️ מחק היסטוריה
            </button>
        </form>
        <div class="history-container">
            <div class="history-header">
                <h3>היסטוריית גלישה (${total_entries} רשומות)</h3>
            </div>
            <div class="history-list">
                ${history_entries}
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

