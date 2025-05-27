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


