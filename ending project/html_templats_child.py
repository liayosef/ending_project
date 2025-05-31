REGISTRATION_HTML_TEMPLATE = '''<!DOCTYPE html>
<html lang="he" dir="rtl">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>רישום - בקרת הורים</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        html, body {
            height: 100%;
            width: 100%;
            font-family: 'Segoe UI', Tahoma, Arial, sans-serif;
            background: linear-gradient(135deg, #f8f9fa 0%, #e9ecef 100%);
            display: flex;
            justify-content: center;
            align-items: center;
            overflow: hidden;
        }

        .full-container {
            position: fixed;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            display: flex;
            justify-content: center;
            align-items: center;
            background: linear-gradient(135deg, #f8f9fa 0%, #e9ecef 100%);
            min-height: 100vh;
            width: 100vw;
        }

        .form-container {
            background: rgba(255, 255, 255, 0.95);
            backdrop-filter: blur(10px);
            padding: 60px 50px;
            border-radius: 20px;
            width: 90%;
            max-width: 500px;
            box-shadow: 0 20px 40px rgba(0, 0, 0, 0.3);
            text-align: center;
            border: 1px solid rgba(255, 255, 255, 0.2);
        }

        .logo-circle {
            background: linear-gradient(135deg, #4a6fa5, #6a5acd);
            width: 100px;
            height: 100px;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 50px;
            color: white;
            margin: 0 auto 30px;
            box-shadow: 0 10px 20px rgba(0, 0, 0, 0.2);
        }

        h1 {
            color: #2c3e50;
            font-size: 32px;
            margin: 0 0 20px;
            font-weight: bold;
        }

        .subtitle {
            color: #555;
            font-size: 18px;
            margin-bottom: 40px;
            line-height: 1.5;
        }

        .form-group {
            margin-bottom: 30px;
            text-align: right;
        }

        label {
            display: block;
            font-weight: bold;
            margin-bottom: 10px;
            color: #2c3e50;
            font-size: 18px;
        }

        input[type="text"] {
            width: 100%;
            padding: 18px 20px;
            border: 2px solid #e1e8ed;
            border-radius: 12px;
            font-size: 18px;
            text-align: right;
            transition: all 0.3s ease;
            background: rgba(255, 255, 255, 0.9);
        }

        input[type="text"]:focus {
            outline: none;
            border-color: #4a6fa5;
            box-shadow: 0 0 0 3px rgba(74, 111, 165, 0.1);
            background: white;
        }

        .submit-btn {
            background: linear-gradient(135deg, #4a6fa5, #6a5acd);
            color: white;
            padding: 18px 40px;
            border: none;
            border-radius: 12px;
            font-size: 18px;
            font-weight: bold;
            cursor: pointer;
            width: 100%;
            margin-top: 20px;
            transition: all 0.3s ease;
            box-shadow: 0 5px 15px rgba(74, 111, 165, 0.3);
        }

        .submit-btn:hover {
            transform: translateY(-2px);
            box-shadow: 0 8px 25px rgba(74, 111, 165, 0.4);
        }

        .info-text {
            background: rgba(248, 249, 250, 0.9);
            padding: 20px;
            border-radius: 12px;
            border-left: 4px solid #4a6fa5;
            margin-top: 30px;
            font-size: 16px;
            color: #555;
            line-height: 1.5;
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

        /* אנימציות */
        @keyframes fadeIn {
            from {
                opacity: 0;
                transform: translateY(30px);
            }
            to {
                opacity: 1;
                transform: translateY(0);
            }
        }

        .form-container {
            animation: fadeIn 0.8s ease-out;
        }

        /* ריספונסיבי */
        @media (max-width: 600px) {
            .form-container {
                padding: 40px 30px;
                margin: 20px;
                width: calc(100% - 40px);
            }

            h1 {
                font-size: 28px;
            }

            .logo-circle {
                width: 80px;
                height: 80px;
                font-size: 40px;
            }
        }
    </style>
</head>
<body>
    <div class="full-container">
        <div class="form-container">
            <div class="logo-circle">🛡️</div>
            <h1>מערכת בקרת הורים</h1>
            <div class="subtitle">האינטרנט מוגבל עד לרישום במערכת</div>
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
    </div>
</body>
</html>'''

BLOCK_HTML_TEMPLATE = '''<!DOCTYPE html>
<html lang="he" dir="rtl">
<head>
    <meta charset="UTF-8">
    <title>אתר חסום - {child_name}</title>
    <style>
        body {{ 
            font-family: 'Segoe UI', Tahoma, Arial, sans-serif;
            background: linear-gradient(135deg, #ff4757, #ff6b6b);
            min-height: 100vh;
            display: flex;
            justify-content: center;
            align-items: center;
            padding: 20px;
            margin: 0;
            color: white;
        }}
        .child-name-tag {{
            position: fixed;
            top: 20px;
            right: 20px;
            background: rgba(0,0,0,0.8);
            padding: 10px 20px;
            border-radius: 25px;
            font-size: 14px;
            font-weight: bold;
        }}
        .block-container {{
            background: rgba(255,255,255,0.1);
            backdrop-filter: blur(10px);
            padding: 50px;
            border-radius: 20px;
            max-width: 600px;
            width: 100%;
            box-shadow: 0 15px 35px rgba(0,0,0,0.3);
            border: 1px solid rgba(255,255,255,0.2);
            text-align: center;
        }}
        .block-icon {{
            background: rgba(255,255,255,0.2);
            width: 100px;
            height: 100px;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 50px;
            margin: 0 auto 30px;
        }}
        h1 {{
            font-size: 36px;
            margin: 0 0 20px;
            font-weight: bold;
        }}
        .warning-box {{
            background: rgba(255,255,255,0.15);
            border: 2px solid rgba(255,255,255,0.3);
            border-radius: 15px;
            padding: 25px;
            margin: 30px 0;
        }}
        .warning-box p {{
            margin: 10px 0;
            font-size: 18px;
        }}
        .warning-box strong {{
            font-weight: bold;
            color: #fff;
        }}
        .description {{
            font-size: 18px;
            line-height: 1.6;
            margin: 20px 0;
            opacity: 0.9;
        }}
        .advice {{
            background: rgba(255,255,255,0.1);
            padding: 20px;
            border-radius: 10px;
            margin-top: 30px;
            font-size: 16px;
        }}
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
    """יצירת דף שגיאה - גרסה מתוקנת שתמיד מחזירה תוכן תקף"""

    # ודא שהפרמטרים תקינים
    if not title:
        title = "שגיאה"
    if not message:
        message = "אירעה שגיאה במערכת"

    buttons = ""

    if retry_button:
        buttons += '''
        <button onclick="tryAgain()" class="submit-btn retry-btn">נסה שוב</button>
        '''

    if back_button:
        buttons += '''
        <button onclick="goBack()" class="submit-btn back-btn">חזור</button>
        '''

    script = '''
    <script>
        function goBack() {
            console.log("מנסה לחזור...");

            try {
                if (window.history.length > 1) {
                    window.history.back();
                    setTimeout(function() {
                        window.location.href = '/';
                    }, 1000);
                } else {
                    window.location.href = '/';
                }
            } catch (e) {
                console.log("שגיאה בחזרה:", e);
                window.location.href = '/';
            }
        }

        function tryAgain() {
            console.log("חוזר לדף הרישום...");
            window.location.href = '/';
        }

        window.onload = function() {
            console.log("אורך היסטוריה:", window.history.length);

            var backButton = document.querySelector('button[onclick*="goBack"]');
            if (backButton && window.history.length <= 1) {
                backButton.textContent = 'דף הרישום';
            }
        }

        window.addEventListener('error', function(e) {
            console.log('שגיאת JavaScript:', e.error);
        });
    </script>
    '''

    html_content = f'''<!DOCTYPE html>
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
            transition: all 0.3s ease;
        }}
        .submit-btn:hover {{
            opacity: 0.9;
            transform: translateY(-2px);
        }}
        .button-container {{
            margin-top: 30px;
        }}
        .retry-btn {{
            background: #28a745;
            margin-left: 10px;
        }}
        .back-btn {{
            background: #95a5a6;
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

    return html_content


def create_success_page(title, message):
    """יצירת דף הצלחה - גרסה מתוקנת"""

    if not title:
        title = "הצלחה"
    if not message:
        message = "הפעולה הושלמה בהצלחה"

    html_content = f'''<!DOCTYPE html>
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
            color: #28a745; 
            font-size: 24px; 
            margin-bottom: 20px; 
        }}
        p {{ 
            color: #666; 
            font-size: 16px; 
            line-height: 1.6; 
        }}
        .highlight {{ 
            background: #d4edda; 
            padding: 15px; 
            border-radius: 8px; 
            margin: 20px 0; 
            border-left: 4px solid #28a745; 
        }}
        .auto-close {{
            color: #888;
            font-size: 14px;
            margin-top: 20px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="icon">🎉</div>
        <h1>{title}</h1>
        <div class="highlight">{message}</div>
        <p>תוכל לסגור את הדף הזה ולהתחיל לגלוש באינטרנט</p>
        <div class="auto-close">הדף יסגר אוטומטית בעוד <span id="countdown">5</span> שניות</div>
    </div>

    <script>
        let countdown = 5;
        const countdownElement = document.getElementById('countdown');

        const timer = setInterval(function() {{
            countdown--;
            countdownElement.textContent = countdown;

            if (countdown <= 0) {{
                clearInterval(timer);
                window.close();
                setTimeout(function() {{
                    window.location.href = '/';
                }}, 500);
            }}
        }}, 1000);
    </script>
</body>
</html>'''

    return html_content


def create_connection_error_page():
    """דף שגיאה מיוחד לבעיות חיבור לשרת הורים"""

    return create_error_page(
        "שרת ההורים לא זמין",
        "לא ניתן להתחבר לשרת בקרת ההורים.<br><br>"
        "🔍 ודא ש:<br>"
        "• שרת ההורים פועל<br>"
        "• החיבור לרשת תקין<br>"
        "• הגדרות הפיירוול מתירות חיבור<br><br>"
        "💡 נסה להפעיל את שרת ההורים ואז רענן את הדף",
        back_button=True,
        retry_button=True
    )


def create_not_registered_page(child_name):
    """דף שגיאה מיוחד לילד שלא רשום"""

    return create_error_page(
        "לא רשום במערכת",
        f"השם '{child_name}' לא רשום במערכת בקרת ההורים.<br><br>"
        "💡 בקש מההורים להוסיף אותך דרך לוח הבקרה:<br>"
        "1. ניהול ילדים<br>"
        "2. הוסף ילד חדש<br>"
        "3. הכנס את השם שלך<br><br>"
        "🔄 אחרי שההורים יוסיפו אותך, חזור ונסה שוב",
        back_button=True,
        retry_button=True
    )