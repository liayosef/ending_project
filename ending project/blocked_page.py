from http.server import BaseHTTPRequestHandler, HTTPServer
import socket

PORT = 8080


class BlockPageHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        # שליחת סטטוס
        self.send_response(200)
        # שליחת כותרות
        self.send_header('Content-type', 'text/html; charset=utf-8')
        self.end_headers()

        # קבלת הדומיין שנחסם
        requested_domain = self.headers.get('Host', 'לא ידוע')

        # תבנית HTML מעוצבת
        html = f"""<!DOCTYPE html>
<html lang="he" dir="rtl">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>אתר חסום</title>
    <style>
        /* אפס עיצוב ברירת מחדל */
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}

        /* עיצוב גוף הדף */
        body {{
            font-family: 'Segoe UI', Arial, sans-serif;
            background: linear-gradient(135deg, #f5f7fa 0%, #c3cfe2 100%);
            min-height: 100vh;
            display: flex;
            justify-content: center;
            align-items: center;
            padding: 20px;
            direction: rtl;
        }}

        /* מיכל ראשי */
        .blocked-container {{
            background-color: #ffffff;
            border-radius: 20px;
            box-shadow: 0 15px 35px rgba(50, 50, 93, 0.1), 0 5px 15px rgba(0, 0, 0, 0.07);
            padding: 40px;
            width: 100%;
            max-width: 600px;
            text-align: center;
            position: relative;
            overflow: hidden;
        }}

        /* אייקון נעילה */
        .lock-icon {{
            width: 100px;
            height: 100px;
            background-color: #f44336;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            margin: 0 auto 30px;
            font-size: 50px;
            color: white;
            box-shadow: 0 5px 15px rgba(244, 67, 54, 0.4);
        }}

        /* כותרות */
        .title {{
            color: #303952;
            font-size: 36px;
            margin-bottom: 10px;
            font-weight: 700;
        }}

        .subtitle {{
            color: #596275;
            font-size: 18px;
            margin-bottom: 30px;
            font-weight: 400;
        }}

        /* תיבת הדומיין */
        .domain-box {{
            background-color: #f8f9fa;
            border: 2px solid #ff9800;
            border-radius: 10px;
            padding: 15px;
            margin: 20px 0;
            font-weight: 600;
            font-size: 18px;
            color: #303952;
            word-break: break-all;
            box-shadow: 0 3px 8px rgba(255, 152, 0, 0.2);
            position: relative;
        }}

        .domain-box::before {{
            content: 'דומיין:';
            position: absolute;
            top: -12px;
            right: 20px;
            background-color: #f8f9fa;
            padding: 0 10px;
            font-size: 14px;
            color: #ff9800;
            font-weight: 600;
        }}

        /* הודעה */
        .message {{
            color: #596275;
            font-size: 16px;
            margin-bottom: 30px;
            line-height: 1.6;
        }}

        /* כפתור */
        .back-button {{
            background-color: #f44336;
            color: white;
            border: none;
            border-radius: 50px;
            padding: 12px 30px;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
            text-decoration: none;
            display: inline-block;
            transition: all 0.3s ease;
            box-shadow: 0 4px 6px rgba(244, 67, 54, 0.2);
        }}

        .back-button:hover {{
            background-color: #d32f2f;
            transform: translateY(-2px);
            box-shadow: 0 7px 14px rgba(244, 67, 54, 0.3);
        }}

        /* קישוט רקע */
        .decoration {{
            position: absolute;
            width: 200px;
            height: 200px;
            border-radius: 50%;
            opacity: 0.05;
            z-index: 0;
        }}

        .decoration-1 {{
            background-color: #f44336;
            top: -100px;
            left: -100px;
        }}

        .decoration-2 {{
            background-color: #ff9800;
            bottom: -100px;
            right: -100px;
        }}

        /* תוכן - על הקישוט */
        .content {{
            position: relative;
            z-index: 1;
        }}

        /* תמיכה במסכים קטנים */
        @media (max-width: 480px) {{
            .blocked-container {{
                padding: 30px 20px;
            }}

            .title {{
                font-size: 28px;
            }}

            .subtitle {{
                font-size: 16px;
            }}

            .lock-icon {{
                width: 80px;
                height: 80px;
                font-size: 40px;
                margin-bottom: 20px;
            }}
        }}
    </style>
</head>
<body>
    <div class="blocked-container">
        <!-- קישוטי רקע -->
        <div class="decoration decoration-1"></div>
        <div class="decoration decoration-2"></div>

        <!-- תוכן העמוד -->
        <div class="content">
            <div class="lock-icon">🔒</div>
            <h1 class="title">הגישה נחסמה</h1>
            <h2 class="subtitle">האתר שביקשת חסום על-ידי מערכת ההגנה</h2>

            <div class="domain-box">
                {requested_domain}
            </div>

            <p class="message">
                אתר זה נחסם בהתאם למדיניות הגלישה הבטוחה.<br>
                לקבלת גישה, אנא פנה להורים או למנהל המערכת.
            </p>

            <a href="javascript:history.back()" class="back-button">חזרה לדף הקודם</a>
        </div>
    </div>
</body>
</html>"""

        # שליחת התוכן
        self.wfile.write(html.encode('utf-8'))
        print(f"נשלח דף חסימה ל-{requested_domain}")


def get_local_ip():
    """מציאת כתובת IP מקומית"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except:
        return "127.0.0.1"


def run_server(port=PORT):
    """הפעלת שרת דף החסימה"""
    server_address = ('', port)
    httpd = HTTPServer(server_address, BlockPageHandler)

    local_ip = get_local_ip()

    print(f"[*] שרת דף החסימה פועל!")
    print(f"[*] גישה מקומית: http://localhost:{port}")
    print(f"[*] גישה ברשת: http://{local_ip}:{port}")
    print("[*] לחץ Ctrl+C כדי לעצור")

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] עצירת שרת החסימה")
        httpd.server_close()
    except Exception as e:
        print(f"[!] שגיאה: {e}")


if __name__ == '__main__':
    try:
        run_server()
    except PermissionError:
        print("[!] שגיאת הרשאות: לא ניתן להאזין לפורט")
        print("[*] מנסה להשתמש בפורט 8081 במקום...")
        run_server(8081)