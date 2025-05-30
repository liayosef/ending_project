import socket
import threading
import time
import os
from urllib.parse import parse_qs

# קבועים עבור השרת
QUEUE_SIZE = 10
SOCKET_TIMEOUT = 10
MAX_PACKET = 1024
HTTP_VERSION = "HTTP/1.1"

# תגובות HTTP
OK_RESPONSE = "200 OK"
BAD_REQUEST = "400 BAD REQUEST"
NOT_FOUND = "404 NOT FOUND"
INTERNAL_ERROR = "500 INTERNAL SERVER ERROR"

# סוגי תוכן
CONTENT_TYPES = {
    '.html': "text/html; charset=utf-8",
    '.css': "text/css",
    '.js': "text/javascript; charset=utf-8",
    '.png': "image/png",
    '.jpg': "image/jpeg",
    '.ico': "image/x-icon",
    '.txt': "text/plain; charset=utf-8"
}


class ParentalControlHTTPServer:
    """שרת HTTP מותאם אישית למערכת בקרת הורים"""

    def __init__(self, ip="127.0.0.1", port=8080):
        self.ip = ip
        self.port = port
        self.server_socket = None
        self.running = False

        # נתונים מהמערכת הראשית (יועברו מבחוץ)
        self.child_name = None
        self.registration_html = ""
        self.block_html_template = ""
        self.verify_child_callback = None

        # פונקציות חיצוניות לעיצוב דפים
        self.external_create_error_page = None
        self.external_create_success_page = None

    def set_templates(self, registration_html, block_html_template):
        """הגדרת תבניות HTML"""
        self.registration_html = registration_html
        self.block_html_template = block_html_template

    def set_child_data(self, child_name):
        """עדכון נתוני הילד"""
        self.child_name = child_name

    def set_external_functions(self, create_error_func=None, create_success_func=None):
        """הגדרת פונקציות חיצוניות ליצירת דפים"""
        self.external_create_error_page = create_error_func
        self.external_create_success_page = create_success_func

    def set_verify_callback(self, callback_func):
        """הגדרת פונקציית callback לאימות ילד"""
        self.verify_child_callback = callback_func

    def start_server(self):
        """התחלת השרת"""
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind((self.ip, self.port))
            self.server_socket.listen(QUEUE_SIZE)
            self.running = True

            print(f"[+] שרת HTTP מותאם אישית פועל על {self.ip}:{self.port}")

            while self.running:
                try:
                    client_socket, client_address = self.server_socket.accept()
                    print(f"[*] חיבור חדש מ-{client_address[0]}:{client_address[1]}")

                    # טיפול בלקוח בthread נפרד
                    client_thread = threading.Thread(
                        target=self.handle_client,
                        args=(client_socket,),
                        daemon=True
                    )
                    client_thread.start()

                except socket.error as e:
                    if self.running:  # רק אם לא סגרנו בכוונה
                        print(f"[!] שגיאה בקבלת חיבור: {e}")

        except Exception as e:
            print(f"[!] שגיאה בהפעלת השרת: {e}")
        finally:
            self.stop_server()

    def stop_server(self):
        """עצירת השרת"""
        self.running = False
        if self.server_socket:
            try:
                self.server_socket.close()
                print("[*] שרת HTTP נסגר")
            except:
                pass

    def handle_client(self, client_socket):
        """טיפול בלקוח - מבוסס על הקוד המקורי"""
        try:
            client_socket.settimeout(SOCKET_TIMEOUT)

            # קבלת הבקשה בחלקים
            request_data = b''
            while True:
                try:
                    chunk = client_socket.recv(MAX_PACKET)
                    if not chunk:
                        break
                    request_data += chunk

                    # בדיקה אם הבקשה הושלמה
                    if b'\r\n\r\n' in request_data:
                        break

                except socket.timeout:
                    break
                except socket.error:
                    break

            if request_data:
                # ניתוח הבקשה
                request_str = request_data.decode('utf-8', errors='ignore')
                valid_http, method, uri, headers = self.validate_http_request(request_str)

                if valid_http:
                    print(f"[+] בקשה תקינה: {method} {uri}")

                    # טיפול בבקשה לפי סוג
                    if method == "GET":
                        response = self.handle_get_request(uri)
                    elif method == "POST":
                        # חילוץ גוף ההודעה לPOST
                        post_data = self.extract_post_data(request_str)
                        response = self.handle_post_request(uri, post_data)
                    else:
                        response = self.create_error_response(400, "Method Not Allowed")

                    self.send_response(client_socket, response)
                else:
                    print("[!] בקשה לא תקינה")
                    error_response = self.create_error_response(400, "Bad Request")
                    self.send_response(client_socket, error_response)

        except Exception as e:
            print(f"[!] שגיאה בטיפול בלקוח: {e}")
        finally:
            try:
                client_socket.close()
            except:
                pass

    def validate_http_request(self, request):
        """בדיקת תקינות בקשת HTTP - מבוסס על הקוד המקורי"""
        try:
            lines = request.split('\r\n')
            if not lines:
                return False, "", "", {}

            # שורת הבקשה הראשונה
            request_line_parts = lines[0].split(' ')
            if len(request_line_parts) != 3:
                return False, "", "", {}

            method, uri, version = request_line_parts

            # בדיקות תקינות
            if version != "HTTP/1.1":
                return False, "", "", {}
            if method not in ["GET", "POST"]:
                return False, "", "", {}
            if not uri.startswith("/"):
                return False, "", "", {}

            # חילוץ headers
            headers = {}
            for line in lines[1:]:
                if line.strip() == "":
                    break
                if ':' in line:
                    key, value = line.split(':', 1)
                    headers[key.strip().lower()] = value.strip()

            return True, method, uri, headers

        except Exception as e:
            print(f"[!] שגיאה בניתוח בקשה: {e}")
            return False, "", "", {}

    def extract_post_data(self, request_str):
        """חילוץ נתוני POST"""
        try:
            # מציאת גוף ההודעה (אחרי \r\n\r\n)
            body_start = request_str.find('\r\n\r\n')
            if body_start != -1:
                return request_str[body_start + 4:]
            return ""
        except:
            return ""

    def handle_get_request(self, uri):
        """טיפול בבקשות GET"""
        try:
            # דף בית / דף רישום
            if uri == "/" or uri == "/register":
                if not self.child_name:
                    # דף רישום
                    html_content = self.registration_html
                    return self.create_response(200, "OK", html_content, "text/html")
                else:
                    # דף חסימה
                    current_time = time.strftime('%H:%M:%S')
                    block_html = self.block_html_template.format(
                        child_name=self.child_name,
                        host="אתר חסום",
                        current_time=current_time
                    )
                    return self.create_response(200, "OK", block_html, "text/html")

            # קבצים סטטיים (אם נדרש)
            elif uri.startswith("/static/"):
                return self.serve_static_file(uri)

            # 404 לכל השאר
            else:
                error_html = self.create_error_page("דף לא נמצא", "הדף המבוקש לא קיים")
                return self.create_response(404, "NOT FOUND", error_html, "text/html")

        except Exception as e:
            print(f"[!] שגיאה בטיפול ב-GET: {e}")
            return self.create_error_response(500, "Internal Server Error")

    def handle_post_request(self, uri, post_data):
        """טיפול בבקשות POST"""
        try:
            if uri == "/register":
                # טיפול ברישום
                return self.handle_registration(post_data)
            else:
                return self.create_error_response(404, "Not Found")

        except Exception as e:
            print(f"[!] שגיאה בטיפול ב-POST: {e}")
            return self.create_error_response(500, "Internal Server Error")

    def handle_registration(self, post_data):
        """טיפול ברישום ילד"""
        try:
            # פיענוח נתוני הטופס
            form_data = parse_qs(post_data)
            child_name = ""

            if 'child_name' in form_data:
                child_name = form_data['child_name'][0].strip()

            print(f"[*] ניסיון רישום: '{child_name}'")

            # בדיקות תקינות
            if not child_name:
                if self.external_create_error_page:
                    error_html = self.external_create_error_page("שגיאה", "השם לא יכול להיות ריק!", back_button=True,
                                                                 retry_button=True)
                else:
                    error_html = self.create_error_page("שגיאה", "השם לא יכול להיות ריק!")
                return self.create_response(400, "BAD REQUEST", error_html, "text/html")

            if len(child_name) < 2:
                if self.external_create_error_page:
                    error_html = self.external_create_error_page("שגיאה", "השם חייב להכיל לפחות 2 תווים!",
                                                                 back_button=True, retry_button=True)
                else:
                    error_html = self.create_error_page("שגיאה", "השם חייב להכיל לפחות 2 תווים!")
                return self.create_response(400, "BAD REQUEST", error_html, "text/html")

            # קריאה לפונקציית האימות מהמערכת הראשית
            if self.verify_child_callback:
                if self.verify_child_callback(child_name):
                    # רישום הצליח
                    self.child_name = child_name
                    if self.external_create_success_page:
                        success_html = self.external_create_success_page(
                            f"ברוך הבא {child_name}!",
                            "נרשמת בהצלחה במערכת בקרת ההורים<br>כעת תוכל לגלוש באינטרנט בבטחה"
                        )
                    else:
                        success_html = self.create_success_page(
                            f"ברוך הבא {child_name}!",
                            "נרשמת בהצלחה במערכת בקרת ההורים<br>כעת תוכל לגלוש באינטרנט בבטחה"
                        )
                    return self.create_response(200, "OK", success_html, "text/html")
                else:
                    # הילד לא רשום במערכת
                    if self.external_create_error_page:
                        error_html = self.external_create_error_page(
                            "לא רשום במערכת",
                            f"השם '{child_name}' לא רשום במערכת בקרת ההורים.<br>💡 בקש מההורים להוסיף אותך דרך לוח הבקרה.",
                            back_button=True,
                            retry_button=True
                        )
                    else:
                        error_html = self.create_error_page(
                            "לא רשום במערכת",
                            f"השם '{child_name}' לא רשום במערכת בקרת ההורים.<br>💡 בקש מההורים להוסיף אותך דרך לוח הבקרה."
                        )
                    return self.create_response(403, "FORBIDDEN", error_html, "text/html")
            else:
                return self.create_error_response(500, "Registration system not available")

        except Exception as e:
            print(f"[!] שגיאה בטיפול ברישום: {e}")
            return self.create_error_response(500, "Internal Server Error")

    def serve_static_file(self, uri):
        """הגשת קבצים סטטיים"""
        try:
            # הסרת /static/ מההתחלה
            file_path = uri[8:]  # מסיר /static/

            # בדיקת אבטחה - מניעת ../ attacks
            if ".." in file_path or file_path.startswith("/"):
                return self.create_error_response(403, "Forbidden")

            # קביעת סוג התוכן
            file_extension = os.path.splitext(file_path)[1].lower()
            content_type = CONTENT_TYPES.get(file_extension, "application/octet-stream")

            # קריאת הקובץ (זה רק דוגמה - בפועל תצטרך לאמת שהקובץ קיים)
            file_data = b"<h1>Static file not implemented</h1>"

            return self.create_response(200, "OK", file_data, content_type)

        except Exception as e:
            return self.create_error_response(404, "File Not Found")

    def create_response(self, status_code, status_text, content, content_type):
        """יצירת תגובת HTTP מלאה"""
        try:
            # המרה לbytes אם נדרש
            if isinstance(content, str):
                content_bytes = content.encode('utf-8')
            else:
                content_bytes = content

            # בניית headers
            response_line = f"{HTTP_VERSION} {status_code} {status_text}\r\n"
            headers = f"Content-Type: {content_type}\r\n"
            headers += f"Content-Length: {len(content_bytes)}\r\n"
            headers += "Connection: close\r\n"
            headers += "\r\n"

            # חיבור הכל
            response_headers = (response_line + headers).encode('utf-8')
            return response_headers + content_bytes

        except Exception as e:
            print(f"[!] שגיאה ביצירת תגובה: {e}")
            return self.create_error_response(500, "Internal Server Error")

    def create_error_response(self, status_code, status_text):
        """יצירת תגובת שגיאה"""
        error_html = f"""
        <!DOCTYPE html>
        <html dir="rtl" lang="he">
        <head>
            <meta charset="UTF-8">
            <title>שגיאה {status_code}</title>
        </head>
        <body>
            <h1>שגיאה {status_code}</h1>
            <p>{status_text}</p>
        </body>
        </html>
        """
        return self.create_response(status_code, status_text, error_html, "text/html")

    def create_error_page(self, title, message):
        """יצירת דף שגיאה מעוצב"""
        return f"""
        <!DOCTYPE html>
        <html dir="rtl" lang="he">
        <head>
            <meta charset="UTF-8">
            <title>{title}</title>
            <style>
                body {{ font-family: Arial, sans-serif; text-align: center; margin: 50px; }}
                .error-container {{ max-width: 500px; margin: 0 auto; }}
                .error-title {{ color: #e74c3c; font-size: 24px; margin-bottom: 20px; }}
                .error-message {{ color: #666; margin-bottom: 30px; }}
                .btn {{ padding: 10px 20px; background: #3498db; color: white; text-decoration: none; border-radius: 5px; }}
            </style>
        </head>
        <body>
            <div class="error-container">
                <h1 class="error-title">{title}</h1>
                <p class="error-message">{message}</p>
                <a href="/" class="btn">חזרה לדף הבית</a>
            </div>
        </body>
        </html>
        """

    def create_success_page(self, title, message):
        """יצירת דף הצלחה מעוצב"""
        return f"""
        <!DOCTYPE html>
        <html dir="rtl" lang="he">
        <head>
            <meta charset="UTF-8">
            <title>{title}</title>
            <style>
                body {{ font-family: Arial, sans-serif; text-align: center; margin: 50px; background: #f8f9fa; }}
                .success-container {{ max-width: 500px; margin: 0 auto; background: white; padding: 40px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
                .success-title {{ color: #27ae60; font-size: 28px; margin-bottom: 20px; }}
                .success-message {{ color: #666; margin-bottom: 30px; font-size: 16px; }}
                .checkmark {{ font-size: 60px; color: #27ae60; margin-bottom: 20px; }}
            </style>
        </head>
        <body>
            <div class="success-container">
                <div class="checkmark">✅</div>
                <h1 class="success-title">{title}</h1>
                <p class="success-message">{message}</p>
            </div>
        </body>
        </html>
        """

    def send_response(self, client_socket, response):
        """שליחת תגובה ללקוח - מבוסס על הקוד המקורי"""
        try:
            sent = 0
            while sent < len(response):
                bytes_sent = client_socket.send(response[sent:])
                if bytes_sent == 0:
                    break
                sent += bytes_sent
        except socket.error as e:
            print(f"[!] שגיאה בשליחת תגובה: {e}")


# דוגמה לשימוש אם מריצים את הקובץ ישירות
if __name__ == "__main__":
    print("🧪 מריץ דוגמה לשרת HTTP מותאם אישית...")

    # יצירת השרת
    server = ParentalControlHTTPServer("127.0.0.1", 8080)

    # הגדרת תבניות פשוטות לבדיקה
    registration_html = """
    <!DOCTYPE html>
    <html dir="rtl" lang="he">
    <head><meta charset="UTF-8"><title>דף רישום</title></head>
    <body>
        <h1>דף רישום</h1>
        <form method="post" action="/register">
            <input name="child_name" placeholder="שם הילד" required>
            <button type="submit">רישום</button>
        </form>
    </body>
    </html>
    """

    block_html = """
    <!DOCTYPE html>
    <html dir="rtl" lang="he">
    <head><meta charset="UTF-8"><title>אתר חסום</title></head>
    <body>
        <h1>אתר חסום</h1>
        <p>ילד: {child_name}</p>
        <p>זמן: {current_time}</p>
    </body>
    </html>
    """

    server.set_templates(registration_html, block_html)

    def verify_child_example(name):
        allowed_children = ["ילד 1", "ילד 2", "test"]
        return name in allowed_children


    server.set_verify_callback(verify_child_example)

    # הפעלת השרת
    try:
        print("🌐 שרת פועל על http://127.0.0.1:8080")
        print("🛑 לחץ Ctrl+C לעצירה")
        server.start_server()
    except KeyboardInterrupt:
        print("\n[*] עוצר שרת...")
        server.stop_server()