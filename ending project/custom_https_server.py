# custom_https_server.py
"""
שרת HTTPS מותאם אישית למערכת בקרת הורים
מספק תמיכה מלאה ב-HTTPS כדי להציג דפי חסימה עבור אתרים מאובטחים
"""

import socket
import threading
import time
import os
import ssl
from urllib.parse import parse_qs
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import datetime
import ipaddress
from datetime import timezone

# יבוא השרת HTTP הרגיל כגיבוי
try:
    from custom_http_server import ParentalControlHTTPServer

    HTTP_SERVER_AVAILABLE = True
    print("[DEBUG HTTPS] ✅ ParentalControlHTTPServer imported successfully")
except ImportError:
    ParentalControlHTTPServer = None
    HTTP_SERVER_AVAILABLE = False
    print("[DEBUG HTTPS] ❌ ParentalControlHTTPServer import failed")


class HTTPSBlockServer:
    """שרת HTTPS לחסימת אתרים"""

    def __init__(self, ip="127.0.0.1", https_port=443, http_port=8080):
        self.ip = ip
        self.https_port = https_port
        self.http_port = http_port
        self.running = False

        # נתוני התצורה
        self.child_name = None
        self.registration_html = ""
        self.block_html_template = ""
        self.verify_child_callback = None
        self.external_create_error_page = None
        self.external_create_success_page = None

        # שרת HTTP כגיבוי
        self.fallback_http_server = None

        print(f"[DEBUG HTTPS] 🔧 HTTPSBlockServer initialized: {ip}:{https_port}")

    def set_templates(self, registration_html, block_html_template):
        """הגדרת תמלטים"""
        self.registration_html = registration_html
        self.block_html_template = block_html_template
        print("[DEBUG HTTPS] ✅ Templates set")

    def set_verify_callback(self, callback_func):
        """הגדרת פונקציית אימות"""
        self.verify_child_callback = callback_func
        print("[DEBUG HTTPS] ✅ Verify callback set")

    def set_external_functions(self, create_error_func, create_success_func):
        """הגדרת פונקציות עיצוב"""
        self.external_create_error_page = create_error_func
        self.external_create_success_page = create_success_func
        print("[DEBUG HTTPS] ✅ External functions set")

    def set_child_data(self, child_name):
        """עדכון נתוני ילד"""
        self.child_name = child_name
        print(f"[DEBUG HTTPS] ✅ Child data set: {child_name}")

    def create_ssl_certificate(self):
        """יצירת תעודת SSL עצמית"""
        cert_file = "block_server_cert.pem"
        key_file = "block_server_key.pem"

        # אם הקבצים כבר קיימים
        if os.path.exists(cert_file) and os.path.exists(key_file):
            print("[DEBUG HTTPS] ✅ SSL certificates already exist")
            return cert_file, key_file

        try:
            print("[*] 🔒 יוצר תעודת SSL לשרת חסימה...")

            # יצירת מפתח פרטי
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
            )

            # פרטי התעודה
            subject = issuer = x509.Name([
                x509.NameAttribute(NameOID.COUNTRY_NAME, "IL"),
                x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Israel"),
                x509.NameAttribute(NameOID.LOCALITY_NAME, "Tel Aviv"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Parental Control Block Server"),
                x509.NameAttribute(NameOID.COMMON_NAME, "localhost"),
            ])

            # יצירת התעודה
            cert = x509.CertificateBuilder().subject_name(
                subject
            ).issuer_name(
                issuer
            ).public_key(
                private_key.public_key()
            ).serial_number(
                x509.random_serial_number()
            ).not_valid_before(
                datetime.datetime.now(timezone.utc)
            ).not_valid_after(
                datetime.datetime.now(timezone.utc) + datetime.timedelta(days=365)
            ).add_extension(
                x509.SubjectAlternativeName([
                    x509.DNSName("localhost"),
                    x509.DNSName("127.0.0.1"),
                    x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
                ]),
                critical=False,
            ).sign(private_key, hashes.SHA256())

            # שמירת התעודה
            with open(cert_file, "wb") as f:
                f.write(cert.public_bytes(serialization.Encoding.PEM))

            # שמירת המפתח הפרטי
            with open(key_file, "wb") as f:
                f.write(private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                ))

            print(f"[+] ✅ תעודת SSL נוצרה: {cert_file}, {key_file}")
            return cert_file, key_file

        except Exception as e:
            print(f"[!] ❌ שגיאה ביצירת תעודת SSL: {e}")
            return None, None

    def start_https_server(self):
        """הפעלת שרת HTTPS עם debugging מפורט"""
        try:
            print(f"[HTTPS DEBUG] 🔒 מתחיל HTTPS server על פורט {self.https_port}")

            # יצירת תעודת SSL
            cert_file, key_file = self.create_ssl_certificate()
            if not cert_file or not key_file:
                print("[HTTPS DEBUG] ❌ לא ניתן ליצור תעודת SSL")
                return False

            print(f"[HTTPS DEBUG] 📜 תעודות SSL: {cert_file}, {key_file}")

            # יצירת סוקט HTTPS
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

            print(f"[HTTPS DEBUG] 🔐 יוצר SSL context...")

            # הגדרת SSL context
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(cert_file, key_file)

            print(f"[HTTPS DEBUG] 🔗 עוטף סוקט ב-SSL...")

            # עטיפת הסוקט ב-SSL
            server_socket = context.wrap_socket(server_socket, server_side=True)
            server_socket.bind((self.ip, self.https_port))
            server_socket.listen(10)

            print(f"[HTTPS DEBUG] 👂 מאזין על {self.ip}:{self.https_port}")
            print("[*] HTTPS מאזין לחיבורים...")

            # thread לטיפול בחיבורים
            def handle_connections():
                while self.running:
                    try:
                        print(f"[HTTPS DEBUG] ⏳ ממתין לחיבור...")
                        client_socket, client_address = server_socket.accept()
                        print(f"[HTTPS DEBUG] 🤝 חיבור HTTPS מ-{client_address[0]}:{client_address[1]}")

                        # טיפול בלקוח בthread נפרד
                        client_thread = threading.Thread(
                            target=self.handle_https_client,
                            args=(client_socket,),
                            daemon=True
                        )
                        client_thread.start()
                        print(f"[HTTPS DEBUG] 🔄 Thread נוצר ללקוח")

                    except Exception as e:
                        if self.running:
                            print(f"[HTTPS DEBUG] ❌ שגיאה בקבלת חיבור HTTPS: {e}")

            connection_thread = threading.Thread(target=handle_connections, daemon=True)
            connection_thread.start()

            print(f"[+] 🔒 שרת HTTPS פועל על פורט {self.https_port}")
            return True

        except PermissionError:
            print(f"[HTTPS DEBUG] 🚫 אין הרשאות לפורט {self.https_port} - נסה להריץ כמנהל")
            return False
        except Exception as e:
            print(f"[HTTPS DEBUG] ❌ שגיאה בהפעלת HTTPS: {e}")
            import traceback
            traceback.print_exc()
            return False

    def handle_https_client(self, client_socket):
        """טיפול בלקוח HTTPS עם debugging מפורט"""
        try:
            client_socket.settimeout(10)
            print(f"[HTTPS DEBUG] 🔐 מטפל בלקוח HTTPS...")

            # קבלת הבקשה
            request_data = b''
            while True:
                try:
                    chunk = client_socket.recv(1024)
                    if not chunk:
                        break
                    request_data += chunk
                    if b'\r\n\r\n' in request_data:
                        break
                except:
                    break

            if not request_data:
                print(f"[HTTPS DEBUG] ❌ לא התקבלו נתונים")
                return

            # ניתוח הבקשה
            request_str = request_data.decode('utf-8', errors='ignore')
            lines = request_str.split('\r\n')
            if not lines:
                print(f"[HTTPS DEBUG] ❌ בקשה ריקה")
                return

            # חילוץ נתוני הבקשה
            request_line = lines[0]
            print(f"[HTTPS DEBUG] 📥 בקשה: {request_line}")

            method, path, _ = request_line.split(' ', 2) if len(request_line.split(' ')) >= 3 else (
            'GET', '/', 'HTTP/1.1')

            # חילוץ Host header
            host = "localhost"
            for line in lines[1:]:
                if line.lower().startswith('host:'):
                    host = line.split(':', 1)[1].strip()
                    break

            print(f"[HTTPS DEBUG] 🌐 {method} {path} - Host: {host}")

            # טיפול בבקשות שונות
            if path == "/" or path.startswith("/register"):
                print(f"[HTTPS DEBUG] 📝 טיפול בבקשת רישום")
                response = self.handle_registration_request(method, request_str)
            else:
                print(f"[HTTPS DEBUG] 🚫 טיפול בבקשת חסימה")
                response = self.handle_block_request(host)

            print(f"[HTTPS DEBUG] 📤 שולח תגובה ({len(response)} bytes)")

            # שליחת התגובה
            client_socket.send(response.encode('utf-8'))
            print(f"[HTTPS DEBUG] ✅ תגובה נשלחה בהצלחה")

        except Exception as e:
            print(f"[HTTPS DEBUG] ❌ שגיאה בטיפול בלקוח HTTPS: {e}")
            import traceback
            traceback.print_exc()
        finally:
            try:
                client_socket.close()
                print(f"[HTTPS DEBUG] 🔌 חיבור נסגר")
            except:
                pass

    def handle_registration_request(self, method, request_str):
        """טיפול בבקשת רישום"""
        if method == "POST":
            return self.handle_registration_post(request_str)
        else:
            # GET - החזרת דף הרישום
            html_content = self.registration_html
            return self.create_response(200, "OK", html_content, "text/html")

    def handle_registration_post(self, request_str):
        """טיפול ברישום ילד - עם השימוש בעיצוב הקיים"""
        try:
            # חילוץ נתוני POST
            post_data = ""
            if '\r\n\r\n' in request_str:
                post_data = request_str.split('\r\n\r\n', 1)[1]

            form_data = parse_qs(post_data)
            child_name = ""

            if 'child_name' in form_data:
                child_name = form_data['child_name'][0].strip()

            print(f"[HTTPS] ניסיון רישום: '{child_name}'")

            if not child_name:
                if self.external_create_error_page:
                    error_html = self.external_create_error_page("שגיאה", "השם לא יכול להיות ריק!", back_button=True,
                                                                 retry_button=True)
                else:
                    error_html = self.create_simple_error_page("שגיאה", "השם לא יכול להיות ריק!")
                return self.create_response(400, "BAD REQUEST", error_html, "text/html")

            if len(child_name) < 2:
                if self.external_create_error_page:
                    error_html = self.external_create_error_page("שגיאה", "השם חייב להכיל לפחות 2 תווים!",
                                                                 back_button=True, retry_button=True)
                else:
                    error_html = self.create_simple_error_page("שגיאה", "השם חייב להכיל לפחות 2 תווים!")
                return self.create_response(400, "BAD REQUEST", error_html, "text/html")

            # קריאה לפונקציית האימות
            if self.verify_child_callback:
                if self.verify_child_callback(child_name):
                    self.child_name = child_name
                    if self.external_create_success_page:
                        success_html = self.external_create_success_page(
                            f"ברוך הבא {child_name}!",
                            "נרשמת בהצלחה במערכת בקרת ההורים<br>כעת תוכל לגלוש באינטרנט בבטחה"
                        )
                    else:
                        success_html = self.create_simple_success_page(f"ברוך הבא {child_name}!",
                                                                       "נרשמת בהצלחה במערכת בקרת ההורים")
                    return self.create_response(200, "OK", success_html, "text/html")
                else:
                    if self.external_create_error_page:
                        error_html = self.external_create_error_page(
                            "לא רשום במערכת",
                            f"השם '{child_name}' לא רשום במערכת בקרת ההורים.<br>💡 בקש מההורים להוסיף אותך דרך לוח הבקרה.",
                            back_button=True,
                            retry_button=True
                        )
                    else:
                        error_html = self.create_simple_error_page("לא רשום במערכת",
                                                                   f"השם '{child_name}' לא רשום במערכת בקרת ההורים.")
                    return self.create_response(403, "FORBIDDEN", error_html, "text/html")

        except Exception as e:
            print(f"[!] שגיאה בטיפול ברישום HTTPS: {e}")
            return self.create_error_response(500, "Internal Server Error")

    def handle_block_request(self, host):
        """טיפול בבקשת חסימה עם debugging"""
        print(f"[HTTPS DEBUG] 🚫 יוצר דף חסימה עבור: {host}")

        current_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        block_html = self.block_html_template.format(
            host=host,
            current_time=current_time,
            child_name=self.child_name or "אורח"
        )

        print(f"[HTTPS DEBUG] 📄 דף חסימה נוצר ({len(block_html)} תווים)")

        response = self.create_response(200, "OK", block_html, "text/html")
        print(f"[HTTPS DEBUG] 📦 תגובה HTTP נוצרה ({len(response)} bytes)")

        return response


    def create_simple_error_page(self, title, message):
        """יצירת דף שגיאה פשוט אם הפונקציות החיצוניות לא זמינות"""
        return f"""
        <!DOCTYPE html>
        <html dir="rtl" lang="he">
        <head>
            <meta charset="UTF-8">
            <title>{title}</title>
            <style>
                body {{ font-family: Arial, sans-serif; text-align: center; margin: 50px; }}
                h1 {{ color: #e74c3c; }}
                .btn {{ padding: 10px 20px; background: #3498db; color: white; text-decoration: none; border-radius: 5px; }}
            </style>
        </head>
        <body>
            <h1>{title}</h1>
            <p>{message}</p>
            <a href="/" class="btn">חזרה לדף הבית</a>
        </body>
        </html>
        """

    def create_simple_success_page(self, title, message):
        """יצירת דף הצלחה פשוט אם הפונקציות החיצוניות לא זמינות"""
        return f"""
        <!DOCTYPE html>
        <html dir="rtl" lang="he">
        <head>
            <meta charset="UTF-8">
            <title>{title}</title>
            <style>
                body {{ font-family: Arial, sans-serif; text-align: center; margin: 50px; background: #f8f9fa; }}
                .container {{ max-width: 500px; margin: 0 auto; background: white; padding: 40px; border-radius: 10px; }}
                h1 {{ color: #27ae60; }}
                .checkmark {{ font-size: 60px; color: #27ae60; }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="checkmark">✅</div>
                <h1>{title}</h1>
                <p>{message}</p>
            </div>
        </body>
        </html>
        """

    def create_response(self, status_code, status_text, content, content_type):
        """יצירת תגובת HTTP"""
        response = f"""HTTP/1.1 {status_code} {status_text}\r
Content-Type: {content_type}; charset=utf-8\r
Content-Length: {len(content.encode('utf-8'))}\r
Connection: close\r
\r
{content}"""
        return response

    def create_error_response(self, status_code, status_text):
        """יצירת תגובת שגיאה"""
        content = f"<html><body><h1>{status_code} {status_text}</h1></body></html>"
        return self.create_response(status_code, status_text, content, "text/html")

    def start_fallback_http_server(self):
        """הפעלת שרת HTTP כגיבוי - תיקון מלא"""
        print(f"[DEBUG HTTPS] 🔍 start_fallback_http_server called")
        print(f"[DEBUG HTTPS] HTTP_SERVER_AVAILABLE: {HTTP_SERVER_AVAILABLE}")
        print(f"[DEBUG HTTPS] ParentalControlHTTPServer: {ParentalControlHTTPServer}")

        try:
            if not HTTP_SERVER_AVAILABLE:
                print("[DEBUG HTTPS] ❌ HTTP_SERVER_AVAILABLE is False")
                return False

            if ParentalControlHTTPServer is None:
                print("[DEBUG HTTPS] ❌ ParentalControlHTTPServer is None")
                return False

            print(f"[DEBUG HTTPS] 🔨 Creating ParentalControlHTTPServer instance...")

            # יצירת אובייקט מהמחלקה
            self.fallback_http_server = ParentalControlHTTPServer(self.ip, self.http_port)
            print(f"[DEBUG HTTPS] ✅ Instance created: {type(self.fallback_http_server)}")

            # העברת הגדרות עם בדיקות
            if hasattr(self.fallback_http_server, 'set_templates'):
                self.fallback_http_server.set_templates(self.registration_html, self.block_html_template)
                print("[DEBUG HTTPS] ✅ Templates set")
            else:
                print("[DEBUG HTTPS] ⚠️ No set_templates method")

            if hasattr(self.fallback_http_server, 'set_verify_callback'):
                self.fallback_http_server.set_verify_callback(self.verify_child_callback)
                print("[DEBUG HTTPS] ✅ Verify callback set")
            else:
                print("[DEBUG HTTPS] ⚠️ No set_verify_callback method")

            if hasattr(self.fallback_http_server, 'set_external_functions'):
                self.fallback_http_server.set_external_functions(
                    self.external_create_error_page,
                    self.external_create_success_page
                )
                print("[DEBUG HTTPS] ✅ External functions set")
            else:
                print("[DEBUG HTTPS] ⚠️ No set_external_functions method")

            # הפעלה בthread נפרד
            if hasattr(self.fallback_http_server, 'start_server'):
                fallback_thread = threading.Thread(
                    target=self.fallback_http_server.start_server,
                    daemon=True
                )
                fallback_thread.start()
                print(f"[DEBUG HTTPS] ✅ Server thread started")
            else:
                print("[DEBUG HTTPS] ❌ No start_server method")
                return False

            print(f"[+] 🔓 שרת HTTP גיבוי פועל על פורט {self.http_port}")
            return True

        except TypeError as e:
            print(f"[DEBUG HTTPS] ❌ TypeError creating instance: {e}")
            print(f"[DEBUG HTTPS] ParentalControlHTTPServer callable? {callable(ParentalControlHTTPServer)}")
            return False
        except Exception as e:
            print(f"[DEBUG HTTPS] ❌ General error: {e}")
            import traceback
            traceback.print_exc()
            return False

    def start_server(self):
        """התחלת השרת עם HTTPS ו-HTTP - עם debug מלא"""
        print(f"[DEBUG HTTPS] 🚀 start_server called")

        try:
            self.running = True

            # ניסיון הפעלת HTTPS
            print(f"[DEBUG HTTPS] 🔒 מנסה להפעיל HTTPS על פורט {self.https_port}...")
            https_started = self.start_https_server()
            print(f"[DEBUG HTTPS] HTTPS result: {https_started}")

            # הפעלת HTTP כגיבוי אם HTTPS לא עבד
            if not https_started:
                print(f"[DEBUG HTTPS] 🔄 HTTPS נכשל, עובר ל-HTTP על פורט {self.http_port}...")
                http_started = self.start_fallback_http_server()
                print(f"[DEBUG HTTPS] HTTP fallback result: {http_started}")

                if not http_started:
                    print("[DEBUG HTTPS] ❌ גם HTTP נכשל")
                    return False
            else:
                print(f"[DEBUG HTTPS] ✅ HTTPS הצליח על פורט {self.https_port}")

            # המתנה לקריאות
            print(f"[DEBUG HTTPS] ⏳ נכנס לloop המתנה...")
            try:
                while self.running:
                    time.sleep(1)
            except KeyboardInterrupt:
                print("\n[DEBUG HTTPS] 🛑 KeyboardInterrupt - עוצר שרת...")
                self.stop_server()

            return True

        except Exception as e:
            print(f"[DEBUG HTTPS] ❌ שגיאה כללית בstart_server: {e}")
            import traceback
            traceback.print_exc()
            return False

    def stop_server(self):
        """עצירת השרת"""
        self.running = False
        print("[DEBUG HTTPS] 🛑 Server stopped")


if __name__ == "__main__":
    # בדיקה עצמאית
    print("🔒 בודק שרת HTTPS לחסימה...")

    # תמלטים לבדיקה
    registration_template = """<!DOCTYPE html>
<html dir="rtl"><head><meta charset="UTF-8"><title>רישום</title></head>
<body><h1>דף רישום</h1><form method="post"><input name="child_name" placeholder="שם"><button type="submit">שלח</button></form></body></html>"""

    block_template = """<!DOCTYPE html>
<html dir="rtl"><head><meta charset="UTF-8"><title>חסום</title></head>
<body><h1>אתר חסום!</h1><p>אתר: {host}</p><p>זמן: {current_time}</p></body></html>"""

    server = HTTPSBlockServer("127.0.0.1", 443, 8080)
    server.set_templates(registration_template, block_template)

    print("🔒 מפעיל שרת חסימה עם HTTPS...")
    print("⚠️  אם הדפדפן מתריע - לחץ 'Advanced' ואז 'Proceed to localhost'")

    try:
        server.start_server()
    except KeyboardInterrupt:
        print("\n🛑 שרת נעצר על ידי המשתמש")
    finally:
        server.stop_server()