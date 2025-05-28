import http.server
import socketserver
import json
import threading
from datetime import timezone
import ipaddress
import os
import time
from history_utils import group_browsing_by_main_site, format_simple_grouped_entry
import webbrowser
import hashlib
from urllib.parse import parse_qs, urlparse, quote, unquote
from protocol import Protocol, COMMUNICATION_PORT
import ssl
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import datetime
import socket
from html_templates_parent import (REGISTER_TEMPLATE, LOGIN_TEMPLATE, DASHBOARD_TEMPLATE,
                                   BROWSING_HISTORY_TEMPLATE, MANAGE_CHILDREN_TEMPLATE,)

HTTP_PORT = 8000
HTTPS_PORT = 8443

# נתונים עבור ילדים
children_data = {}
data_lock = threading.Lock()
active_connections = {}

# היסטוריית גלישה
browsing_history = {}  # מילון לפי שם ילד
history_lock = threading.Lock()


def create_ssl_certificate():
    """יצירת תעודת SSL לשרת ההורים"""
    if os.path.exists("parent_cert.pem") and os.path.exists("parent_key.pem"):
        print("[*] ✅ תעודת SSL כבר קיימת")
        return True

    try:
        print("[*] יוצר תעודת SSL לשרת ההורים...")

        # יצירת מפתח פרטי
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )

        # יצירת תעודה
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "IL"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Parent Control Server"),
            x509.NameAttribute(NameOID.COMMON_NAME, "localhost"),
        ])

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

        # שמירה
        with open("parent_cert.pem", "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))

        with open("parent_key.pem", "wb") as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))

        print("[+] ✅ תעודת SSL נוצרה: parent_cert.pem, parent_key.pem")
        return True

    except ImportError:
        print("[!] ⚠️  ספריית cryptography לא זמינה")
        print("[!] הרץ: pip install cryptography")
        return create_fallback_cert()
    except Exception as e:
        print(f"[!] שגיאה ביצירת תעודה: {e}")
        return create_fallback_cert()


def create_fallback_cert():
    """תעודת חירום"""
    cert_content = """-----BEGIN CERTIFICATE-----
MIIDXTCCAkWgAwIBAgIJAKoK/heBjcOuMA0GCSqGSIb3DQEBBQUAMEUxCzAJBgNV
BAYTAklMMRIwEAYDVQQKDAlQYXJlbnQgQ29udHJvbDESMBAGA1UEAwwJbG9jYWxo
b3N0MB4XDTI0MTIxMDAwMDAwMFoXDTI1MTIxMDAwMDAwMFowRTELMAkGA1UEBhMC
SUwxEjAQBgNVBAoMCVBhcmVudCBDb250cm9sMRIwEAYDVQQDDAlsb2NhbGhvc3Qw
ggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDMQiXPRhmA3O2M1gvG+ZAf
BNxf4WIaUfZltccCAwEAAQKCAQEAioSbz0NmZj0Oc/MWIBc+MTe0Fpgv-----END CERTIFICATE-----"""

    key_content = """-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDMQiXPRhmA3O2M
1gvG+ZAfBNxf4WIaUfZltccCAwEAAQKCAQEAioSbz0NmZj0Oc/MWIBc+MTe0Fpgv
-----END PRIVATE KEY-----"""

    try:
        with open("parent_cert.pem", "w") as f:
            f.write(cert_content)
        with open("parent_key.pem", "w") as f:
            f.write(key_content)
        print("[+] ✅ תעודת SSL בסיסית נוצרה")
        return True
    except:
        return False


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


def load_browsing_history():
    """טעינת היסטוריית גלישה מקובץ"""
    global browsing_history
    try:
        try:
            with open('browsing_history.json', 'r', encoding='utf-8') as f:
                browsing_history = json.load(f)
                print(f"[DEBUG LOAD] טעינת היסטוריה: {len(browsing_history)} ילדים")
                for child, entries in browsing_history.items():
                    print(f"[DEBUG LOAD] {child}: {len(entries)} רשומות")
                    if entries:
                        print(f"[DEBUG LOAD] דוגמה אחרונה: {entries[-1]}")
        except FileNotFoundError:
           browsing_history = {}
           print("[*] נוצר קובץ היסטוריה חדש")
    except Exception as e:
        print(f"[!] שגיאה בטעינת היסטוריה: {e}")
        browsing_history = {}


def save_browsing_history():
    """שמירת היסטוריית גלישה לקובץ"""
    try:
        with open('browsing_history.json', 'w', encoding='utf-8') as f:
            json.dump(browsing_history, f, ensure_ascii=False, indent=2)
    except Exception as e:
        print(f"[!] שגיאה בשמירת היסטוריה: {e}")


def add_to_browsing_history(child_name, entries):
    """הוספת רשומות להיסטוריית גלישה של ילד"""
    with history_lock:
        if child_name not in browsing_history:
            browsing_history[child_name] = []

        browsing_history[child_name].extend(entries)

        # שמירה על מקסימום 5000 רשומות לכל ילד
        if len(browsing_history[child_name]) > 5000:
            browsing_history[child_name] = browsing_history[child_name][-5000:]

        save_browsing_history()
        print(f"[HISTORY] נוספו {len(entries)} רשומות עבור {child_name}")



class ParentServer:
    def __init__(self):
        self.running = True
        self.server_socket = None
        self.connection_threads = []
        self.load_children_data()
        load_browsing_history()

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
            children_data['ילד 3'] = {"blocked_domains": {"twitter.com"}, "client_address": None, "last_seen": None}
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

                # מחיקת היסטוריה של הילד
                with history_lock:
                    if child_name in browsing_history:
                        del browsing_history[child_name]
                        save_browsing_history()

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
            print(f"[DEBUG] התקבלה הודעה: {msg_type}, נתונים: {data}")

            if msg_type == Protocol.REGISTER_CHILD:
                child_name = data.get('name')
                if child_name and child_name in children_data:
                    with data_lock:
                        children_data[child_name]['client_address'] = address
                        children_data[child_name]['last_seen'] = time.time()

                    Protocol.send_message(client_socket, Protocol.ACK, {"status": "registered"})
                    print(f"[+] {child_name} נרשם בהצלחה")

                    active_connections[child_name] = {"socket": client_socket, "address": address}

                    # עכשיו נמשיך לטפל בתקשורת
                    self.handle_child_communication(client_socket, child_name)
                else:
                    Protocol.send_message(client_socket, Protocol.ERROR, {"message": "Invalid child name"})
                    print(f"[!] שם ילד לא תקין: {child_name}")

            elif msg_type == Protocol.VERIFY_CHILD:
                # 🆕 טיפול באימות ילד
                requested_child = data.get("child_name")
                print(f"[VERIFY] בקשת אימות עבור: '{requested_child}'")

                with data_lock:
                    is_valid = requested_child in children_data

                Protocol.send_message(client_socket, Protocol.VERIFY_RESPONSE, {"is_valid": is_valid})
                print(f"[VERIFY] תגובה ל-'{requested_child}': {'✅ תקף' if is_valid else '❌ לא תקף'}")

                # ⚠️ חשוב! לא לסגור את החיבור כאן אם הילד תקף
                if is_valid:
                    # עדכון פרטי הילד
                    with data_lock:
                        children_data[requested_child]['client_address'] = address
                        children_data[requested_child]['last_seen'] = time.time()

                    child_name = requested_child
                    active_connections[requested_child] = {"socket": client_socket, "address": address}
                    print(f"[+] ילד '{requested_child}' אומת ונרשם")

                    # ⚠️ כאן הייתה הבעיה - לא היינו ממשיכים לטפל בתקשורת!
                    self.handle_child_communication(client_socket, child_name)
                else:
                    # אם הילד לא תקף, סוגרים את החיבור
                    client_socket.close()
                    return

        except Exception as e:
            print(f"[!] שגיאה בחיבור {child_name}: {e}")
            import traceback
            traceback.print_exc()
        finally:
            # רק נסגור את החיבור אם זה לא ילד תקף שמחובר
            if child_name not in active_connections:
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
                print(f"[DEBUG] התקבלה הודעה: {msg_type} מ-{child_name}")

                if msg_type == Protocol.GET_DOMAINS:
                    with data_lock:
                        domains = list(children_data[child_name]['blocked_domains'])
                    Protocol.send_message(client_socket, Protocol.UPDATE_DOMAINS, {"domains": domains})
                    print(f"[+] נשלחו דומיינים ל-{child_name}: {domains}")

                elif msg_type == Protocol.CHILD_STATUS:
                    with data_lock:
                        children_data[child_name]['last_seen'] = time.time()
                    Protocol.send_message(client_socket, Protocol.ACK)
                    print(f"[DEBUG]  ACK נשלח ל-{child_name}")

                elif msg_type == Protocol.BROWSING_HISTORY:
                    print(f"[DEBUG] התקבלה היסטוריה מ-{child_name}!")
                    child_name_from_data = data.get("child_name")
                    history_entries = data.get("history", [])
                    print(f"[DEBUG] נתונים: child_name='{child_name_from_data}', entries={len(history_entries)}")

                    if child_name_from_data and history_entries:
                        print(f"[DEBUG]  מוסיף היסטוריה...")
                        add_to_browsing_history(child_name_from_data, history_entries)
                        Protocol.send_message(client_socket, Protocol.ACK)
                        print(f"[+]  התקבלה היסטוריה מ-{child_name}: {len(history_entries)} רשומות")
                    else:
                        print(f"[DEBUG] ❌ נתונים לא תקינים")

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


print("[*] ParentServer אותחל עם פונקציות ניהול ילדים והיסטוריית גלישה")


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
                        sock = conn_info["socket"]
                        domains = list(children_data[child_name]['blocked_domains'])
                        Protocol.send_message(sock, Protocol.UPDATE_DOMAINS, {"domains": domains})
                        print(f"[*] נשלח עדכון מיידי ל-{child_name}")
                    except Exception as e:
                        print(f"[!] שגיאה בעדכון {child_name}: {e}")

    def end_headers(self):
        """הוספת headers אבטחה ל-HTTPS"""
        self.send_header('Strict-Transport-Security', 'max-age=31536000')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('X-Frame-Options', 'DENY')
        self.send_header('X-XSS-Protection', '1; mode=block')
        super().end_headers()

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

        elif parsed_path.path == '/browsing_history':
            # בדיקה אם המשתמש מחובר
            logged_in_user = self.is_logged_in()
            if not logged_in_user:
                self.send_response(302)
                self.send_header('Location', '/login')
                self.end_headers()
                return

            user_name = user_manager.get_user_fullname(logged_in_user)

            # פילטרים
            child_filter = query_params.get('child', [''])[0]
            status_filter = query_params.get('status', [''])[0]
            domain_filter = query_params.get('domain', [''])[0]

            # בניית אפשרויות ילדים
            children_options = []
            with data_lock:
                for child_name in children_data.keys():
                    selected = 'selected' if child_name == child_filter else ''
                    children_options.append(f'<option value="{child_name}" {selected}>{child_name}</option>')

            # סינון והצגת היסטוריה - ללא קיבוץ
            filtered_history = []
            total_entries = 0
            stats = {'blocked': 0, 'allowed': 0, 'total_children': 0}
            print(f"[DEBUG VIEW] כל ההיסטוריה:")
            for child_name, entries in browsing_history.items():
                print(f"[DEBUG VIEW] {child_name}: {len(entries)} רשומות")
                if entries:
                    print(f"[DEBUG VIEW] אחרונה: {entries[-1]}")
            with history_lock:
                stats['total_children'] = len(browsing_history)
                for child_name, entries in browsing_history.items():
                    if child_filter and child_name != child_filter:
                        continue

                    for entry in entries:
                        total_entries += 1

                        # סינון לפי סטטוס
                        if status_filter == 'blocked' and not entry.get('was_blocked', False):
                            continue
                        if status_filter == 'allowed' and entry.get('was_blocked', False):
                            continue

                        # סינון לפי דומיין
                        if domain_filter and domain_filter.lower() not in entry.get('domain', '').lower():
                            continue

                        filtered_history.append(entry)

                        if entry.get('was_blocked', False):
                            stats['blocked'] += 1
                        else:
                            stats['allowed'] += 1

            # מיון לפי זמן (חדש ביותר קודם)
            filtered_history.sort(key=lambda x: x.get('timestamp', ''), reverse=True)

            # הגבלה ל-200 רשומות
            filtered_history = filtered_history[:200]
            # קיבוץ ההיסטוריה לפי אתרים ראשיים
            print(f"[DEBUG] לפני קיבוץ: {len(filtered_history)} רשומות")

            # בדיקת הנתונים המקוריים
            if filtered_history:
                print(f"[DEBUG] דוגמת רשומה מקורית:")
                sample = filtered_history[0]
                for key, value in sample.items():
                    print(f"  {key}: {value}")

            grouped_history = group_browsing_by_main_site(filtered_history, time_window_minutes=30)
            print(f"[DEBUG] אחרי קיבוץ: {len(grouped_history)} רשומות")

            # בניית HTML לרשומות מקובצות (ללא הצגת מספר ביקורים)
            history_entries = []
            for entry in grouped_history:
                formatted_entry = format_simple_grouped_entry(entry)
                history_entries.append(formatted_entry)

            # עדכון סטטיסטיקות לפי הרשומות המקובצות
            unique_sites = len(
                set(entry.get('display_name', entry.get('main_domain', '')) for entry in grouped_history))
            total_blocked = sum(1 for entry in grouped_history if entry.get('was_blocked', False))
            total_allowed = len(grouped_history) - total_blocked

            stats_cards = f'''
                            <div class="stat-card">
                                <div class="stat-number">{len(grouped_history)}</div>
                                <div class="stat-label">פעילויות מוצגות</div>
                            </div>
                            <div class="stat-card">
                                <div class="stat-number">{unique_sites}</div>
                                <div class="stat-label">אתרים ייחודיים</div>
                            </div>
                            <div class="stat-card">
                                <div class="stat-number">{total_blocked}</div>
                                <div class="stat-label">פעילויות חסומות</div>
                            </div>
                            <div class="stat-card">
                                <div class="stat-number">{total_allowed}</div>
                                <div class="stat-label">פעילויות מותרות</div>
                            </div>
                        '''

            history_html = BROWSING_HISTORY_TEMPLATE.replace('${user_name}', user_name)
            history_html = history_html.replace('${children_options}', ''.join(children_options))
            history_html = history_html.replace('${domain_filter}', domain_filter)
            history_html = history_html.replace('${total_entries}', str(len(grouped_history)))
            history_html = history_html.replace('${stats_cards}', stats_cards)
            history_html = history_html.replace('${message}', '')

            if history_entries:
                history_html = history_html.replace('${history_entries}', ''.join(history_entries))
            else:
                history_html = history_html.replace('${history_entries}',
                                                    '<div class="empty-message">אין רשומות מתאימות לחיפוש</div>')

            self.send_response(200)
            self.send_header('Content-type', 'text/html; charset=utf-8')
            self.end_headers()
            self.wfile.write(history_html.encode('utf-8'))

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
        elif self.path == '/clear_history':
                # בדיקה אם המשתמש מחובר
                logged_in_user = self.is_logged_in()
                if not logged_in_user:
                    self.send_response(302)
                    self.send_header('Location', '/login')
                    self.end_headers()
                    return

                child_name = post_params.get('child', [''])[0].strip()
                print(f"[DEBUG] בקשה למחיקת היסטוריה עבור: '{child_name}'")

                if child_name:
                    with history_lock:
                        if child_name in browsing_history:
                            del browsing_history[child_name]
                            save_browsing_history()
                            print(f"[+] ✅ היסטוריה של '{child_name}' נמחקה בהצלחה")
                        else:
                            print(f"[!] ⚠️ לא נמצאה היסטוריה עבור '{child_name}'")

                # חזרה לדף היסטוריה
                self.send_response(302)
                self.send_header('Location', '/browsing_history')
                self.end_headers()
        else:
            self.send_response(404)
            self.end_headers()


user_manager = UserManager()

if __name__ == "__main__":
    parent_server = ParentServer()
    try:
        print("[*] 🔒 מתחיל שרת בקרת הורים עם HTTPS")
        print(f"[*] מנהל משתמשים: {len(user_manager.users)} משתמשים רשומים")
        parent_server.start_communication_server()

        # יצירת תעודת SSL
        if create_ssl_certificate():
            print("[*] ✅ מפעיל שרת HTTPS")

            with socketserver.TCPServer(("", HTTPS_PORT), ParentHandler) as httpd:
                try:
                    # הגדרת SSL
                    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                    context.load_cert_chain('parent_cert.pem', 'parent_key.pem')

                    # הגדרות אבטחה חזקות
                    context.set_ciphers('ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:!aNULL:!MD5:!DSS')
                    context.options |= ssl.OP_NO_SSLv2
                    context.options |= ssl.OP_NO_SSLv3

                    httpd.socket = context.wrap_socket(httpd.socket, server_side=True)

                    print(f"[*] 🔒 שרת HTTPS פועל על https://localhost:{HTTPS_PORT}")
                    print(f"[*] 📡 שרת תקשורת פועל על פורט {COMMUNICATION_PORT}")
                    print(f"[*] 🎯 מוכן לקבל חיבורים מילדים")

                    server_url = f"https://localhost:{HTTPS_PORT}"
                    print(f"[*] 🌐 פותח דפדפן: {server_url}")
                    print("[!] ⚠️  אם הדפדפן מתריע - לחץ 'Advanced' ← 'Proceed to localhost'")
                    print("[*] 👤 משתמש דמו: admin@example.com / admin123")

                    webbrowser.open(server_url)
                    print("[*] לחץ Ctrl+C לעצירת השרת")
                    httpd.serve_forever()

                except ssl.SSLError as e:
                    print(f"[!] ❌ שגיאת SSL: {e}")
                    raise

        else:
            raise Exception("לא ניתן ליצור תעודת SSL")

    except KeyboardInterrupt:
        print("\n[*] עצירת השרת...")
        parent_server.shutdown()
    except Exception as e:
        print(f"[!] ❌ שגיאה בהפעלת HTTPS: {e}")
        print("[*] 🔄 עובר למצב HTTP כגיבוי...")

        # גיבוי HTTP
        try:
            with socketserver.TCPServer(("", HTTP_PORT), ParentHandler) as httpd:
                print(f"[*] 🔓 שרת HTTP פועל על http://localhost:{HTTP_PORT}")
                print("[*] 👤 משתמש דמו: admin@example.com / admin123")
                server_url = f"http://localhost:{HTTP_PORT}"
                webbrowser.open(server_url)
                print("[*] לחץ Ctrl+C לעצירת השרת")
                httpd.serve_forever()
        except KeyboardInterrupt:
            print("\n[*] עצירת השרת...")
            parent_server.shutdown()
