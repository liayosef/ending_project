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
from encryption_module import SimpleEncryption, SafeFileManager
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import datetime
import socket
from html_templates_parent import (REGISTER_TEMPLATE, LOGIN_TEMPLATE, DASHBOARD_TEMPLATE,
                                   BROWSING_HISTORY_TEMPLATE, MANAGE_CHILDREN_TEMPLATE, )

HTTP_PORT = 8000
HTTPS_PORT = 8443

# נתונים עבור ילדים
children_data = {}
data_lock = threading.Lock()
active_connections = {}

# היסטוריית גלישה
browsing_history = {}  # מילון לפי שם ילד
history_lock = threading.Lock()

encryption_system = None
file_manager = None


# אתחול מיידי של מערכת ההצפנה - מסונכרן עם הפרוטוקול
def ensure_encryption():
    """וידוא שמערכת ההצפנה פועלת ומסונכרנת"""
    global encryption_system, file_manager
    if encryption_system is None or file_manager is None:
        try:
            from encryption_module import SimpleEncryption, SafeFileManager
            encryption_system = SimpleEncryption("parent_control_system")
            file_manager = SafeFileManager(encryption_system)
            print("[🔒] מערכת הצפנה אותחלה")

            # סנכרון עם מפתח התקשורת
            Protocol.sync_encryption_keys()

        except Exception as e:
            print(f"[❌] שגיאה באתחול הצפנה: {e}")
            return False
    return True


def initialize_encryption():
    """יצירת מערכת ההצפנה ומפתחות התקשורת"""
    global encryption_system, file_manager

    # הצפנה לקבצי נתונים
    encryption_system = SimpleEncryption("parent_control_system")
    file_manager = SafeFileManager(encryption_system)
    print("[🔒] מערכת הצפנה לנתונים אותחלה")

    # סנכרון מפתח התקשורת
    if Protocol.sync_encryption_keys():
        print("[🔒] מפתח תקשורת מסונכרן")
    else:
        print("[⚠️] בעיה בסנכרון מפתח תקשורת")


def create_ssl_certificate():
    """יצירת תעודת SSL לשרת ההורים"""
    if os.path.exists("parent_cert.pem") and os.path.exists("parent_key.pem"):
        print("[*] תעודת SSL כבר קיימת")
        return True

    try:
        print("[*] יוצר תעודת SSL לשרת ההורים...")

        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )

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

        print("[+] תעודת SSL נוצרה: parent_cert.pem, parent_key.pem")
        return True

    except ImportError:
        print("[!] ספריית cryptography לא זמינה")
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
        print("[+] תעודת SSL בסיסית נוצרה")
        return True
    except:
        return False


# פונקציות עזר גלובליות לניהול נתונים
def save_children_data():
    """שמירת נתוני ילדים - פונקציה גלובלית מתוקנת ומוצפנת"""
    global children_data

    if file_manager is None:
        initialize_encryption()

    try:
        # הכנת הנתונים לשמירה
        data_to_save = {}
        for child, info in children_data.items():
            blocked_domains = info["blocked_domains"]
            if isinstance(blocked_domains, set):
                blocked_domains = list(blocked_domains)

            data_to_save[child] = {
                "blocked_domains": blocked_domains,
                "last_seen": info.get("last_seen")
            }

        # שמירה מוצפנת
        success = file_manager.safe_save_json('children_data.json', data_to_save, encrypted=True)

        if success:
            print(f"[CHILDREN] 🔒 נתוני ילדים נשמרו מוצפנים: {len(data_to_save)} ילדים")
            return True
        else:
            raise Exception("שמירה מוצפנת נכשלה")

    except Exception as e:
        print(f"[CHILDREN] ❌ שגיאה בשמירת נתוני ילדים: {e}")
        return False


def load_children_data():
    """טעינת נתוני ילדים - פונקציה גלובלית מתוקנת ומוצפנת"""
    global children_data

    if file_manager is None:
        initialize_encryption()

    try:
        # נסיון טעינה מוצפנת תחילה
        data = file_manager.safe_load_json('children_data.json', encrypted=True)

        if data:
            for child, info in data.items():
                info['blocked_domains'] = set(info['blocked_domains'])
                info.setdefault('client_address', None)
                info.setdefault('last_seen', None)
            children_data.update(data)
            print(f"[CHILDREN] ✅ נתוני ילדים נטענו מוצפנים: {len(children_data)} ילדים")
        else:
            # אם אין קובץ מוצפן, נסה לטעון רגיל ולהמיר
            try:
                with open('children_data.json', 'r', encoding='utf-8') as f:
                    old_data = json.load(f)

                for child, info in old_data.items():
                    info['blocked_domains'] = set(info['blocked_domains'])
                    info.setdefault('client_address', None)
                    info.setdefault('last_seen', None)
                children_data.update(old_data)

                print("[CHILDREN] 🔄 ממיר נתוני ילדים קיימים להצפנה...")
                save_children_data()
                print("[CHILDREN] ✅ נתוני ילדים הומרו להצפנה")

            except FileNotFoundError:
                # נתוני ברירת מחדל
                children_data.update({
                    'ילד 1': {"blocked_domains": {"facebook.com", "youtube.com"},
                              "client_address": None, "last_seen": None},
                    'ילד 2': {"blocked_domains": {"instagram.com", "tiktok.com"},
                              "client_address": None, "last_seen": None},
                    'ילד 3': {"blocked_domains": {"twitter.com"},
                              "client_address": None, "last_seen": None}
                })
                save_children_data()
                print(f"[CHILDREN] ✅ נתוני ברירת מחדל נוצרו מוצפנים: {len(children_data)} ילדים")

    except Exception as e:
        print(f"[CHILDREN] ❌ שגיאה בטעינת נתוני ילדים: {e}")
        # נתוני חירום
        children_data['ילד 1'] = {"blocked_domains": set(), "client_address": None, "last_seen": None}


def save_browsing_history():
    """שמירת היסטוריית גלישה - פונקציה גלובלית מתוקנת ומוצפנת"""
    global browsing_history

    if file_manager is None:
        initialize_encryption()

    try:
        # שמירה מוצפנת
        success = file_manager.safe_save_json('browsing_history.json', browsing_history, encrypted=True)

        if success:
            total_entries = sum(len(entries) for entries in browsing_history.values())
            print(f"[HISTORY] 🔒 היסטוריה נשמרה מוצפנת: {total_entries} רשומות סה\"כ")
            return True
        else:
            raise Exception("שמירה מוצפנת נכשלה")

    except Exception as e:
        print(f"[HISTORY] ❌ שגיאה בשמירת היסטוריה: {e}")
        return False


def load_browsing_history():
    """טעינת היסטוריית גלישה - פונקציה גלובלית מתוקנת ומוצפנת"""
    global browsing_history

    if file_manager is None:
        initialize_encryption()

    try:
        # נסיון טעינה מוצפנת תחילה
        data = file_manager.safe_load_json('browsing_history.json', encrypted=True)

        if data and isinstance(data, dict):
            browsing_history = data
            total_entries = sum(len(entries) for entries in browsing_history.values())
            print(f"[HISTORY] ✅ היסטוריה נטענה מוצפנת:")
            print(f"[HISTORY]   📊 {len(browsing_history)} ילדים")
            print(f"[HISTORY]   📊 {total_entries} רשומות סה\"כ")
        else:
            # אם אין קובץ מוצפן, נסה לטעון רגיל ולהמיר
            try:
                with open('browsing_history.json', 'r', encoding='utf-8') as f:
                    old_data = json.load(f)

                if old_data and isinstance(old_data, dict):
                    browsing_history = old_data
                    print("[HISTORY] 🔄 ממיר היסטוריה קיימה להצפנה...")
                    save_browsing_history()
                    print("[HISTORY] ✅ היסטוריה הומרה להצפנה")

            except FileNotFoundError:
                print(f"[HISTORY] 🆕 לא נמצאו קבצי היסטוריה - יוצר חדש")
                browsing_history = {}
                save_browsing_history()

    except Exception as e:
        print(f"[HISTORY] ❌ שגיאה בטעינת היסטוריה: {e}")
        browsing_history = {}


def add_to_browsing_history(child_name, entries):
    """הוספת רשומות להיסטוריית גלישה - פונקציה גלובלית מתוקנת"""
    global browsing_history

    if not child_name or not entries:
        print(f"[HISTORY] ❌ נתונים ריקים: child_name='{child_name}', entries={len(entries) if entries else 0}")
        return

    print(f"[HISTORY] 📥 מתחיל עיבוד היסטוריה עבור {child_name}: {len(entries)} רשומות חדשות")

    with history_lock:
        try:
            if child_name not in browsing_history:
                browsing_history[child_name] = []
                print(f"[HISTORY] 🆕 יצרתי רשימה חדשה עבור {child_name}")

            old_count = len(browsing_history[child_name])
            browsing_history[child_name].extend(entries)
            new_count = len(browsing_history[child_name])

            print(f"[HISTORY] ✅ נוספו {len(entries)} רשומות. סה\"כ: {old_count} → {new_count}")

            if len(browsing_history[child_name]) > 5000:
                removed = len(browsing_history[child_name]) - 5000
                browsing_history[child_name] = browsing_history[child_name][-5000:]
                print(f"[HISTORY] 🗑️ הוסרו {removed} רשומות ישנות (שמירה על 5000)")

            try:
                save_browsing_history()
                print(f"[HISTORY] 💾 היסטוריה נשמרה בהצלחה לקובץ")
            except Exception as save_error:
                print(f"[HISTORY] ❌ שגיאה בשמירה: {save_error}")

        except Exception as e:
            print(f"[HISTORY] ❌ שגיאה קריטית בעיבוד היסטוריה: {e}")
            import traceback
            traceback.print_exc()


class UserManager:
    """מחלקה לניהול משתמשים - הרשמה, התחברות ושמירת נתונים מוצפן"""

    def __init__(self, data_file='users_data.json'):
        self.data_file = data_file
        self.users = {}
        self.load_users_encrypted()

    def load_users_encrypted(self):
        """טעינת נתוני משתמשים - גרסה מוצפנת"""
        if file_manager is None:
            initialize_encryption()

        try:
            # נסיון טעינה מוצפנת תחילה
            self.users = file_manager.safe_load_json(self.data_file, encrypted=True)

            if self.users:
                print(f"[🔒] נטענו נתונים מוצפנים עבור {len(self.users)} משתמשים")
                return

            # אם אין מוצפן, נסה רגיל והמר
            try:
                with open(self.data_file, 'r', encoding='utf-8') as f:
                    self.users = json.load(f)
                print(f"[*] נטענו נתונים עבור {len(self.users)} משתמשים")
                # המר להצפנה
                self.save_users_encrypted()
                print("[*] נתוני משתמשים הומרו להצפנה")
            except FileNotFoundError:
                # יצירת משתמש דמו
                self.users = {
                    'admin@example.com': {
                        'fullname': 'מנהל המערכת',
                        'password_hash': self._hash_password('admin123')
                    }
                }
                self.save_users_encrypted()
                print("[*] נוצר קובץ משתמשים חדש מוצפן")
        except Exception as e:
            print(f"[!] שגיאה בטעינת נתוני משתמשים: {e}")
            self.users = {}

    def save_users_encrypted(self):
        """שמירת נתוני משתמשים - גרסה מוצפנת"""
        if file_manager is None:
            initialize_encryption()

        try:
            success = file_manager.safe_save_json(self.data_file, self.users, encrypted=True)
            if success:
                print("[🔒] נתוני משתמשים נשמרו מוצפנים")
            else:
                print("[!] שגיאה בשמירת נתוני משתמשים מוצפנים")
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

        self.save_users_encrypted()
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


class ParentServer:
    def __init__(self):
        self.running = True
        self.server_socket = None
        self.connection_threads = []
        self.threads_lock = threading.Lock()

        # טעינת נתונים מוצפנים
        load_children_data()
        load_browsing_history()

        # הפעלת שמירה תקופתית
        self.start_periodic_save()

        # הפעלת ניקוי threads
        self.cleanup_thread = threading.Thread(target=self._cleanup_dead_threads, daemon=True)
        self.cleanup_thread.start()

    def _cleanup_dead_threads(self):
        """ניקוי threads שמתו כל 30 שניות"""
        while self.running:
            try:
                time.sleep(30)
                with self.threads_lock:
                    alive_threads = [t for t in self.connection_threads if t.is_alive()]
                    removed_count = len(self.connection_threads) - len(alive_threads)
                    if removed_count > 0:
                        self.connection_threads = alive_threads
                        print(f"[CLEANUP] 🧹 נוקו {removed_count} threads מתים")
            except Exception as e:
                print(f"[!] שגיאה בניקוי threads: {e}")

    def start_periodic_save(self):
        """הפעלת שמירה תקופתית כל 30 שניות"""

        def save_periodically():
            while self.running:
                try:
                    time.sleep(30)
                    save_browsing_history()
                except Exception as e:
                    print(f"[SAVE] ❌ שגיאה בשמירה תקופתית: {e}")

        save_thread = threading.Thread(target=save_periodically, daemon=True, name="PeriodicSaver")
        save_thread.start()
        print(f"[SAVE] 🕒 שמירה תקופתית הופעלה")

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

            children_data[child_name] = {
                "blocked_domains": set(),
                "client_address": None,
                "last_seen": None
            }

            print(f"[DEBUG] ✅ ילד '{child_name}' נוסף למילון")
            print(f"[DEBUG] כעת יש {len(children_data)} ילדים")

            try:
                save_children_data()
                print(f"[+] ✅ ילד '{child_name}' נוסף בהצלחה ונשמר")
                return True
            except Exception as e:
                print(f"[!] ❌ שגיאה בשמירת ילד חדש: {e}")
                del children_data[child_name]
                return False

    def remove_child(self, child_name):
        """מחיקת ילד"""
        print(f"[DEBUG] 🔹 מנסה למחוק ילד: '{child_name}'")

        if not child_name or not child_name.strip():
            print("[DEBUG] ❌ שם ילד ריק")
            return False

        child_name = child_name.strip()

        with data_lock:
            if child_name not in children_data:
                print(f"[DEBUG] ❌ ילד '{child_name}' לא קיים")
                return False

            # מחיקת הילד
            del children_data[child_name]

            # מחיקת ההיסטוריה שלו
            with history_lock:
                if child_name in browsing_history:
                    del browsing_history[child_name]

            print(f"[DEBUG] ✅ ילד '{child_name}' נמחק מהמילון")

            try:
                save_children_data()
                save_browsing_history()
                print(f"[+] ✅ ילד '{child_name}' נמחק בהצלחה")
                return True
            except Exception as e:
                print(f"[!] ❌ שגיאה בשמירה אחרי מחיקה: {e}")
                return False

    def handle_child_connection(self, client_socket, address):
        print(f"[*] חיבור חדש מ-{address}")
        child_name = None

        try:
            # שימוש בפרוטוקול המוצפן
            msg_type, data = Protocol.receive_message(client_socket)
            print(f"[DEBUG] התקבלה הודעה מוצפנת: {msg_type}, נתונים: {data}")

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

            elif msg_type == Protocol.VERIFY_CHILD:
                requested_child = data.get("child_name")
                print(f"[VERIFY] בקשת אימות עבור: '{requested_child}'")

                with data_lock:
                    is_valid = requested_child in children_data

                Protocol.send_message(client_socket, Protocol.VERIFY_RESPONSE, {"is_valid": is_valid})
                print(f"[VERIFY] תגובה ל-'{requested_child}': {'✅ תקף' if is_valid else '❌ לא תקף'}")

                if is_valid:
                    with data_lock:
                        children_data[requested_child]['client_address'] = address
                        children_data[requested_child]['last_seen'] = time.time()

                    child_name = requested_child
                    active_connections[requested_child] = {"socket": client_socket, "address": address}
                    print(f"[+] ילד '{requested_child}' אומת ונרשם")

                    self.handle_child_communication(client_socket, child_name)
                else:
                    client_socket.close()
                    return

        except Exception as e:
            print(f"[!] שגיאה בחיבור {child_name}: {e}")
            import traceback
            traceback.print_exc()
        finally:
            if child_name and child_name in active_connections:
                client_socket.close()
                with data_lock:
                    if child_name in children_data:
                        children_data[child_name]['client_address'] = None
                    if child_name in active_connections:
                        del active_connections[child_name]
                print(f"[-] {child_name} התנתק")

    def handle_child_communication(self, client_socket, child_name):
        """טיפול בתקשורת מוצפנת עם ילד"""
        print(f"[COMM] 🔄 התחלת תקשורת מוצפנת עם {child_name}")

        while self.running:
            try:
                client_socket.settimeout(30)
                msg_type, data = Protocol.receive_message(client_socket)
                print(f"[COMM] 📨 התקבלה הודעה מוצפנת: {msg_type} מ-{child_name}")

                if msg_type == Protocol.GET_DOMAINS:
                    with data_lock:
                        domains = list(children_data[child_name]['blocked_domains'])
                    Protocol.send_message(client_socket, Protocol.UPDATE_DOMAINS, {"domains": domains})
                    print(f"[COMM] 📤 נשלחו דומיינים מוצפנים ל-{child_name}: {domains}")

                elif msg_type == Protocol.CHILD_STATUS:
                    with data_lock:
                        children_data[child_name]['last_seen'] = time.time()
                    Protocol.send_message(client_socket, Protocol.ACK)
                    print(f"[COMM] ✅ ACK מוצפן נשלח ל-{child_name}")

                elif msg_type == Protocol.BROWSING_HISTORY:
                    print(f"[COMM] 🔍 מעבד הודעת היסטוריה מוצפנת מ-{child_name}...")

                    if not isinstance(data, dict):
                        print(f"[COMM] ❌ נתונים לא תקינים - לא מילון: {type(data)}")
                        continue

                    child_name_from_data = data.get("child_name")
                    history_entries = data.get("history", [])

                    if not child_name_from_data:
                        print(f"[COMM] ❌ שם ילד ריק")
                        continue

                    if not isinstance(history_entries, list):
                        print(f"[COMM] ❌ רשומות היסטוריה לא רשימה: {type(history_entries)}")
                        continue

                    if len(history_entries) == 0:
                        print(f"[COMM] ⚠️ רשימת היסטוריה ריקה")
                        Protocol.send_message(client_socket, Protocol.ACK)
                        continue

                    try:
                        print(f"[COMM] 🔄 מוסיף היסטוריה מוצפנת לבסיס הנתונים...")
                        add_to_browsing_history(child_name_from_data, history_entries)

                        Protocol.send_message(client_socket, Protocol.ACK)
                        print(f"[COMM] ✅ היסטוריה מוצפנת מ-{child_name} עובדה בהצלחה וACK נשלח")

                    except Exception as history_error:
                        print(f"[COMM] ❌ שגיאה בעיבוד היסטוריה מוצפנת: {history_error}")
                        continue

                elif msg_type == Protocol.ERROR:
                    print(f"[COMM] ❌ שגיאה מהילד {child_name}: {data}")
                    break

            except socket.timeout:
                continue
            except Exception as e:
                print(f"[COMM] ❌ שגיאה בתקשורת מוצפנת עם {child_name}: {e}")
                break

        print(f"[COMM] 🔚 סיום תקשורת מוצפנת עם {child_name}")

    def start_communication_server(self):
        def run_server():
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind(('', COMMUNICATION_PORT))
            self.server_socket.listen(5)
            print(f"[*] 🔒 שרת תקשורת מוצפן מאזין על פורט {COMMUNICATION_PORT}")

            while self.running:
                try:
                    client_socket, address = self.server_socket.accept()
                    with self.threads_lock:
                        if len(self.connection_threads) >= 50:
                            print(f"[!] יותר מדי חיבורים ({len(self.connection_threads)}) - דוחה חיבור")
                            client_socket.close()
                            continue

                    client_thread = threading.Thread(
                        target=self.handle_child_connection,
                        args=(client_socket, address),
                        name=f"Child-{address[0]}-{address[1]}"
                    )
                    client_thread.daemon = True
                    client_thread.start()
                    with self.threads_lock:
                        self.connection_threads.append(client_thread)

                except Exception as e:
                    if self.running:
                        print(f"[!] שגיאה בקבלת חיבור: {e}")

        comm_thread = threading.Thread(target=run_server, name="CommunicationServer")
        comm_thread.daemon = True
        comm_thread.start()

    def shutdown(self):
        """סגירה נקייה של שרת ההורים"""
        print("[*] מתחיל סגירה נקייה של שרת ההורים...")

        self.running = False

        if self.server_socket:
            try:
                self.server_socket.close()
                print("[*] שרת תקשורת מוצפן נסגר")
            except:
                pass

        disconnected = 0
        for child_name, conn_info in list(active_connections.items()):
            try:
                if conn_info and conn_info.get("socket"):
                    conn_info["socket"].close()
                    disconnected += 1
            except:
                pass

        active_connections.clear()
        print(f"[*] ניתקתי {disconnected} ילדים")

        try:
            save_children_data()
            save_browsing_history()
            print("[*] ✅ נתונים מוצפנים נשמרו")
        except Exception as e:
            print(f"[!] שגיאה בשמירת נתונים: {e}")

        print("[*] 🎉 סגירת שרת ההורים הושלמה")


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
        """עדכון מיידי מוצפן לילד"""
        print(f"[DEBUG] מנסה לעדכן {child_name} בתקשורת מוצפנת...")
        with data_lock:
            if child_name in active_connections:
                conn_info = active_connections[child_name]
                if conn_info and conn_info.get("socket"):
                    try:
                        sock = conn_info["socket"]
                        domains = list(children_data[child_name]['blocked_domains'])
                        # שליחה מוצפנת
                        Protocol.send_message(sock, Protocol.UPDATE_DOMAINS, {"domains": domains})
                        print(f"[*] נשלח עדכון מוצפן מיידי ל-{child_name}")
                        # הוספת פקודת ניקוי cache מיידית
                        try:
                            Protocol.send_message(sock, "FORCE_DNS_CLEAR", {})
                            print(f"[*] נשלחה פקודת ניקוי DNS מיידית ל-{child_name}")
                        except:
                            pass
                    except Exception as e:
                        print(f"[!] שגיאה בעדכון מוצפן {child_name}: {e}")

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
            self.send_response(302)
            self.send_header('Set-Cookie', 'user_email=; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT')
            self.send_header('Location', '/login')
            self.end_headers()

        elif parsed_path.path == '/system_status':
            logged_in_user = self.is_logged_in()
            if not logged_in_user:
                self.send_response(302)
                self.send_header('Location', '/login')
                self.end_headers()
                return

            user_name = user_manager.get_user_fullname(logged_in_user)

            # בדיקת מצב ההצפנה המסונכרנת
            encryption_enabled = encryption_system is not None and file_manager is not None
            protocol_encryption = Protocol.test_encryption()

            # בדיקת קיום קבצים מוצפנים
            children_encrypted = os.path.exists('children_data.json.encrypted')
            history_encrypted = os.path.exists('browsing_history.json.encrypted')
            users_encrypted = os.path.exists('users_data.json.encrypted')
            communication_key = os.path.exists('communication_key.key')

            # סטטיסטיקות מערכת
            total_children = len(children_data)
            total_domains_blocked = sum(len(info['blocked_domains']) for info in children_data.values())
            total_history_entries = sum(len(entries) for entries in browsing_history.values())
            connected_children = sum(1 for info in children_data.values() if info.get('client_address') is not None)

            status_color = "green" if encryption_enabled and protocol_encryption else "orange"
            status_text = "מוצפן ומסונכרן 🔒" if encryption_enabled and protocol_encryption else "חלקי 🔓"

            system_html = f"""
            <!DOCTYPE html>
            <html dir="rtl" lang="he">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>מצב המערכת - בקרת הורים מוצפנת</title>
                <style>
                    body {{ 
                        font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; 
                        margin: 0; 
                        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                        min-height: 100vh;
                    }}
                    .container {{ 
                        max-width: 1200px; 
                        margin: 0 auto; 
                        padding: 20px; 
                    }}
                    .header {{ 
                        background: rgba(255,255,255,0.95); 
                        color: #333; 
                        padding: 30px; 
                        border-radius: 15px; 
                        margin-bottom: 20px; 
                        box-shadow: 0 10px 30px rgba(0,0,0,0.2);
                        text-align: center;
                    }}
                    .header h1 {{ margin: 0; font-size: 2.5em; color: #667eea; }}
                    .status-card {{ 
                        background: rgba(255,255,255,0.95); 
                        padding: 25px; 
                        border-radius: 15px; 
                        box-shadow: 0 10px 30px rgba(0,0,0,0.1); 
                        margin: 20px 0; 
                    }}
                    .status-indicator {{ 
                        font-size: 24px; 
                        font-weight: bold; 
                        color: {status_color}; 
                        margin: 15px 0;
                    }}
                    .nav {{ 
                        margin: 20px 0; 
                        text-align: center;
                    }}
                    .nav a {{ 
                        margin: 0 10px; 
                        padding: 10px 20px; 
                        background: rgba(255,255,255,0.9); 
                        color: #667eea; 
                        text-decoration: none; 
                        border-radius: 25px;
                        font-weight: bold;
                        transition: all 0.3s ease;
                    }}
                    .nav a:hover {{ 
                        background: white; 
                        transform: translateY(-2px);
                        box-shadow: 0 5px 15px rgba(0,0,0,0.2);
                    }}
                    .stats-grid {{
                        display: grid;
                        grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
                        gap: 20px;
                        margin: 20px 0;
                    }}
                    .stat-card {{
                        background: rgba(255,255,255,0.95);
                        padding: 20px;
                        border-radius: 15px;
                        box-shadow: 0 5px 15px rgba(0,0,0,0.1);
                        text-align: center;
                    }}
                    .stat-number {{
                        font-size: 3em;
                        font-weight: bold;
                        color: #667eea;
                        margin: 10px 0;
                    }}
                    .stat-label {{
                        font-size: 1.1em;
                        color: #666;
                    }}
                    .file-status {{ 
                        margin: 15px 0; 
                        padding: 15px; 
                        background: #f8f9fa; 
                        border-left: 4px solid #007bff; 
                        border-radius: 5px;
                        display: flex;
                        justify-content: space-between;
                        align-items: center;
                    }}
                    .status-badge {{
                        display: inline-block;
                        padding: 5px 12px;
                        border-radius: 20px;
                        font-size: 14px;
                        font-weight: bold;
                    }}
                    .encrypted {{ background: #d4edda; color: #155724; }}
                    .regular {{ background: #fff3cd; color: #856404; }}
                    .connection-indicator {{
                        display: inline-block;
                        width: 12px;
                        height: 12px;
                        border-radius: 50%;
                        margin-left: 10px;
                    }}
                    .online {{ background: #28a745; }}
                    .offline {{ background: #dc3545; }}
                </style>
            </head>
            <body>
                <div class="container">
                    <div class="header">
                        <h1>🔒 מצב המערכת המוצפנת</h1>
                        <p style="font-size: 1.2em; margin: 10px 0;">שלום {user_name}! בקרה מלאה על המערכת המאובטחת</p>
                    </div>

                    <div class="nav">
                        <a href="/dashboard">🏠 דף הבית</a>
                        <a href="/manage_children">👶 ניהול ילדים</a>
                        <a href="/browsing_history">📊 היסטוריה</a>
                        <a href="/system_status">📊 מצב המערכת</a>
                        <a href="/logout">🚪 יציאה</a>
                    </div>

                    <div class="stats-grid">
                        <div class="stat-card">
                            <div class="stat-number">{total_children}</div>
                            <div class="stat-label">ילדים במערכת</div>
                            <div class="connection-indicator {'online' if connected_children > 0 else 'offline'}"></div>
                            <small>{connected_children} מחוברים מוצפנים</small>
                        </div>
                        <div class="stat-card">
                            <div class="stat-number">{total_domains_blocked}</div>
                            <div class="stat-label">אתרים חסומים</div>
                        </div>
                        <div class="stat-card">
                            <div class="stat-number">{total_history_entries}</div>
                            <div class="stat-label">רשומות מוצפנות</div>
                        </div>
                        <div class="stat-card">
                            <div class="stat-number">{"🔒" if encryption_enabled and protocol_encryption else "⚠️"}</div>
                            <div class="stat-label">מצב הצפנה</div>
                        </div>
                    </div>

                    <div class="status-card">
                        <h2>🔒 מצב הצפנה מסונכרנת</h2>
                        <div class="status-indicator">סטטוס: {status_text}</div>
                        <p>מערכת הצפנה דו-שכבתית: נתונים + תקשורת</p>

                        <div style="margin-top: 20px;">
                            <h3>📁 קבצי המערכת</h3>
                            <div class="file-status">
                                <div>
                                    <strong>נתוני ילדים</strong><br>
                                    <small>רשימת ילדים ואתרים חסומים</small>
                                </div>
                                <span class="status-badge {'encrypted' if children_encrypted else 'regular'}">
                                    {'🔒 מוצפן' if children_encrypted else '🔓 רגיל'}
                                </span>
                            </div>
                            <div class="file-status">
                                <div>
                                    <strong>היסטוריית גלישה</strong><br>
                                    <small>רשומות פעילות מוצפנות</small>
                                </div>
                                <span class="status-badge {'encrypted' if history_encrypted else 'regular'}">
                                    {'🔒 מוצפן' if history_encrypted else '🔓 רגיל'}
                                </span>
                            </div>
                            <div class="file-status">
                                <div>
                                    <strong>נתוני משתמשים</strong><br>
                                    <small>פרטי התחברות מוצפנים</small>
                                </div>
                                <span class="status-badge {'encrypted' if users_encrypted else 'regular'}">
                                    {'🔒 מוצפן' if users_encrypted else '🔓 רגיל'}
                                </span>
                            </div>
                            <div class="file-status">
                                <div>
                                    <strong>מפתח תקשורת</strong><br>
                                    <small>הצפנת הודעות בין הורה לילד</small>
                                </div>
                                <span class="status-badge {'encrypted' if communication_key else 'regular'}">
                                    {'🔒 קיים' if communication_key else '❌ חסר'}
                                </span>
                            </div>
                        </div>
                    </div>

                    <div class="status-card">
                        <h3>🔐 מידע על ההצפנה המסונכרנת</h3>
                        <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 15px; margin-top: 15px;">
                            <div style="background: #e8f4fd; padding: 15px; border-radius: 8px;">
                                <strong>💾 הצפנת נתונים</strong><br>
                                כל קובץ מוצפן ברמה צבאית (AES-256)
                            </div>
                            <div style="background: #fff2e8; padding: 15px; border-radius: 8px;">
                                <strong>📡 הצפנת תקשורת</strong><br>
                                כל הודעה בין הורה לילד מוצפנת
                            </div>
                            <div style="background: #e8f8e8; padding: 15px; border-radius: 8px;">
                                <strong>🔑 ניהול מפתחות</strong><br>
                                מפתחות נפרדים לנתונים ותקשורת
                            </div>
                            <div style="background: #f0e8ff; padding: 15px; border-radius: 8px;">
                                <strong>🔄 סנכרון אוטומטי</strong><br>
                                המערכת מסנכרנת מפתחות אוטומטית
                            </div>
                        </div>
                    </div>

                    <div style="text-align: center; margin: 30px 0;">
                        <p style="color: rgba(255,255,255,0.8); font-size: 14px;">
                            מערכת בקרת הורים מוצפנת לחלוטין | הצפנה דו-שכבתית
                        </p>
                    </div>
                </div>
            </body>
            </html>
            """

            self.send_response(200)
            self.send_header('Content-type', 'text/html; charset=utf-8')
            self.end_headers()
            self.wfile.write(system_html.encode('utf-8'))

        elif parsed_path.path == '/browsing_history':
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

            # סינון והצגת היסטוריה
            filtered_history = []
            with history_lock:
                for child_name, entries in browsing_history.items():
                    if child_filter and child_name != child_filter:
                        continue

                    for entry in entries:
                        # סינון לפי סטטוס
                        if status_filter == 'blocked' and not entry.get('was_blocked', False):
                            continue
                        if status_filter == 'allowed' and entry.get('was_blocked', False):
                            continue

                        # סינון לפי דומיין
                        if domain_filter and domain_filter.lower() not in entry.get('domain', '').lower():
                            continue

                        filtered_history.append(entry)

            # מיון לפי זמן (חדש ביותר קודם)
            filtered_history.sort(key=lambda x: x.get('timestamp', ''), reverse=True)
            filtered_history = filtered_history[:200]

            # קיבוץ ההיסטוריה
            grouped_history = group_browsing_by_main_site(filtered_history, time_window_minutes=30)

            # בניית HTML לרשומות
            history_entries = []
            for entry in grouped_history:
                formatted_entry = format_simple_grouped_entry(entry)
                history_entries.append(formatted_entry)

            # סטטיסטיקות
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

        elif parsed_path.path == '/manage_children':
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
                    status_text = "מחובר מוצפן" if is_connected else "לא מחובר"
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

        elif parsed_path.path == '/dashboard':
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
                        status_text = "מחובר מוצפן" if is_connected else "לא מחובר"
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

        else:
            self.send_error(404)

    def do_POST(self):
        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length)
        post_params = parse_qs(post_data.decode('utf-8'))

        if self.path == '/add_domain':
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
                save_children_data()
                print(f"[+] נוסף דומיין {domain} עבור {child_name}")
                self.notify_child_immediate(child_name)

            encoded_child_name = quote(child_name)
            self.send_response(302)
            self.send_header('Location', f'/dashboard?child={encoded_child_name}')
            self.end_headers()

        elif self.path == '/remove_domain':
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
                save_children_data()
                print(f"[-] הוסר דומיין {domain} מ-{child_name}")
                self.notify_child_immediate(child_name)

            encoded_child_name = quote(child_name)
            self.send_response(302)
            self.send_header('Location', f'/dashboard?child={encoded_child_name}')
            self.end_headers()

        elif self.path == '/register':
            fullname = post_params.get('fullname', [''])[0].strip()
            email = post_params.get('email', [''])[0].strip()
            password = post_params.get('password', [''])[0]
            confirm_password = post_params.get('confirm_password', [''])[0]

            if password != confirm_password:
                error_message = '<div class="message error-message">הסיסמאות אינן תואמות</div>'
                register_html = REGISTER_TEMPLATE.replace('${message}', error_message)
                self.send_response(200)
                self.send_header('Content-type', 'text/html; charset=utf-8')
                self.end_headers()
                self.wfile.write(register_html.encode('utf-8'))
                return

            success, message = user_manager.register_user(email, fullname, password)

            if success:
                success_message = '<div class="message success-message">ההרשמה הושלמה בהצלחה! כעת תוכל להתחבר</div>'
                login_html = LOGIN_TEMPLATE.replace('${message}', success_message)
                self.send_response(200)
                self.send_header('Content-type', 'text/html; charset=utf-8')
                self.end_headers()
                self.wfile.write(login_html.encode('utf-8'))
            else:
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

            if user_manager.validate_login(email, password):
                self.send_response(302)
                self.send_header('Set-Cookie', f'user_email={quote(email)}; Path=/')
                self.send_header('Location', '/dashboard')
                self.end_headers()
                print(f"[+] משתמש התחבר: {email}")
            else:
                error_message = '<div class="message error-message">שם משתמש או סיסמה שגויים</div>'
                login_html = LOGIN_TEMPLATE.replace('${message}', error_message)
                self.send_response(200)
                self.send_header('Content-type', 'text/html; charset=utf-8')
                self.end_headers()
                self.wfile.write(login_html.encode('utf-8'))

        elif self.path == '/add_child':
            print("[DEBUG] 🔹 נכנסתי לטיפול בהוספת ילד")

            try:
                logged_in_user = self.is_logged_in()
                if not logged_in_user:
                    self.send_response(302)
                    self.send_header('Location', '/login')
                    self.end_headers()
                    return

                child_name = post_params.get('child_name', [''])[0].strip()
                print(f"[DEBUG] שם הילד שהתקבל: '{child_name}'")

                if child_name:
                    success = parent_server.add_child(child_name)
                    if success:
                        print(f"[✅] ילד '{child_name}' נוסף בהצלחה!")
                    else:
                        print(f"[❌] כישלון בהוספת ילד '{child_name}'")

                self.send_response(302)
                self.send_header('Location', '/manage_children')
                self.end_headers()

            except Exception as e:
                print(f"[!] שגיאה ב-add_child: {e}")
                self.send_response(500)
                self.send_header('Content-type', 'text/html')
                self.end_headers()
                self.wfile.write(b'<h1>Server Error</h1>')

        elif self.path == '/remove_child':
            print("[DEBUG] 🔹 נכנסתי לטיפול במחיקת ילד")

            try:
                logged_in_user = self.is_logged_in()
                if not logged_in_user:
                    self.send_response(302)
                    self.send_header('Location', '/login')
                    self.end_headers()
                    return

                child_name = post_params.get('child_name', [''])[0].strip()
                print(f"[DEBUG] שם הילד למחיקה: '{child_name}'")

                if child_name:
                    success = parent_server.remove_child(child_name)
                    if success:
                        print(f"[✅] ילד '{child_name}' נמחק בהצלחה!")
                    else:
                        print(f"[❌] כישלון במחיקת ילד '{child_name}'")

                self.send_response(302)
                self.send_header('Location', '/manage_children')
                self.end_headers()

            except Exception as e:
                print(f"[!] שגיאה ב-remove_child: {e}")
                self.send_response(500)
                self.send_header('Content-type', 'text/html')
                self.end_headers()
                self.wfile.write(b'<h1>Server Error</h1>')

        elif self.path == '/clear_history':
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

            self.send_response(302)
            self.send_header('Location', '/browsing_history')
            self.end_headers()

        elif self.path == '/toggle_encryption':
            # מכיוון שתמיד צריך להיות מוצפן, אין טעם בפונקציה הזו
            logged_in_user = self.is_logged_in()
            if not logged_in_user:
                self.send_response(302)
                self.send_header('Location', '/login')
                self.end_headers()
                return

            # הפניה לדף מצב המערכת
            self.send_response(302)
            self.send_header('Location', '/system_status')
            self.end_headers()

        # יתר הפונקציות ממשיכות...
        else:
            self.send_response(404)
            self.end_headers()


# פונקציות עזר נוספות לניהול המערכת
def get_encryption_status():
    """קבלת מצב ההצפנה הנוכחי"""
    return {
        "enabled": encryption_system is not None and file_manager is not None,
        "files": {
            "children_data_encrypted": os.path.exists('children_data.json.encrypted'),
            "browsing_history_encrypted": os.path.exists('browsing_history.json.encrypted'),
            "users_data_encrypted": os.path.exists('users_data.json.encrypted')
        },
        "key_file_exists": os.path.exists('parent_control_system_encryption.key')
    }


def cleanup_old_files():
    """ניקוי קבצים ישנים ואפיונים לא נחוצים"""
    old_files = [
        'browsing_history_backup.json',
        'children_data_backup.json',
        'users_data_backup.json'
    ]

    cleaned = 0
    for file in old_files:
        if os.path.exists(file):
            try:
                os.remove(file)
                cleaned += 1
                print(f"[CLEANUP] 🗑️ נמחק קובץ ישן: {file}")
            except Exception as e:
                print(f"[CLEANUP] ❌ לא ניתן למחוק {file}: {e}")

    if cleaned > 0:
        print(f"[CLEANUP] ✅ נוקו {cleaned} קבצים ישנים")
    return cleaned


def backup_all_data():
    """יצירת גיבוי מלא של כל הנתונים"""
    import datetime
    import shutil

    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_dir = f"backup_{timestamp}"

    try:
        os.makedirs(backup_dir, exist_ok=True)

        files_to_backup = [
            'children_data.json.encrypted',
            'browsing_history.json.encrypted',
            'users_data.json.encrypted',
            'children_data.json',
            'browsing_history.json',
            'users_data.json',
            'parent_control_system_encryption.key'
        ]

        backed_up = 0
        for file in files_to_backup:
            if os.path.exists(file):
                try:
                    shutil.copy2(file, os.path.join(backup_dir, file))
                    backed_up += 1
                except Exception as e:
                    print(f"[BACKUP] ❌ לא ניתן לגבות {file}: {e}")

        print(f"[BACKUP] ✅ נוצר גיבוי עם {backed_up} קבצים ב-{backup_dir}")
        return backup_dir

    except Exception as e:
        print(f"[BACKUP] ❌ שגיאה ביצירת גיבוי: {e}")
        return None


def final_check():
    """בדיקה סופית שהכל מוכן"""
    print("\n🔍 בדיקה סופית של המערכת...")

    required_files = [
        'encryption_module.py',
        'protocol.py',
        'history_utils.py',
        'html_templates_parent.py'
    ]

    missing_files = []
    for file in required_files:
        if not os.path.exists(file):
            missing_files.append(file)

    if missing_files:
        print(f"❌ חסרים קבצים: {missing_files}")
        print("⚠️  המערכת עלולה לא לעבוד ללא קבצים אלה")
        return False

    print("✅ כל הקבצים הנדרשים במקום")

    # בדיקת הרשאות
    try:
        test_file = "test_permissions.tmp"
        with open(test_file, 'w') as f:
            f.write("test")
        os.remove(test_file)
        print("✅ הרשאות כתיבה תקינות")
    except Exception as e:
        print(f"⚠️  בעיית הרשאות: {e}")

    print("✅ מוכן להפעלה!")

    print("""
🎯 להפעלה:
1. python parent_server.py
2. גש ל-https://localhost:8443
3. התחבר עם: admin@example.com / admin123
4. עבור למצב המערכת: /system_status
""")
    return True


print("[*] ParentServer אותחל עם פונקציות ניהול ילדים והיסטוריית גלישה")
print("[*] 🔒 מערכת הצפנה מתקדמת מוכנה")

# יצירת מנהל משתמשים גלובלי
user_manager = UserManager()

if __name__ == "__main__":
    print("🚀 מתחיל שרת בקרת הורים מוצפן...")
    print("=" * 50)

    # אתחול מערכת ההצפנה המסונכרנת
    initialize_encryption()

    # יצירת שרת ההורים
    parent_server = ParentServer()

    print("[🔒] מערכת הצפנה מסונכרנת מוכנה!")
    print(f"[👥] {len(user_manager.users)} משתמשים רשומים")
    print(f"[👶] {len(children_data)} ילדים במערכת")
    print("[📡] תקשורת מוצפנת עם הילדים")

    try:
        print("\n[*] 🔒 מתחיל שרת בקרת הורים עם HTTPS")
        parent_server.start_communication_server()

        # יצירת תעודת SSL
        if create_ssl_certificate():
            print("[*] ✅ מפעיל שרת HTTPS מוצפן")

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

                    print(f"\n🎉 השרת המוצפן מוכן!")
                    print(f"[*] 🔒 שרת HTTPS פועל על https://localhost:{HTTPS_PORT}")
                    print(f"[*] 📡 שרת תקשורת מוצפן פועל על פורט {COMMUNICATION_PORT}")
                    print(f"[*] 🎯 מוכן לקבל חיבורים מוצפנים מילדים")

                    server_url = f"https://localhost:{HTTPS_PORT}"
                    print(f"\n[*] 🌐 פותח דפדפן: {server_url}")
                    print("[!] ⚠️  אם הדפדפן מתריע - לחץ 'Advanced' ← 'Proceed to localhost'")
                    print("\n" + "=" * 50)
                    print("[*] 🔒 כל התקשורת והנתונים מוצפנים")
                    print("[*] לחץ Ctrl+C לעצירת השרת")
                    print("=" * 50)

                    webbrowser.open(server_url)
                    httpd.serve_forever()

                except ssl.SSLError as e:
                    print(f"[!] ❌ שגיאת SSL: {e}")
                    raise

        else:
            raise Exception("לא ניתן ליצור תעודת SSL")

    except KeyboardInterrupt:
        print("\n[*] 🛑 עצירת השרת המוצפן על ידי המשתמש...")
        parent_server.shutdown()
        print("[*] ✅ השרת המוצפן נסגר בבטחה")

    except Exception as e:
        print(f"[!] ❌ שגיאה בהפעלת HTTPS: {e}")
        parent_server.shutdown()
        print("[*] 🔄 עובר למצב HTTP כגיבוי...")

        # גיבוי HTTP
        try:
            with socketserver.TCPServer(("", HTTP_PORT), ParentHandler) as httpd:
                print(f"\n[*] 🔓 שרת HTTP פועל על http://localhost:{HTTP_PORT}")
                print("[*] 👤 משתמש דמו: admin@example.com / admin123")
                print("[*] ⚠️  במצב HTTP - אין הצפנת תעבורה!")
                print("[*] 🔒 אבל הנתונים והתקשורת עדיין מוצפנים")

                server_url = f"http://localhost:{HTTP_PORT}"
                webbrowser.open(server_url)
                print(f"[*] 🌐 דפדפן נפתח: {server_url}")
                print("[*] לחץ Ctrl+C לעצירת השרת")

                httpd.serve_forever()

        except KeyboardInterrupt:
            print("\n[*] 🛑 עצירת שרת HTTP...")
            parent_server.shutdown()
            print("[*] ✅ השרת נסגר בבטחה")

        except Exception as http_error:
            print(f"[!] ❌ שגיאה גם בשרת HTTP: {http_error}")
            parent_server.shutdown()

        finally:
            try:
                parent_server.shutdown()
                print("[*] 🔒 נתונים מוצפנים נשמרו")
                print("[*] 👋 להתראות!")
            except:
                pass
