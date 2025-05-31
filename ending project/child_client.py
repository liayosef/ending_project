from scapy.all import *
from scapy.layers.dns import DNS, DNSQR, DNSRR
import json
from contextlib import contextmanager
import threading
import time
import re
from urllib.parse import urlparse
import atexit
import subprocess
from collections import defaultdict
import platform
import os
import ctypes
from protocol import Protocol, COMMUNICATION_PORT
import socket
from datetime import datetime
import sys
import webbrowser
from html_templats_child import (
    REGISTRATION_HTML_TEMPLATE,
    BLOCK_HTML_TEMPLATE,
    create_error_page,
    create_success_page
)
from custom_http_server import ParentalControlHTTPServer
# 🆕 Import עבור שרת HTTPS
try:
    from custom_https_server import HTTPSBlockServer
    HTTPS_AVAILABLE = True
    print("[*] ✅ מודול HTTPS זמין")
except ImportError:
    HTTPSBlockServer = None
    HTTPS_AVAILABLE = False
    print("[*] ⚠️ מודול HTTPS לא זמין - רק HTTP")

# 🆕 הפונקציה שחסרה
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
custom_http_server = None
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
    'clarity.ms', 'mktoresp.com', 'optimizely.com', 'googlezip.net',
    'heyday', 'jquery.com', 'rss.app', 'gostreaming.tv',
]


def verify_child_with_parent_callback(child_name):
    """פונקציית callback לשרת HTTP"""
    try:
        success = verify_child_with_parent(child_name)
        if success:
            global CHILD_NAME
            CHILD_NAME = child_name
            save_registration(child_name)
            if custom_http_server and hasattr(custom_http_server, 'set_child_data'):
                custom_http_server.set_child_data(child_name)
            child_client.child_name = CHILD_NAME
        return success
    except Exception as e:
        print(f"[!] שגיאה באימות: {e}")
        return False

def emergency_dns_cleanup():
    print("\n[!] 🚨 ניקוי DNS חירום...")
    try:
        # חזרה ל-DHCP
        subprocess.run(['netsh', 'interface', 'ip', 'set', 'dns', 'Wi-Fi', 'dhcp'],
                       capture_output=True, timeout=5)
        print("[!] ✅ DNS הוחזר!")
    except:
        pass


atexit.register(emergency_dns_cleanup)


class NetworkManager:
    """מחלקה לניהול יעיל של סוקטים - מונעת דליפות"""

    def __init__(self):
        # סוקט קבוע לשאילתות DNS
        self._dns_query_socket = None
        self._dns_socket_lock = threading.Lock()

        # Pool של סוקטים לתקשורת עם שרת הורים
        self._parent_socket_pool = []
        self._pool_lock = threading.Lock()
        self._max_pool_size = 5

        # סוקט קבוע לתקשורת ארוכת טווח
        self._persistent_parent_socket = None
        self._persistent_socket_lock = threading.Lock()

    def get_dns_query_socket(self):
        """מחזיר סוקט UDP לשאילתות DNS - יוצר רק פעם אחת"""
        with self._dns_socket_lock:
            if self._dns_query_socket is None:
                self._dns_query_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                self._dns_query_socket.settimeout(5)
                print("[NETWORK] יצרתי סוקט DNS קבוע")
            return self._dns_query_socket

    @contextmanager
    def get_parent_socket_from_pool(self):
        """Context manager לסוקט זמני לשרת הורים - גרסה מתוקנת"""
        sock = None
        try:
            # תמיד יוצר סוקט חדש - פשוט יותר ובטוח יותר
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            print("[NETWORK] ✅ יצרתי סוקט חדש (לא pool)")

            yield sock

        except Exception as e:
            print(f"[NETWORK] ❌ שגיאה בסוקט: {e}")
            raise
        finally:
            # תמיד סוגר את הסוקט - אין pool!
            if sock:
                try:
                    sock.close()
                    print("[NETWORK] 🗑️ סוקט נסגר")
                except:
                    pass

    def get_persistent_parent_socket(self):
        """סוקט קבוע לתקשורת ארוכת טווח עם שרת הורים"""
        with self._persistent_socket_lock:
            if self._persistent_parent_socket is None:
                self._persistent_parent_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                print("[NETWORK] יצרתי סוקט קבוע לשרת הורים")
            return self._persistent_parent_socket

    def close_persistent_socket(self):
        """סגירת הסוקט הקבוע"""
        with self._persistent_socket_lock:
            if self._persistent_parent_socket:
                try:
                    self._persistent_parent_socket.shutdown(socket.SHUT_RDWR)
                    self._persistent_parent_socket.close()
                    print("[NETWORK] ✅ סגרתי סוקט קבוע")
                except:
                    pass
                self._persistent_parent_socket = None

    def cleanup_all(self):
        """ניקוי כל הסוקטים - לקריאה בסוף התוכנית"""
        print("[NETWORK] 🧹 מנקה את כל הסוקטים...")

        # סגירת סוקט DNS
        with self._dns_socket_lock:
            if self._dns_query_socket:
                try:
                    self._dns_query_socket.close()
                    print("[NETWORK] ✅ סוקט DNS נסגר")
                except:
                    pass
                self._dns_query_socket = None

        # סגירת pool
        with self._pool_lock:
            for sock in self._parent_socket_pool:
                try:
                    sock.close()
                except:
                    pass
            cleared_count = len(self._parent_socket_pool)
            self._parent_socket_pool.clear()
            print(f"[NETWORK] ✅ Pool נוקה ({cleared_count} סוקטים)")

        # סגירת סוקט קבוע
        self.close_persistent_socket()

        print("[NETWORK] 🎉 כל הסוקטים נוקו!")


# אובייקט גלובלי
network_manager = NetworkManager()


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
            print(f"[+]  ילד רשום: {CHILD_NAME}")
            return True
        else:
            print(f"[!] רישום של '{saved_name}' לא תקף יותר")
            try:
                os.remove(REGISTRATION_FILE)
            except:
                pass
    return False


def verify_child_with_parent(child_name):
    """גרסה משופרת שמשתמשת ב-NetworkManager"""
    try:
        print(f"[DEBUG] מנסה לאמת ילד: {child_name}")

        with network_manager.get_parent_socket_from_pool() as sock:
            sock.connect((PARENT_SERVER_IP, COMMUNICATION_PORT))

            verify_data = {"child_name": child_name}
            Protocol.send_message(sock, Protocol.VERIFY_CHILD, verify_data)

            msg_type, data = Protocol.receive_message(sock)
            is_valid = data.get("is_valid", False)

            print(f"[DEBUG]  אימות הושלם")
            return is_valid

    except Exception as e:
        print(f"[!] שגיאה באימות: {e}")
        return False


def wait_for_registration():
    print("\n🔧 מכין דף רישום...")
    print("⏳ ממתין שהשרת יהיה מוכן...")

    time.sleep(2)

    # בדיקת מוכנות השרת
    max_attempts = 10
    for i in range(max_attempts):
        try:
            test_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            test_sock.settimeout(0.5)
            result = test_sock.connect_ex(('127.0.0.1', BLOCK_SERVER_PORT))
            test_sock.close()

            if result == 0:
                print("[✅] השרת מוכן!")
                break
        except:
            pass

        print(f"[⏳] ממתין לשרת... ({i + 1}/{max_attempts})")
        time.sleep(0.5)

    # פתיחת דפדפן עם הפרוטוקול הנכון
    try:
        if BLOCK_SERVER_PORT:
            # קביעת הפרוטוקול לפי הפורט
            if BLOCK_SERVER_PORT in [443, 8443]:
                protocol = "https"
                print("⚠️  הדפדפן עלול להתריע על תעודה לא מאומתת")
                print("   לחץ 'Advanced' ואז 'Proceed to localhost'")
            else:
                protocol = "http"

            if BLOCK_SERVER_PORT in [80, 443]:
                registration_url = f"{protocol}://127.0.0.1"
            else:
                registration_url = f"{protocol}://127.0.0.1:{BLOCK_SERVER_PORT}"

            print(f"🌐 פותח דפדפן: {registration_url}")
            webbrowser.open(registration_url)
            print("📝 הזן את השם שלך בטופס שמופיע בדפדפן")
        else:
            print("[!] שרת לא הצליח להתחיל")
            return False
    except Exception as e:
        print(f"[!] שגיאה בפתיחת דפדפן: {e}")

    # שאר הקוד נשאר זהה...
    max_wait = 300
    waited = 0

    while not CHILD_NAME and waited < max_wait:
        time.sleep(5)
        waited += 5

        if waited % 30 == 0:
            print(f"[*] ממתין לרישום... ({waited}/{max_wait} שניות)")
            if BLOCK_SERVER_PORT:
                if BLOCK_SERVER_PORT in [443, 8443]:
                    protocol = "https"
                else:
                    protocol = "http"

                if BLOCK_SERVER_PORT in [80, 443]:
                    print(f"[*] 🔗 נסה לגשת ל: {protocol}://127.0.0.1")
                else:
                    print(f"[*] 🔗 נסה לגשת ל: {protocol}://127.0.0.1:{BLOCK_SERVER_PORT}")

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
                if not child_client.connected:
                    print(f"[!] הילד '{CHILD_NAME}' לא מחובר יותר!")
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
    print("[!]  אינטרנט חסום - ילד לא רשום!")


def extract_main_site_name(domain):
    """
    מחלץ את השם הראשי של האתר מכל דומיין
    """
    if not domain:
        return domain

    # ניקוי הדומיין
    domain = domain.lower().strip()

    # הסרת פרוטוקול אם קיים
    if '://' in domain:
        domain = urlparse(domain).netloc or domain

    # הסרת פורט
    if ':' in domain:
        domain = domain.split(':')[0]

    # הסרת תת-דומיינים טכניים נפוצים
    technical_subdomains = [
        'www', 'www2', 'www3', 'm', 'mobile', 'api', 'cdn', 'static',
        'assets', 'img', 'images', 'css', 'js', 'analytics', 'tracking',
        'ads', 'ad', 'media', 'content', 'secure', 'ssl', 'login',
        'auth', 'oauth', 'sso', 'mail', 'email', 'smtp', 'pop', 'imap'
    ]

    parts = domain.split('.')

    # אם יש רק 2 חלקים (name.com) - זה הדומיין הראשי
    if len(parts) <= 2:
        return domain

    # הסרת תת-דומיינים טכניים
    while len(parts) > 2 and parts[0] in technical_subdomains:
        parts = parts[1:]

    # טיפול בדומיינים ישראליים ובינלאומיים
    common_tlds = [
        'co.il', 'ac.il', 'gov.il', 'org.il', 'net.il',
        'com.au', 'co.uk', 'co.za', 'com.br'
    ]

    # בדיקה אם יש TLD מורכב
    if len(parts) >= 3:
        last_two = '.'.join(parts[-2:])
        if last_two in common_tlds:
            # TLD מורכב - נשמור 3 חלקים אחרונים
            if len(parts) >= 3:
                return '.'.join(parts[-3:])

    # במקרה הרגיל - נשמור 2 חלקים אחרונים
    return '.'.join(parts[-2:])


def get_site_display_name(domain):
    # בדיקה במיפוי הישראלי קודם
    if 'ebag.cet.ac.il' in domain:
        return 'אופק על יסודי'
    elif 'cet.ac.il' in domain and 'ebag' not in domain:
        return 'מטח'
    elif 'ynet.co.il' in domain:
        return 'Ynet'
    elif 'walla.co.il' in domain:
        return 'וואלה'
    elif 'mako.co.il' in domain:
        return 'מאקו'

    main_domain = extract_main_site_name(domain)

    if not main_domain:
        return domain

    # חילוץ השם בלבד (ללא סיומת)
    parts = main_domain.split('.')
    if len(parts) >= 2:
        site_name = parts[0]  # החלק הראשון

        # שיפור התצוגה
        site_name = site_name.replace('-', ' ').replace('_', ' ')

        # קפיטליזציה
        if len(site_name) <= 3:
            # אתרים קצרים - כל האותיות גדולות
            site_name = site_name.upper()
        else:
            # אתרים ארוכים - רק האות הראשונה גדולה
            site_name = site_name.capitalize()

        return site_name

    return main_domain


def is_obviously_technical(domain):
    """
    בודק אם הדומיין הוא טכני/פרסומי ולא מעניין להורים
    """
    domain_lower = domain.lower()

    # דפוסים טכניים ברורים
    technical_patterns = [
        'analytics', 'tracking', 'ads', 'doubleclick', 'googletagmanager',
        'cdn', 'cache', 'static', 'assets', 'edge', 'akamai', 'cloudflare',
        'api', 'ws', 'websocket', 'ajax', 'xhr', 'heartbeat', 'status',
        'telemetry', 'metrics', 'logs', 'monitoring', 'beacon',
        'googlesyndication', 'googleadservices', 'facebook.com/tr',
        'connect.facebook.net', 'platform.twitter.com', 'google.com',
    ]

    for pattern in technical_patterns:
        if pattern in domain_lower:
            return True

    # תת-דומיינים ארוכים מדי (סימן לטכני)
    parts = domain_lower.split('.')
    if len(parts) > 4:  # יותר מדי תת-דומיינים
        return True

    # בדיקת דומיינים קצרים מדי או ארוכים מדי
    main_part = parts[0] if parts else ''
    if len(main_part) < 2 or len(main_part) > 20:
        return True

    # דומיינים שהם רק מספרים או תווים מוזרים
    if re.match(r'^[0-9\-_]+$', main_part):
        return True

    return False


def add_to_history(domain, timestamp, was_blocked=False):
    """הוספת רשומה להיסטוריה - פשוט וללא סינון יתר"""

    # דילוג רק על דומיינים טכניים ברורים
    if is_obviously_technical(domain):
        return

    # חילוץ שם האתר
    main_domain = extract_main_site_name(domain)
    display_name = get_site_display_name(domain)

    with history_lock:
        entry = {
            "original_domain": domain,
            "main_domain": main_domain,
            "display_name": display_name,
            "timestamp": timestamp,
            "was_blocked": was_blocked,
            "child_name": CHILD_NAME
        }

        browsing_history.append(entry)

        if len(browsing_history) > MAX_HISTORY_ENTRIES:
            browsing_history.pop(0)

        print(f"[HISTORY] ✅ נוסף: {display_name} ({main_domain}) ({'חסום' if was_blocked else 'מותר'})")


def send_history_update():
    if hasattr(child_client, 'connected'):
        print(f"[DEBUG] child_client.connected = {child_client.connected}")
    print(f"[DEBUG] browsing_history length = {len(browsing_history)}")
    print(f"[DEBUG] CHILD_NAME = {CHILD_NAME}")

    if hasattr(child_client, 'connected') and child_client.connected and browsing_history:
        try:
            print(f"[DEBUG]  תנאים מתקיימים - שולח היסטוריה...")
            with history_lock:
                recent_history = browsing_history.copy()
            data = {"child_name": CHILD_NAME, "history": recent_history}
            print(f"[DEBUG] נתונים לשליחה: {len(recent_history)} רשומות")

            Protocol.send_message(child_client.sock, Protocol.BROWSING_HISTORY, data)
            print(f"[HISTORY]  נשלח עדכון לשרת: {len(recent_history)} רשומות")
        except Exception as e:
            print(f"[!]  שגיאה בשליחת היסטוריה: {e}")
            import traceback
            traceback.print_exc()
    else:
        print(f"[DEBUG]  תנאים לא מתקיימים:")
        print(f"[DEBUG] - connected: {hasattr(child_client, 'connected') and child_client.connected}")
        print(f"[DEBUG] - history: {len(browsing_history)} רשומות")


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
    global BLOCK_SERVER_PORT, custom_http_server

    print("[*] מפעיל שרת HTTP/HTTPS מותאם אישית...")

    # רשימת פורטים לניסיון - HTTPS קודם (רק אם זמין)
    ports_to_try = []

    if HTTPS_AVAILABLE:
        ports_to_try.extend([
            (443, 'HTTPS'),  # פורט HTTPS סטנדרטי
            (8443, 'HTTPS'),  # פורט HTTPS חלופי
        ])

    ports_to_try.extend([
        (80, 'HTTP'),  # פורט HTTP סטנדרטי
        (8080, 'HTTP')  # פורט HTTP חלופי
    ])

    for port, protocol in ports_to_try:
        try:
            if protocol == 'HTTPS' and HTTPS_AVAILABLE and HTTPSBlockServer is not None:
                # ניסיון הפעלת שרת HTTPS
                custom_http_server = HTTPSBlockServer("127.0.0.1", port, port + 1000)

            elif protocol == 'HTTP':
                # שרת HTTP רגיל
                custom_http_server = ParentalControlHTTPServer("127.0.0.1", port)

            else:
                continue

            # הגדרת התבניות
            custom_http_server.set_templates(REGISTRATION_HTML_TEMPLATE, BLOCK_HTML_TEMPLATE)

            # הגדרת פונקציית האימות
            custom_http_server.set_verify_callback(verify_child_with_parent_callback)

            # הגדרת הפונקציות המעוצבות
            custom_http_server.set_external_functions(create_error_page, create_success_page)

            # הפעלת השרת בthread נפרד
            server_thread = threading.Thread(target=custom_http_server.start_server, daemon=True)
            server_thread.start()

            # המתנה להתחלה
            if protocol == 'HTTPS':
                time.sleep(2)  # HTTPS צריך יותר זמן
            else:
                time.sleep(1)

            BLOCK_SERVER_PORT = port
            print(f"[+] ✅ שרת {protocol} מותאם אישית פועל על פורט {port}")
            return port

        except Exception as e:
            print(f"[!] שגיאה בפורט {port} ({protocol}): {e}")
            if "Permission denied" in str(e) or "WinError 10013" in str(e):
                print(f"[!] ⚠️ אין הרשאות לפורט {port} - נסה להריץ כמנהל")
            custom_http_server = None
            continue

    print("[!] ❌ כישלון בהפעלת כל השרתים")
    BLOCK_SERVER_PORT = None
    return None

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


def graceful_shutdown():
    print("\n🔄 מתחיל סגירה נקייה...")
    try:
        print("[*] סוגר חיבורי רשת...")
        network_manager.cleanup_all()

        print("[*] משחזר הגדרות DNS מקוריות...")
        if dns_manager.restore_original_dns():
            print("[+] ✅ DNS שוחזר בהצלחה")
        else:
            print("[!] ❌ כישלון בשחזור DNS")
    except Exception as e:
        print(f"[!] שגיאה בסגירה: {e}")


class ChildClient:
    def __init__(self):
        self.child_name = CHILD_NAME
        self.connected = False
        self.keep_running = True
        self.connection_event = threading.Event()
        self._main_socket = None

    @property
    def sock(self):
        return self._main_socket

    def connect_to_parent(self):
        retry_count = 0
        max_retries = 5

        while self.keep_running and retry_count < max_retries:
            try:
                print(f"[*] מנסה להתחבר לשרת הורים (ניסיון {retry_count + 1}/{max_retries})...")

                self._main_socket = network_manager.get_persistent_parent_socket()
                self._main_socket.settimeout(3)
                self._main_socket.connect((PARENT_SERVER_IP, COMMUNICATION_PORT))

                register_data = {"name": self.child_name}
                Protocol.send_message(self._main_socket, Protocol.REGISTER_CHILD, register_data)

                self._main_socket.settimeout(5)
                msg_type, _ = Protocol.receive_message(self._main_socket)

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
            network_manager.close_persistent_socket()

            if retry_count < max_retries:
                print(f"[*] ממתין {2} שניות לפני ניסיון חוזר...")
                time.sleep(2)

        print(f"[!] נכשל בחיבור לשרת הורים אחרי {max_retries} ניסיונות")
        self.connection_event.set()

    def request_domains_update(self):
        if self.connected and self._main_socket:
            try:
                Protocol.send_message(self._main_socket, Protocol.GET_DOMAINS)
                print("[*] בקשה לעדכון דומיינים נשלחה")
            except Exception as e:
                print(f"[!] שגיאה בבקשת עדכון דומיינים: {e}")
                self.connected = False

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

    def send_status_update(self):
        while self.keep_running:
            if self.connected and self._main_socket:
                try:
                    Protocol.send_message(self._main_socket, Protocol.CHILD_STATUS)
                    send_history_update()
                except:
                    self.connected = False
            time.sleep(3)

    def listen_for_updates(self):
        print(f"[*] מתחיל להאזין לעדכונים מהשרת...")
        while self.connected and self.keep_running:
            try:
                self._main_socket.settimeout(30)
                msg_type, data = Protocol.receive_message(self._main_socket)

                if msg_type == Protocol.UPDATE_DOMAINS:
                    domains = data.get('domains', [])
                    global BLOCKED_DOMAINS
                    BLOCKED_DOMAINS = set(domains)
                    print(f"[+] עודכנו דומיינים חסומים: {len(BLOCKED_DOMAINS)} דומיינים")

                elif msg_type == Protocol.CHILD_STATUS:
                    Protocol.send_message(self._main_socket, Protocol.ACK)

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

        else:
            print(f"[+] מעביר את הבקשה ל-DNS האמיתי ({REAL_DNS_SERVER})")
            add_to_history(query_name, current_time, was_blocked=False)

            try:
                dns_sock = network_manager.get_dns_query_socket()
                dns_sock.sendto(data, (REAL_DNS_SERVER, 53))
                response_data, _ = dns_sock.recvfrom(4096)

                try:
                    response_dns = DNS(response_data)
                    for answer in response_dns.an:
                        answer.ttl = 0
                    sock.sendto(bytes(response_dns), addr)
                except:
                    sock.sendto(response_data, addr)

            except socket.timeout:
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
                # 🆕 המשך במקום לקרוס!
                continue
    except KeyboardInterrupt:
        print("\n[*] עצירת השרת על ידי המשתמש.")
    except Exception as e:  # 🆕 תפוס כל שגיאה!
        print(f"\n[!] שגיאה קריטית ב-DNS Proxy: {e}")
    finally:
        sock.close()
        print("[*] משחזר הגדרות DNS מקוריות...")
        dns_manager.restore_original_dns()
        print("[*] השרת נסגר.")


def display_startup_messages():
    print("\n" + "=" * 70)
    print("🛡  מערכת בקרת הורים - ילד")
    print("=" * 70)
    print(f" ילד: {CHILD_NAME}")
    print(f" מצב: {'רשום במערכת' if CHILD_NAME else 'לא רשום - אינטרנט חסום'}")
    print(f" DNS: 127.0.0.1 (מקומי)")
    print(f" שרת הורים: {PARENT_SERVER_IP}:{COMMUNICATION_PORT}")
    print("=" * 70)
    if CHILD_NAME:
        print(" המערכת פועלת - אינטרנט זמין עם חסימות")
    else:
        print(" נדרש רישום - אינטרנט חסום לחלוטין")
    print("=" * 70)


if __name__ == "__main__":
    try:
        print("\n מתחיל מערכת בקרת הורים...")
        print("[*] בודק רישום קיים...")
        if check_child_registration():
            print(f"[+]  נמצא רישום: {CHILD_NAME}")
        else:
            print("[!]  לא נמצא רישום תקף")
            print("[*]  מכין דף רישום...")

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

        try:
            start_dns_proxy()
        except Exception as dns_error:
            print(f"[!] שגיאה ב-DNS Proxy: {dns_error}")
    except KeyboardInterrupt:
        print("\n🛑 התקבלה בקשת עצירה...")
    except Exception as e:
        print(f"\n[!] ❌ שגיאה קריטית: {e}")
    finally:
        # 🆕 כעת זה יתבצע תמיד!
        print("[*] 🔄 מתחיל סגירה סופית...")
        graceful_shutdown()
        network_manager.cleanup_all()
