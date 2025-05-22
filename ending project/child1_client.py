import socket
from scapy.all import *
from scapy.layers.dns import DNS, DNSQR, DNSRR
import json
import threading
import time
import subprocess
import platform
import os
import ctypes
from protocol import Protocol, COMMUNICATION_PORT
import http.server
import socketserver
from urllib.parse import urlparse


# קונפיגורציה ספציפית לילד 3
CHILD_NAME = "ילד 3"

REAL_DNS_SERVER = "8.8.8.8"  # DNS אמיתי
LISTEN_IP = "0.0.0.0"
LISTEN_PORT = 53

# כתובת IP של עמוד החסימה שלך
BLOCK_PAGE_IP = "127.0.0.1"

# הגדרות חיבור לשרת ההורים
PARENT_SERVER_IP = "127.0.0.1"  # במערכת אמיתית נשנה לכתובת IP של שרת ההורים

# דומיינים חסומים ברירת מחדל
BLOCKED_DOMAINS = set()

# משתנה לשמירת DNS המקורי
ORIGINAL_DNS = None


class BlockHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        """טיפול בבקשות HTTP"""
        self.send_response(200)
        self.send_header('Content-type', 'text/html; charset=utf-8')
        self.end_headers()

        # דף חסימה בעברית
        block_page = """
        <!DOCTYPE html>
        <html dir="rtl" lang="he">
        <head>
            <meta charset="UTF-8">
            <title>אתר חסום</title>
            <style>
                body { 
                    font-family: Arial, sans-serif; 
                    text-align: center; 
                    background: linear-gradient(135deg, #ff6b6b, #4ecdc4);
                    color: white;
                    margin: 0;
                    padding: 50px;
                }
                .container {
                    background: rgba(255,255,255,0.1);
                    padding: 40px;
                    border-radius: 20px;
                    box-shadow: 0 8px 32px rgba(0,0,0,0.3);
                    max-width: 600px;
                    margin: 0 auto;
                }
                .icon { font-size: 80px; margin-bottom: 20px; }
                h1 { font-size: 2.5em; margin-bottom: 20px; }
                p { font-size: 1.2em; line-height: 1.6; }
            </style>
        </head>
        <body>
            <div class="container">
                <div class="icon">🚫</div>
                <h1>אתר זה חסום</h1>
                <p>הגישה לאתר זה נחסמה על ידי מערכת בקרת ההורים.</p>
                <p><strong>אתר:</strong> {}</p>
                <hr style="margin: 30px 0; border: 1px solid rgba(255,255,255,0.3);">
                <p style="font-size: 0.9em;">אם אתה חושב שזו טעות, פנה להורים.</p>
            </div>
        </body>
        </html>
        """.format(self.headers.get('Host', 'לא ידוע'))

        self.wfile.write(block_page.encode('utf-8'))

    def do_POST(self):
        """טיפול בבקשות POST"""
        self.do_GET()

    def log_message(self, format, *args):
        """השתק לוגים של השרת"""
        return


def clear_dns_cache():
    """ניקוי cache של DNS במערכת"""
    try:
        result = subprocess.run(['ipconfig', '/flushdns'],
                                capture_output=True, text=True, encoding='utf-8')
        if result.returncode == 0:
            print("[+] cache של DNS נוקה בהצלחה")
        else:
            print(f"[!] בעיה בניקוי cache: {result.stderr}")
    except Exception as e:
        print(f"[!] שגיאה בניקוי cache: {e}")


def start_block_server():
    """הפעלת שרת HTTP להצגת דף חסימה"""
    try:
        with socketserver.TCPServer(("127.0.0.1", 80), BlockHandler) as httpd:
            print("[+] שרת דף חסימה פועל על http://127.0.0.1")
            httpd.serve_forever()
    except PermissionError:
        print("[!] שגיאת הרשאות לפורט 80. מנסה פורט 8080...")
        try:
            with socketserver.TCPServer(("127.0.0.1", 8080), BlockHandler) as httpd:
                print("[+] שרת דף חסימה פועל על http://127.0.0.1:8080")
                httpd.serve_forever()
        except Exception as e:
            print(f"[!] לא ניתן להפעיל שרת חסימה: {e}")
    except Exception as e:
        print(f"[!] שגיאה בהפעלת שרת חסימה: {e}")


class DNSManager:
    """מחלקה לניהול הגדרות DNS במערכת"""

    def __init__(self):
        self.system = platform.system()
        self.original_dns = None

    def is_admin(self):
        """בדיקה האם התוכנית רצה עם הרשאות מנהל"""
        try:
            if self.system == "Windows":
                return ctypes.windll.shell32.IsUserAnAdmin()
            else:
                return os.geteuid() == 0
        except:
            return False

    def get_wifi_interface_name(self):
        """מציאת שם ממשק Wi-Fi באמצעות PowerShell"""
        try:
            # שימוש ב-PowerShell לקבלת שם ממשק Wi-Fi
            cmd = ['powershell', '-Command',
                   'Get-NetAdapter | Where-Object {$_.Status -eq "Up" -and ($_.Name -like "*Wi-Fi*" -or $_.Name -like "*Wireless*" -or $_.InterfaceDescription -like "*Wireless*")} | Select-Object -First 1 -ExpandProperty Name']

            result = subprocess.run(cmd, capture_output=True, text=True, encoding='utf-8')

            if result.returncode == 0 and result.stdout.strip():
                interface_name = result.stdout.strip()
                print(f"[*] נמצא ממשק Wi-Fi: {interface_name}")
                return interface_name

        except Exception as e:
            print(f"[!] שגיאה בחיפוש ממשק Wi-Fi: {e}")

        # אם PowerShell נכשל, נסה שיטה מסורתית
        try:
            result = subprocess.run(['netsh', 'wlan', 'show', 'profiles'],
                                    capture_output=True, text=True, encoding='utf-8')

            if result.returncode == 0:
                # אם יש פרופילי Wi-Fi, כנראה שיש ממשק Wi-Fi
                return "Wi-Fi"

        except:
            pass

        return None

    def get_ethernet_interface_name(self):
        """מציאת שם ממשק Ethernet באמצעות PowerShell"""
        try:
            cmd = ['powershell', '-Command',
                   'Get-NetAdapter | Where-Object {$_.Status -eq "Up" -and ($_.Name -like "*Ethernet*" -or $_.InterfaceDescription -like "*Ethernet*")} | Select-Object -First 1 -ExpandProperty Name']

            result = subprocess.run(cmd, capture_output=True, text=True, encoding='utf-8')

            if result.returncode == 0 and result.stdout.strip():
                interface_name = result.stdout.strip()
                print(f"[*] נמצא ממשק Ethernet: {interface_name}")
                return interface_name

        except Exception as e:
            print(f"[!] שגיאה בחיפוש ממשק Ethernet: {e}")

        return None

    def get_active_interface(self):
        """מציאת ממשק הרשת הפעיל"""
        # נסה Wi-Fi קודם
        wifi_interface = self.get_wifi_interface_name()
        if wifi_interface:
            return wifi_interface

        # אחר כך Ethernet
        ethernet_interface = self.get_ethernet_interface_name()
        if ethernet_interface:
            return ethernet_interface

        # אם כלום לא עבד, נסה שמות נפוצים
        common_names = ['Wi-Fi', 'Ethernet', 'Local Area Connection', 'Wireless Network Connection']
        for name in common_names:
            try:
                # בדוק אם הממשק קיים
                result = subprocess.run(['netsh', 'interface', 'ip', 'show', 'config',
                                         f'name={name}'],
                                        capture_output=True, text=True, encoding='utf-8')
                if result.returncode == 0:
                    print(f"[*] נמצא ממשק: {name}")
                    return name
            except:
                continue

        return None

    def set_dns_powershell(self, interface_name, dns_server):
        """הגדרת DNS באמצעות PowerShell"""
        try:
            # פקודת PowerShell להגדרת DNS
            cmd = ['powershell', '-Command',
                   f'Set-DnsClientServerAddress -InterfaceAlias "{interface_name}" -ServerAddresses "{dns_server}"']

            result = subprocess.run(cmd, capture_output=True, text=True, encoding='utf-8')

            if result.returncode == 0:
                print(f"[+] DNS הוגדר בהצלחה (PowerShell) ל-{dns_server}")
                return True
            else:
                print(f"[!] שגיאה ב-PowerShell: {result.stderr}")
                return False

        except Exception as e:
            print(f"[!] שגיאה בהגדרת DNS עם PowerShell: {e}")
            return False

    def set_dns_windows(self, interface_name, dns_server):
        """הגדרת DNS ב-Windows"""
        try:
            print(f"[*] מנסה להגדיר DNS ל-{dns_server} בממשק '{interface_name}'")

            # נסה קודם עם PowerShell
            if self.set_dns_powershell(interface_name, dns_server):
                return True

            # אם PowerShell נכשל, נסה עם netsh
            cmd = ['netsh', 'interface', 'ip', 'set', 'dns',
                   f'name={interface_name}', 'source=static',
                   f'addr={dns_server}']

            result = subprocess.run(cmd, capture_output=True, text=True, encoding='utf-8')

            if result.returncode == 0:
                print(f"[+] DNS הוגדר בהצלחה ל-{dns_server} בממשק {interface_name}")
                return True
            else:
                print(f"[!] שגיאה בהגדרת DNS: {result.stderr}")

                # נסה עם IPv4
                cmd_ipv4 = ['netsh', 'interface', 'ipv4', 'set', 'dns',
                            f'name={interface_name}', 'source=static',
                            f'address={dns_server}']

                result2 = subprocess.run(cmd_ipv4, capture_output=True, text=True, encoding='utf-8')
                if result2.returncode == 0:
                    print(f"[+] DNS הוגדר בהצלחה (IPv4) ל-{dns_server}")
                    return True
                else:
                    print(f"[!] שגיאה גם בפקודה חלופית: {result2.stderr}")

                return False

        except Exception as e:
            print(f"[!] שגיאה בהגדרת DNS: {e}")
            return False

    def restore_dns_windows(self, interface_name):
        """שחזור הגדרות DNS אוטומטיות ב-Windows"""
        try:
            # נסה קודם עם PowerShell
            cmd_ps = ['powershell', '-Command',
                      f'Set-DnsClientServerAddress -InterfaceAlias "{interface_name}" -ResetServerAddresses']

            result = subprocess.run(cmd_ps, capture_output=True, text=True, encoding='utf-8')
            if result.returncode == 0:
                print(f"[+] DNS שוחזר להגדרות אוטומטיות (PowerShell) בממשק {interface_name}")
                return True

            # אם PowerShell נכשל, נסה עם netsh
            subprocess.run(['netsh', 'interface', 'ip', 'set', 'dns',
                            f'name={interface_name}', 'source=dhcp'], check=True)
            print(f"[+] DNS שוחזר להגדרות אוטומטיות בממשק {interface_name}")
            return True
        except subprocess.CalledProcessError as e:
            print(f"[!] שגיאה בשחזור DNS: {e}")
            return False

    def setup_dns_redirect(self):
        """הגדרת הפניית DNS למחשב המקומי"""
        if not self.is_admin():
            print("[!] נדרשות הרשאות מנהל לשינוי הגדרות DNS")
            print("[!] אנא הפעל את התוכנית כמנהל (Run as Administrator)")
            return False

        if self.system == "Windows":
            interface_name = self.get_active_interface()
            if interface_name:
                # שמירת הגדרות DNS המקוריות
                self.original_dns = (interface_name, [])  # נשמור רק את שם הממשק
                print(f"[*] ממשק נבחר: {interface_name}")

                # הגדרת DNS למחשב המקומי
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
        if not self.original_dns:
            return

        if self.system == "Windows":
            interface_name, _ = self.original_dns
            self.restore_dns_windows(interface_name)


dns_manager = DNSManager()


class ChildClient:
    def __init__(self):
        self.sock = None
        self.child_name = CHILD_NAME
        self.connected = False
        self.keep_running = True
        self.last_update = time.time()

    def connect_to_parent(self):
        """חיבור לשרת ההורים"""
        while self.keep_running:
            try:
                self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.sock.connect((PARENT_SERVER_IP, COMMUNICATION_PORT))

                # שליחת הודעת רישום
                register_data = {"name": self.child_name}
                Protocol.send_message(self.sock, Protocol.REGISTER_CHILD, register_data)

                # קבלת אישור
                msg_type, _ = Protocol.receive_message(self.sock)
                if msg_type == Protocol.ACK:
                    self.connected = True
                    print(f"[+] מחובר לשרת הורים כ-{self.child_name}")

                    # קבלת רשימת דומיינים חסומים ראשונית
                    self.request_domains_update()

                    # לולאת האזנה לעדכונים
                    self.listen_for_updates()

            except Exception as e:
                print(f"[!] שגיאת חיבור: {e}")
                self.connected = False
                time.sleep(5)  # נסה להתחבר שוב אחרי 5 שניות

    def request_domains_update(self):
        """בקשה לעדכון רשימת דומיינים"""
        if self.connected:
            try:
                Protocol.send_message(self.sock, Protocol.GET_DOMAINS)
            except:
                self.connected = False

    def listen_for_updates(self):
        """האזנה לעדכונים מהשרת"""
        while self.connected and self.keep_running:
            try:
                msg_type, data = Protocol.receive_message(self.sock)

                if msg_type == Protocol.UPDATE_DOMAINS:
                    domains = data.get('domains', [])

                    # הוספת global בתחילת השימוש
                    global BLOCKED_DOMAINS
                    old_domains = BLOCKED_DOMAINS.copy()  # שמור את הרשימה הישנה

                    BLOCKED_DOMAINS = set(domains)

                    print(f"[+] עודכנו דומיינים חסומים עבור {self.child_name}: {list(BLOCKED_DOMAINS)}")
                    print(f"[INFO] מספר דומיינים חסומים: {len(BLOCKED_DOMAINS)}")

                    # אם הרשימה השתנתה, נקה cache
                    if old_domains != BLOCKED_DOMAINS:
                        print("[*] הרשימה השתנתה - מנקה cache של DNS...")
                        clear_dns_cache()

                    self.last_update = time.time()

                elif msg_type == Protocol.ERROR:
                    print(f"[!] שגיאה מהשרת: {data}")
                    self.connected = False
                    break

            except Exception as e:
                print(f"[!] שגיאה בקבלת עדכון: {e}")
                self.connected = False
                break

    def send_status_update(self):
        """שליחת עדכון סטטוס לשרת"""
        while self.keep_running:
            if self.connected:
                try:
                    Protocol.send_message(self.sock, Protocol.CHILD_STATUS)
                except:
                    self.connected = False
            time.sleep(30)


child_client = ChildClient()

def is_blocked_domain(query_name):
    """גרסה פשוטה יותר - חוסם כל דומיין שמכיל את השם הבסיסי"""
    original_query = query_name
    query_name = query_name.lower().strip('.')

    print(f"[DEBUG] בודק דומיין: '{original_query}' -> '{query_name}'")
    print(f"[DEBUG] רשימת דומיינים חסומים: {BLOCKED_DOMAINS}")

    # בדיקה ישירה
    if query_name in BLOCKED_DOMAINS:
        print(f"[DEBUG] ✓ נמצא התאמה ישירה: {query_name}")
        return True

    # עבור כל דומיין חסום
    for blocked_domain in BLOCKED_DOMAINS:
        blocked_domain = blocked_domain.lower().strip('.')

        # בדיקה רגילה של תת-דומיינים
        if query_name.endswith('.' + blocked_domain):
            print(f"[DEBUG] ✓ תת-דומיין: {query_name} סיומת של .{blocked_domain}")
            return True

        # בדיקה מורחבת - אם הדומיין החסום הוא example.com
        # אז חסום גם example.us, example.net וכו'
        if '.' in blocked_domain:
            base_name = blocked_domain.split('.')[0]  # example
            if base_name in query_name.split('.'):
                print(f"[DEBUG] ✓ דומיין קשור: {query_name} מכיל {base_name}")
                return True

    print(f"[DEBUG] ❌ {query_name} לא חסום")
    return False


def is_blocked_domain_advanced(query_name):
    """בודק אם הדומיין או תת-דומיין חסום - גרסה משופרת"""
    query_name = query_name.lower().strip('.')

    # בדיקה ישירה
    if query_name in BLOCKED_DOMAINS:
        return True

    # בדיקת תתי-דומיינים
    for blocked_domain in BLOCKED_DOMAINS:
        blocked_domain = blocked_domain.lower().strip('.')

        # אם הדומיין המבוקש זהה לדומיין החסום
        if query_name == blocked_domain:
            return True

        # אם הדומיין המבוקש הוא תת-דומיין של הדומיין החסום
        if query_name.endswith('.' + blocked_domain):
            return True

        # בדיקה הפוכה - אם הדומיין החסום הוא תת-דומיין של המבוקש
        # זה יכול לעזור במקרים מיוחדים
        if blocked_domain.endswith('.' + query_name):
            return True

    return False


def handle_dns_request(data, addr, sock):
    """טיפול בבקשת DNS נכנסת"""
    try:
        packet_response = DNS(data)
    except Exception as e:
        print(f"[!] שגיאה בניתוח בקשת DNS: {e}")
        return

    if packet_response.opcode == 0 and packet_response.qr == 0:  # רק בקשות DNS, לא תגובות
        try:
            query_name = packet_response[DNSQR].qname.decode().strip(".")
        except Exception as e:
            print(f"[!] שגיאה בקריאת שם הדומיין: {e}")
            return

        print(f"[+] בקשת DNS ל: {query_name}")

        if is_blocked_domain(query_name):
            print(f"[-] חוסם את {query_name}, מפנה ל-{BLOCK_PAGE_IP}")
            # מחזיר כתובת IP של עמוד החסימה
            response = DNS(
                id=packet_response.id,
                qr=1,  # תגובה
                aa=1,  # מענה סמכותי
                qd=packet_response.qd,
                an=DNSRR(rrname=packet_response.qd.qname, ttl=0, rdata=BLOCK_PAGE_IP)  # TTL של 1 שנייה

            )
            sock.sendto(bytes(response), addr)
            print(f"[+] נשלחה תשובה לחסימת {query_name} עם הפניה ל-{BLOCK_PAGE_IP}")
        else:
            print(f"[+] מעביר את הבקשה ל-DNS האמיתי ({REAL_DNS_SERVER})")
            try:
                # יצירת סוקט רגיל, לא Scapy, כדי לשלוח בקשת DNS לשרת האמיתי
                proxy_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                proxy_sock.settimeout(5)
                # שולח את הבקשה ל-DNS האמיתי
                proxy_sock.sendto(data, (REAL_DNS_SERVER, 53))

                # מקבל את התשובה מה-DNS האמיתי
                response, _ = proxy_sock.recvfrom(4096)  # הגדלתי את גודל הבאפר
                proxy_sock.close()
                # שולח את התשובה חזרה למבקש
                sock.sendto(response, addr)
                print(f"[+] התקבלה והועברה תשובת DNS עבור {query_name}")
            except socket.timeout:
                print(f"[!] תם הזמן בהמתנה לתשובה מ-DNS האמיתי")
                error_response = DNS(id=packet_response.id, qr=1, aa=1, rcode=2,
                                     qd=packet_response.qd)  # rcode=2 זה SERVER_FAILURE
                sock.sendto(bytes(error_response), addr)
            except Exception as e:
                print(f"[!] שגיאה בהעברת הבקשה ל-DNS האמיתי: {e}")
                # במקרה של שגיאה, מחזירים תשובת שגיאה ריקה
                error_response = DNS(id=packet_response.id, qr=1, aa=1, rcode=2, qd=packet_response.qd)
                sock.sendto(bytes(error_response), addr)


def start_dns_proxy():
    """הפעלת שרת Proxy DNS"""
    print(f"[*] מפעיל Proxy DNS ל-{CHILD_NAME} על {LISTEN_IP}:{LISTEN_PORT}...")
    print(f"[*] דומיינים חסומים: {', '.join(BLOCKED_DOMAINS) if BLOCKED_DOMAINS else 'ממתין לעדכון מהשרת'}")
    print(f"[*] דף חסימה יוצג מכתובת: {BLOCK_PAGE_IP}")

    try:
        # נסה ליצור את הסוקט
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind((LISTEN_IP, LISTEN_PORT))
    except PermissionError:
        print("[!] שגיאת הרשאות: לא ניתן להאזין לפורט 53. נסה להריץ את התוכנית כמנהל (administrator).")
        return
    except socket.error as e:
        print(f"[!] שגיאת סוקט: {e}")
        return

    print("[*] DNS Proxy פועל. לחץ Ctrl+C כדי לעצור.")

    try:
        while True:
            try:
                data, addr = sock.recvfrom(512)
                # טיפול בכל בקשה בחוט נפרד
                threading.Thread(target=handle_dns_request, args=(data, addr, sock), daemon=True).start()
            except Exception as e:
                print(f"[!] שגיאה בטיפול בבקשה: {e}")
    except KeyboardInterrupt:
        print("\n[*] עצירת השרת על ידי המשתמש.")
    finally:
        sock.close()
        # שחזור הגדרות DNS מקוריות
        print("[*] משחזר הגדרות DNS מקוריות...")
        dns_manager.restore_original_dns()
        print("[*] השרת נסגר.")


if __name__ == "__main__":
    print(f"[*] מתחיל תוכנת בקרת הורים עבור {CHILD_NAME}")

    # בדיקה אם שרת ההורים פועל
    print("[*] בודק חיבור לשרת ההורים...")
    try:
        test_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        test_sock.settimeout(2)
        test_sock.connect((PARENT_SERVER_IP, COMMUNICATION_PORT))
        test_sock.close()
        print("[+] שרת ההורים זמין")
    except:
        print("[!] שרת ההורים לא פועל!")
        print(f"[!] ודא שהפעלת את שרת ההורים על {PARENT_SERVER_IP}:{COMMUNICATION_PORT}")
        input("לחץ Enter כדי להמשיך בכל זאת...")

    # הגדרת DNS אוטומטית
    print("[*] מגדיר הפניית DNS...")
    if dns_manager.setup_dns_redirect():
        print("[+] הגדרות DNS עודכנו בהצלחה")
    else:
        print("[!] לא ניתן להגדיר DNS אוטומטית")
        print("[!] יש להגדיר ידנית את ה-DNS ל-127.0.0.1")
        print("\n--- הגדרה ידנית ---")
        print("1. פתח 'הגדרות רשת' או 'Network Settings'")
        print("2. לחץ על 'שנה אפשרויות מתאם' או 'Change adapter options'")
        print("3. לחץ ימני על הרשת שלך ובחר 'מאפיינים' או 'Properties'")
        print("4. בחר 'Internet Protocol Version 4 (TCP/IPv4)' ולחץ 'מאפיינים'")
        print("5. בחר 'השתמש בכתובות DNS הבאות' ובשדה הראשון הכנס: 127.0.0.1")
        print("6. לחץ OK לשמירה")
        print("-------------------------\n")
        input("לחץ Enter אחרי שהגדרת את ה-DNS...")

    # הפעלת חוט לחיבור עם שרת ההורים
    connection_thread = threading.Thread(target=child_client.connect_to_parent)
    connection_thread.daemon = True
    connection_thread.start()

    # הפעלת חוט לעדכוני סטטוס
    status_thread = threading.Thread(target=child_client.send_status_update)
    status_thread.daemon = True
    status_thread.start()

    # המתנה קצרה לחיבור
    time.sleep(2)

    # הפעלת שרת דף חסימה
    block_server_thread = threading.Thread(target=start_block_server)
    block_server_thread.daemon = True
    block_server_thread.start()

    print("[*] מפעיל שרת דף חסימה...")
    time.sleep(1)

    # הפעלת DNS proxy
    start_dns_proxy()
