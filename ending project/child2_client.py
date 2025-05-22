import socket
from scapy.all import *
from scapy.layers.dns import DNS, DNSQR, DNSRR
import json
import threading
import time
import subprocess
import os
from protocol import Protocol, COMMUNICATION_PORT

# קונפיגורציה ספציפית לילד 2
CHILD_NAME = "ילד 2"

REAL_DNS_SERVER = "8.8.8.8"  # DNS אמיתי
LISTEN_IP = "0.0.0.0"
LISTEN_PORT = 53

# כתובת IP של עמוד החסימה שלך
BLOCK_PAGE_IP = "127.0.0.1"

# הגדרות חיבור לשרת ההורים
PARENT_SERVER_IP = "127.0.0.1"

# דומיינים חסומים - כברירת מחדל ריק
BLOCKED_DOMAINS = set()

# מטמון DNS
DNS_CACHE = {}
DNS_CACHE_LOCK = threading.Lock()

# זמן האחרון שבו הדומיינים עודכנו
LAST_UPDATE_TIME = 0

# חשוב מאוד - תדירות בדיקת עדכונים בשניות
CHECK_UPDATES_INTERVAL = 2  # בדיקת עדכונים כל 2 שניות

# תדירות ניקוי מטמון DNS
FLUSH_DNS_INTERVAL = 5  # ניקוי DNS כל 5 שניות

# האם להדפיס כל בקשת DNS
DEBUG_DNS = False


class ChildClient:
    def __init__(self):
        self.child_name = CHILD_NAME
        self.connected = False
        self.keep_running = True
        self.client_sock = None
        self.domains_updated = threading.Event()
        self.last_update_time = 0
        self.last_flush_time = 0

    def connect_to_parent(self):
        """חיבור לשרת ההורים"""
        while self.keep_running:
            try:
                if self.client_sock:
                    try:
                        self.client_sock.close()
                    except:
                        pass

                self.client_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.client_sock.connect((PARENT_SERVER_IP, COMMUNICATION_PORT))

                # שליחת הודעת רישום
                register_data = {"name": self.child_name}
                Protocol.send_message(self.client_sock, Protocol.REGISTER_CHILD, register_data)

                # קבלת אישור
                msg_type, _ = Protocol.receive_message(self.client_sock)
                if msg_type == Protocol.ACK:
                    self.connected = True
                    print(f"[+] מחובר לשרת הורים כ-{self.child_name}")

                    # קבלת רשימת דומיינים חסומים ראשונית
                    self.request_domains_update()

                    # מאזין רציף
                    self.listen_for_updates()

            except Exception as e:
                print(f"[!] שגיאת התחברות: {e}")
                self.connected = False
                time.sleep(5)  # נסה להתחבר שוב אחרי 5 שניות

    def request_domains_update(self):
        """בקשה לעדכון רשימת דומיינים"""
        if self.connected and self.client_sock:
            try:
                Protocol.send_message(self.client_sock, Protocol.GET_DOMAINS)
                return True
            except:
                self.connected = False
                return False
        return False

    def listen_for_updates(self):
        """האזנה רציפה לעדכונים מהשרת"""
        global BLOCKED_DOMAINS, LAST_UPDATE_TIME

        while self.connected and self.keep_running:
            try:
                msg_type, data = Protocol.receive_message(self.client_sock)

                if msg_type == Protocol.UPDATE_DOMAINS:
                    domains = data.get('domains', [])
                    old_domains = BLOCKED_DOMAINS.copy()
                    BLOCKED_DOMAINS = set(domains)

                    # אישור קבלה מיידי
                    try:
                        Protocol.send_message(self.client_sock, Protocol.ACK, {"status": "received_domains"})
                    except:
                        pass

                    # רישום שינויים
                    added = BLOCKED_DOMAINS - old_domains
                    removed = old_domains - BLOCKED_DOMAINS

                    if added:
                        print(f"[+] נוספו דומיינים: {added}")
                    if removed:
                        print(f"[-] הוסרו דומיינים: {removed}")

                    # עדכון זמן
                    LAST_UPDATE_TIME = time.time()
                    self.last_update_time = LAST_UPDATE_TIME

                    # ניקוי מטמון DNS מיידי לאפקט מהיר יותר
                    self.flush_dns()

                    # איפוס מטמון DNS פנימי
                    with DNS_CACHE_LOCK:
                        DNS_CACHE.clear()

                    # סימון שהדומיינים עודכנו
                    self.domains_updated.set()

                elif msg_type == Protocol.ACK:
                    pass  # לא עושה כלום עם אישורים

                elif msg_type == Protocol.ERROR:
                    print(f"[!] שגיאה מהשרת: {data}")
                    # לא מנתקים בגלל שגיאה

                else:
                    print(f"[!] סוג הודעה לא מוכר: {msg_type}")

            except Exception as e:
                print(f"[!] שגיאה בהאזנה: {e}")
                self.connected = False
                break

    def flush_dns(self):
        """ניקוי מטמון DNS - במקביל"""

        def _flush_dns():
            try:
                # Windows
                subprocess.run(["ipconfig", "/flushdns"],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                               timeout=1)

                # נסיון ניקוי כרום - דופק על הקובץ שלו
                try:
                    # מסלולים אפשריים לנתוני מטמון של כרום
                    chrome_paths = [
                        os.path.expanduser("~\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Cache"),
                        os.path.expanduser(
                            "~\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Network\\http_cache"),
                        os.path.expanduser("~\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Code Cache"),
                    ]

                    # יצירת קובץ זמני בכל תיקיה כדי לאלץ את כרום לרענן את המטמון
                    for path in chrome_paths:
                        if os.path.exists(path):
                            try:
                                temp_file = os.path.join(path, "flush_dns_trigger.tmp")
                                with open(temp_file, 'w') as f:
                                    f.write("trigger dns flush")
                                os.remove(temp_file)
                            except:
                                pass
                except:
                    pass

            except:
                pass

        # הפעלת ניקוי ה-DNS בתהליכון נפרד כדי לא לעכב
        threading.Thread(target=_flush_dns, daemon=True).start()

    def periodic_status_update(self):
        """עדכון סטטוס וניקוי DNS תקופתי"""
        while self.keep_running:
            now = time.time()

            # בדיקה אם עבר מספיק זמן מאז הניקוי האחרון
            if now - self.last_flush_time > FLUSH_DNS_INTERVAL:
                self.flush_dns()
                self.last_flush_time = now

            # עדכון אם מחובר
            if self.connected and self.client_sock:
                try:
                    # שליחת סטטוס
                    Protocol.send_message(self.client_sock, Protocol.CHILD_STATUS)
                except:
                    self.connected = False

            # המתנה קצרה - בדיקה תכופה יותר
            time.sleep(CHECK_UPDATES_INTERVAL)

            # בקשת עדכון תכופה יותר
            if self.connected and self.client_sock:
                try:
                    self.request_domains_update()
                except:
                    pass


child_client = ChildClient()


def is_blocked_domain(query_name):
    """בדיקה האם דומיין חסום - גרסה מהירה"""
    query_name = query_name.lower().strip('.')

    # בדיקה ישירה
    if query_name in BLOCKED_DOMAINS:
        return True

    # בדיקת תתי-דומיינים
    parts = query_name.split('.')
    for i in range(1, len(parts)):
        parent_domain = '.'.join(parts[i:])
        if parent_domain in BLOCKED_DOMAINS:
            return True

    return False


def handle_dns_request(data, addr, sock):
    """טיפול בבקשת DNS"""
    try:
        packet_response = DNS(data)
    except Exception as e:
        print(f"[!] שגיאה בניתוח בקשת DNS: {e}")
        return

    if packet_response.opcode == 0 and packet_response.qr == 0:
        try:
            query_name = packet_response[DNSQR].qname.decode().strip(".")
            query_type = packet_response[DNSQR].qtype
        except Exception as e:
            print(f"[!] שגיאה בקריאת שם הדומיין: {e}")
            return

        if DEBUG_DNS:
            print(f"[+] בקשת DNS ל: {query_name}")

        # בדיקה אם במטמון
        cache_key = f"{query_name}:{query_type}"
        with DNS_CACHE_LOCK:
            if cache_key in DNS_CACHE:
                # עדכון ID לתשובה
                response = DNS_CACHE[cache_key]
                response.id = packet_response.id
                sock.sendto(bytes(response), addr)
                return

        # בדיקה אם הדומיין חסום
        if is_blocked_domain(query_name):
            print(f"[-] חוסם את {query_name}")
            response = DNS(
                id=packet_response.id,
                qr=1,
                aa=1,
                qd=packet_response.qd,
                an=DNSRR(rrname=packet_response.qd.qname, ttl=1, rdata=BLOCK_PAGE_IP)
            )

            # שמירה במטמון
            with DNS_CACHE_LOCK:
                DNS_CACHE[cache_key] = response.copy()

            sock.sendto(bytes(response), addr)
        else:
            try:
                proxy_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                proxy_sock.settimeout(3)
                proxy_sock.sendto(data, (REAL_DNS_SERVER, 53))
                response_data, _ = proxy_sock.recvfrom(4096)
                proxy_sock.close()

                # שמירה במטמון
                try:
                    response = DNS(response_data)
                    with DNS_CACHE_LOCK:
                        DNS_CACHE[cache_key] = response.copy()
                except:
                    pass

                sock.sendto(response_data, addr)
            except Exception as e:
                print(f"[!] שגיאה: {e}")
                # במקרה של שגיאה, מחזירים תשובת שגיאה
                error_response = DNS(id=packet_response.id, qr=1, aa=1, rcode=2, qd=packet_response.qd)
                sock.sendto(bytes(error_response), addr)


def start_dns_proxy():
    """הפעלת שרת Proxy DNS"""
    print(f"[*] מפעיל DNS Proxy ל-{CHILD_NAME} על {LISTEN_IP}:{LISTEN_PORT}...")
    print(f"[*] תדירות בדיקת עדכונים: כל {CHECK_UPDATES_INTERVAL} שניות")
    print(f"[*] תדירות ניקוי DNS: כל {FLUSH_DNS_INTERVAL} שניות")

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind((LISTEN_IP, LISTEN_PORT))
    except PermissionError:
        print("[!] דרוש הרשאות מנהל להפעלת שרת DNS על פורט 53")
        return
    except socket.error as e:
        print(f"[!] שגיאת סוקט: {e}")
        return

    print("[*] DNS proxy פועל")

    try:
        while True:
            try:
                data, addr = sock.recvfrom(512)
                # טיפול בכל בקשה בחוט נפרד
                threading.Thread(target=handle_dns_request, args=(data, addr, sock), daemon=True).start()
            except Exception as e:
                print(f"[!] שגיאה: {e}")
    except KeyboardInterrupt:
        print("\n[*] עצירת השרת על ידי המשתמש")
    finally:
        sock.close()


if __name__ == "__main__":
    # בקשת עדכון DNS מראש
    child_client.flush_dns()

    # הפעלת חוט חיבור לשרת
    connection_thread = threading.Thread(target=child_client.connect_to_parent)
    connection_thread.daemon = True
    connection_thread.start()

    # הפעלת חוט עדכון סטטוס
    status_thread = threading.Thread(target=child_client.periodic_status_update)
    status_thread.daemon = True
    status_thread.start()

    # המתנה לחיבור ראשוני
    time.sleep(2)

    # הפעלת DNS proxy
    start_dns_proxy()