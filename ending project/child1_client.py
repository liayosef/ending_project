import socket
from scapy.all import *
from scapy.layers.dns import DNS, DNSQR, DNSRR
import json
import threading
import time
from protocol import Protocol, COMMUNICATION_PORT

# קונפיגורציה ספציפית לילד 1
CHILD_NAME = "ילד 1"

REAL_DNS_SERVER = "8.8.8.8"  # DNS אמיתי
LISTEN_IP = "0.0.0.0"
LISTEN_PORT = 5055

# כתובת IP של עמוד החסימה שלך
BLOCK_PAGE_IP = "127.0.0.1"

# הגדרות חיבור לשרת ההורים
PARENT_SERVER_IP = "127.0.0.1"  # במערכת אמיתית נשנה לכתובת IP של שרת ההורים

# דומיינים חסומים ברירת מחדל
BLOCKED_DOMAINS = set()


class ChildClient:
    def __init__(self):
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
                    print(f"Connected to parent server as {self.child_name}")

                    # קבלת רשימת דומיינים חסומים ראשונית
                    self.request_domains_update()

                    # לולאת האזנה לעדכונים
                    self.listen_for_updates()

            except Exception as e:
                print(f"Connection error: {e}")
                self.connected = False
                time.sleep(5)  # נסה להתחבר שוב אחרי 5 שניות

    def request_domains_update(self):
        """בקשה לעדכון רשימת דומיינים"""
        Protocol.send_message(self.sock, Protocol.GET_DOMAINS)

    def listen_for_updates(self):
        """האזנה לעדכונים מהשרת"""
        while self.connected and self.keep_running:
            try:
                msg_type, data = Protocol.receive_message(self.sock)

                if msg_type == Protocol.UPDATE_DOMAINS:
                    domains = data.get('domains', [])
                    global BLOCKED_DOMAINS
                    BLOCKED_DOMAINS = set(domains)
                    print(f"Updated blocked domains for {self.child_name}: {domains}")
                    self.last_update = time.time()

                elif msg_type == Protocol.ERROR:
                    print(f"Error from server: {data}")
                    self.connected = False
                    break

            except Exception as e:
                print(f"Error receiving update: {e}")
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


def load_blocked_domains():
    """טעינת דומיינים חסומים מקובץ JSON"""
    global BLOCKED_DOMAINS
    try:
        with open('blocked_domains_child1.json', 'r') as f:
            BLOCKED_DOMAINS = set(json.load(f))
            print(f"[*] נטענו {len(BLOCKED_DOMAINS)} דומיינים חסומים")
    except FileNotFoundError:
        # אם אין קובץ, נשתמש ברירת מחדל
        BLOCKED_DOMAINS = {"facebook.com", "youtube.com"}
        print(f"[*] שימוש ברשימה ברירת מחדל: {BLOCKED_DOMAINS}")


def is_blocked_domain(query_name):
    """בודק אם הדומיין או תת-דומיין חסום"""
    for domain in BLOCKED_DOMAINS:
        if query_name == domain or query_name.endswith("." + domain):
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
                an=DNSRR(rrname=packet_response.qd.qname, ttl=60, rdata=BLOCK_PAGE_IP)
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
    # טעינה ראשונית של דומיינים חסומים
    load_blocked_domains()

    print(f"[*] מפעיל Proxy DNS לילד 1 על {LISTEN_IP}:{LISTEN_PORT}...")
    print(f"[*] דומיינים חסומים: {', '.join(BLOCKED_DOMAINS)}")
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

    print("[*] השרת פועל. לחץ Ctrl+C כדי לעצור.")

    try:
        while True:
            try:
                data, addr = sock.recvfrom(512)
                handle_dns_request(data, addr, sock)
            except Exception as e:
                print(f"[!] שגיאה בטיפול בבקשה: {e}")
    except KeyboardInterrupt:
        print("\n[*] עצירת השרת על ידי המשתמש.")
    finally:
        sock.close()
        print("[*] השרת נסגר.")


if __name__ == "__main__":
    # הפעלת חוט לחיבור עם שרת ההורים
    connection_thread = threading.Thread(target=child_client.connect_to_parent)
    connection_thread.daemon = True
    connection_thread.start()

    # הפעלת חוט לעדכוני סטטוס
    status_thread = threading.Thread(target=child_client.send_status_update)
    status_thread.daemon = True
    status_thread.start()

    # הפעלת DNS proxy
    start_dns_proxy()