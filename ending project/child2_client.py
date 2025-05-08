import socket
from scapy.all import *
from scapy.layers.dns import DNS, DNSQR, DNSRR
import json
import threading
import time
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

# דומיינים חסומים ברירת מחדל
BLOCKED_DOMAINS = set()


class ChildClient:
    def __init__(self):
        self.child_name = CHILD_NAME
        self.connected = False
        self.keep_running = True
        self.client_sock = None
        self.domains_updated = threading.Event()

    def connect_to_parent(self):
        """חיבור לשרת ההורים"""
        while self.keep_running:
            try:
                self.client_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.client_sock.connect((PARENT_SERVER_IP, COMMUNICATION_PORT))

                # שליחת הודעת רישום
                register_data = {"name": self.child_name}
                Protocol.send_message(self.client_sock, Protocol.REGISTER_CHILD, register_data)

                # קבלת אישור
                msg_type, _ = Protocol.receive_message(self.client_sock)
                if msg_type == Protocol.ACK:
                    self.connected = True
                    print(f"Connected to parent server as {self.child_name}")

                    # קבלת רשימת דומיינים חסומים ראשונית
                    self.request_domains_update()

                    # מאזין רציף
                    self.listen_for_updates()

            except Exception as e:
                print(f"Connection error: {e}")
                self.connected = False
                if self.client_sock:
                    self.client_sock.close()
                time.sleep(5)  # נסה להתחבר שוב אחרי 5 שניות

    def request_domains_update(self):
        """בקשה לעדכון רשימת דומיינים"""
        if self.connected and self.client_sock:
            Protocol.send_message(self.client_sock, Protocol.GET_DOMAINS)

    def listen_for_updates(self):
        """האזנה רציפה לעדכונים מהשרת"""
        while self.connected and self.keep_running:
            try:
                msg_type, data = Protocol.receive_message(self.client_sock)

                if msg_type == Protocol.UPDATE_DOMAINS:
                    domains = data.get('domains', [])
                    global BLOCKED_DOMAINS
                    old_domains = BLOCKED_DOMAINS.copy()
                    BLOCKED_DOMAINS = set(domains)

                    added = BLOCKED_DOMAINS - old_domains
                    removed = old_domains - BLOCKED_DOMAINS

                    if added:
                        print(f"[+] נוספו דומיינים: {added}")
                    if removed:
                        print(f"[-] הוסרו דומיינים: {removed}")
                    print(f"[*] רשימת דומיינים עכשיו: {list(BLOCKED_DOMAINS)}")

                    # סימון שהדומיינים עודכנו
                    self.domains_updated.set()

                elif msg_type == Protocol.ACK:
                    pass
                elif msg_type == Protocol.ERROR:
                    print(f"Error from server: {data}")
                    self.connected = False
                    break

            except Exception as e:
                print(f"Error in listening: {e}")
                self.connected = False
                break

    def periodic_status_update(self):
        """עדכון סטטוס תקופתי"""
        while self.keep_running:
            if self.connected and self.client_sock:
                try:
                    # שליחת סטטוס (כדי שהשרת ידע שמחובר)
                    Protocol.send_message(self.client_sock, Protocol.CHILD_STATUS)
                    # סימול שככה הילד יקבל עדכונים מהשרת
                    self.request_domains_update()
                except:
                    self.connected = False
            time.sleep(5)  # כל 5 שניות - לתגובה מהירה יותר


child_client = ChildClient()


def is_blocked_domain(query_name):
    """בדיקה אם הדומיין חסום"""
    # בדיקה פשוטה - האם הדומיין נמצא ברשימה החסומה
    for domain in BLOCKED_DOMAINS:
        if domain in query_name:
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
        except Exception as e:
            print(f"[!] שגיאה בקריאת שם הדומיין: {e}")
            return

        print(f"[+] בקשת DNS ל: {query_name}")

        # תמיד בודק במצב הנוכחי של רשימת הדומיינים החסומים
        if is_blocked_domain(query_name):
            print(f"[-] חוסם את {query_name}")
            response = DNS(
                id=packet_response.id,
                qr=1,
                aa=1,
                qd=packet_response.qd,
                an=DNSRR(rrname=packet_response.qd.qname, ttl=60, rdata=BLOCK_PAGE_IP)
            )
            sock.sendto(bytes(response), addr)
        else:
            print(f"[+] מעביר ל-DNS אמיתי")
            try:
                proxy_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                proxy_sock.settimeout(5)
                proxy_sock.sendto(data, (REAL_DNS_SERVER, 53))
                response, _ = proxy_sock.recvfrom(4096)
                proxy_sock.close()
                sock.sendto(response, addr)
            except Exception as e:
                print(f"[!] שגיאה: {e}")


def start_dns_proxy():
    """הפעלת שרת Proxy DNS"""
    print(f"[*] מפעיל DNS Proxy ל-{CHILD_NAME} על {LISTEN_IP}:{LISTEN_PORT}...")

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind((LISTEN_IP, LISTEN_PORT))
    except PermissionError:
        print("[!] דרוש הרשאות מנהל")
        return
    except socket.error as e:
        print(f"[!] שגיאת סוקט: {e}")
        return

    print("[*] DNS proxy פועל")

    try:
        while True:
            try:
                data, addr = sock.recvfrom(512)
                handle_dns_request(data, addr, sock)
            except Exception as e:
                print(f"[!] שגיאה: {e}")
    except KeyboardInterrupt:
        print("\n[*] עצירה")
    finally:
        sock.close()


if __name__ == "__main__":
    # הפעלת חוט חיבור לשרת
    connection_thread = threading.Thread(target=child_client.connect_to_parent)
    connection_thread.daemon = True
    connection_thread.start()

    # הפעלת חוט עדכון סטטוס תקופתי
    status_thread = threading.Thread(target=child_client.periodic_status_update)
    status_thread.daemon = True
    status_thread.start()

    # המתנה לחיבור ראשוני
    time.sleep(2)

    # הפעלת DNS proxy
    start_dns_proxy()