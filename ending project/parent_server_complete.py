import http.server
import socketserver
import json
import socket
import threading
import os
import time
from urllib.parse import parse_qs, urlparse, quote, unquote
from protocol import Protocol, COMMUNICATION_PORT

HTTP_PORT = 8000
# נתונים עבור ילדים
children_data = {}
data_lock = threading.Lock()
active_connections = {}

LOGIN_TEMPLATE = """<!DOCTYPE html>
<html lang="he" dir="rtl">
<head>
    <meta charset="UTF-8">
    <title>בקרת הורים - כניסה</title>
    <style>
        body { 
            font-family: 'Segoe UI', Tahoma, Arial, sans-serif;
            background: linear-gradient(135deg, #f5f7fa 0%, #c3cfe2 100%);
            min-height: 100vh;
            display: flex;
            justify-content: center;
            align-items: center;
            padding: 20px;
            margin: 0;
        }
        .form-container {
            background: white;
            padding: 50px;
            border-radius: 15px;
            max-width: 450px;
            width: 100%;
            box-shadow: 0 10px 20px rgba(0,0,0,0.1);
        }
        .logo-circle {
            background-color: #4a6fa5;
            width: 50px;
            height: 50px;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 24px;
            color: white;
            margin: 0 auto 20px;
        }
        h1 {
            color: #4a6fa5;
            font-size: 24px;
            margin: 0 0 30px;
            text-align: center;
        }
        .form-group {
            margin-bottom: 20px;
        }
        label {
            display: block;
            font-weight: bold;
            margin-bottom: 5px;
            color: #555;
        }
        input {
            width: 100%;
            padding: 12px 15px;
            border: 2px solid #e1e8ed;
            border-radius: 8px;
            font-size: 16px;
            box-sizing: border-box;
        }
        button {
            background: #4a6fa5;
            color: white;
            border: none;
            padding: 12px 20px;
            border-radius: 8px;
            cursor: pointer;
            width: 100%;
            font-size: 16px;
            font-weight: bold;
        }
    </style>
</head>
<body>
    <div class="form-container">
        <div class="logo-circle">🛡️</div>
        <h1>בקרת הורים</h1>
        <form method="post" action="/login">
            <div class="form-group">
                <label for="email">כתובת אימייל</label>
                <input type="email" id="email" name="email" placeholder="הכנס כתובת אימייל" required>
            </div>
            <div class="form-group">
                <label for="password">סיסמה</label>
                <input type="password" id="password" name="password" placeholder="הכנס סיסמה" required>
            </div>
            <button type="submit">התחבר</button>
        </form>
    </div>
</body>
</html>"""

DASHBOARD_TEMPLATE = """<!DOCTYPE html>
<html lang="he" dir="rtl">
<head>
    <meta charset="UTF-8">
    <title>לוח בקרה - בקרת הורים</title>
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Arial, sans-serif;
            background: #f5f7fa;
            margin: 0;
            padding: 0;
        }
        .header {
            background: linear-gradient(90deg, #4a6fa5 0%, #3a5a8a 100%);
            color: white;
            padding: 20px;
            box-shadow: 0 2px 5px rgba(0,0,0,0.1);
        }
        .header-content {
            max-width: 1200px;
            margin: 0 auto;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .logo-container {
            display: flex;
            align-items: center;
            gap: 15px;
        }
        .logo-circle {
            background-color: white;
            width: 40px;
            height: 40px;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            color: #4a6fa5;
            font-size: 20px;
        }
        .main-content {
            max-width: 1200px;
            margin: 40px auto;
            padding: 0 20px;
        }
        .children-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 20px;
            margin-top: 30px;
        }
        .child-card {
            background: white;
            border-radius: 15px;
            padding: 30px;
            box-shadow: 0 5px 15px rgba(0,0,0,0.05);
            cursor: pointer;
            transition: transform 0.2s, box-shadow 0.2s;
        }
        .child-card:hover {
            transform: translateY(-5px);
            box-shadow: 0 8px 25px rgba(0,0,0,0.1);
        }
        .child-icon {
            width: 80px;
            height: 80px;
            background-color: #4a6fa5;
            border-radius: 15px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 40px;
            color: white;
            margin: 0 auto 15px;
        }
        .child-name {
            font-size: 24px;
            font-weight: bold;
            text-align: center;
            margin-bottom: 10px;
        }
        .child-status {
            text-align: center;
            padding: 5px 10px;
            border-radius: 15px;
            display: inline-block;
            font-size: 14px;
        }
        .status-online {
            background-color: #d4edda;
            color: #155724;
        }
        .status-offline {
            background-color: #f8d7da;
            color: #721c24;
        }
        .domain-controls {
            background: white;
            padding: 30px;
            border-radius: 15px;
            margin: 20px 0;
            box-shadow: 0 5px 15px rgba(0,0,0,0.05);
        }
        .domain-form {
            display: flex;
            gap: 15px;
            margin-bottom: 30px;
        }
        .domain-input {
            flex: 1;
            padding: 12px 15px;
            border: 2px solid #e1e8ed;
            border-radius: 8px;
            font-size: 16px;
        }
        .primary-btn {
            background: #4a6fa5;
            color: white;
            border: none;
            padding: 12px 30px;
            border-radius: 8px;
            cursor: pointer;
            font-weight: bold;
        }
        .domain-list {
            margin-top: 30px;
            border: 2px solid #e1e8ed;
            border-radius: 10px;
            max-height: 400px;
            overflow-y: auto;
            background: #f9f9f9;
        }
        .domain-item {
            padding: 15px 20px;
            border-bottom: 1px solid #e1e8ed;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .remove-btn {
            background: #e74c3c;
            color: white;
            border: none;
            padding: 8px 15px;
            border-radius: 6px;
            cursor: pointer;
        }
        .back-btn {
            background: #95a5a6;
            color: white;
            border: none;
            padding: 10px 20px;
            border-radius: 8px;
            cursor: pointer;
            text-decoration: none;
            display: inline-block;
        }
        .empty-message {
            padding: 20px;
            text-align: center;
            color: #666;
            font-style: italic;
        }
    </style>
</head>
<body>
    <div class="header">
        <div class="header-content">
            <div class="logo-container">
                <div class="logo-circle">🛡️</div>
                <h1>בקרת הורים</h1>
            </div>
        </div>
    </div>

    <div class="main-content">
        <div class="children-grid">
            ${children_cards}
        </div>

        <div class="domain-controls" style="display: ${display_child_controls}">
            <h3>ניהול דומיינים חסומים עבור: ${current_child}</h3>
            <form method="post" action="/add_domain" class="domain-form">
                <input type="hidden" name="child" value="${current_child}">
                <input type="text" name="domain" class="domain-input" placeholder="הכנס דומיין לחסימה">
                <button type="submit" class="primary-btn">הוסף דומיין</button>
            </form>

            <h3>דומיינים חסומים כרגע</h3>
            <div class="domain-list">
                ${blocked_domains_html}
            </div>

            <div style="text-align: center; margin-top: 30px;">
                <a href="/dashboard" class="back-btn">חזור לרשימת הילדים</a>
            </div>
        </div>
    </div>
</body>
</html>"""


class ParentServer:
    def __init__(self):
        self.running = True
        self.server_socket = None
        self.connection_threads = []
        self.load_children_data()

    def load_children_data(self):
        try:
            with open('children_data.json', 'r') as f:
                data = json.load(f)
                for child, info in data.items():
                    info['blocked_domains'] = set(info['blocked_domains'])
                    info.setdefault('client_address', None)
                    info.setdefault('last_seen', None)
                children_data.update(data)
                print(f"[*] נטענו נתונים עבור {len(children_data)} ילדים")
        except FileNotFoundError:
            children_data['ילד 1'] = {"blocked_domains": set(["facebook.com", "youtube.com"]), "client_address": None,
                                      "last_seen": None}
            children_data['ילד 2'] = {"blocked_domains": set(["instagram.com", "tiktok.com"]), "client_address": None,
                                      "last_seen": None}
            children_data['ילד 3'] = {"blocked_domains": set(["twitter.com"]), "client_address": None,
                                      "last_seen": None}
            self.save_children_data()
            print(f"[*] נוצרו נתוני ברירת מחדל עבור {len(children_data)} ילדים")

    def save_children_data(self):
        with data_lock:
            data_to_save = {}
            for child, info in children_data.items():
                data_to_save[child] = {
                    "blocked_domains": list(info["blocked_domains"]),
                    "last_seen": info["last_seen"]
                }
            with open('children_data.json', 'w') as f:
                json.dump(data_to_save, f)

    def handle_child_connection(self, client_socket, address):
        print(f"[*] חיבור חדש מ-{address}")
        child_name = None

        try:
            msg_type, data = Protocol.receive_message(client_socket)

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

        except Exception as e:
            print(f"[!] שגיאה בחיבור {child_name}: {e}")
        finally:
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

                if msg_type == Protocol.GET_DOMAINS:
                    with data_lock:
                        domains = list(children_data[child_name]['blocked_domains'])
                    Protocol.send_message(client_socket, Protocol.UPDATE_DOMAINS, {"domains": domains})
                    print(f"[+] נשלחו דומיינים ל-{child_name}: {domains}")

                elif msg_type == Protocol.CHILD_STATUS:
                    with data_lock:
                        children_data[child_name]['last_seen'] = time.time()
                    Protocol.send_message(client_socket, Protocol.ACK)

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


parent_server = ParentServer()


class ParentHandler(http.server.SimpleHTTPRequestHandler):
    def notify_child_immediate(self, child_name):
        """עדכון מיידי לילד"""
        with data_lock:
            if child_name in active_connections:
                conn_info = active_connections[child_name]
                if conn_info and conn_info.get("socket"):
                    try:
                        socket = conn_info["socket"]
                        domains = list(children_data[child_name]['blocked_domains'])
                        Protocol.send_message(socket, Protocol.UPDATE_DOMAINS, {"domains": domains})
                        print(f"[*] נשלח עדכון מיידי ל-{child_name}")
                    except Exception as e:
                        print(f"[!] שגיאה בעדכון {child_name}: {e}")

    def do_GET(self):
        path = unquote(self.path)
        parsed_path = urlparse(path)
        query_params = parse_qs(parsed_path.query)

        if parsed_path.path in ['/', '/login']:
            self.send_response(200)
            self.send_header('Content-type', 'text/html; charset=utf-8')
            self.end_headers()
            self.wfile.write(LOGIN_TEMPLATE.encode('utf-8'))

        elif parsed_path.path == '/dashboard':
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

        if self.path == '/login':
            self.send_response(302)
            self.send_header('Location', '/dashboard')
            self.end_headers()

        elif self.path == '/add_domain':
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


if __name__ == "__main__":
    try:
        parent_server.start_communication_server()

        with socketserver.TCPServer(("", HTTP_PORT), ParentHandler) as httpd:
            print(f"[*] שרת HTTP פועל על http://localhost:{HTTP_PORT}")
            print(f"[*] שרת תקשורת פועל על פורט {COMMUNICATION_PORT}")
            print(f"[*] מוכן לקבל חיבורים מילדים")
            print("[*] Press Ctrl+C to stop the server")
            try:
                httpd.serve_forever()
            except KeyboardInterrupt:
                print("\n[*] עצירת השרת...")
                parent_server.shutdown()
                httpd.shutdown()
    except Exception as e:
        print(f"[!] שגיאה בהפעלת השרת: {e}")
