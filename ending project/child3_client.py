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
import ssl
import ipaddress
from protocol import Protocol, COMMUNICATION_PORT
import http.server
import socketserver
from urllib.parse import urlparse
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import datetime

# קונפיגורציה ספציפית לילד 3
CHILD_NAME = "ילד 3"

REAL_DNS_SERVER = "8.8.8.8"
LISTEN_IP = "0.0.0.0"
LISTEN_PORT = 53

BLOCK_PAGE_IP = "127.0.0.1"

PARENT_SERVER_IP = "127.0.0.1"

BLOCKED_DOMAINS = set()

ORIGINAL_DNS = None

# רשימת היסטוריית גלישה
browsing_history = []
history_lock = threading.Lock()
MAX_HISTORY_ENTRIES = 1000  # מקסימום רשומות היסטוריה

TECHNICAL_DOMAINS = {
    # Google infrastructure
    'gstatic.com', 'googleapis.com', 'googleusercontent.com', 'googlevideo.com',
    'googletagmanager.com', 'google-analytics.com', 'googleadservices.com',
    'fonts.googleapis.com', 'ajax.googleapis.com', 'analytics.google.com',
    'doubleclick.net', 'googletagservices.com', 'googlesyndication.com',
    'googleoptimize.com', 'googletagservices.com',

    # CDN ו-Infrastructure
    'cloudflare.com', 'amazonaws.com', 'akamai.net', 'fastly.com',
    'cloudfront.net', 'azureedge.net', 'jsdelivr.net', 'unpkg.com',
    'cdnjs.cloudflare.com', 'maxcdn.bootstrapcdn.com', 'fastly-insights.com',
    'rlcdn.com', 'contentsquare.net',

    # Ads & Analytics & Tracking
    'googleads.g.doubleclick.net', 'securepubads.g.doubleclick.net',
    'tpc.googlesyndication.com', 'pagead2.googlesyndication.com',
    'adsystem.com', 'amazon-adsystem.com', 'adsafeprotected.com',
    'scorecardresearch.com', 'company-target.com',

    # Social media CDN - רק הטכניים
    'scontent.xx.fbcdn.net', 'static.xx.fbcdn.net', 'connect.facebook.net',
    'abs.twimg.com', 'ton.twimg.com', 'video.twimg.com',
    'i.ytimg.com', 'yt3.ggpht.com', 'yt4.ggpht.com',

    # Microsoft & Apple
    'windows.com', 'live.com', 'msn.com', 'office.com', 'skype.com',
    'microsoftonline.com', 'outlook.com', 'hotmail.com',
    'icloud.com', 'me.com', 'apple.com', 'itunes.apple.com',

    # Security & certificates
    'digicert.com', 'symantec.com', 'verisign.com', 'godaddy.com',
    'letsencrypt.org', 'ssl.com', 'globalsign.com',

    # Analytics & Tracking
    'statsig.anthropic.com', 'mixpanel.com', 'amplitude.com',
    'segment.com', 'hotjar.com', 'fullstory.com', 'logrocket.com',
    'sentry.io', 'bugsnag.com', 'rollbar.com', 'newrelic.com',
    'datadog.com', 'splunk.com', 'intercom.io', 'zendesk.com',
    'freshworks.com', 'salesforce.com', 'hubspot.com',

    # Spotify specific CDN/Analytics
    'spotifycdn.com', 'scdn.co', 'spotify-com.akamaized.net',

    # TikTok specific CDN/Analytics
    'tiktokv.com', 'ttwstatic.com', 'tiktokcdn.com', 'byteoversea.com',
    'muscdn.com', 'musical.ly', 'ttlivecdn.com', 'tiktok-web.com',

    # Netflix specific
    'nflxext.com', 'nflximg.net', 'nflxso.net', 'nflxvideo.net',

    # YouTube specific
    'ytimg.com', 'ggpht.com', 'googlevideo.com',

    # Facebook specific
    'fbcdn.net', 'facebook.net',

    # טכניים נוספים
    'pingdom.com', 'statuspage.io', 'pingdom.net', 'uptime.com',
    'gravatar.com', 'wp.com', 'wordpress.com', 'typekit.net',
    'adobe.com', 'adobedtm.com', 'omtrdc.net', 'demdex.net'
}

# רשימת סיומות דומיינים טכניים
TECHNICAL_SUFFIXES = {
    '.gstatic.com', '.googleapis.com', '.googleusercontent.com',
    '.googlevideo.com', '.googletagmanager.com', '.doubleclick.net',
    '.cloudflare.com', '.amazonaws.com', '.akamai.net', '.fastly.com',
    '.cloudfront.net', '.azureedge.net', '.fbcdn.net', '.twimg.com',
    '.ytimg.com', '.ggpht.com', '.anthropic.com',
    '.spotifycdn.com', '.scdn.co', '.nflxext.com', '.nflximg.net',
    '.tiktokv.com', '.ttwstatic.com', '.byteoversea.com', '.muscdn.com'
}

# מפת אתרים עיקריים - דומיינים שייחשבו כמייצגים את האתר העיקרי
MAIN_SITE_DOMAINS = {
    'spotify.com': ['spotifycdn.com', 'scdn.co', 'spotify-com.akamaized.net'],
    'tiktok.com': ['tiktokv.com', 'ttwstatic.com', 'tiktokcdn.com', 'byteoversea.com', 'muscdn.com', 'ttlivecdn.com'],
    'netflix.com': ['nflxext.com', 'nflximg.net', 'nflxso.net', 'nflxvideo.net'],
    'youtube.com': ['ytimg.com', 'ggpht.com', 'googlevideo.com'],
    'facebook.com': ['fbcdn.net', 'facebook.net', 'connect.facebook.net'],
    'instagram.com': ['fbcdn.net'],
    'twitter.com': ['twimg.com'],
    'google.com': ['gstatic.com', 'googleapis.com']
}

def is_technical_domain(domain):
    """בדיקה משופרת אם זה דומיין טכני שלא צריך להופיע בהיסטוריה"""
    domain_lower = domain.lower().strip('.')

    # בדיקה של דומיינים מלאים
    if domain_lower in TECHNICAL_DOMAINS:
        return True

    # בדיקה של סיומות
    for suffix in TECHNICAL_SUFFIXES:
        if domain_lower.endswith(suffix):
            return True

    # בדיקת תבניות נוספות
    technical_patterns = [
        'ads.', 'ad.', 'analytics.', 'tracking.', 'metrics.', 'stats.',
        'pixel.', 'beacon.', 'api.', 'cdn.', 'static.', 'assets.',
        'js.', 'css.', 'fonts.', 'img.', 'images.', 'media.',
        'ajax.', 'widget.', 'embed.', 'plugin.', 'tools.',
        'telemetry.', 'collect.', 'events.', 'ping.', 'heartbeat.',
        'edge-', 'cache-', 'content-'
    ]

    for pattern in technical_patterns:
        if domain_lower.startswith(pattern):
            return True

    # בדיקת תבניות מיוחדות לאנליטיקס וCDN
    technical_keywords = [
        'analytics', 'tracking', 'stats', 'metrics', 'telemetry', 'events',
        'cdn', 'cache', 'edge', 'akamai', 'cloudflare', 'fastly',
        'insights', 'optimize', 'research', 'target', 'content'
    ]
    for keyword in technical_keywords:
        if keyword in domain_lower:
            return True

    return False


def get_main_domain_from_subdomain(domain):
    """מנסה לזהות לאיזה אתר עיקרי שייך הדומיין"""
    domain_lower = domain.lower().strip('.')

    # בדיקה במפת האתרים העיקריים
    for main_site, subdomains in MAIN_SITE_DOMAINS.items():
        for subdomain in subdomains:
            if domain_lower == subdomain or domain_lower.endswith('.' + subdomain):
                return main_site

    return None


def get_main_domain(domain):
    """חילוץ הדומיין הראשי - עם אלגוריתם חכם לסינון"""
    original_domain = domain
    domain = domain.lower().strip('.')

    # בדיקה ראשונה - אם זה דומיין טכני ברור
    if is_technical_domain(domain):
        print(f"[FILTER] דומיין טכני: {original_domain} -> מסונן")
        return None

    # הסרת www
    if domain.startswith('www.'):
        domain = domain[4:]

    # בדיקה אם זה תת-דומיין של אתר עיקרי מוכר
    main_site = get_main_domain_from_subdomain(domain)
    if main_site:
        print(f"[FILTER] תת-דומיין: {original_domain} -> {main_site}")
        return main_site

    # רשימת תתי-דומיינים שכן רוצים להציג (רק אם הם לא טכניים)
    important_subdomains = ['m.', 'mobile.', 'mail.', 'drive.', 'docs.', 'maps.', 'translate.']

    # בדיקה אם זה תת-דומיין חשוב
    for subdomain in important_subdomains:
        if domain.startswith(subdomain):
            print(f"[FILTER] תת-דומיין חשוב: {original_domain} -> {domain}")
            return domain

    # חילוץ הדומיין הראשי (domain.com)
    parts = domain.split('.')
    if len(parts) >= 2:
        main_domain = '.'.join(parts[-2:])  # שני החלקים האחרונים

        # בדיקה נוספת שהדומיין הראשי לא טכני
        if not is_technical_domain(main_domain):
            print(f"[FILTER] דומיין עיקרי: {original_domain} -> {main_domain}")
            return main_domain
        else:
            print(f"[FILTER] דומיין עיקרי טכני: {original_domain} -> מסונן")
            return None

    print(f"[FILTER] לא זוהה: {original_domain} -> מסונן")
    return None


# מטמון לעיכוב בקשות דומות (למניעת ספאם)
domain_visit_cache = {}
VISIT_GROUPING_SECONDS = 300  # 5 דקות


def should_add_to_history(domain, timestamp, was_blocked):
    """בדיקה משופרת אם להוסיף רשומה להיסטוריה"""
    main_domain = get_main_domain(domain)

    # אם זה דומיין טכני שלא רוצים להציג
    if main_domain is None:
        return False, None

    # בדיקה של קיבוץ ביקורים - כל ביקור לאותו דומיין תוך 5 דקות נחשב כאחד
    current_time = datetime.datetime.now()
    domain_key = f"{main_domain}_{was_blocked}"  # מפריד בין חסום למותר

    if domain_key in domain_visit_cache:
        time_diff = (current_time - domain_visit_cache[domain_key]).total_seconds()
        if time_diff < VISIT_GROUPING_SECONDS:
            # עדכון הזמן בלבד, לא הוספת רשומה חדשה
            domain_visit_cache[domain_key] = current_time
            print(f"[FILTER] דילוג - ביקור אחרון ב-{main_domain}: {int(time_diff)} שניות")
            return False, main_domain

    # רשומה חדשה
    domain_visit_cache[domain_key] = current_time
    print(f"[FILTER] רשומה חדשה: {main_domain}")
    return True, main_domain


last_visit_time = {}
VISIT_GROUPING_SECONDS = 120  # קיבוץ ביקורים שקורים תוך דקה


def should_add_to_history(domain, timestamp, was_blocked):
    """בדיקה אם להוסיף רשומה להיסטוריה"""
    main_domain = get_main_domain(domain)

    # אם זה דומיין טכני שלא רוצים להציג
    if main_domain is None:
        return False, None

    # בדיקה של קיבוץ ביקורים - כל ביקור לאותו דומיין תוך 2 דקות נחשב כאחד
    current_time = datetime.datetime.now()
    domain_key = main_domain  # רק לפי דומיין, לא לפי סטטוס חסימה

    if domain_key in last_visit_time:
        time_diff = (current_time - last_visit_time[domain_key]).total_seconds()
        if time_diff < VISIT_GROUPING_SECONDS:
            # עדכון הזמן בלבד, לא הוספת רשומה חדשה
            last_visit_time[domain_key] = current_time
            return False, main_domain

    # רשומה חדשה
    last_visit_time[domain_key] = current_time
    return True, main_domain


def add_to_history(domain, timestamp, was_blocked=False):
    """הוספת רשומה להיסטוריית הגלישה עם סינון חכם"""
    should_add, main_domain = should_add_to_history(domain, timestamp, was_blocked)

    if not should_add:
        if main_domain:
            print(f"[HISTORY] דילוג על {domain} (כבר בוקר {main_domain} לאחרונה)")
        else:
            print(f"[HISTORY] דילוג על {domain} (דומיין טכני)")
        return

    with history_lock:
        entry = {
            "domain": main_domain,
            "timestamp": timestamp,
            "was_blocked": was_blocked,
            "child_name": CHILD_NAME
        }

        browsing_history.append(entry)

        # שמירה על מגבלת הרשומות
        if len(browsing_history) > MAX_HISTORY_ENTRIES:
            browsing_history.pop(0)  # הסרת הרשומה הישנה ביותר

        print(f"[HISTORY] נוסף לרשימה: {main_domain} ({'חסום' if was_blocked else 'מותר'})")

        # שליחה מיידית לשרת ההורים
        threading.Thread(target=send_single_history_update, args=(entry,), daemon=True).start()


def send_single_history_update(entry):
    """שליחת עדכון היסטוריה מיידי לשרת ההורים"""
    if child_client.connected:
        try:
            data = {
                "child_name": CHILD_NAME,
                "history": [entry]  # שליחת רשומה אחת בלבד
            }

            Protocol.send_message(child_client.sock, Protocol.BROWSING_HISTORY, data)
            print(f"[HISTORY] נשלח עדכון מיידי לשרת: {entry['domain']}")

        except Exception as e:
            print(f"[!] שגיאה בשליחת עדכון מיידי: {e}")


def send_history_update():
    """שליחת עדכון היסטוריה מלא לשרת ההורים (גיבוי)"""
    if child_client.connected and browsing_history:
        try:
            with history_lock:
                # שליחת כל ההיסטוריה כגיבוי
                recent_history = browsing_history.copy()

            data = {
                "child_name": CHILD_NAME,
                "history": recent_history
            }

            Protocol.send_message(child_client.sock, Protocol.BROWSING_HISTORY, data)
            print(f"[HISTORY] נשלח עדכון מלא לשרת: {len(recent_history)} רשומות")

        except Exception as e:
            print(f"[!] שגיאה בשליחת היסטוריה מלאה: {e}")


def create_simple_block_cert():
    """יצירת תעודה פשוטה לשרת החסימה"""
    if os.path.exists("block_cert.pem"):
        return True

    try:
        print("[*] יוצר תעודת SSL לשרת החסימה...")

        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "IL"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, f"Block Server - {CHILD_NAME}"),
            x509.NameAttribute(NameOID.COMMON_NAME, "127.0.0.1"),
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
            datetime.datetime.now(datetime.timezone.utc)
        ).not_valid_after(
            datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365)
        ).add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName("localhost"),
                x509.DNSName("127.0.0.1"),
                x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
            ]),
            critical=False,
        ).sign(private_key, hashes.SHA256())

        with open("block_cert.pem", "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))

        print("[+] תעודת SSL נוצרה לשרת החסימה")
        return True

    except ImportError:
        print("[*] ספריית cryptography לא זמינה - רק HTTP")
        return False
    except Exception as e:
        print(f"[*] לא ניתן ליצור תעודה: {e}")
        return False


class BlockHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        """טיפול בבקשות HTTP/HTTPS"""
        self.send_response(200)
        self.send_header('Content-type', 'text/html; charset=utf-8')
        self.end_headers()

        is_https = hasattr(self.request, 'context') or hasattr(self.connection, 'context')
        protocol = "HTTPS" if is_https else "HTTP"

        block_page = f"""<!DOCTYPE html>
<html dir="rtl" lang="he">
<head>
    <meta charset="UTF-8">
    <title>אתר חסום - {CHILD_NAME}</title>
    <style>
        body {{ 
            font-family: 'Segoe UI', Tahoma, Arial, sans-serif; 
            text-align: center; 
            background: linear-gradient(135deg, #ff4757, #ff6b6b);
            color: white;
            margin: 0;
            padding: 20px;
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
        }}
        .container {{
            background: rgba(0,0,0,0.8);
            backdrop-filter: blur(10px);
            padding: 50px;
            border-radius: 20px;
            box-shadow: 0 15px 35px rgba(0,0,0,0.5);
            max-width: 600px;
            border: 2px solid rgba(255,255,255,0.3);
            animation: pulse 2s infinite;
        }}
        @keyframes pulse {{
            0% {{ transform: scale(1); }}
            50% {{ transform: scale(1.02); }}
            100% {{ transform: scale(1); }}
        }}
        .icon {{ 
            font-size: 100px; 
            margin-bottom: 30px;
            text-shadow: 0 0 20px rgba(255,255,255,0.5);
        }}
        h1 {{ 
            font-size: 3em; 
            margin-bottom: 20px; 
            text-shadow: 2px 2px 4px rgba(0,0,0,0.5);
            animation: glow 2s ease-in-out infinite alternate;
        }}
        @keyframes glow {{
            from {{ text-shadow: 0 0 20px #fff, 0 0 30px #fff, 0 0 40px #ff0080; }}
            to {{ text-shadow: 0 0 30px #fff, 0 0 40px #fff, 0 0 50px #ff0080; }}
        }}
        p {{ font-size: 1.3em; line-height: 1.8; margin: 20px 0; }}
        .protocol {{ 
            position: absolute; 
            top: 20px; 
            left: 20px; 
            background: rgba(0,0,0,0.7); 
            padding: 10px 15px; 
            border-radius: 15px;
            font-size: 0.9em;
            border: 1px solid rgba(255,255,255,0.3);
        }}
        .child-name {{
            position: absolute;
            top: 20px;
            right: 20px;
            background: rgba(0,0,0,0.7);
            padding: 10px 15px;
            border-radius: 15px;
            font-size: 0.9em;
            border: 1px solid rgba(255,255,255,0.3);
        }}
        .warning-box {{
            background: rgba(255,255,255,0.1);
            border: 2px solid #fff;
            border-radius: 15px;
            padding: 20px;
            margin: 30px 0;
        }}
    </style>
</head>
<body>
    <div class="protocol">{protocol}</div>
    <div class="child-name">{CHILD_NAME}</div>
    <div class="container">
        <div class="icon">🚫</div>
        <h1>אתר חסום!</h1>

        <div class="warning-box">
            <p><strong>אתר:</strong> {self.headers.get('Host', 'לא ידוע')}</p>
            <p><strong>זמן:</strong> {time.strftime('%H:%M:%S')}</p>
            <p><strong>פרוטוקול:</strong> {protocol}</p>
        </div>

        <p>הגישה לאתר זה נחסמה על ידי מערכת בקרת ההורים</p>
        <p>אם אתה חושב שזו טעות, פנה להורים שלך</p>
    </div>
</body>
</html>"""

        self.wfile.write(block_page.encode('utf-8'))

    def do_POST(self):
        self.do_GET()

    def log_message(self, format, *args):
        return


def clear_dns_cache():
    """ניקוי DNS cache"""
    print("[*] מנקה DNS cache...")

    try:
        result = subprocess.run(['ipconfig', '/flushdns'],
                                capture_output=True, text=True, encoding='utf-8')
        if result.returncode == 0:
            print("[+] Windows DNS cache נוקה")
        else:
            print(f"[!] בעיה בניקוי cache: {result.stderr}")
    except Exception as e:
        print(f"[!] שגיאה בניקוי cache: {e}")


def start_block_server():
    """שרת חסימה עם תמיכה ב-HTTP ו-HTTPS"""

    def start_http_server():
        """שרת HTTP על פורט 80/8080"""
        try:
            with socketserver.TCPServer(("127.0.0.1", 80), BlockHandler) as httpd:
                print("[+] שרת חסימה HTTP פועל על פורט 80")
                httpd.serve_forever()
        except PermissionError:
            try:
                with socketserver.TCPServer(("127.0.0.1", 8080), BlockHandler) as httpd:
                    print("[+] שרת חסימה HTTP פועל על פורט 8080")
                    httpd.serve_forever()
            except Exception as e:
                print(f"[!] שגיאה בשרת HTTP: {e}")

    def start_https_server():
        """שרת HTTPS על פורט 443/8443"""
        if not create_simple_block_cert():
            print("[*] לא ניתן ליצור תעודת SSL לשרת החסימה")
            return

        try:
            with socketserver.TCPServer(("127.0.0.1", 443), BlockHandler) as httpd:
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                context.load_cert_chain("block_cert.pem")
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE

                httpd.socket = context.wrap_socket(httpd.socket, server_side=True)
                print("[+] שרת חסימה HTTPS פועל על פורט 443")
                httpd.serve_forever()
        except PermissionError:
            try:
                with socketserver.TCPServer(("127.0.0.1", 8443), BlockHandler) as httpd:
                    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                    context.load_cert_chain("block_cert.pem")
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_NONE

                    httpd.socket = context.wrap_socket(httpd.socket, server_side=True)
                    print("[+] שרת חסימה HTTPS פועל על פורט 8443")
                    httpd.serve_forever()
            except Exception as e:
                print(f"[!] שגיאה בשרת HTTPS: {e}")

    print("[*] מפעיל שרתי חסימה (HTTP + HTTPS)...")

    http_thread = threading.Thread(target=start_http_server, daemon=True)
    http_thread.start()

    https_thread = threading.Thread(target=start_https_server, daemon=True)
    https_thread.start()

    time.sleep(0.5)


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
            cmd = ['powershell', '-Command',
                   'Get-NetAdapter | Where-Object {$_.Status -eq "Up" -and ($_.Name -like "*Wi-Fi*" -or $_.Name -like "*Wireless*" -or $_.InterfaceDescription -like "*Wireless*")} | Select-Object -First 1 -ExpandProperty Name']

            result = subprocess.run(cmd, capture_output=True, text=True, encoding='utf-8')

            if result.returncode == 0 and result.stdout.strip():
                interface_name = result.stdout.strip()
                print(f"[*] נמצא ממשק Wi-Fi: {interface_name}")
                return interface_name

        except Exception as e:
            print(f"[!] שגיאה בחיפוש ממשק Wi-Fi: {e}")

        try:
            result = subprocess.run(['netsh', 'wlan', 'show', 'profiles'],
                                    capture_output=True, text=True, encoding='utf-8')

            if result.returncode == 0:
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
        wifi_interface = self.get_wifi_interface_name()
        if wifi_interface:
            return wifi_interface

        ethernet_interface = self.get_ethernet_interface_name()
        if ethernet_interface:
            return ethernet_interface

        common_names = ['Wi-Fi', 'Ethernet', 'Local Area Connection', 'Wireless Network Connection']
        for name in common_names:
            try:
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

            if self.set_dns_powershell(interface_name, dns_server):
                return True

            cmd = ['netsh', 'interface', 'ip', 'set', 'dns',
                   f'name={interface_name}', 'source=static',
                   f'addr={dns_server}']

            result = subprocess.run(cmd, capture_output=True, text=True, encoding='utf-8')

            if result.returncode == 0:
                print(f"[+] DNS הוגדר בהצלחה ל-{dns_server} בממשק {interface_name}")
                return True
            else:
                print(f"[!] שגיאה בהגדרת DNS: {result.stderr}")

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
            cmd_ps = ['powershell', '-Command',
                      f'Set-DnsClientServerAddress -InterfaceAlias "{interface_name}" -ResetServerAddresses']

            result = subprocess.run(cmd_ps, capture_output=True, text=True, encoding='utf-8')
            if result.returncode == 0:
                print(f"[+] DNS שוחזר להגדרות אוטומטיות (PowerShell) בממשק {interface_name}")
                return True

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
                self.original_dns = (interface_name, [])
                print(f"[*] ממשק נבחר: {interface_name}")

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


class ChildClient:
    def __init__(self):
        self.sock = None
        self.child_name = CHILD_NAME
        self.connected = False
        self.keep_running = True
        self.last_update = time.time()
        self.connection_event = threading.Event()

    def connect_to_parent(self):
        """חיבור לשרת ההורים"""
        retry_count = 0
        max_retries = 5

        while self.keep_running and retry_count < max_retries:
            try:
                print(f"[*] מנסה להתחבר לשרת הורים (ניסיון {retry_count + 1}/{max_retries})...")

                self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.sock.settimeout(3)
                self.sock.connect((PARENT_SERVER_IP, COMMUNICATION_PORT))

                register_data = {"name": self.child_name}
                Protocol.send_message(self.sock, Protocol.REGISTER_CHILD, register_data)

                self.sock.settimeout(5)
                msg_type, _ = Protocol.receive_message(self.sock)

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
            if self.sock:
                try:
                    self.sock.close()
                except:
                    pass

            if retry_count < max_retries:
                print(f"[*] ממתין {2} שניות לפני ניסיון חוזר...")
                time.sleep(2)

        print(f"[!] נכשל בחיבור לשרת הורים אחרי {max_retries} ניסיונות")
        print("[*] ממשיך בפעולה ללא שרת הורים")
        self.connection_event.set()

    def wait_for_connection(self, timeout=10):
        """ממתין לחיבור או timeout"""
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

    def request_domains_update(self):
        if self.connected:
            try:
                Protocol.send_message(self.sock, Protocol.GET_DOMAINS)
                print("[*] בקשה לעדכון דומיינים נשלחה")
            except Exception as e:
                print(f"[!] שגיאה בבקשת עדכון דומיינים: {e}")
                self.connected = False

    def listen_for_updates(self):
        print(f"[*] מתחיל להאזין לעדכונים מהשרת...")

        while self.connected and self.keep_running:
            try:
                self.sock.settimeout(30)
                msg_type, data = Protocol.receive_message(self.sock)

                if msg_type == Protocol.UPDATE_DOMAINS:
                    domains = data.get('domains', [])
                    global BLOCKED_DOMAINS
                    old_domains = BLOCKED_DOMAINS.copy()
                    BLOCKED_DOMAINS = set(domains)

                    print(f"[+] עודכנו דומיינים חסומים: {len(BLOCKED_DOMAINS)} דומיינים")
                    if len(BLOCKED_DOMAINS) <= 10:
                        print(f"[DEBUG] דומיינים: {list(BLOCKED_DOMAINS)}")

                    if old_domains != BLOCKED_DOMAINS:
                        print("[*] מנקה DNS cache...")
                        clear_dns_cache()

                    self.last_update = time.time()

                elif msg_type == Protocol.CHILD_STATUS:
                    Protocol.send_message(self.sock, Protocol.ACK)

                elif msg_type == Protocol.GET_HISTORY:
                    # שליחת היסטוריית הגלישה לשרת
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

    def send_status_update(self):
        while self.keep_running:
            if self.connected:
                try:
                    Protocol.send_message(self.sock, Protocol.CHILD_STATUS)
                except:
                    self.connected = False
            time.sleep(30)


child_client = ChildClient()
dns_manager = DNSManager()


def is_blocked_domain(query_name):
    """בודק אם הדומיין או תת-דומיין חסום"""
    original_query = query_name
    query_name = query_name.lower().strip('.')

    print(f"[DEBUG] בודק דומיין: '{original_query}' -> '{query_name}'")
    print(f"[DEBUG] רשימת דומיינים חסומים: {BLOCKED_DOMAINS}")

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

        if blocked_domain.endswith('.' + query_name):
            print(f"[DEBUG] דומיין אב: {blocked_domain} סיומת של .{query_name}")
            return True

    print(f"[DEBUG] {query_name} לא חסום")
    return False


def handle_dns_request(data, addr, sock):
    """טיפול בבקשת DNS נכנסת"""
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

        # הוספה להיסטוריית הגלישה
        current_time = datetime.datetime.now().isoformat()

        if is_blocked_domain(query_name):
            print(f"[-] חוסם את {query_name}, מפנה ל-{BLOCK_PAGE_IP}")
            print(f"[DEBUG] יוצר תגובת DNS עם IP: {BLOCK_PAGE_IP}")

            # הוספה להיסטוריה כחסום
            add_to_history(query_name, current_time, was_blocked=True)

            response = DNS(
                id=packet_response.id,
                qr=1,
                aa=1,
                qd=packet_response.qd,
                an=DNSRR(rrname=packet_response.qd.qname, ttl=0, rdata=BLOCK_PAGE_IP)
            )

            sock.sendto(bytes(response), addr)
            print(f"[+] נשלחה תשובה לחסימת {query_name} עם TTL=0 ל-{addr[0]}")

            print(f"[DEBUG] תגובת DNS: ID={response.id}, IP={BLOCK_PAGE_IP}")

        else:
            print(f"[+] מעביר את הבקשה ל-DNS האמיתי ({REAL_DNS_SERVER})")

            # הוספה להיסטוריה כלא חסום
            add_to_history(query_name, current_time, was_blocked=False)

            try:
                proxy_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                proxy_sock.settimeout(5)
                proxy_sock.sendto(data, (REAL_DNS_SERVER, 53))

                response_data, _ = proxy_sock.recvfrom(4096)
                proxy_sock.close()

                try:
                    response_dns = DNS(response_data)
                    for answer in response_dns.an:
                        answer.ttl = 0

                    sock.sendto(bytes(response_dns), addr)
                    print(f"[+] התקבלה והועברה תשובת DNS עבור {query_name} עם TTL=0 ל-{addr[0]}")
                except:
                    sock.sendto(response_data, addr)
                    print(f"[+] התקבלה והועברה תשובת DNS עבור {query_name} ל-{addr[0]}")

            except socket.timeout:
                print(f"[!] תם הזמן בהמתנה לתשובה מ-DNS האמיתי")
                error_response = DNS(id=packet_response.id, qr=1, aa=1, rcode=2, qd=packet_response.qd)
                sock.sendto(bytes(error_response), addr)
            except Exception as e:
                print(f"[!] שגיאה בהעברת הבקשה ל-DNS האמיתי: {e}")
                error_response = DNS(id=packet_response.id, qr=1, aa=1, rcode=2, qd=packet_response.qd)
                sock.sendto(bytes(error_response), addr)



def check_dns_settings():
    """בדיקה שהגדרות DNS נקבעו נכון"""
    try:
        result = subprocess.run(['nslookup', 'instagram.com'],
                                capture_output=True, text=True, encoding='utf-8')
        print(f"[DEBUG] nslookup instagram.com:")
        print(result.stdout)

        if "127.0.0.1" in result.stdout:
            print("[+] DNS מופנה נכון!")
        else:
            print("[!] DNS לא מופנה - בדוק הגדרות רשת!")

    except Exception as e:
        print(f"[!] שגיאה בבדיקת DNS: {e}")


def start_dns_proxy():
    """הפעלת שרת Proxy DNS"""
    print(f"[*] מפעיל Proxy DNS ל-{CHILD_NAME} על {LISTEN_IP}:{LISTEN_PORT}...")
    print(f"[*] דומיינים חסומים: {', '.join(BLOCKED_DOMAINS) if BLOCKED_DOMAINS else 'ממתין לעדכון מהשרת'}")
    print(f"[*] דף חסימה יוצג מכתובת: {BLOCK_PAGE_IP}")

    try:
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
                threading.Thread(target=handle_dns_request, args=(data, addr, sock), daemon=True).start()
            except Exception as e:
                print(f"[!] שגיאה בטיפול בבקשה: {e}")
    except KeyboardInterrupt:
        print("\n[*] עצירת השרת על ידי המשתמש.")
    finally:
        sock.close()
        print("[*] משחזר הגדרות DNS מקוריות...")
        dns_manager.restore_original_dns()
        print("[*] השרת נסגר.")


if __name__ == "__main__":
    print(f"[*] מתחיל תוכנת בקרת הורים עבור {CHILD_NAME}")
    print("=" * 60)

    print("[*] מגדיר הפניית DNS...")
    if dns_manager.setup_dns_redirect():
        print("[+] הגדרות DNS עודכנו בהצלחה")
    else:
        print("[!] לא ניתן להגדיר DNS אוטומטית")
        print("\n--- הגדרה ידנית ---")
        print("1. פתח 'הגדרות רשת' או 'Network Settings'")
        print("2. לחץ על 'שנה אפשרויות מתאם' או 'Change adapter options'")
        print("3. לחץ ימני על הרשת שלך ובחר 'מאפיינים' או 'Properties'")
        print("4. בחר 'Internet Protocol Version 4 (TCP/IPv4)' ולחץ 'מאפיינים'")
        print("5. בחר 'השתמש בכתובות DNS הבאות' ובשדה הראשון הכנס: 127.0.0.1")
        print("6. לחץ OK לשמירה")
        print("-------------------------\n")
        input("לחץ Enter אחרי שהגדרת את ה-DNS...")

    print("[*] מפעיל שרת דף חסימה...")
    block_server_thread = threading.Thread(target=start_block_server, daemon=True)
    block_server_thread.start()
    time.sleep(1)

    print("[*] מתחיל חיבור לשרת הורים...")
    connection_thread = threading.Thread(target=child_client.connect_to_parent, daemon=True)
    connection_thread.start()

    child_client.wait_for_connection(timeout=8)

    status_thread = threading.Thread(target=child_client.send_status_update, daemon=True)
    status_thread.start()

    if not child_client.connected:
        print("[*] פועל ללא שרת הורים - רק דומיינים שיתקבלו מאוחר יותר יחסמו")

    print("[*] בודק הגדרות DNS...")
    check_dns_settings()

    print("=" * 60)
    print(f"[+] מערכת בקרת הורים פעילה עבור {CHILD_NAME}")
    print(f"[+] דומיינים חסומים: {len(BLOCKED_DOMAINS)}")
    print("[*] מפעיל DNS Proxy...")
    print("=" * 60)

    start_dns_proxy()