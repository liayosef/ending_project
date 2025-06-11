import logging
import sys
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
import webbrowser
import psutil
import hashlib
from html_templats_child import (
    REGISTRATION_HTML_TEMPLATE,
    BLOCK_HTML_TEMPLATE,
    create_error_page,
    create_success_page
)
from custom_http_server import ParentalControlHTTPServer
from child_vpn_dns_protection import ChildVPNDNSProtection


# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('parental_control_child.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

# HTTPS Import for secure blocking
try:
    from custom_https_server import HTTPSBlockServer

    HTTPS_AVAILABLE = True
    logger.info("HTTPS module available")
except ImportError:
    HTTPSBlockServer = None
    HTTPS_AVAILABLE = False
    logger.warning("HTTPS module not available - HTTP only")

# Configuration Constants
last_sent_history_count = 0
REGISTRATION_FILE = "child_registration.json"
REGISTRATION_CHECK_INTERVAL = 30
CHILD_NAME = None
REAL_DNS_SERVER = "8.8.8.8"
LISTEN_IP = "0.0.0.0"
LISTEN_PORT = 53
BLOCK_PAGE_IP = "127.0.0.1"
PARENT_SERVER_IP = "192.168.1.111"
BLOCKED_DOMAINS = set()
ORIGINAL_DNS = None
BLOCK_SERVER_PORT = None
custom_http_server = None
browsing_history = []
history_lock = threading.Lock()
MAX_HISTORY_ENTRIES = 1000
REGISTRATION_PORT = 80  # Registration page port
BLOCK_PORT = 8080  # Block pages port
HTTPS_BLOCK_PORT = 8443
child_security_protection = None

# Domain visit tracking within time window
domain_visits = defaultdict(list)
domain_visits_lock = threading.Lock()
MAIN_SITE_WINDOW_SECONDS = 30

# Technical patterns for filtering non-essential domains
OBVIOUS_TECHNICAL_PATTERNS = [
    'analytics', 'tracking', 'ads', 'doubleclick', 'googletagmanager',
    'cdn', 'cache', 'static', 'assets', 'edge', 'akamai', 'cloudflare',
    'api', 'ws', 'websocket', 'ajax', 'xhr', 'heartbeat', 'status',
    'clarity.ms', 'mktoresp.com', 'optimizely.com', 'googlezip.net',
    'heyday', 'jquery.com', 'rss.app', 'gostreaming.tv',
]


def graceful_shutdown():
    """
    Performs graceful shutdown of all system components.
    Restores original DNS settings and closes network connections.
    """
    logger.info("Starting graceful shutdown...")
    try:
        stop_security_protection()
        logger.info("Closing network connections...")
        network_manager.cleanup_all()

        logger.info("Restoring original DNS settings...")
        if dns_manager.restore_original_dns():
            logger.info("DNS restored successfully")
        else:
            logger.error("Failed to restore DNS")
    except Exception as e:
        logger.error(f"Error during shutdown: {e}")


def emergency_dns_cleanup():
    """
    Emergency DNS cleanup function called at program exit.
    Attempts to restore DHCP DNS settings if normal cleanup fails.
    """
    logger.warning("Emergency DNS cleanup...")
    try:
        # Restore to DHCP
        subprocess.run(['netsh', 'interface', 'ip', 'set', 'dns', 'Wi-Fi', 'dhcp'],
                       capture_output=True, timeout=5)
        logger.info("DNS restored to DHCP")
    except Exception as e:
        logger.error(f"Emergency DNS cleanup failed: {e}")


atexit.register(emergency_dns_cleanup)


def verify_child_with_parent_callback(child_name):
    """
    Callback function for HTTP server to verify child with parent.
    Enhanced with security checks.
    """
    try:
        logger.info(f" Verifying child with security check: {child_name}")

        if child_security_protection:
            security_result = child_security_protection.comprehensive_security_check()

            if security_result["overall_risk"] in ["high", "critical"]:
                logger.critical(f" SECURITY RISK DETECTED during registration!")
                logger.critical(f"Threats: {security_result['threats_detected']}")
                return False

        success = verify_child_with_parent(child_name)
        if success:
            global CHILD_NAME
            CHILD_NAME = child_name
            save_registration(child_name)
            if custom_http_server and hasattr(custom_http_server, 'set_child_data'):
                custom_http_server.set_child_data(child_name)
            child_client.child_name = CHILD_NAME

            start_security_protection()

            logger.info(f" Child verification successful: {child_name}")
        return success
    except Exception as e:
        logger.error(f"Error in child verification: {e}")
        return False


def start_security_protection():
    """Start security protection for the child device"""
    global child_security_protection

    try:
        if not child_security_protection:
            logger.info(" Starting child security protection...")

            child_security_protection = ChildVPNDNSProtection(
                report_callback=report_security_to_parent
            )
            child_security_protection.start_monitoring(check_interval=30)

            logger.info(" Child security protection started successfully")
    except Exception as e:
        logger.error(f"Failed to start security protection: {e}")


def stop_security_protection():
    """Stop security protection"""
    global child_security_protection

    if child_security_protection and hasattr(child_security_protection, 'stop_monitoring'):
        try:
            child_security_protection.stop_monitoring()
            logger.info(" Security protection stopped")
        except Exception as e:
            logger.error(f"Error stopping security protection: {e}")
        finally:
            child_security_protection = None


def report_security_to_parent(alert_type, security_data):
    """Report security issues to parent server"""
    try:
        message_data = {
            "alert_type": alert_type,
            "security_data": security_data,
            "child_name": CHILD_NAME,
            "timestamp": time.time(),
            "device_info": {
                "platform": platform.system(),
                "hostname": socket.gethostname()
            }
        }

        if child_client.connected and child_client._main_socket:
            Protocol.send_message(
                child_client._main_socket,
                "SECURITY_ALERT",
                message_data
            )
            logger.critical(f"Security alert sent to parent: {alert_type}")
        else:
            logger.error("No parent connection - security alert not sent")

    except Exception as e:
        logger.error(f"Failed to report security to parent: {e}")


class NetworkManager:
    """
    Efficient socket management class - prevents socket leaks.
    Manages DNS query sockets, parent server communication, and connection pooling.
    """

    def __init__(self):
        # Fixed socket for DNS queries
        self._dns_query_socket = None
        self._dns_socket_lock = threading.Lock()

        # Socket pool for parent server communication
        self._parent_socket_pool = []
        self._pool_lock = threading.Lock()
        self._max_pool_size = 5

        # Fixed socket for long-term communication
        self._persistent_parent_socket = None
        self._persistent_socket_lock = threading.Lock()

        logger.info("NetworkManager initialized")

    def get_dns_query_socket(self):
        """
        Returns UDP socket for DNS queries - creates only once.

        Returns:
            socket.socket: UDP socket for DNS queries
        """
        with self._dns_socket_lock:
            if self._dns_query_socket is None:
                self._dns_query_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                self._dns_query_socket.settimeout(5)
                logger.debug("Created fixed DNS socket")
            return self._dns_query_socket

    @contextmanager
    def get_parent_socket_from_pool(self):
        """
        Context manager for temporary socket to parent server - improved version.
        Always creates new socket for simplicity and safety.

        Yields:
            socket.socket: TCP socket for parent server communication
        """
        sock = None
        try:
            # Always create new socket - simpler and safer
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            logger.debug("Created new socket (not pooled)")

            yield sock

        except Exception as e:
            logger.error(f"Socket error: {e}")
            raise
        finally:
            # Always close socket - no pooling!
            if sock:
                try:
                    sock.close()
                    logger.debug("Socket closed")
                except:
                    pass

    def get_persistent_parent_socket(self):
        """
        Fixed socket for long-term communication with parent server.

        Returns:
            socket.socket: Persistent TCP socket for parent communication
        """
        with self._persistent_socket_lock:
            if self._persistent_parent_socket is None:
                self._persistent_parent_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                logger.debug("Created persistent socket for parent server")
            return self._persistent_parent_socket

    def close_persistent_socket(self):
        """Closes the persistent socket"""
        with self._persistent_socket_lock:
            if self._persistent_parent_socket:
                try:
                    self._persistent_parent_socket.shutdown(socket.SHUT_RDWR)
                    self._persistent_parent_socket.close()
                    logger.debug("Closed persistent socket")
                except:
                    pass
                self._persistent_parent_socket = None

    def cleanup_all(self):
        """
        Cleanup all sockets - called at program end.
        Properly closes all network resources.
        """
        logger.info("Cleaning up all sockets...")

        # Close DNS socket
        with self._dns_socket_lock:
            if self._dns_query_socket:
                try:
                    self._dns_query_socket.close()
                    logger.debug("DNS socket closed")
                except:
                    pass
                self._dns_query_socket = None

        # Close pool
        with self._pool_lock:
            for sock in self._parent_socket_pool:
                try:
                    sock.close()
                except:
                    pass
            cleared_count = len(self._parent_socket_pool)
            self._parent_socket_pool.clear()
            logger.debug(f"Pool cleared ({cleared_count} sockets)")

        # Close persistent socket
        self.close_persistent_socket()

        logger.info("All sockets cleaned up")


# Global network manager instance
network_manager = NetworkManager()


def load_registration():
    """
    Load child registration data from file.

    Returns:
        tuple: (child_name, is_registered) or (None, False) if not found
    """
    try:
        with open(REGISTRATION_FILE, 'r', encoding='utf-8') as f:
            data = json.load(f)
            child_name = data.get('child_name')
            is_registered = data.get('is_registered', False)
            logger.info(f"Loaded registration: {child_name}, registered: {is_registered}")
            return child_name, is_registered
    except FileNotFoundError:
        logger.debug("Registration file not found")
        return None, False
    except Exception as e:
        logger.error(f"Error loading registration: {e}")
        return None, False


def save_registration(child_name, is_registered=True):
    """
    Save child registration data to file.

    Args:
        child_name (str): Name of the child
        is_registered (bool): Registration status

    Returns:
        bool: True if saved successfully, False otherwise
    """
    try:
        data = {
            'child_name': child_name,
            'is_registered': is_registered,
            'registration_time': datetime.now().isoformat()
        }
        with open(REGISTRATION_FILE, 'w', encoding='utf-8') as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        logger.info(f"Registration saved: {child_name}")
        return True
    except Exception as e:
        logger.error(f"Error saving registration: {e}")
        return False


def check_child_registration():
    """
    Check if child is already registered and verify with parent server.

    Returns:
        bool: True if child is registered and verified, False otherwise
    """
    global CHILD_NAME
    saved_name, is_registered = load_registration()

    if saved_name and is_registered:
        logger.info("Running security check before registration verification...")
        temp_protection = ChildVPNDNSProtection()
        security_result = temp_protection.comprehensive_security_check()

        if security_result["overall_risk"] in ["high", "critical"]:
            logger.critical(f" SECURITY RISK detected during startup!")
            logger.critical(f"Threats: {security_result['threats_detected']}")
            return False

        if verify_child_with_parent(saved_name):
            CHILD_NAME = saved_name
            start_security_protection()
            logger.info(f" Registered child found: {CHILD_NAME}")
            return True
        if verify_child_with_parent(saved_name):
            CHILD_NAME = saved_name
            logger.info(f"Registered child found: {CHILD_NAME}")
            return True
        else:
            logger.warning(f"Registration for '{saved_name}' is no longer valid")
            try:
                os.remove(REGISTRATION_FILE)
                logger.info("Removed invalid registration file")
            except:
                pass
    return False


def verify_child_with_parent(child_name):
    """
    Enhanced version using NetworkManager to verify child with parent server.

    Args:
        child_name (str): Name of child to verify

    Returns:
        bool: True if child is verified by parent, False otherwise
    """
    try:
        logger.debug(f"Attempting to verify child: {child_name}")

        with network_manager.get_parent_socket_from_pool() as sock:
            sock.connect((PARENT_SERVER_IP, COMMUNICATION_PORT))

            verify_data = {"child_name": child_name}
            Protocol.send_message(sock, Protocol.VERIFY_CHILD, verify_data)

            msg_type, data = Protocol.receive_message(sock)
            is_valid = data.get("is_valid", False)

            logger.debug(f"Child verification completed: {is_valid}")
            return is_valid

    except Exception as e:
        logger.error(f"Error in child verification: {e}")
        return False


def wait_for_registration():
    """
    Wait for child registration through web interface.
    Opens browser for registration and waits for completion.

    Returns:
        bool: True if registration completed successfully, False if timeout
    """
    logger.info("Preparing registration page...")
    logger.info("Waiting for server to be ready...")

    time.sleep(3)  # Additional time for HTTPS server

    # Check server readiness
    max_attempts = 15
    servers_ready = []

    for i in range(max_attempts):
        # Check HTTP server on port 80
        try:
            test_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            test_sock.settimeout(0.5)
            result = test_sock.connect_ex(('127.0.0.1', 80))
            test_sock.close()
            if result == 0 and "HTTP:80" not in servers_ready:
                servers_ready.append("HTTP:80")
        except:
            pass

        if servers_ready:
            logger.info(f"Servers ready: {', '.join(servers_ready)}")
            break

        logger.info(f"Waiting for servers... ({i + 1}/{max_attempts})")
        time.sleep(0.5)

    # Open browser
    try:
        if servers_ready:
            if "HTTP:80" in servers_ready:
                registration_url = "http://127.0.0.1"
            else:
                registration_url = "http://127.0.0.1"
                logger.info("Opening browser with HTTP")

            logger.info(f"URL: {registration_url}")
            webbrowser.open(registration_url)
            logger.info("Please enter your name in the form that appears in the browser")
        else:
            logger.error("No server could start")
            return False
    except Exception as e:
        logger.error(f"Error opening browser: {e}")

    # Wait for registration
    max_wait = 300
    waited = 0

    while not CHILD_NAME and waited < max_wait:
        time.sleep(5)
        waited += 5

        if waited % 30 == 0:
            logger.info(f"Waiting for registration... ({waited}/{max_wait} seconds)")
            if servers_ready:
                for server in servers_ready:
                    logger.info(f"Try accessing: http://127.0.0.1")

    if CHILD_NAME:
        logger.info("Registration completed through browser!")
        logger.info(f"Name: {CHILD_NAME}")
        return True
    else:
        logger.error("Registration timeout")
        return False


def periodic_registration_check():
    """
    Periodic check to ensure child is still registered and connected.
    Runs in background thread to monitor connection status.
    """
    global CHILD_NAME
    while True:
        try:
            time.sleep(REGISTRATION_CHECK_INTERVAL)
            if CHILD_NAME:
                if not child_client.connected:
                    logger.warning(f"Child '{CHILD_NAME}' is no longer connected!")
                    CHILD_NAME = None
                    block_all_internet()
        except Exception as e:
            logger.error(f"Error in periodic check: {e}")


def block_all_internet():
    """
    Block all internet access by adding common domains to blocked list.
    Used when child is not registered.
    """
    global BLOCKED_DOMAINS
    common_domains = {
        "google.com", "youtube.com", "facebook.com", "instagram.com",
        "twitter.com", "tiktok.com", "netflix.com", "amazon.com",
        "microsoft.com", "apple.com", "yahoo.com", "bing.com"
    }
    BLOCKED_DOMAINS.update(common_domains)
    logger.warning("Internet blocked - child not registered!")


def extract_main_site_name(domain):
    """
    Extract the main site name from any domain.
    Handles subdomains, technical prefixes, and international TLDs.

    Args:
        domain (str): Domain name to process

    Returns:
        str: Main domain name without technical subdomains
    """
    if not domain:
        return domain

    # Clean the domain
    domain = domain.lower().strip()

    # Remove protocol if present
    if '://' in domain:
        domain = urlparse(domain).netloc or domain

    # Remove port
    if ':' in domain:
        domain = domain.split(':')[0]

    # Remove common technical subdomains
    technical_subdomains = [
        'www', 'www2', 'www3', 'm', 'mobile', 'api', 'cdn', 'static',
        'assets', 'img', 'images', 'css', 'js', 'analytics', 'tracking',
        'ads', 'ad', 'media', 'content', 'secure', 'ssl', 'login',
        'auth', 'oauth', 'sso', 'mail', 'email', 'smtp', 'pop', 'imap'
    ]

    parts = domain.split('.')

    # If only 2 parts (name.com) - this is the main domain
    if len(parts) <= 2:
        return domain

    # Remove technical subdomains
    while len(parts) > 2 and parts[0] in technical_subdomains:
        parts = parts[1:]

    # Handle Israeli and international domains
    common_tlds = [
        'co.il', 'ac.il', 'gov.il', 'org.il', 'net.il',
        'com.au', 'co.uk', 'co.za', 'com.br'
    ]

    # Check for compound TLD
    if len(parts) >= 3:
        last_two = '.'.join(parts[-2:])
        if last_two in common_tlds:
            # Compound TLD - keep last 3 parts
            if len(parts) >= 3:
                return '.'.join(parts[-3:])

    # Normal case - keep last 2 parts
    return '.'.join(parts[-2:])


def get_site_display_name(domain):
    """
    Get a user-friendly display name for a website.
    Handles special cases and formatting for better readability.

    Args:
        domain (str): Domain name to process

    Returns:
        str: User-friendly site name
    """
    # Check Israeli mapping first
    if 'ebag.cet.ac.il' in domain:
        return 'Elementary Horizon'
    elif 'cet.ac.il' in domain and 'ebag' not in domain:
        return 'CET Education'
    elif 'ynet.co.il' in domain:
        return 'Ynet'
    elif 'walla.co.il' in domain:
        return 'Walla'
    elif 'mako.co.il' in domain:
        return 'Mako'

    main_domain = extract_main_site_name(domain)

    if not main_domain:
        return domain

    # Extract name only (without extension)
    parts = main_domain.split('.')
    if len(parts) >= 2:
        site_name = parts[0]  # First part

        # Improve display
        site_name = site_name.replace('-', ' ').replace('_', ' ')

        # Capitalization
        if len(site_name) <= 3:
            # Short sites - all caps
            site_name = site_name.upper()
        else:
            # Long sites - only first letter caps
            site_name = site_name.capitalize()

        return site_name

    return main_domain


def is_obviously_technical(domain):
    """
    Check if domain is technical/advertising and not interesting to parents.

    Args:
        domain (str): Domain to check

    Returns:
        bool: True if domain is obviously technical, False otherwise
    """
    domain_lower = domain.lower()

    # Clear technical patterns
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

    # Too many subdomains (sign of technical)
    parts = domain_lower.split('.')
    if len(parts) > 4:  # Too many subdomains
        return True

    # Check domains too short or too long
    main_part = parts[0] if parts else ''
    if len(main_part) < 2 or len(main_part) > 20:
        return True

    # Domains that are only numbers or strange characters
    if re.match(r'^[0-9\-_]+$', main_part):
        return True

    return False


def add_to_history(domain, timestamp, was_blocked=False):
    """
    Add entry to browsing history - simple and without over-filtering.

    Args:
        domain (str): Domain that was accessed
        timestamp (str): ISO format timestamp
        was_blocked (bool): Whether the domain was blocked
    """
    # Skip only obviously technical domains
    if is_obviously_technical(domain):
        return

    if any(word in domain.lower() for word in ['beacon', 'analytics', 'tracking', 'telemetry']):
        return

    # Extract site name
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

        logger.debug(f"Added to history: {display_name} ({main_domain}) ({'blocked' if was_blocked else 'allowed'})")


def send_history_update():
    """Send browsing history update to parent server."""
    global last_sent_history_count

    if hasattr(child_client, 'connected') and child_client.connected and browsing_history:
        try:
            with history_lock:
                # שלח רק רשומות חדשות!
                if not hasattr(send_history_update, 'last_sent_count'):
                    send_history_update.last_sent_count = 0

                # רק הרשומות החדשות
                new_history = browsing_history[send_history_update.last_sent_count:]

                if new_history:  # רק אם יש רשומות חדשות
                    data = {"child_name": CHILD_NAME, "history": new_history}
                    Protocol.send_message(child_client.sock, Protocol.BROWSING_HISTORY, data)  #type:ignore
                    logger.info(f"History update sent to server: {len(new_history)} NEW entries")

                    # עדכן מונה
                    send_history_update.last_sent_count = len(browsing_history)
                else:
                    logger.debug("No new history to send")

        except Exception as e:
            logger.error(f"Error sending history: {e}")
    else:
        logger.debug("Cannot send history - not connected or no history")


def clear_dns_cache():
    """
    Clear Windows DNS cache to ensure fresh lookups.
    """
    logger.info("Clearing DNS cache...")
    try:
        result = subprocess.run(['ipconfig', '/flushdns'], capture_output=True, text=True, encoding='utf-8')
        if result.returncode == 0:
            logger.info("Windows DNS cache cleared")
        else:
            logger.warning(f"Issue clearing cache: {result.stderr}")
    except Exception as e:
        logger.error(f"Error clearing cache: {e}")


def start_block_server():
    """
    Start custom HTTP/HTTPS server for block pages and registration.

    Returns:
        int or None: Port number if server started successfully, None otherwise
    """
    global BLOCK_SERVER_PORT, custom_http_server

    logger.info("Starting custom HTTP/HTTPS server...")

    # Early SSL certificate check
    if HTTPS_AVAILABLE:
        logger.info("Checking SSL certificates...")
        check_ssl_certificates()

    servers_started = []

    # Try starting HTTPS on port 443
    if HTTPS_AVAILABLE and HTTPSBlockServer is not None:
        try:
            logger.info("Trying to start HTTPS server on port 443...")

            https_server = HTTPSBlockServer("127.0.0.1", 443, 8080)

            # Set templates
            https_server.set_templates(REGISTRATION_HTML_TEMPLATE, BLOCK_HTML_TEMPLATE)
            https_server.set_verify_callback(verify_child_with_parent_callback)
            https_server.set_external_functions(create_error_page, create_success_page)

            # Start server in separate thread
            https_thread = threading.Thread(target=https_server.start_server, daemon=True)
            https_thread.start()

            time.sleep(3)  # Additional time for HTTPS server to stabilize

            # Save HTTPS server as primary
            custom_http_server = https_server
            BLOCK_SERVER_PORT = 443
            servers_started.append("HTTPS:443")
            logger.info("HTTPS server running on port 443")

        except Exception as e:
            logger.error(f"Error starting HTTPS on port 443: {e}")
            if "Permission denied" in str(e) or "WinError 10013" in str(e):
                logger.warning("Administrator privileges required for port 443")
                logger.info("Run the program as Administrator")

    # Start HTTP on port 80
    try:
        logger.info("Trying to start HTTP server on port 80...")

        http_server = ParentalControlHTTPServer("127.0.0.1", 80)

        # Set templates
        http_server.set_templates(REGISTRATION_HTML_TEMPLATE, BLOCK_HTML_TEMPLATE)
        http_server.set_verify_callback(verify_child_with_parent_callback)
        http_server.set_external_functions(create_error_page, create_success_page)

        # Start server in separate thread
        http_thread = threading.Thread(target=http_server.start_server, daemon=True)
        http_thread.start()

        time.sleep(1)

        # If HTTPS didn't work, HTTP will be primary
        if not custom_http_server:
            custom_http_server = http_server
            BLOCK_SERVER_PORT = 80

        servers_started.append("HTTP:80")
        logger.info("HTTP server running on port 80")

    except Exception as e:
        logger.error(f"Error starting HTTP on port 80: {e}")
        if "Permission denied" in str(e) or "WinError 10013" in str(e):
            logger.warning("Administrator privileges required for port 80")

    # Check that at least one server is working
    if servers_started:
        logger.info(f"Block servers active: {', '.join(servers_started)}")

        # Important messages for user
        if "HTTPS:443" in servers_started:
            logger.info("Blocked HTTPS sites (Instagram, Facebook, etc.) will be handled by HTTPS server")
            logger.info("First time browser will ask for certificate approval - please approve!")
        if "HTTP:80" in servers_started:
            logger.info("Blocked HTTP sites will be handled by regular HTTP server")

        return BLOCK_SERVER_PORT or 80
    else:
        logger.error("Failed to start all servers")
        logger.info("Check that the program runs as Administrator")
        BLOCK_SERVER_PORT = None
        return None


class DNSManager:
    """
    DNS configuration manager for Windows systems.
    Handles setting up DNS redirection and restoring original settings.
    """

    def __init__(self):
        self.system = platform.system()
        self.original_dns = None
        self.interface_name = None
        logger.info("DNSManager initialized")

    def is_admin(self):
        """
        Check if running with administrator privileges.

        Returns:
            bool: True if running as admin, False otherwise
        """
        try:
            if self.system == "Windows":
                return ctypes.windll.shell32.IsUserAnAdmin()
            else:
                return os.geteuid() == 0
        except:
            return False

    def get_current_dns(self, interface_name):
        """
        Save current DNS settings.

        Args:
            interface_name (str): Network interface name

        Returns:
            list: Current DNS servers or empty list
        """
        try:
            cmd = ['powershell', '-Command',
                   f'Get-DnsClientServerAddress -InterfaceAlias "{interface_name}" | Select-Object -ExpandProperty ServerAddresses']
            result = subprocess.run(cmd, capture_output=True, text=True, encoding='utf-8')
            if result.returncode == 0 and result.stdout.strip():
                dns_servers = [line.strip() for line in result.stdout.strip().split('\n') if line.strip()]
                logger.info(f"Current DNS: {dns_servers}")
                return dns_servers
            else:
                logger.info("No specific DNS configured (automatic)")
                return []
        except Exception as e:
            logger.error(f"Error reading current DNS: {e}")
            return []

    def get_active_interface(self):
        """
        Find active network interface.

        Returns:
            str or None: Name of active network interface
        """
        try:
            cmd = ['powershell', '-Command',
                   'Get-NetAdapter | Where-Object {$_.Status -eq "Up"} | Select-Object -First 1 -ExpandProperty Name']
            result = subprocess.run(cmd, capture_output=True, text=True, encoding='utf-8')
            if result.returncode == 0 and result.stdout.strip():
                interface_name = result.stdout.strip()
                logger.info(f"Found interface: {interface_name}")
                return interface_name
        except Exception as e:
            logger.error(f"Error finding interface: {e}")

        # Backup - try common names
        common_names = ['Wi-Fi', 'Ethernet', 'Local Area Connection']
        for name in common_names:
            try:
                result = subprocess.run(['netsh', 'interface', 'ip', 'show', 'config', f'name={name}'],
                                        capture_output=True, text=True, encoding='utf-8')
                if result.returncode == 0:
                    logger.info(f"Found interface: {name}")
                    return name
            except:
                continue
        return None

    def set_dns_windows(self, interface_name, dns_server):
        """
        Set DNS server on Windows interface.

        Args:
            interface_name (str): Network interface name
            dns_server (str): DNS server IP address

        Returns:
            bool: True if DNS set successfully, False otherwise
        """
        try:
            logger.info(f"Trying to set DNS to {dns_server} on interface '{interface_name}'")

            cmd = ['powershell', '-Command',
                   f'Set-DnsClientServerAddress -InterfaceAlias "{interface_name}" -ServerAddresses "{dns_server}"']
            result = subprocess.run(cmd, capture_output=True, text=True, encoding='utf-8')

            if result.returncode == 0:
                logger.info(f"DNS set successfully to {dns_server}")
                return True
            else:
                logger.error(f"PowerShell error: {result.stderr}")
                return False
        except Exception as e:
            logger.error(f"Error setting DNS: {e}")
            return False

    def setup_dns_redirect(self):
        """
        Setup DNS redirection to local machine.

        Returns:
            bool: True if DNS redirect setup successfully, False otherwise
        """
        if not self.is_admin():
            logger.error("Administrator privileges required to change DNS settings")
            logger.error("Please run the program as Administrator")
            return False

        if self.system == "Windows":
            interface_name = self.get_active_interface()
            if interface_name:
                self.interface_name = interface_name

                # Important! Save current DNS settings before changing
                current_dns = self.get_current_dns(interface_name)
                self.original_dns = current_dns

                logger.info(f"Saving original DNS: {current_dns}")

                if self.set_dns_windows(interface_name, "127.0.0.1"):
                    logger.info("DNS successfully set to local machine")
                    return True
            else:
                logger.error("No active network interface found")
        else:
            logger.error("Operating system not currently supported (Windows only)")
        return False

    def restore_original_dns(self):
        """
        Restore original DNS settings.

        Returns:
            bool: True if DNS restored successfully, False otherwise
        """
        if not self.interface_name:
            logger.error("No network interface information")
            return False

        if self.system == "Windows":
            try:
                if self.original_dns and len(self.original_dns) > 0:
                    # Restore specific DNS that existed
                    dns_list = ','.join(f'"{dns}"' for dns in self.original_dns)
                    cmd = ['powershell', '-Command',
                           f'Set-DnsClientServerAddress -InterfaceAlias "{self.interface_name}" -ServerAddresses {dns_list}']
                    logger.info(f"Restoring DNS to: {self.original_dns}")
                else:
                    # Restore to automatic settings
                    cmd = ['powershell', '-Command',
                           f'Set-DnsClientServerAddress -InterfaceAlias "{self.interface_name}" -ResetServerAddresses']
                    logger.info("Restoring DNS to automatic settings")

                result = subprocess.run(cmd, capture_output=True, text=True, encoding='utf-8')
                if result.returncode == 0:
                    logger.info(f"DNS successfully restored on interface {self.interface_name}")

                    # Clear DNS cache
                    clear_dns_cache()
                    return True
                else:
                    logger.error(f"Error restoring DNS: {result.stderr}")
                    return False
            except Exception as e:
                logger.error(f"Error restoring DNS: {e}")
                return False
        return False


def clear_dns_cache_when_updated():
    """
    Clear DNS cache when blocked list is updated.
    """
    try:
        logger.info("Clearing DNS cache after update...")
        result = subprocess.run(['ipconfig', '/flushdns'],
                                capture_output=True, text=True, encoding='utf-8')
        if result.returncode == 0:
            logger.info("DNS cache cleared")
        else:
            logger.warning(f"Issue clearing cache: {result.stderr}")
    except Exception as e:
        logger.error(f"Error clearing cache: {e}")



class ChildClient:
    """
    Client for communication with parent server.
    Handles registration, domain updates, and status reporting.
    """

    def __init__(self):
        self.child_name = CHILD_NAME
        self.connected = False
        self.keep_running = True
        self.connection_event = threading.Event()
        self._main_socket = None
        logger.info("ChildClient initialized")

    @property
    def sock(self):
        """
        Get the main communication socket.

        Returns:
            socket.socket: Main socket for parent communication
        """
        return self._main_socket

    def connect_to_parent(self):
        """
        Connect to parent server with retry logic.
        Attempts multiple connections before giving up.
        """
        retry_count = 0
        max_retries = 5

        while self.keep_running and retry_count < max_retries:
            try:
                logger.info(f"Attempting to connect to parent server (attempt {retry_count + 1}/{max_retries})...")

                self._main_socket = network_manager.get_persistent_parent_socket()
                self._main_socket.settimeout(3)
                self._main_socket.connect((PARENT_SERVER_IP, COMMUNICATION_PORT))

                register_data = {"name": self.child_name}
                Protocol.send_message(self._main_socket, Protocol.REGISTER_CHILD, register_data) #type:ignore

                self._main_socket.settimeout(5)
                msg_type, _ = Protocol.receive_message(self._main_socket) #type:ignore

                if msg_type == Protocol.ACK:
                    self.connected = True
                    self.connection_event.set()
                    logger.info(f"Connected to parent server as {self.child_name}")
                    self.request_domains_update()
                    time.sleep(1)
                    self.listen_for_updates()
                    return

            except socket.timeout:
                logger.warning("Timeout connecting to parent server")
                retry_count += 1
            except Exception as e:
                logger.error(f"Connection error: {e}")
                retry_count += 1

            self.connected = False
            network_manager.close_persistent_socket()

            if retry_count < max_retries:
                logger.info(f"Waiting {2} seconds before retry...")
                time.sleep(2)

        logger.error(f"Failed to connect to parent server after {max_retries} attempts")
        self.connection_event.set()

    def request_domains_update(self):
        """
        Request domain update from parent server.
        """
        if self.connected and self._main_socket:
            try:
                Protocol.send_message(self._main_socket, Protocol.GET_DOMAINS)
                logger.info("Domain update request sent")
            except Exception as e:
                logger.error(f"Error requesting domain update: {e}")
                self.connected = False

    def wait_for_connection(self, timeout=10):
        """
        Wait for connection to parent server.

        Args:
            timeout (int): Maximum seconds to wait

        Returns:
            bool: True if connected successfully, False if timeout/failed
        """
        logger.info(f"Waiting for parent server connection (up to {timeout} seconds)...")
        if self.connection_event.wait(timeout):
            if self.connected:
                logger.info("Parent server connection completed successfully")
                return True
            else:
                logger.warning("Connection failed, continuing in standalone mode")
                return False
        else:
            logger.warning("Timeout connecting to parent server")
            return False

    def send_status_update(self):
        """
        Send periodic status updates to parent server.
        Runs in background thread.
        """
        while self.keep_running:
            if self.connected and self._main_socket:
                try:
                    Protocol.send_message(self._main_socket, Protocol.CHILD_STATUS)
                    send_history_update()
                except:
                    self.connected = False
            time.sleep(3)

    def listen_for_updates(self):
        """Listen for updates from parent server."""
        logger.info("Started listening for server updates...")
        while self.connected and self.keep_running:
            try:
                self._main_socket.settimeout(30)
                msg_type, data = Protocol.receive_message(self._main_socket)

                if msg_type == Protocol.UPDATE_DOMAINS:
                    domains = data.get('domains', [])
                    logger.info(f" RECEIVED DOMAIN UPDATE: {domains}")

                    global BLOCKED_DOMAINS
                    old_domains = BLOCKED_DOMAINS.copy()
                    BLOCKED_DOMAINS = set(domains)

                    logger.info(f" OLD DOMAINS: {old_domains}")
                    logger.info(f" NEW DOMAINS: {BLOCKED_DOMAINS}")

                    # If list changed - clear cache
                    if old_domains != BLOCKED_DOMAINS:
                        logger.info(" DOMAINS CHANGED - CLEARING DNS CACHE")
                        clear_dns_cache_when_updated()
                    else:
                        logger.info(" DOMAINS UNCHANGED - NO CACHE CLEAR")

                elif msg_type == Protocol.CHILD_STATUS:
                    Protocol.send_message(self._main_socket, Protocol.ACK)

                elif msg_type == Protocol.GET_HISTORY:
                    send_history_update()

                elif msg_type == "SECURITY_CHECK_REQUEST":
                    logger.info("🔒 Security check requested by parent")
                    try:
                        if child_security_protection:
                            # Use available methods
                            vpn_result = child_security_protection.detect_vpn_processes()
                            dns_result = child_security_protection.monitor_dns_configuration()

                            security_result = {
                                "overall_risk": "low",
                                "threats_detected": [],
                                "vpn_check": vpn_result,
                                "dns_check": dns_result,
                                "timestamp": time.time()
                            }

                            # Determine overall risk
                            threats = []
                            if vpn_result.get("vpn_processes_found", False):
                                threats.append("VPN processes detected")
                                security_result["overall_risk"] = "high"

                            if dns_result.get("forbidden_dns_found", False):
                                threats.append("Forbidden DNS detected")
                                security_result["overall_risk"] = "high"

                            if dns_result.get("dns_modified", False):
                                threats.append("DNS configuration modified")
                                if security_result["overall_risk"] == "low":
                                    security_result["overall_risk"] = "medium"

                            security_result["threats_detected"] = threats
                        else:
                            security_result = {"overall_risk": "unknown", "threats_detected": []}

                        logger.info(f"🔒 Security check result: {security_result}")
                    except Exception as e:
                        logger.error(f"Security check failed: {e}")
                        security_result = {"overall_risk": "error", "threats_detected": [str(e)]}

                    Protocol.send_message(self._main_socket, "SECURITY_CHECK_RESPONSE", security_result)

                elif msg_type == "FORCE_SECURITY_ACTION":
                    action = data.get("action")
                    logger.critical(f"🔒 Forced security action: {action}")

                    result = False
                    try:
                        if child_security_protection:
                            if action == "kill_vpn":
                                if hasattr(child_security_protection, 'kill_vpn_processes'):
                                    result = child_security_protection.kill_vpn_processes()
                                    logger.info(f"🔒 Forced VPN kill result: {result}")
                                else:
                                    logger.warning("VPN kill function not available")

                            elif action == "restore_dns":
                                if hasattr(child_security_protection, 'attempt_dns_restoration'):
                                    result = child_security_protection.attempt_dns_restoration()
                                    logger.info(f"🔒 Forced DNS restore result: {result}")
                                else:
                                    logger.warning("DNS restore function not available")
                                    # Try manual DNS restore
                                    try:
                                        dns_manager.restore_original_dns()
                                        result = True
                                        logger.info("🔒 Manual DNS restore successful")
                                    except Exception as dns_error:
                                        logger.error(f"Manual DNS restore failed: {dns_error}")
                                        result = False
                            else:
                                logger.warning(f"Unknown security action: {action}")
                        else:
                            logger.warning("No security protection available")

                    except Exception as e:
                        logger.error(f"Error executing security action: {e}")
                        result = False

                    # Send response back to parent
                    try:
                        Protocol.send_message(self._main_socket, "SECURITY_ACTION_RESULT", {
                            "action": action,
                            "success": result,
                            "timestamp": time.time()
                        })
                    except Exception as e:
                        logger.error(f"Failed to send security action result: {e}")

                elif msg_type == Protocol.ERROR:
                    logger.error(f"Server error: {data}")
                    self.connected = False
                    break

            except socket.timeout:
                continue
            except Exception as e:
                logger.error(f"Error receiving update: {e}")
                self.connected = False
                break

        logger.info("Stopped listening to parent server")


child_client = ChildClient()
dns_manager = DNSManager()


def is_blocked_domain(query_name):
    """Check if a domain should be blocked."""
    # If child not registered - block everything!
    if not CHILD_NAME:
        logger.debug(f"Child not registered - blocking all: {query_name}")
        return True

    vpn_domains = [
        'nordvpn.com', 'expressvpn.com', 'surfshark.com', 'cyberghost.com',
        'protonvpn.com', 'tunnelbear.com', 'hotspotshield.com', 'windscribe.com'
    ]

    query_lower = query_name.lower()
    for vpn_domain in vpn_domains:
        if vpn_domain in query_lower:
            logger.warning(f" VPN domain blocked: {query_name}")
            return True

    # Clean domain
    original_query = query_name
    query_name = query_name.lower().strip('.')

    logger.info(f" CHECKING: '{original_query}' -> '{query_name}'")
    logger.info(f" BLOCKED LIST: {BLOCKED_DOMAINS}")

    # Extract main domain parts
    main_domain_parts = query_name.split('.')

    for blocked_domain in BLOCKED_DOMAINS:
        blocked_domain = blocked_domain.lower().strip('.')
        blocked_parts = blocked_domain.split('.')

        logger.info(f" COMPARING {query_name} with {blocked_domain}")

        # 1. Exact match
        if query_name == blocked_domain:
            logger.info(f" EXACT MATCH BLOCKED: {query_name}")
            return True

        # 2. Regular subdomain
        if query_name.endswith('.' + blocked_domain):
            logger.info(f" SUBDOMAIN BLOCKED: {query_name}")
            return True

        # 3. Handle www
        if query_name == 'www.' + blocked_domain:
            logger.info(f" WWW BLOCKED: {query_name}")
            return True

        # 4. Block by site name
        if len(blocked_parts) >= 2 and len(main_domain_parts) >= 2:
            if (blocked_parts[0] == main_domain_parts[0] and len(blocked_parts[0]) > 3):
                logger.info(f" SITE NAME BLOCKED: {main_domain_parts[0]}")
                return True

        # 5. Related domains
        blocked_name = blocked_parts[0]
        if blocked_name in query_name and len(blocked_name) > 4:
            logger.info(f" RELATED DOMAIN BLOCKED: {query_name} contains {blocked_name}")
            return True

    logger.info(f" ALLOWED: {query_name}")
    return False


def handle_dns_request(data, addr, sock):
    """
    Handle incoming DNS request.

    Args:
        data (bytes): Raw DNS request data
        addr (tuple): Client address (IP, port)
        sock (socket.socket): DNS server socket
    """
    try:
        packet_response = DNS(data)
    except Exception as e:
        logger.error(f"Error parsing DNS request: {e}")
        return

    if packet_response.opcode == 0 and packet_response.qr == 0:
        try:
            query_name = packet_response[DNSQR].qname.decode().strip(".")
        except Exception as e:
            logger.error(f"Error reading domain name: {e}")
            return

        logger.info(f"DNS request from {addr[0]} to: {query_name}")
        current_time = datetime.now().isoformat()

        if is_blocked_domain(query_name):
            logger.info(f"Blocking {query_name}, redirecting to {BLOCK_PAGE_IP}")
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
            logger.info(f"Forwarding request to real DNS ({REAL_DNS_SERVER})")
            add_to_history(query_name, current_time, was_blocked=False)

            try:
                dns_sock = network_manager.get_dns_query_socket()
                dns_sock.sendto(data, (REAL_DNS_SERVER, 53))
                response_data, _ = dns_sock.recvfrom(4096)

                try:
                    response_dns = DNS(response_data)
                    # Set low TTL for regular responses too!
                    for answer in response_dns.an:
                        answer.ttl = 0  # So browser won't remember the response
                    sock.sendto(bytes(response_dns), addr)
                except:
                    sock.sendto(response_data, addr)

            except socket.timeout:
                error_response = DNS(id=packet_response.id, qr=1, aa=1, rcode=2, qd=packet_response.qd)
                sock.sendto(bytes(error_response), addr)
            except Exception as e:
                logger.error(f"Error forwarding request to real DNS: {e}")
                error_response = DNS(id=packet_response.id, qr=1, aa=1, rcode=2, qd=packet_response.qd)
                sock.sendto(bytes(error_response), addr)


def start_dns_proxy():
    """
    Start DNS proxy server.
    Main function that handles DNS interception and filtering.
    """
    logger.info(f"Starting DNS Proxy for {CHILD_NAME} on {LISTEN_IP}:{LISTEN_PORT}...")
    logger.info(f"Blocked domains: {', '.join(BLOCKED_DOMAINS) if BLOCKED_DOMAINS else 'waiting for server update'}")
    logger.info(f"Block page will be shown from address: {BLOCK_PAGE_IP}")

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind((LISTEN_IP, LISTEN_PORT))
    except PermissionError:
        logger.error("Permission error: Cannot listen on port 53. Try running the program as administrator.")
        return
    except socket.error as e:
        logger.error(f"Socket error: {e}")
        return

    logger.info("DNS Proxy running. Press Ctrl+C to stop.")

    try:
        while True:
            try:
                data, addr = sock.recvfrom(512)
                threading.Thread(target=handle_dns_request, args=(data, addr, sock), daemon=True).start()
            except Exception as e:
                logger.error(f"Error handling request: {e}")
                # Continue instead of crashing!
                continue
    except KeyboardInterrupt:
        logger.info("Server stopped by user.")
        graceful_shutdown()
    except Exception as e:  # Catch any error!
        logger.error(f"Critical error in DNS Proxy: {e}")
        graceful_shutdown()
    finally:
        sock.close()
        logger.info("Restoring original DNS settings...")
        dns_manager.restore_original_dns()
        logger.info("Server closed.")


def display_startup_messages():
    """
    Display startup information and status messages.
    """
    print("\n" + "=" * 70)
    print("Parental Control System - Child")
    print("=" * 70)
    print(f" Child: {CHILD_NAME}")
    print(f" Status: {'Registered in system' if CHILD_NAME else 'Not registered - Internet blocked'}")
    print(f" DNS: 127.0.0.1 (local)")
    print(f" Parent server: {PARENT_SERVER_IP}:{COMMUNICATION_PORT}")

    print(" Block servers:")
    if HTTPS_AVAILABLE:
        print("   HTTPS on port 443 - Secure sites (Instagram, Facebook, etc.)")
    print("   HTTP on port 80 - Regular sites")

    print("=" * 70)
    if CHILD_NAME:
        print(" System running - Internet available with secure blocking")
        print(" Blocked HTTPS sites will show block page without security warnings")
        print("")
        print("How to handle 'Not private connection' first time:")
        print("   1. Browser will show: 'Your connection is not private'")
        print("   2. Click: 'Advanced'")
        print("   3. Click: 'Proceed to localhost (unsafe)'")
        print("   4. This will only happen once per browser!")
        print("   From next time - beautiful and secure block pages!")
    else:
        print(" Registration required - Internet completely blocked")
    print("=" * 70)


def check_ssl_certificates():
    """
    Check that SSL certificates were created properly.

    Returns:
        bool: True if certificates are valid, False otherwise
    """
    cert_file = "block_server_cert.pem"
    key_file = "block_server_key.pem"

    if os.path.exists(cert_file) and os.path.exists(key_file):
        try:
            # Basic check that files are valid
            with open(cert_file, 'r') as f:
                cert_content = f.read()
            with open(key_file, 'r') as f:
                key_content = f.read()

            if 'BEGIN CERTIFICATE' in cert_content and 'BEGIN PRIVATE KEY' in key_content:
                logger.info("SSL certificates are valid")
                return True
            else:
                logger.warning("SSL certificates are not valid")
                return False
        except Exception as e:
            logger.error(f"Error checking certificates: {e}")
            return False
    else:
        logger.warning("SSL certificates not found")
        return False


if __name__ == "__main__":
    try:
        logger.info("Starting parental control system...")
        logger.info("Checking existing registration...")
        if check_child_registration():
            logger.info(f"Found registration: {CHILD_NAME}")
        else:
            logger.warning("No valid registration found")
            logger.info("Preparing registration page...")

            # Start block server before registration
            logger.info("Starting registration page server...")
            server_port = start_block_server()

            if not server_port:
                logger.error("Server failed to start - check permissions")
                sys.exit(1)

            # Also set DNS so page works
            logger.info("Setting up DNS redirect...")
            if dns_manager.setup_dns_redirect():
                logger.info("DNS settings updated successfully")
            else:
                logger.error("Administrator privileges required - run as administrator")
                sys.exit(1)

            time.sleep(3)  # Give server time to start

            if not wait_for_registration():
                logger.error("Exiting without registration")
                graceful_shutdown()
                sys.exit(1)

        display_startup_messages()

        # If we haven't set DNS yet (case where child was already registered)
        if not dns_manager.original_dns:
            logger.info("Setting up DNS redirect...")
            if dns_manager.setup_dns_redirect():
                logger.info("DNS settings updated successfully")
            else:
                logger.warning("Cannot set DNS automatically")
                print("\n--- Manual Setup ---")
                print("1. Open 'Network Settings'")
                print("2. Click 'Change adapter options'")
                print("3. Right-click your network and select 'Properties'")
                print("4. Select 'Internet Protocol Version 4 (TCP/IPv4)' and click 'Properties'")
                print("5. Select 'Use the following DNS server addresses' and in first field enter: 127.0.0.1")
                print("6. Click OK to save")
                print("-------------------------\n")
                input("Press Enter after setting up DNS...")

        # Only if server isn't already running (case where child was already registered)
        if BLOCK_SERVER_PORT is None:
            logger.info("Starting block page server...")
            start_block_server()

        logger.info("Starting connection to parent server...")
        child_client.child_name = CHILD_NAME
        connection_thread = threading.Thread(target=child_client.connect_to_parent, daemon=True)
        connection_thread.start()

        child_client.wait_for_connection(timeout=8)

        registration_check_thread = threading.Thread(target=periodic_registration_check, daemon=True)
        registration_check_thread.start()

        status_thread = threading.Thread(target=child_client.send_status_update, daemon=True)
        status_thread.start()

        if not child_client.connected:
            logger.info("Running without parent server - only domains received later will be blocked")

        print("=" * 70)
        print(f"Parental Control System active for {CHILD_NAME}")
        print(f"Blocked domains: {len(BLOCKED_DOMAINS)}")
        print("Starting DNS Proxy...")
        print("Press Ctrl+C to stop system")
        print("=" * 70)

        try:
            start_dns_proxy()
        except Exception as dns_error:
            logger.error(f"Error in DNS Proxy: {dns_error}")
            graceful_shutdown()
    except KeyboardInterrupt:
        logger.info("Stop request received...")
        graceful_shutdown()
    except Exception as e:
        logger.error(f"Critical error: {e}")
        graceful_shutdown()
    finally:
        # This will now always execute!
        logger.info("Starting final shutdown...")
        graceful_shutdown()
        network_manager.cleanup_all()