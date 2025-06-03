import logging
import sys
import http.server
import socketserver
import json
import threading
import socket
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
from abc import ABC, abstractmethod
from vpn_dns_protection import VPNDNSProtection
from typing import Dict, List, Optional, Any
from html_templates_parent import (REGISTER_TEMPLATE, LOGIN_TEMPLATE, DASHBOARD_TEMPLATE,
                                   BROWSING_HISTORY_TEMPLATE, MANAGE_CHILDREN_TEMPLATE, )
from database_manager import get_database, initialize_database

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('parental_control_parent.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

# Configuration Constants
HTTP_PORT = 8000
HTTPS_PORT = 8443

# Global data storage
children_data = {}
data_lock = threading.Lock()
active_connections = {}
db = None

# Browsing history storage
browsing_history = {}  # Dictionary by child name
history_lock = threading.Lock()

# Encryption system components
encryption_system = None
file_manager = None
parent_server = None


class ParentalControlException(Exception):
    """Base exception for parental control system"""
    def __init__(self, message: str, error_code: Optional[str] = None):
        super().__init__(message)
        self.error_code = error_code


class EncryptionError(ParentalControlException):
    """Encryption related errors"""
    pass


class ConnectionError(ParentalControlException):
    """Connection related errors"""
    pass


class DataValidationError(ParentalControlException):
    """Data validation errors"""
    pass

def ensure_encryption():
    """
    Ensure encryption system is operational and synchronized.

    Returns:
        bool: True if encryption system is ready, False otherwise
    """
    global encryption_system, file_manager
    if encryption_system is None or file_manager is None:
        try:
            from encryption_module import SimpleEncryption, SafeFileManager
            encryption_system = SimpleEncryption("parent_control_system")
            file_manager = SafeFileManager(encryption_system)
            logger.info("Encryption system initialized")

            # Synchronize with communication keys
            Protocol.sync_encryption_keys()

        except Exception as e:
            logger.error(f"Error initializing encryption: {e}")
            return False
    return True


def initialize_encryption():
    """
    Initialize encryption system and communication keys.
    Sets up both data encryption and communication encryption.
    """
    global encryption_system, file_manager

    # Data encryption
    encryption_system = SimpleEncryption("parent_control_system")
    file_manager = SafeFileManager(encryption_system)
    logger.info("Data encryption system initialized")

    # Communication key synchronization
    if Protocol.sync_encryption_keys():
        logger.info("Communication key synchronized")
    else:
        logger.warning("Issue with communication key synchronization")


def create_ssl_certificate():
    """
    Create SSL certificate for parent server.

    Returns:
        bool: True if certificate created successfully, False otherwise
    """
    if os.path.exists("parent_cert.pem") and os.path.exists("parent_key.pem"):
        logger.info("SSL certificate already exists")
        return True

    try:
        logger.info("Creating SSL certificate for parent server...")

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

        # Save certificate and key
        with open("parent_cert.pem", "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))

        with open("parent_key.pem", "wb") as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))

        logger.info("SSL certificate created: parent_cert.pem, parent_key.pem")
        return True

    except ImportError:
        logger.error("cryptography library not available")
        logger.error("Run: pip install cryptography")
        return create_fallback_cert()
    except Exception as e:
        logger.error(f"Error creating certificate: {e}")
        return create_fallback_cert()


def create_fallback_cert():
    """
    Create emergency fallback certificate.

    Returns:
        bool: True if fallback certificate created, False otherwise
    """
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
        logger.info("Basic SSL certificate created")
        return True
    except:
        return False


def init_database():
    """Initialize database and migrate data if needed"""
    global db
    if db is None:
        db = initialize_database()

    # Migrate existing JSON data if exists
    try:
        if os.path.exists('children_data.json'):
            with open('children_data.json', 'r', encoding='utf-8') as f:
                old_children = json.load(f)

            for child_name, child_info in old_children.items():
                # Add child to database
                db.add_child(child_name)

                # Add blocked domains
                blocked_domains = child_info.get('blocked_domains', [])
                for domain in blocked_domains:
                    db.add_blocked_domain(child_name, domain)

                # Update connection info
                if child_info.get('last_seen'):
                    db.update_child_connection(
                        child_name,
                        child_info.get('client_address'),
                        child_info.get('last_seen')
                    )

            # Backup and remove old file
            os.rename('children_data.json', 'children_data.json.backup')
            logger.info("Migrated children data to database")

    except FileNotFoundError:
        pass
    except Exception as e:
        logger.error(f"Error migrating children data: {e}")

    try:
        if os.path.exists('browsing_history.json'):
            with open('browsing_history.json', 'r', encoding='utf-8') as f:
                old_history = json.load(f)

            for entry in old_history:
                child_name = entry.get('child_name')
                if child_name:
                    db.add_browsing_history(child_name, [entry])

            os.rename('browsing_history.json', 'browsing_history.json.backup')
            logger.info("Migrated browsing history to database")

    except FileNotFoundError:
        pass
    except Exception as e:
        logger.error(f"Error migrating browsing history: {e}")

    return db

def load_children_data():
    """Compatibility function - loads from database"""
    try:
        database = get_database()
        return database.get_all_children()
    except Exception as e:
        logger.error(f"Error loading children data: {e}")
        return {}


def save_children_data():
    """Compatibility function - data auto-saved in database"""
    pass  # Database auto-saves


def add_to_browsing_history(child_name, entries):
    """Add browsing history using database"""
    try:
        database = get_database()
        if entries:
            database.add_browsing_history(child_name, entries)
            logger.info(f"Added {len(entries)} history entries for {child_name}")
    except Exception as e:
        logger.error(f"Error adding browsing history: {e}")


class BaseManager(ABC):
    """Abstract base class for all manager classes"""

    def __init__(self, name: str):
        self.name = name
        self.logger = logging.getLogger(f"{__name__}.{name}")
        self.is_initialized = False
        self.is_running = False

    @abstractmethod
    def initialize(self) -> bool:
        """Initialize the manager"""
        pass

    @abstractmethod
    def cleanup(self) -> bool:
        """Cleanup resources"""
        pass

    def start(self) -> bool:
        """Start the manager"""
        if not self.is_initialized:
            if not self.initialize():
                return False
        self.is_running = True
        self.logger.info(f"{self.name} started successfully")
        return True

    def stop(self) -> bool:
        """Stop parent server with VPN/DNS protection cleanup"""
        logger.info("Stopping parent server...")

        # עצור ניטור VPN/DNS
        if hasattr(self, 'vpn_dns_protection'):
            self.vpn_dns_protection.stop_monitoring()
            self.running = False
        """Stop the manager"""
        if self.is_running:
            self.is_running = False
            result = self.cleanup()
            self.logger.info(f"{self.name} stopped")
            return result
        return True



class UserManager:
    """Database-backed user manager with encryption"""

    def __init__(self):
        self.db = get_database()
        # אין צורך בהצפנה נפרדת - הדאטהבייס עושה הכל

    def register_user(self, email, fullname, password):
        # DatabaseManager כבר מבצע hashing וcצפנה
        return self.db.register_user(email, fullname, password)

    def validate_login(self, email, password):
        # DatabaseManager כבר מבצע hashing ובדיקה
        return self.db.validate_login(email, password)

    def get_user_fullname(self, email):
        return self.db.get_user_fullname(email)


class ParentServer(BaseManager):
    """
    Main parent server class handling encrypted communication with children.
    """

    def __init__(self):
        """Initialize parent server with encrypted data loading."""
        super().__init__("ParentServer")
        self.running = True
        self.db = get_database()
        self.server_socket = None
        self.connection_threads = []
        self.threads_lock = threading.Lock()

        self.vpn_dns_protection = VPNDNSProtection()
        self.vpn_dns_protection.start_monitoring(check_interval=60)  # בדיקה כל דקה

        global db
        if not db:
            init_database()

        # Load children data into memory for compatibility
        global children_data
        children_data = self.db.get_all_children()


        # Start periodic save
        self.start_periodic_save()

        # Start thread cleanup
        self.cleanup_thread = threading.Thread(target=self._cleanup_dead_threads, daemon=True)
        self.cleanup_thread.start()

        logger.info("ParentServer initialized with encrypted data")

    def _cleanup_dead_threads(self):
        """Clean up dead threads every 30 seconds"""
        while self.running:
            try:
                time.sleep(30)
                with self.threads_lock:
                    alive_threads = [t for t in self.connection_threads if t.is_alive()]
                    removed_count = len(self.connection_threads) - len(alive_threads)
                    if removed_count > 0:
                        self.connection_threads = alive_threads
                        logger.debug(f"Cleaned {removed_count} dead threads")
            except Exception as e:
                logger.error(f"Error cleaning threads: {e}")

    def start_periodic_save(self):
        """Start periodic save every 30 seconds"""

        def save_periodically():
            while self.running:
                try:
                    time.sleep(30)
                    # Database auto-saves, but we can do maintenance here
                    if db:
                        # Optional: cleanup old data
                        try:
                            from database_manager import cleanup_old_data
                            cleanup_old_data(days_to_keep=30)
                        except:
                            pass
                except Exception as e:
                    logger.error(f"Error in periodic maintenance: {e}")

        save_thread = threading.Thread(target=save_periodically, daemon=True, name="PeriodicSaver")
        save_thread.start()
        logger.info("Periodic save started")

    def add_child(self, child_name):
        if not self.db.add_child(child_name):
            return False

        # Update memory for compatibility
        with data_lock:
            children_data[child_name] = {
                "blocked_domains": set(),
                "client_address": None,
                "last_seen": None
            }
        return True

    def notify_child_immediate(self, child_name: str) -> None:
        """
        Send immediate encrypted update to child.

        Args:
            child_name (str): Name of child to notify
        """
        logger.debug(f"Trying to update {child_name} with encrypted communication...")
        with data_lock:
            if child_name in active_connections:
                conn_info = active_connections[child_name]
                if conn_info and conn_info.get("socket"):
                    try:
                        sock = conn_info["socket"]
                        domains = list(children_data[child_name]['blocked_domains'])
                        # Encrypted send
                        Protocol.send_message(sock, Protocol.UPDATE_DOMAINS, {"domains": domains})
                        logger.info(f"Sent immediate encrypted update to {child_name}")
                        # Add immediate DNS cache clear command
                        try:
                            Protocol.send_message(sock, "FORCE_DNS_CLEAR", {})
                            logger.info(f"Sent immediate DNS clear command to {child_name}")
                        except:
                            pass
                    except Exception as e:
                        logger.error(f"Error in encrypted update {child_name}: {e}")

    def remove_child(self, child_name):
        """Remove child using database"""
        # Use the class database instance
        if not self.db.remove_child(child_name):
            return False

        # Update memory for compatibility
        with data_lock:
            if child_name in children_data:
                del children_data[child_name]
        return True

    def send_security_alert(self, security_result):
        """Send security alert to parent dashboard"""
        alert_data = {
            "type": "SECURITY_ALERT",
            "timestamp": time.time(),
            "client_ip": security_result["client_ip"],
            "risk_level": security_result["overall_risk"],
            "vpn_detected": security_result["vpn_check"].get("vpn_detected", False),
            "vpn_provider": security_result["vpn_check"].get("vpn_provider"),
            "dns_issues": security_result["dns_check"].get("issues", []),
            "actions_taken": security_result["actions_taken"]
        }

        # שמור התראת אבטחה בדאטהבייס
        if self.db:
            try:
                self.db.add_security_alert(
                    client_ip=security_result["client_ip"],
                    risk_level=security_result["overall_risk"],
                    alert_type="SECURITY_ALERT",
                    details=alert_data
                )
                logger.info("Security alert saved to database")
            except Exception as e:
                logger.error(f"Error saving security alert: {e}")

        logger.critical(f" SECURITY ALERT LOGGED: {alert_data}")

        # שלח התראה מיידית לממשק האינטרנט (אם יש חיבור פעיל)
        self._broadcast_security_alert(alert_data)

    def _broadcast_security_alert(self, alert_data):
        """Broadcast security alert to web interface"""
        try:
            # זה יכול להיות דרך WebSocket או polling
            # לעת עתה רק נתעד ב-log
            logger.info(f"Broadcasting security alert to web interface")
        except Exception as e:
            logger.error(f"Failed to broadcast security alert: {e}")

    def handle_child_connection(self, client_socket, address):
        """
        Handle encrypted connection from child device.

        Args:
            client_socket (socket.socket): Client socket connection
            address (tuple): Client address (IP, port)
        """
        client_ip = address[0]

        # בדיקת אבטחה לפני המשך
        security_result = self.vpn_dns_protection.check_client_security(client_ip)

        if security_result["overall_risk"] == "high":
            logger.critical(f" HIGH SECURITY RISK from {client_ip}")
            logger.critical(f"VPN detected: {security_result['vpn_check'].get('vpn_detected', False)}")
            logger.critical(f"DNS issues: {security_result['dns_check'].get('issues', [])}")

            # שלח התראת אבטחה לממשק ההורה
            self.send_security_alert(security_result)

            # סגור חיבור
            try:
                client_socket.close()
            except:
                pass
            return

        elif security_result["overall_risk"] == "medium":
            logger.warning(f"⚠️ MEDIUM SECURITY RISK from {client_ip}")
            self.send_security_alert(security_result)

        logger.info(f"New connection from {address}")
        child_name = None

        try:
            # Use encrypted protocol
            msg_type, data = Protocol.receive_message(client_socket) #type:ignore
            logger.debug(f"Received encrypted message: {msg_type}, data: {data}")

            if msg_type == Protocol.REGISTER_CHILD:
                child_name = data.get('name')
                if child_name and child_name in children_data:
                    with data_lock:
                        children_data[child_name]['client_address'] = address
                        children_data[child_name]['last_seen'] = time.time()

                    Protocol.send_message(client_socket, Protocol.ACK, {"status": "registered"}) # type: ignore
                    logger.info(f"{child_name} registered successfully")

                    active_connections[child_name] = {"socket": client_socket, "address": address}
                    self.handle_child_communication(client_socket, child_name)
                else:
                    Protocol.send_message(client_socket, Protocol.ERROR, {"message": "Invalid child name"}) # type: ignore
                    logger.warning(f"Invalid child name: {child_name}")

            elif msg_type == Protocol.VERIFY_CHILD:
                requested_child = data.get("child_name")
                logger.info(f"Verification request for: '{requested_child}'")

                with data_lock:
                    is_valid = requested_child in children_data

                Protocol.send_message(client_socket, Protocol.VERIFY_RESPONSE, {"is_valid": is_valid}) # type: ignore
                logger.info(f"Response to '{requested_child}': {'valid' if is_valid else 'invalid'}")

                if is_valid:
                    with data_lock:
                        children_data[requested_child]['client_address'] = address
                        children_data[requested_child]['last_seen'] = time.time()

                    child_name = requested_child
                    active_connections[requested_child] = {"socket": client_socket, "address": address}
                    logger.info(f"Child '{requested_child}' verified and registered")

                    self.handle_child_communication(client_socket, child_name)
                else:
                    client_socket.close()
                    return

        except Exception as e:
            logger.error(f"Error in connection {child_name}: {e}")
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
                logger.info(f"{child_name} disconnected")

    def handle_child_communication(self, client_socket, child_name):
        """
        Handle encrypted communication with child.

        Args:
            client_socket (socket.socket): Child socket connection
            child_name (str): Name of the child
        """
        logger.info(f"Started encrypted communication with {child_name}")

        while self.running:
            try:
                client_socket.settimeout(30)
                msg_type, data = Protocol.receive_message(client_socket)
                logger.debug(f"Received encrypted message: {msg_type} from {child_name}")

                if msg_type == Protocol.GET_DOMAINS:
                    with data_lock:
                        domains = list(children_data[child_name]['blocked_domains'])
                    Protocol.send_message(client_socket, Protocol.UPDATE_DOMAINS, {"domains": domains})
                    logger.debug(f"Sent encrypted domains to {child_name}: {domains}")

                elif msg_type == Protocol.CHILD_STATUS:
                    with data_lock:
                        children_data[child_name]['last_seen'] = time.time()
                    Protocol.send_message(client_socket, Protocol.ACK)
                    logger.debug(f"Encrypted ACK sent to {child_name}")

                elif msg_type == Protocol.BROWSING_HISTORY:
                    logger.debug(f"Processing encrypted history message from {child_name}...")

                    if not isinstance(data, dict):
                        logger.error(f"Invalid data - not dictionary: {type(data)}")
                        continue

                    child_name_from_data = data.get("child_name")
                    history_entries = data.get("history", [])

                    if not child_name_from_data:
                        logger.error("Empty child name")
                        continue

                    if not isinstance(history_entries, list):
                        logger.error(f"History entries not list: {type(history_entries)}")
                        continue

                    if len(history_entries) == 0:
                        logger.warning("Empty history list")
                        Protocol.send_message(client_socket, Protocol.ACK, {})
                        continue

                    try:
                        logger.debug("Adding encrypted history to database...")
                        add_to_browsing_history(child_name_from_data, history_entries)

                        Protocol.send_message(client_socket, Protocol.ACK) #type:ignore
                        logger.info(f"Encrypted history from {child_name} processed successfully and ACK sent")

                    except Exception as history_error:
                        logger.error(f"Error processing encrypted history: {history_error}")
                        continue

                elif msg_type == Protocol.ERROR:
                    logger.error(f"Error from child {child_name}: {data}")
                    break

            except socket.timeout:
                continue
            except Exception as e:
                logger.error(f"Error in encrypted communication with {child_name}: {e}")
                break

        logger.info(f"Ended encrypted communication with {child_name}")

    def start_communication_server(self):
        """Start encrypted communication server for child connections."""

        def run_server():
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind(('', COMMUNICATION_PORT))
            self.server_socket.listen(5)
            logger.info(f"Encrypted communication server listening on port {COMMUNICATION_PORT}")

            while self.running:
                try:
                    client_socket, address = self.server_socket.accept()
                    with self.threads_lock:
                        if len(self.connection_threads) >= 50:
                            logger.warning(
                                f"Too many connections ({len(self.connection_threads)}) - rejecting connection")
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
                        logger.error(f"Error accepting connection: {e}")

        comm_thread = threading.Thread(target=run_server, name="CommunicationServer")
        comm_thread.daemon = True
        comm_thread.start()

    def shutdown(self):
        """Clean shutdown of parent server"""
        logger.info("Starting clean shutdown of parent server...")

        self.running = False

        if self.server_socket:
            try:
                self.server_socket.close()
                logger.info("Encrypted communication server closed")
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
        logger.info(f"Disconnected {disconnected} children")

        try:
            # Database auto-saves, but let's make sure
            logger.info("Database auto-saved")
        except Exception as e:
            logger.error(f"Error during shutdown: {e}")

        logger.info("Parent server shutdown completed")

    def initialize(self) -> bool:
        """Initialize server"""
        try:
            self.is_initialized = True
            return True
        except Exception as e:
            self.logger.error(f"Failed to initialize: {e}")
            return False

    def cleanup(self) -> bool:
        """Cleanup server"""
        try:
            self.shutdown()  # הפונקציה הקיימת שלך
            return True
        except Exception as e:
            self.logger.error(f"Error during cleanup: {e}")
            return False

    def add_blocked_domain(self, child_name: str, domain: str) -> bool:
        if not self.db.add_blocked_domain(child_name, domain):  # <-- self.db
            return False

        # Update memory for compatibility
        with data_lock:
            if child_name in children_data:
                children_data[child_name]['blocked_domains'].add(domain)
        return True

    def remove_blocked_domain(self, child_name: str, domain: str) -> bool:
        if not self.db.remove_blocked_domain(child_name, domain):  # <-- self.db
            return False

        # Update memory for compatibility
        with data_lock:
            if child_name in children_data:
                children_data[child_name]['blocked_domains'].discard(domain)
        return True


class ParentHandler(http.server.SimpleHTTPRequestHandler):
    """
    HTTP request handler for parent web interface.
    Handles authentication, child management, and browsing history.
    """

    def get_cookies(self):
        """
        Get cookies from request.

        Returns:
            dict: Dictionary of cookie name-value pairs
        """
        cookies = {}
        if "Cookie" in self.headers:
            raw_cookies = self.headers["Cookie"].split(";")
            for cookie in raw_cookies:
                if "=" in cookie:
                    name, value = cookie.strip().split("=", 1)
                    cookies[name] = unquote(value)
        return cookies

    def is_logged_in(self):
        """
        Check login status.

        Returns:
            str or None: User email if logged in, None otherwise
        """
        cookies = self.get_cookies()
        email = cookies.get("user_email")
        if email and user_manager.get_user_fullname(email):
            return email
        return None

    def end_headers(self):
        """Add security headers for HTTPS"""
        self.send_header('Strict-Transport-Security', 'max-age=31536000')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('X-Frame-Options', 'DENY')
        self.send_header('X-XSS-Protection', '1; mode=block')
        super().end_headers()

    def do_GET(self):
        """Handle GET requests for web interface"""
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

            # Check synchronized encryption status
            encryption_enabled = encryption_system is not None and file_manager is not None
            protocol_encryption = Protocol.test_encryption()

            # Check existence of encrypted files
            children_encrypted = os.path.exists('children_data.json.encrypted')
            history_encrypted = os.path.exists('browsing_history.json.encrypted')
            users_encrypted = os.path.exists('users_data.json.encrypted')
            communication_key = os.path.exists('communication_key.key')

            # System statistics
            total_children = len(children_data)
            total_domains_blocked = sum(len(info['blocked_domains']) for info in children_data.values())
            total_history_entries = sum(len(entries) for entries in browsing_history.values())
            connected_children = sum(1 for info in children_data.values() if info.get('client_address') is not None)

            status_color = "green" if encryption_enabled and protocol_encryption else "orange"
            status_text = "Encrypted and Synchronized" if encryption_enabled and protocol_encryption else "Partial"

            system_html = f"""
            <!DOCTYPE html>
            <html dir="rtl" lang="he">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>System Status - Encrypted Parental Control</title>
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
                        <h1>🔒 Encrypted System Status</h1>
                        <p style="font-size: 1.2em; margin: 10px 0;">Hello {user_name}! Full control over the secure system</p>
                    </div>

                    <div class="nav">
                        <a href="/dashboard">🏠 Home</a>
                        <a href="/manage_children">👶 Manage Children</a>
                        <a href="/browsing_history">📊 History</a>
                        <a href="/system_status">📊 System Status</a>
                        <a href="/logout">🚪 Logout</a>
                    </div>

                    <div class="stats-grid">
                        <div class="stat-card">
                            <div class="stat-number">{total_children}</div>
                            <div class="stat-label">Children in System</div>
                            <div class="connection-indicator {'online' if connected_children > 0 else 'offline'}"></div>
                            <small>{connected_children} encrypted connections</small>
                        </div>
                        <div class="stat-card">
                            <div class="stat-number">{total_domains_blocked}</div>
                            <div class="stat-label">Blocked Sites</div>
                        </div>
                        <div class="stat-card">
                            <div class="stat-number">{total_history_entries}</div>
                            <div class="stat-label">Encrypted Records</div>
                        </div>
                        <div class="stat-card">
                            <div class="stat-number">{"🔒" if encryption_enabled and protocol_encryption else "⚠️"}</div>
                            <div class="stat-label">Encryption Status</div>
                        </div>
                    </div>

                    <div class="status-card">
                        <h2>🔒 Synchronized Encryption Status</h2>
                        <div class="status-indicator">Status: {status_text}</div>
                        <p>Dual-layer encryption system: data + communication</p>

                        <div style="margin-top: 20px;">
                            <h3>📁 System Files</h3>
                            <div class="file-status">
                                <div>
                                    <strong>Children Data</strong><br>
                                    <small>List of children and blocked sites</small>
                                </div>
                                <span class="status-badge {'encrypted' if children_encrypted else 'regular'}">
                                    {'🔒 Encrypted' if children_encrypted else '🔓 Regular'}
                                </span>
                            </div>
                            <div class="file-status">
                                <div>
                                    <strong>Browsing History</strong><br>
                                    <small>Encrypted activity records</small>
                                </div>
                                <span class="status-badge {'encrypted' if history_encrypted else 'regular'}">
                                    {'🔒 Encrypted' if history_encrypted else '🔓 Regular'}
                                </span>
                            </div>
                            <div class="file-status">
                                <div>
                                    <strong>User Data</strong><br>
                                    <small>Encrypted login details</small>
                                </div>
                                <span class="status-badge {'encrypted' if users_encrypted else 'regular'}">
                                    {'🔒 Encrypted' if users_encrypted else '🔓 Regular'}
                                </span>
                            </div>
                            <div class="file-status">
                                <div>
                                    <strong>Communication Key</strong><br>
                                    <small>Encryption of messages between parent and child</small>
                                </div>
                                <span class="status-badge {'encrypted' if communication_key else 'regular'}">
                                    {'🔒 Exists' if communication_key else '❌ Missing'}
                                </span>
                            </div>
                        </div>
                    </div>

                    <div class="status-card">
                        <h3>🔐 Synchronized Encryption Information</h3>
                        <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 15px; margin-top: 15px;">
                            <div style="background: #e8f4fd; padding: 15px; border-radius: 8px;">
                                <strong>💾 Data Encryption</strong><br>
                                Every file encrypted at military level (AES-256)
                            </div>
                            <div style="background: #fff2e8; padding: 15px; border-radius: 8px;">
                                <strong>📡 Communication Encryption</strong><br>
                                Every message between parent and child encrypted
                            </div>
                            <div style="background: #e8f8e8; padding: 15px; border-radius: 8px;">
                                <strong>🔑 Key Management</strong><br>
                                Separate keys for data and communication
                            </div>
                            <div style="background: #f0e8ff; padding: 15px; border-radius: 8px;">
                                <strong>🔄 Auto Sync</strong><br>
                                System synchronizes keys automatically
                            </div>
                        </div>
                    </div>

                    <div style="text-align: center; margin: 30px 0;">
                        <p style="color: rgba(255,255,255,0.8); font-size: 14px;">
                            Fully Encrypted Parental Control System | Dual-Layer Encryption
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

            # Filters
            child_filter = query_params.get('child', [''])[0]
            status_filter = query_params.get('status', [''])[0]
            domain_filter = query_params.get('domain', [''])[0]

            # Build children options
            children_options = []
            with data_lock:
                for child_name in children_data.keys():
                    selected = 'selected' if child_name == child_filter else ''
                    children_options.append(f'<option value="{child_name}" {selected}>{child_name}</option>')

            # ✅ קבל היסטוריה ישירות מדטבייס עם פילטרים
            try:
                database = get_database()
                filtered_history = database.get_browsing_history(
                    child_filter=child_filter if child_filter else None,
                    status_filter=status_filter if status_filter else None,
                    domain_filter=domain_filter if domain_filter else None,
                    limit=200
                )

                logger.info(f"Retrieved {len(filtered_history)} history entries from database")

            except Exception as e:
                logger.error(f"Error getting history from database: {e}")
                import traceback
                traceback.print_exc()
                filtered_history = []

            # Group history
            grouped_history = group_browsing_by_main_site(filtered_history, time_window_minutes=30)

            # Build HTML for entries
            history_entries = []
            for entry in grouped_history:
                formatted_entry = format_simple_grouped_entry(entry)
                history_entries.append(formatted_entry)

            # Statistics
            unique_sites = len(
                set(entry.get('display_name', entry.get('main_domain', '')) for entry in grouped_history))
            total_blocked = sum(1 for entry in grouped_history if entry.get('was_blocked', False))
            total_allowed = len(grouped_history) - total_blocked

            stats_cards = f'''
                <div class="stat-card">
                    <div class="stat-number">{len(grouped_history)}</div>
                    <div class="stat-label">Activities Shown</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number">{unique_sites}</div>
                    <div class="stat-label">Unique Sites</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number">{total_blocked}</div>
                    <div class="stat-label">Blocked Activities</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number">{total_allowed}</div>
                    <div class="stat-label">Allowed Activities</div>
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
                                                    '<div class="empty-message">אין רשומות התואמות לחיפוש</div>')

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

            # Build children list
            children_list = []
            with data_lock:
                for child_name, child_info in children_data.items():
                    is_connected = child_info.get('client_address') is not None
                    status_class = "status-online" if is_connected else "status-offline"
                    status_text = "Connected Encrypted" if is_connected else "Not Connected"
                    encoded_child_name = quote(child_name)

                    children_list.append(f"""
                        <div class="child-item">
                            <div class="child-info">
                                <div class="child-icon">👶</div>
                                <div class="child-details">
                                    <h3>{child_name}</h3>
                                    <p class="{status_class}">{status_text}</p>
                                    <p>{len(child_info['blocked_domains'])} blocked sites</p>
                                </div>
                            </div>
                            <div class="child-actions">
                                <a href="/dashboard?child={encoded_child_name}" class="manage-btn">Manage Blocks</a>
                                <form method="post" action="/remove_child" style="display:inline;">
                                    <input type="hidden" name="child_name" value="{child_name}">
                                    <button type="submit" class="danger-btn" onclick="return confirm('Are you sure you want to delete {child_name}?')">Delete</button>
                                </form>
                            </div>
                        </div>
                    """)

            manage_html = MANAGE_CHILDREN_TEMPLATE.replace('${user_name}', user_name)
            manage_html = manage_html.replace('${children_list}', ''.join(
                children_list) if children_list else '<div style="padding: 20px; text-align: center; color: #666;">No registered children</div>')
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
                                    <button type="submit" class="remove-btn">Remove</button>
                                </form>
                            </div>
                        """)

                dashboard_html = DASHBOARD_TEMPLATE.replace('${children_cards}', '')
                dashboard_html = dashboard_html.replace('${display_child_controls}', 'block')
                dashboard_html = dashboard_html.replace('${current_child}', selected_child)
                dashboard_html = dashboard_html.replace('${user_name}', user_name)
                dashboard_html = dashboard_html.replace('${blocked_domains_html}',
                                                        ''.join(
                                                            domains_html) if domains_html else '<div class="empty-message">No blocked domains</div>')
            else:
                children_cards = []
                with data_lock:
                    for child_name, child_info in children_data.items():
                        is_connected = child_info.get('client_address') is not None
                        status_class = "status-online" if is_connected else "status-offline"
                        status_text = "Connected Encrypted" if is_connected else "Not Connected"
                        encoded_child_name = quote(child_name)

                        children_cards.append(f"""
                            <div class="child-card" onclick="window.location='/dashboard?child={encoded_child_name}'">
                                <div class="child-icon">👶</div>
                                <div class="child-name">{child_name}</div>
                                <div class="child-status {status_class}">{status_text}</div>
                                <p style="text-align: center; margin-top: 10px;">
                                    {len(child_info['blocked_domains'])} blocked sites
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
        """Handle POST requests for web interface"""
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

            if child_name and domain:
                try:
                    parent_server.add_blocked_domain(child_name, domain)
                    parent_server.notify_child_immediate(child_name)
                    logger.info(f"Added domain {domain} for {child_name}")

                except DataValidationError as e:
                    logger.warning(f"Validation error: {e}")
                except EncryptionError as e:
                    logger.error(f"Encryption error: {e}")
                except Exception as e:
                    logger.error(f"Unexpected error: {e}")

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

            if child_name and domain:
                try:
                    parent_server.remove_blocked_domain(child_name, domain)
                    parent_server.notify_child_immediate(child_name)
                    logger.info(f"Removed domain {domain} from {child_name}")

                except DataValidationError as e:
                    logger.warning(f"Validation error: {e}")
                except EncryptionError as e:
                    logger.error(f"Encryption error: {e}")
                except Exception as e:
                    logger.error(f"Unexpected error: {e}")

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
                error_message = '<div class="message error-message">Passwords do not match</div>'
                register_html = REGISTER_TEMPLATE.replace('${message}', error_message)
                self.send_response(200)
                self.send_header('Content-type', 'text/html; charset=utf-8')
                self.end_headers()
                self.wfile.write(register_html.encode('utf-8'))
                return

            success, message = user_manager.register_user(email, fullname, password)

            if success:
                success_message = '<div class="message success-message">Registration completed successfully! You can now login</div>'
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
                error_message = '<div class="message error-message">All fields must be filled</div>'
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
                logger.info(f"User logged in: {email}")
            else:
                error_message = '<div class="message error-message">Invalid username or password</div>'
                login_html = LOGIN_TEMPLATE.replace('${message}', error_message)
                self.send_response(200)
                self.send_header('Content-type', 'text/html; charset=utf-8')
                self.end_headers()
                self.wfile.write(login_html.encode('utf-8'))

        elif self.path == '/add_child':
            logger.debug("Entered add child handler")

            try:
                logged_in_user = self.is_logged_in()
                if not logged_in_user:
                    self.send_response(302)
                    self.send_header('Location', '/login')
                    self.end_headers()
                    return

                child_name = post_params.get('child_name', [''])[0].strip()
                logger.debug(f"Received child name: '{child_name}'")

                if child_name:
                    try:
                        success = parent_server.add_child(child_name)
                        logger.info(f"Child '{child_name}' added successfully!")

                    except DataValidationError as e:
                        logger.warning(f"Validation error: {e}")
                    except EncryptionError as e:
                        logger.error(f"Encryption error: {e}")
                    except Exception as e:
                        logger.error(f"Unexpected error: {e}")

                self.send_response(302)
                self.send_header('Location', '/manage_children')
                self.end_headers()

            except Exception as e:
                logger.error(f"Error in add_child: {e}")
                self.send_response(500)
                self.send_header('Content-type', 'text/html')
                self.end_headers()
                self.wfile.write(b'<h1>Server Error</h1>')

        elif self.path == '/remove_child':
            logger.debug("Entered remove child handler")

            try:
                logged_in_user = self.is_logged_in()
                if not logged_in_user:
                    self.send_response(302)
                    self.send_header('Location', '/login')
                    self.end_headers()
                    return

                child_name = post_params.get('child_name', [''])[0].strip()
                logger.debug(f"Child name for removal: '{child_name}'")

                if child_name:
                    success = parent_server.remove_child(child_name)
                    if success:
                        logger.info(f"Child '{child_name}' removed successfully!")
                    else:
                        logger.error(f"Failed to remove child '{child_name}'")

                self.send_response(302)
                self.send_header('Location', '/manage_children')
                self.end_headers()

            except Exception as e:
                logger.error(f"Error in remove_child: {e}")
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
            logger.debug(f"Request to clear history for: '{child_name}'")

            if child_name:
                try:
                    database = get_database()
                    success = database.clear_child_history(child_name)
                    if success:
                        logger.info(f"History cleared for {child_name}")
                except Exception as e:
                    logger.error(f"Error clearing history: {e}")

            self.send_response(302)
            self.send_header('Location', '/browsing_history')
            self.end_headers()

        elif self.path == '/toggle_encryption':
            # Since encryption should always be on, this function is not needed
            logged_in_user = self.is_logged_in()
            if not logged_in_user:
                self.send_response(302)
                self.send_header('Location', '/login')
                self.end_headers()
                return

            # Redirect to system status page
            self.send_response(302)
            self.send_header('Location', '/system_status')
            self.end_headers()

        else:
            self.send_response(404)
            self.end_headers()


def get_encryption_status():
    """
    Get current encryption status.

    Returns:
        dict: Dictionary containing encryption status information
    """
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
    """
    Clean up old files and unnecessary features.

    Returns:
        int: Number of files cleaned up
    """
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
                logger.info(f"Deleted old file: {file}")
            except Exception as e:
                logger.error(f"Cannot delete {file}: {e}")

    if cleaned > 0:
        logger.info(f"Cleaned {cleaned} old files")
    return cleaned


def backup_all_data():
    """
    Create full backup of all data.

    Returns:
        str or None: Backup directory name if successful, None if failed
    """
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
                    logger.error(f"Cannot backup {file}: {e}")

        logger.info(f"Backup created with {backed_up} files in {backup_dir}")
        return backup_dir

    except Exception as e:
        logger.error(f"Error creating backup: {e}")
        return None


def final_check():
    """
    Final check that everything is ready.

    Returns:
        bool: True if system is ready, False if missing components
    """
    logger.info("Final system check...")

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
        logger.error(f"Missing files: {missing_files}")
        logger.warning("System may not work without these files")
        return False

    logger.info("All required files in place")

    # Check permissions
    try:
        test_file = "test_permissions.tmp"
        with open(test_file, 'w') as f:
            f.write("test")
        os.remove(test_file)
        logger.info("Write permissions OK")
    except Exception as e:
        logger.warning(f"Permission issue: {e}")

    logger.info("Ready for launch!")

    logger.info("""
To run:
1. python parent_server.py
2. Go to https://localhost:8443
3. Login with: admin@example.com / admin123
4. Go to system status: /system_status
""")
    return True


logger.info("ParentServer initialized with child management and browsing history functions")
logger.info("Advanced encryption system ready")

# Create global user manager
user_manager = UserManager()

if __name__ == "__main__":
    logger.info("Starting encrypted parental control server...")
    print("=" * 50)
    init_database()
    initialize_encryption()

    try:
        parent_server = ParentServer()
        if not parent_server.start():  # משתמש בBaseManager.start()
            raise Exception("Failed to start parent server")

        logger.info("Server initialized successfully!")

        logger.info("Synchronized encryption system ready!")
        logger.info("Users system ready (database-backed)")
        logger.info(f"{len(children_data)} children in system")
        logger.info("Encrypted communication with children")
        logger.info("Starting encrypted parental control server with HTTPS")
        parent_server.start_communication_server()

        # Create SSL certificate
        if create_ssl_certificate():
            logger.info("Starting encrypted HTTPS server")

            with socketserver.TCPServer(("", HTTPS_PORT), ParentHandler) as httpd:
                try:
                    # SSL setup
                    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                    context.load_cert_chain('parent_cert.pem', 'parent_key.pem')

                    # Strong security settings
                    context.set_ciphers('ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:!aNULL:!MD5:!DSS')
                    context.options |= ssl.OP_NO_SSLv2
                    context.options |= ssl.OP_NO_SSLv3

                    httpd.socket = context.wrap_socket(httpd.socket, server_side=True)

                    print(f"\nEncrypted server ready!")
                    print(f"HTTPS server running on https://localhost:{HTTPS_PORT}")
                    print(f"Encrypted communication server running on port {COMMUNICATION_PORT}")
                    print(f"Ready to receive encrypted connections from children")

                    server_url = f"https://localhost:{HTTPS_PORT}"
                    print(f"\nOpening browser: {server_url}")
                    print("If browser warns - click 'Advanced' <- 'Proceed to localhost'")
                    print("\n" + "=" * 50)
                    print("All communication and data encrypted")
                    print("Press Ctrl+C to stop server")
                    print("=" * 50)

                    webbrowser.open(server_url)
                    httpd.serve_forever()

                except ssl.SSLError as e:
                    logger.error(f"SSL error: {e}")
                    raise

        else:
            raise Exception("Cannot create SSL certificate")

    except KeyboardInterrupt:
        logger.info("Encrypted server stopped by user...")
        parent_server.shutdown()
        logger.info("Encrypted server closed safely")

    except Exception as e:
        logger.error(f"Error starting HTTPS: {e}")
        parent_server.shutdown()
        logger.info("Switching to HTTP backup mode...")

        # HTTP backup
        try:
            with socketserver.TCPServer(("", HTTP_PORT), ParentHandler) as httpd:
                print(f"\nHTTP server running on http://localhost:{HTTP_PORT}")
                print("Demo user: admin@example.com / admin123")
                print("In HTTP mode - no traffic encryption!")
                print("But data and communication still encrypted")

                server_url = f"http://localhost:{HTTP_PORT}"
                webbrowser.open(server_url)
                print(f"Browser opened: {server_url}")
                print("Press Ctrl+C to stop server")

                httpd.serve_forever()

        except KeyboardInterrupt:
            logger.info("HTTP server stopped...")
            parent_server.shutdown()
            logger.info("Server closed safely")

        except Exception as http_error:
            logger.error(f"Error with HTTP server too: {http_error}")
            parent_server.stop()

        finally:
            try:
                parent_server.shutdown()
                logger.info("Encrypted data saved")
                logger.info("Goodbye!")
            except:
                pass