
import socket
import threading
import time
import os
import ssl
import logging
from urllib.parse import parse_qs
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import datetime
import ipaddress
from datetime import timezone

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Import regular HTTP server as fallback
try:
    from custom_http_server import ParentalControlHTTPServer

    HTTP_SERVER_AVAILABLE = True
    logger.info("ParentalControlHTTPServer imported successfully")
except ImportError:
    ParentalControlHTTPServer = None
    HTTP_SERVER_AVAILABLE = False
    logger.warning("ParentalControlHTTPServer import failed")


class HTTPSBlockServer:
    """
    HTTPS server for website blocking in parental control system.

    Provides secure HTTPS support to display blocking pages for secured websites,
    complete with SSL certificate generation and proper browser compatibility.
    """

    def __init__(self, ip="127.0.0.1", https_port=443, http_port=8080):
        """
        Initialize HTTPS blocking server.

        Args:
            ip (str): Server IP address to bind to
            https_port (int): HTTPS port for secure connections
            http_port (int): HTTP port for fallback server
        """
        self.ip = ip
        self.https_port = https_port
        self.http_port = http_port
        self.running = False

        # Configuration data
        self.child_name = None
        self.registration_html = ""
        self.block_html_template = ""
        self.verify_child_callback = None
        self.external_create_error_page = None
        self.external_create_success_page = None

        # Fallback HTTP server
        self.fallback_http_server = None

        logger.info(f"HTTPSBlockServer initialized on {ip}:{https_port}")

    def set_templates(self, registration_html, block_html_template):
        """
        Set HTML templates for registration and blocking pages.

        Args:
            registration_html (str): HTML content for registration page
            block_html_template (str): HTML template for blocked content page
        """
        self.registration_html = registration_html
        self.block_html_template = block_html_template
        logger.debug("HTML templates configured")

    def set_verify_callback(self, callback_func):
        """
        Set callback function for child verification.

        Args:
            callback_func (callable): Function to verify child registration
        """
        self.verify_child_callback = callback_func
        logger.debug("Child verification callback configured")

    def set_external_functions(self, create_error_func, create_success_func):
        """
        Set external functions for creating styled pages.

        Args:
            create_error_func (callable): Function to create error pages
            create_success_func (callable): Function to create success pages
        """
        self.external_create_error_page = create_error_func
        self.external_create_success_page = create_success_func
        logger.debug("External page creation functions configured")

    def set_child_data(self, child_name):
        """
        Update child data information.

        Args:
            child_name (str): Name of the registered child
        """
        self.child_name = child_name
        logger.info(f"Child data updated: {child_name}")

    def create_ssl_certificate(self):
        """
        Create enhanced self-signed SSL certificate with browser compatibility.

        Generates a strong SSL certificate with proper extensions for better
        browser compatibility and security. Uses 4096-bit RSA key for enhanced security.

        Returns:
            tuple: (cert_file_path, key_file_path) or (None, None) if failed
        """
        cert_file = "block_server_cert.pem"
        key_file = "block_server_key.pem"

        # Remove existing certificates to create fresh ones
        for file in [cert_file, key_file]:
            if os.path.exists(file):
                try:
                    os.remove(file)
                    logger.info(f"Removed old certificate: {file}")
                except:
                    pass

        try:
            logger.info("Creating new SSL certificate for blocking server...")

            # Generate stronger private key
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=4096,  # Enhanced security with larger key
            )

            # Certificate details - more browser-compatible
            subject = issuer = x509.Name([
                x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
                x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Local"),
                x509.NameAttribute(NameOID.LOCALITY_NAME, "localhost"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Parental Control System"),
                x509.NameAttribute(NameOID.COMMON_NAME, "localhost"),
            ])

            # Create certificate with enhanced settings
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
                # Valid for 5 years
                datetime.datetime.now(timezone.utc) + datetime.timedelta(days=1825)
            ).add_extension(
                # More address alternatives for better compatibility
                x509.SubjectAlternativeName([
                    x509.DNSName("localhost"),
                    x509.DNSName("127.0.0.1"),
                    x509.DNSName("*.localhost"),
                    x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
                    x509.IPAddress(ipaddress.IPv6Address("::1")),
                ]),
                critical=False,
            ).add_extension(
                # Additional extensions for compatibility
                x509.KeyUsage(
                    digital_signature=True,
                    key_encipherment=True,
                    key_agreement=False,
                    key_cert_sign=False,
                    crl_sign=False,
                    content_commitment=False,
                    data_encipherment=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            ).add_extension(
                x509.ExtendedKeyUsage([
                    x509.oid.ExtendedKeyUsageOID.SERVER_AUTH,
                    x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH,
                ]),
                critical=True,
            ).sign(private_key, hashes.SHA256())

            # Save certificate
            with open(cert_file, "wb") as f:
                f.write(cert.public_bytes(serialization.Encoding.PEM))

            # Save private key
            with open(key_file, "wb") as f:
                f.write(private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                ))

            logger.info(f"New SSL certificate created: {cert_file}, {key_file}")
            logger.info("Certificate valid for 5 years")

            # Display user instructions
            logger.info("=" * 60)
            logger.info("IMPORTANT: Browser Security Warning Instructions:")
            logger.info("=" * 60)
            logger.info("1. When browser shows 'Your connection is not private'")
            logger.info("2. Click on 'Advanced'")
            logger.info("3. Click on 'Proceed to localhost (unsafe)'")
            logger.info("4. This will only happen once per browser!")
            logger.info("5. After that, all blocked sites will show nice blocking pages")
            logger.info("=" * 60)

            return cert_file, key_file

        except Exception as e:
            logger.error(f"Error creating SSL certificate: {e}", exc_info=True)
            return None, None

    def start_https_server(self):
        """
        Start HTTPS server with enhanced error handling.

        Creates SSL context, loads certificates, and begins accepting
        HTTPS connections with proper error handling for SSL issues.

        Returns:
            bool: True if server started successfully, False otherwise
        """
        try:
            logger.info(f"Starting HTTPS server on port {self.https_port}")

            # Create new SSL certificate for each startup
            cert_file, key_file = self.create_ssl_certificate()
            if not cert_file or not key_file:
                logger.error("Cannot create SSL certificate")
                return False

            # Create HTTPS socket
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

            # Configure enhanced SSL context
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)

            # Advanced SSL settings for better compatibility
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            context.set_ciphers('HIGH:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!MD5:!PSK:!SRP:!CAMELLIA')

            try:
                context.load_cert_chain(cert_file, key_file)
                logger.info("SSL certificates loaded successfully")
            except Exception as e:
                logger.error(f"Error loading certificates: {e}")
                return False

            # Wrap socket with SSL
            try:
                server_socket.bind((self.ip, self.https_port))
                server_socket.listen(10)

                # SSL wrapping after bind
                ssl_socket = context.wrap_socket(server_socket, server_side=True)

                logger.info(f"Listening on {self.ip}:{self.https_port}")

            except Exception as e:
                logger.error(f"Error in SSL wrapping: {e}")
                server_socket.close()
                return False

            # Thread for handling connections with enhanced error handling
            def handle_connections():
                while self.running:
                    try:
                        client_socket, client_address = ssl_socket.accept()
                        logger.info(f"HTTPS connection from {client_address[0]}:{client_address[1]}")

                        # Handle client in separate thread
                        client_thread = threading.Thread(
                            target=self.handle_https_client_safe,
                            args=(client_socket,),
                            daemon=True
                        )
                        client_thread.start()

                    except ssl.SSLError as ssl_err:
                        # Special handling for SSL errors - don't print confusing messages
                        if "certificate unknown" in str(ssl_err).lower():
                            # This is normal - browser doesn't recognize certificate
                            pass
                        else:
                            logger.warning(f"SSL Error: {ssl_err}")

                    except Exception as e:
                        if self.running:
                            logger.error(f"Error accepting connection: {e}")

            connection_thread = threading.Thread(target=handle_connections, daemon=True)
            connection_thread.start()

            logger.info(f"HTTPS server running on port {self.https_port}")
            logger.info("Blocked HTTPS sites will show secure blocking page")
            return True

        except PermissionError:
            logger.error(f"No permissions for port {self.https_port}")
            logger.error("Run the program as Administrator")
            return False
        except Exception as e:
            logger.error(f"General error: {e}")
            return False

    def handle_https_client_safe(self, client_socket):
        """
        Handle HTTPS client with crash prevention.

        Safely processes HTTPS requests with proper timeout handling
        and error recovery to prevent server crashes.

        Args:
            client_socket (ssl.SSLSocket): SSL-wrapped client socket
        """
        try:
            client_socket.settimeout(10)

            # Receive request
            request_data = b''
            while True:
                try:
                    chunk = client_socket.recv(1024)
                    if not chunk:
                        break
                    request_data += chunk
                    if b'\r\n\r\n' in request_data:
                        break
                except socket.timeout:
                    break
                except:
                    break

            if not request_data:
                return

            # Parse request
            try:
                request_str = request_data.decode('utf-8', errors='ignore')
                lines = request_str.split('\r\n')
                if not lines:
                    return

                # Extract request data
                request_line = lines[0]
                parts = request_line.split(' ')
                if len(parts) >= 3:
                    method, path, _ = parts[0], parts[1], parts[2]
                else:
                    method, path = 'GET', '/'

                # Extract Host header
                host = "localhost"
                for line in lines[1:]:
                    if line.lower().startswith('host:'):
                        host = line.split(':', 1)[1].strip()
                        break

                logger.info(f"HTTPS {method} {path} - Host: {host}")

                # Handle different requests
                if path == "/" or path.startswith("/register"):
                    response = self.handle_registration_request(method, request_str)
                else:
                    response = self.handle_block_request(host)

                # Send response
                client_socket.send(response.encode('utf-8'))
                logger.debug(f"Response sent for {host}")

            except Exception as parse_error:
                logger.warning(f"Error parsing request: {parse_error}")

        except Exception as e:
            # Don't print regular SSL errors that are confusing
            if "certificate unknown" not in str(e).lower():
                logger.warning(f"Error handling client: {e}")
        finally:
            try:
                client_socket.close()
            except:
                pass

    def handle_registration_request(self, method, request_str):
        """
        Handle registration requests.

        Routes registration requests to appropriate handlers based on
        HTTP method (GET for form display, POST for form processing).

        Args:
            method (str): HTTP method (GET or POST)
            request_str (str): Complete HTTP request string

        Returns:
            str: HTTP response string
        """
        if method == "POST":
            return self.handle_registration_post(request_str)
        else:
            # GET - return registration page
            html_content = self.registration_html
            return self.create_response(200, "OK", html_content, "text/html")

    def handle_registration_post(self, request_str):
        """
        Handle child registration POST requests.

        Processes registration form data, validates input, and integrates
        with existing styling functions for consistent user experience.

        Args:
            request_str (str): Complete HTTP request string

        Returns:
            str: HTTP response with success or error page
        """
        try:
            # Extract POST data
            post_data = ""
            if '\r\n\r\n' in request_str:
                post_data = request_str.split('\r\n\r\n', 1)[1]

            form_data = parse_qs(post_data)
            child_name = ""

            if 'child_name' in form_data:
                child_name = form_data['child_name'][0].strip()

            logger.info(f"HTTPS registration attempt: '{child_name}'")

            if not child_name:
                if self.external_create_error_page:
                    error_html = self.external_create_error_page("Error", "Name cannot be empty!",
                                                                 back_button=True, retry_button=True)
                else:
                    error_html = self.create_simple_error_page("Error", "Name cannot be empty!")
                return self.create_response(400, "BAD REQUEST", error_html, "text/html")

            if len(child_name) < 2:
                if self.external_create_error_page:
                    error_html = self.external_create_error_page("Error", "Name must contain at least 2 characters!",
                                                                 back_button=True, retry_button=True)
                else:
                    error_html = self.create_simple_error_page("Error", "Name must contain at least 2 characters!")
                return self.create_response(400, "BAD REQUEST", error_html, "text/html")

            # Call verification function
            if self.verify_child_callback:
                if self.verify_child_callback(child_name):
                    self.child_name = child_name
                    logger.info(f"Child '{child_name}' registered successfully via HTTPS")

                    if self.external_create_success_page:
                        success_html = self.external_create_success_page(
                            f"Welcome {child_name}!",
                            "You have been successfully registered in the parental control system<br>You can now browse the internet safely"
                        )
                    else:
                        success_html = self.create_simple_success_page(f"Welcome {child_name}!",
                                                                       "You have been successfully registered in the parental control system")
                    return self.create_response(200, "OK", success_html, "text/html")
                else:
                    logger.warning(f"Child '{child_name}' not found in system")

                    if self.external_create_error_page:
                        error_html = self.external_create_error_page(
                            "Not Registered in System",
                            f"The name '{child_name}' is not registered in the parental control system.<br>Please ask your parents to add you through the control panel.",
                            back_button=True,
                            retry_button=True
                        )
                    else:
                        error_html = self.create_simple_error_page("Not Registered in System",
                                                                   f"The name '{child_name}' is not registered in the parental control system.")
                    return self.create_response(403, "FORBIDDEN", error_html, "text/html")

        except Exception as e:
            logger.error(f"Error handling HTTPS registration: {e}")
            return self.create_error_response(500, "Internal Server Error")

    def handle_block_request(self, host):
        """
        Handle blocking request with debugging information.

        Creates blocking page for requested host with current time
        and child information formatted using the configured template.

        Args:
            host (str): Hostname of the blocked site

        Returns:
            str: HTTP response with blocking page
        """
        logger.info(f"Creating blocking page for: {host}")

        current_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        block_html = self.block_html_template.format(
            host=host,
            current_time=current_time,
            child_name=self.child_name or "Guest"
        )

        logger.debug(f"Blocking page created ({len(block_html)} characters)")

        response = self.create_response(200, "OK", block_html, "text/html")
        logger.debug(f"HTTP response created ({len(response)} bytes)")

        return response

    def create_simple_error_page(self, title, message):
        """
        Create simple error page if external functions are not available.

        Args:
            title (str): Error page title
            message (str): Error message content

        Returns:
            str: HTML content for error page
        """
        return f"""
       <!DOCTYPE html>
       <html lang="en">
       <head>
           <meta charset="UTF-8">
           <title>{title}</title>
           <style>
               body {{ font-family: Arial, sans-serif; text-align: center; margin: 50px; }}
               h1 {{ color: #e74c3c; }}
               .btn {{ padding: 10px 20px; background: #3498db; color: white; text-decoration: none; border-radius: 5px; }}
           </style>
       </head>
       <body>
           <h1>{title}</h1>
           <p>{message}</p>
           <a href="/" class="btn">Back to Home</a>
       </body>
       </html>
       """

    def create_simple_success_page(self, title, message):
        """
        Create simple success page if external functions are not available.

        Args:
            title (str): Success page title
            message (str): Success message content

        Returns:
            str: HTML content for success page
        """
        return f"""
       <!DOCTYPE html>
       <html lang="en">
       <head>
           <meta charset="UTF-8">
           <title>{title}</title>
           <style>
               body {{ font-family: Arial, sans-serif; text-align: center; margin: 50px; background: #f8f9fa; }}
               .container {{ max-width: 500px; margin: 0 auto; background: white; padding: 40px; border-radius: 10px; }}
               h1 {{ color: #27ae60; }}
               .checkmark {{ font-size: 60px; color: #27ae60; }}
           </style>
       </head>
       <body>
           <div class="container">
               <div class="checkmark">✓</div>
               <h1>{title}</h1>
               <p>{message}</p>
           </div>
       </body>
       </html>
       """

    def create_response(self, status_code, status_text, content, content_type):
        """
        Create HTTP response with proper headers.

        Args:
            status_code (int): HTTP status code
            status_text (str): HTTP status text
            content (str): Response body content
            content_type (str): MIME content type

        Returns:
            str: Complete HTTP response string
        """
        response = f"""HTTP/1.1 {status_code} {status_text}\r
Content-Type: {content_type}; charset=utf-8\r
Content-Length: {len(content.encode('utf-8'))}\r
Connection: close\r
\r
{content}"""
        return response

    def create_error_response(self, status_code, status_text):
        """
        Create HTTP error response.

        Args:
            status_code (int): HTTP error status code
            status_text (str): HTTP error status text

        Returns:
            str: HTTP error response string
        """
        content = f"<html><body><h1>{status_code} {status_text}</h1></body></html>"
        return self.create_response(status_code, status_text, content, "text/html")

    def start_fallback_http_server(self):
        """
        Start fallback HTTP server with complete error handling.

        Creates and configures a fallback HTTP server instance with
        all necessary templates and callbacks properly transferred.

        Returns:
            bool: True if fallback server started successfully, False otherwise
        """
        logger.debug("start_fallback_http_server called")
        logger.debug(f"HTTP_SERVER_AVAILABLE: {HTTP_SERVER_AVAILABLE}")
        logger.debug(f"ParentalControlHTTPServer: {ParentalControlHTTPServer}")

        try:
            if not HTTP_SERVER_AVAILABLE:
                logger.error("HTTP_SERVER_AVAILABLE is False")
                return False

            if ParentalControlHTTPServer is None:
                logger.error("ParentalControlHTTPServer is None")
                return False

            logger.debug("Creating ParentalControlHTTPServer instance...")

            # Create instance from class
            self.fallback_http_server = ParentalControlHTTPServer(self.ip, self.http_port)
            logger.debug(f"Instance created: {type(self.fallback_http_server)}")

            # Transfer settings with checks
            if hasattr(self.fallback_http_server, 'set_templates'):
                self.fallback_http_server.set_templates(self.registration_html, self.block_html_template)
                logger.debug("Templates set")
            else:
                logger.warning("No set_templates method")

            if hasattr(self.fallback_http_server, 'set_verify_callback'):
                self.fallback_http_server.set_verify_callback(self.verify_child_callback)
                logger.debug("Verify callback set")
            else:
                logger.warning("No set_verify_callback method")

            if hasattr(self.fallback_http_server, 'set_external_functions'):
                self.fallback_http_server.set_external_functions(
                    self.external_create_error_page,
                    self.external_create_success_page
                )
                logger.debug("External functions set")
            else:
                logger.warning("No set_external_functions method")

            # Start in separate thread
            if hasattr(self.fallback_http_server, 'start_server'):
                fallback_thread = threading.Thread(
                    target=self.fallback_http_server.start_server,
                    daemon=True
                )
                fallback_thread.start()
                logger.debug("Server thread started")
            else:
                logger.error("No start_server method")
                return False

            logger.info(f"HTTP fallback server running on port {self.http_port}")
            return True

        except TypeError as e:
            logger.error(f"TypeError creating instance: {e}")
            logger.debug(f"ParentalControlHTTPServer callable? {callable(ParentalControlHTTPServer)}")
            return False
        except Exception as e:
            logger.error(f"General error: {e}", exc_info=True)
            return False

    def start_server(self):
        """
        Start the server with HTTPS only - HTTP will be started separately.

        Initializes and starts the HTTPS server for handling secure connections.
        The server runs in a loop until stopped via stop_server() or KeyboardInterrupt.

        Returns:
            bool: True if server started successfully, False otherwise
        """
        logger.debug("start_server called")

        try:
            self.running = True

            # Start HTTPS on port 443
            logger.debug(f"Attempting to start HTTPS on port {self.https_port}...")
            https_started = self.start_https_server()

            if https_started:
                logger.info(f"HTTPS successful on port {self.https_port}")
                logger.info("Now blocked HTTPS sites will show blocking page without warnings!")
            else:
                logger.error(f"HTTPS failed on port {self.https_port}")
                logger.info("Ensure the program is running as Administrator")
                return False

            # Wait for requests
            logger.info("HTTPS server ready to receive requests...")
            try:
                while self.running:
                    time.sleep(1)
            except KeyboardInterrupt:
                logger.info("KeyboardInterrupt - stopping server...")
                self.stop_server()

            return True

        except Exception as e:
            logger.error(f"General error in start_server: {e}", exc_info=True)
            return False

    def stop_server(self):
        """
        Stop the HTTPS server and cleanup resources.
        """
        self.running = False
        logger.info("HTTPS server stopped")


def verify_ssl_setup(self):
    """
    Verify that SSL certificate was created successfully.

    Checks for existence and basic validity of SSL certificate files
    required for HTTPS operation.

    Returns:
        bool: True if SSL setup is valid, False otherwise
    """
    cert_file = "block_server_cert.pem"
    key_file = "block_server_key.pem"

    if not os.path.exists(cert_file) or not os.path.exists(key_file):
        logger.error("Certificate files not found")
        return False

    try:
        # Basic validation of certificate files
        with open(cert_file, 'rb') as f:
            cert_data = f.read()
        with open(key_file, 'rb') as f:
            key_data = f.read()

        if b'BEGIN CERTIFICATE' in cert_data and b'BEGIN PRIVATE KEY' in key_data:
            logger.info("Certificate files are valid")
            return True
        else:
            logger.error("Certificate files are corrupted")
            return False

    except Exception as e:
        logger.error(f"Error checking certificate: {e}")
        return False


if __name__ == "__main__":
    # Independent testing
    logger.info("Testing HTTPS blocking server...")

    # Templates for testing
    registration_template = """<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><title>Registration</title></head>
<body><h1>Registration Page</h1><form method="post"><input name="child_name" placeholder="Name"><button type="submit">Submit</button></form></body></html>"""

    block_template = """<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><title>Blocked</title></head>
<body><h1>Site Blocked!</h1><p>Site: {host}</p><p>Time: {current_time}</p></body></html>"""

    server = HTTPSBlockServer("127.0.0.1", 443, 8080)
    server.set_templates(registration_template, block_template)

    logger.info("Starting blocking server with HTTPS...")
    logger.warning("If browser shows warning - click 'Advanced' then 'Proceed to localhost'")

    try:
        server.start_server()
    except KeyboardInterrupt:
        logger.info("Server stopped by user")
    finally:
        server.stop_server()