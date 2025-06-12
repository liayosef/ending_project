import socket
import threading
import time
import os
from urllib.parse import parse_qs
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Server constants
QUEUE_SIZE = 10
SOCKET_TIMEOUT = 10
MAX_PACKET = 1024
HTTP_VERSION = "HTTP/1.1"

# HTTP responses
OK_RESPONSE = "200 OK"
BAD_REQUEST = "400 BAD REQUEST"
NOT_FOUND = "404 NOT FOUND"
INTERNAL_ERROR = "500 INTERNAL SERVER ERROR"

# Content types
CONTENT_TYPES = {
    '.html': "text/html; charset=utf-8",
    '.css': "text/css",
    '.js': "text/javascript; charset=utf-8",
    '.png': "image/png",
    '.jpg': "image/jpeg",
    '.ico': "image/x-icon",
    '.txt': "text/plain; charset=utf-8"
}


class ParentalControlHTTPServer:
    """
    Custom HTTP server implementation for parental control system.

    This server provides registration and blocking functionality for child devices,
    handling HTTP requests with custom templates and validation callbacks.
    """

    def __init__(self, ip="127.0.0.1", port=8080):
        """
        Initialize the HTTP server.

        Args:
            ip (str): Server IP address to bind to
            port (int): Server port to listen on
        """
        self.ip = ip
        self.port = port
        self.server_socket = None
        self.running = False

        # Data from main system (to be set externally)
        self.child_name = None
        self.registration_html = ""
        self.block_html_template = ""
        self.verify_child_callback = None

        # External functions for page design
        self.external_create_error_page = None
        self.external_create_success_page = None

        logger.info(f"ParentalControlHTTPServer initialized on {ip}:{port}")

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

    def set_child_data(self, child_name):
        """
        Update child data information.

        Args:
            child_name (str): Name of the registered child
        """
        self.child_name = child_name
        logger.info(f"Child data updated: {child_name}")

    def set_external_functions(self, create_error_func=None, create_success_func=None):
        """
        Set external functions for creating error and success pages.

        Args:
            create_error_func (callable): Function to create error pages
            create_success_func (callable): Function to create success pages
        """
        self.external_create_error_page = create_error_func
        self.external_create_success_page = create_success_func
        logger.debug("External page creation functions configured")

    def set_verify_callback(self, callback_func):
        """
        Set callback function for child verification.

        Args:
            callback_func (callable): Function to verify child registration
        """
        self.verify_child_callback = callback_func
        logger.debug("Child verification callback configured")

    def start_server(self):
        """
        Start the HTTP server and begin listening for connections.

        Creates server socket, binds to address, and starts accepting client connections
        in separate threads for concurrent handling.
        """
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind((self.ip, self.port))
            self.server_socket.listen(QUEUE_SIZE)
            self.running = True

            logger.info(f"Custom HTTP server running on {self.ip}:{self.port}")

            while self.running:
                try:
                    client_socket, client_address = self.server_socket.accept()
                    logger.info(f"New connection from {client_address[0]}:{client_address[1]}")

                    # Handle client in separate thread
                    client_thread = threading.Thread(
                        target=self.handle_client,
                        args=(client_socket,),
                        daemon=True
                    )
                    client_thread.start()

                except socket.error as e:
                    if self.running:  # Only log if not intentionally closed
                        logger.error(f"Error accepting connection: {e}")

        except Exception as e:
            logger.error(f"Error starting server: {e}")
        finally:
            self.stop_server()

    def stop_server(self):
        """
        Stop the HTTP server and close all connections.
        """
        self.running = False
        if self.server_socket:
            try:
                self.server_socket.close()
                logger.info("HTTP server stopped")
            except:
                pass

    def handle_client(self, client_socket):
        """
        Handle individual client connections.

        Receives HTTP requests, validates them, and routes to appropriate handlers
        based on the request method and URI.

        Args:
            client_socket (socket): Client socket connection
        """
        try:
            client_socket.settimeout(SOCKET_TIMEOUT)

            # Receive request in chunks
            request_data = b''
            while True:
                try:
                    chunk = client_socket.recv(MAX_PACKET)
                    if not chunk:
                        break
                    request_data += chunk

                    # Check if request is complete
                    if b'\r\n\r\n' in request_data:
                        break

                except socket.timeout:
                    break
                except socket.error:
                    break

            if request_data:
                # Parse the request
                request_str = request_data.decode('utf-8', errors='ignore')
                valid_http, method, uri, headers = self.validate_http_request(request_str)

                if valid_http:
                    logger.info(f"Valid request: {method} {uri}")

                    # Handle request by type
                    if method == "GET":
                        response = self.handle_get_request(uri)
                    elif method == "POST":
                        # Extract POST body data
                        post_data = self.extract_post_data(request_str)
                        response = self.handle_post_request(uri, post_data)
                    else:
                        response = self.create_error_response(400, "Method Not Allowed")

                    self.send_response(client_socket, response)
                else:
                    logger.warning("Invalid HTTP request received")
                    error_response = self.create_error_response(400, "Bad Request")
                    self.send_response(client_socket, error_response)

        except Exception as e:
            logger.error(f"Error handling client: {e}")
        finally:
            try:
                client_socket.close()
            except:
                pass

    def validate_http_request(self, request):
        """
        Validate HTTP request format and extract components.

        Parses HTTP request line and headers, validates format compliance
        with HTTP/1.1 specification.

        Args:
            request (str): Raw HTTP request string

        Returns:
            tuple: (is_valid, method, uri, headers)
        """
        try:
            lines = request.split('\r\n')
            if not lines:
                return False, "", "", {}

            # First request line
            request_line_parts = lines[0].split(' ')
            if len(request_line_parts) != 3:
                return False, "", "", {}

            method, uri, version = request_line_parts

            # Validation checks
            if version != "HTTP/1.1":
                logger.warning(f"Unsupported HTTP version: {version}")
                return False, "", "", {}
            if method not in ["GET", "POST"]:
                logger.warning(f"Unsupported HTTP method: {method}")
                return False, "", "", {}
            if not uri.startswith("/"):
                logger.warning(f"Invalid URI format: {uri}")
                return False, "", "", {}

            # Extract headers
            headers = {}
            for line in lines[1:]:
                if line.strip() == "":
                    break
                if ':' in line:
                    key, value = line.split(':', 1)
                    headers[key.strip().lower()] = value.strip()

            return True, method, uri, headers

        except Exception as e:
            logger.error(f"Error parsing request: {e}")
            return False, "", "", {}

    def extract_post_data(self, request_str):
        """
        Extract POST data from HTTP request body.

        Args:
            request_str (str): Complete HTTP request string

        Returns:
            str: POST data body or empty string if not found
        """
        try:
            # Find message body (after \r\n\r\n)
            body_start = request_str.find('\r\n\r\n')
            if body_start != -1:
                return request_str[body_start + 4:]
            return ""
        except:
            return ""

    def handle_get_request(self, uri):
        """
        Handle HTTP GET requests.

        Routes GET requests to appropriate handlers based on URI path.
        Serves registration page, blocked content page, or static files.

        Args:
            uri (str): Request URI path

        Returns:
            bytes: HTTP response data
        """
        try:
            # Home page / registration page
            if uri == "/" or uri == "/register":
                if not self.child_name:
                    # Registration page
                    html_content = self.registration_html
                    return self.create_response(200, "OK", html_content, "text/html")
                else:
                    # Block page
                    current_time = time.strftime('%H:%M:%S')
                    block_html = self.block_html_template.format(
                        child_name=self.child_name,
                        host="Blocked Site",
                        current_time=current_time
                    )
                    return self.create_response(200, "OK", block_html, "text/html")

            # Static files (if needed)
            elif uri.startswith("/static/"):
                return self.serve_static_file(uri)

            # 404 for everything else
            else:
                error_html = self.create_error_page("Page Not Found", "The requested page does not exist")
                return self.create_response(404, "NOT FOUND", error_html, "text/html")

        except Exception as e:
            logger.error(f"Error handling GET request: {e}")
            return self.create_error_response(500, "Internal Server Error")

    def handle_post_request(self, uri, post_data):
        """
        Handle HTTP POST requests.

        Routes POST requests to appropriate handlers, primarily for registration processing.

        Args:
            uri (str): Request URI path
            post_data (str): POST request body data

        Returns:
            bytes: HTTP response data
        """
        try:
            if uri == "/register":
                # Handle registration
                return self.handle_registration(post_data)
            else:
                return self.create_error_response(404, "Not Found")

        except Exception as e:
            logger.error(f"Error handling POST request: {e}")
            return self.create_error_response(500, "Internal Server Error")

    def handle_registration(self, post_data):
        """
        Handle child registration requests.

        Processes registration form data, validates input, and calls verification
        callback to authenticate the child with the parent system.

        Args:
            post_data (str): Form data from registration request

        Returns:
            bytes: HTTP response with success or error page
        """
        try:
            # Decode form data
            form_data = parse_qs(post_data)
            child_name = ""

            if 'child_name' in form_data:
                child_name = form_data['child_name'][0].strip()

            logger.info(f"Registration attempt: '{child_name}'")

            # Validation checks
            if not child_name:
                if self.external_create_error_page:
                    error_html = self.external_create_error_page("Error", "Name cannot be empty!",
                                                                 back_button=True, retry_button=True)
                else:
                    error_html = self.create_error_page("Error", "Name cannot be empty!")
                return self.create_response(400, "BAD REQUEST", error_html, "text/html")

            if len(child_name) < 2:
                if self.external_create_error_page:
                    error_html = self.external_create_error_page("Error", "Name must contain at least 2 characters!",
                                                                 back_button=True, retry_button=True)
                else:
                    error_html = self.create_error_page("Error", "Name must contain at least 2 characters!")
                return self.create_response(400, "BAD REQUEST", error_html, "text/html")

            # Call verification function from main system
            if self.verify_child_callback:
                if self.verify_child_callback(child_name):
                    # Registration successful
                    self.child_name = child_name
                    logger.info(f"Child '{child_name}' registered successfully")

                    if self.external_create_success_page:
                        success_html = self.external_create_success_page(
                            f"Welcome {child_name}!",
                            "You have been successfully registered in the parental control system<br>You can now browse the internet safely"
                        )
                    else:
                        success_html = self.create_success_page(
                            f"Welcome {child_name}!",
                            "You have been successfully registered in the parental control system<br>You can now browse the internet safely"
                        )
                    return self.create_response(200, "OK", success_html, "text/html")
                else:
                    # Child not registered in system
                    logger.warning(f"Child '{child_name}' not found in system")

                    if self.external_create_error_page:
                        error_html = self.external_create_error_page(
                            "Not Registered in System",
                            f"The name '{child_name}' is not registered in the parental control system.<br>Please ask your parents to add you through the control panel.",
                            back_button=True,
                            retry_button=True
                        )
                    else:
                        error_html = self.create_error_page(
                            "Not Registered in System",
                            f"The name '{child_name}' is not registered in the parental control system.<br>Please ask your parents to add you through the control panel."
                        )
                    return self.create_response(403, "FORBIDDEN", error_html, "text/html")
            else:
                logger.error("Registration system not available - no callback configured")
                return self.create_error_response(500, "Registration system not available")

        except Exception as e:
            logger.error(f"Error handling registration: {e}")
            return self.create_error_response(500, "Internal Server Error")

    def serve_static_file(self, uri):
        """
        Serve static files (CSS, JS, images, etc.).

        Handles requests for static content with basic security checks
        to prevent directory traversal attacks.

        Args:
            uri (str): URI path for static file

        Returns:
            bytes: HTTP response with file content or error
        """
        try:
            # Remove /static/ from beginning
            file_path = uri[8:]  # Remove /static/

            # Security check - prevent ../ attacks
            if ".." in file_path or file_path.startswith("/"):
                logger.warning(f"Blocked potential directory traversal attempt: {file_path}")
                return self.create_error_response(403, "Forbidden")

            # Determine content type
            file_extension = os.path.splitext(file_path)[1].lower()
            content_type = CONTENT_TYPES.get(file_extension, "application/octet-stream")

            # Read file (this is just an example - in practice you need to verify file exists)
            file_data = b"<h1>Static file not implemented</h1>"

            return self.create_response(200, "OK", file_data, content_type)

        except Exception as e:
            logger.error(f"Error serving static file: {e}")
            return self.create_error_response(404, "File Not Found")

    def create_response(self, status_code, status_text, content, content_type):
        """
        Create complete HTTP response.

        Builds proper HTTP response with headers and body content.

        Args:
            status_code (int): HTTP status code
            status_text (str): HTTP status text
            content (str|bytes): Response body content
            content_type (str): MIME content type

        Returns:
            bytes: Complete HTTP response
        """
        try:
            # Convert to bytes if needed
            if isinstance(content, str):
                content_bytes = content.encode('utf-8')
            else:
                content_bytes = content

            # Build headers
            response_line = f"{HTTP_VERSION} {status_code} {status_text}\r\n"
            headers = f"Content-Type: {content_type}\r\n"
            headers += f"Content-Length: {len(content_bytes)}\r\n"
            headers += "Connection: close\r\n"
            headers += "\r\n"

            # Combine everything
            response_headers = (response_line + headers).encode('utf-8')
            return response_headers + content_bytes

        except Exception as e:
            logger.error(f"Error creating response: {e}")
            return self.create_error_response(500, "Internal Server Error")

    def create_error_response(self, status_code, status_text):
        """
        Create HTTP error response.

        Generates standardized error response with HTML content.

        Args:
            status_code (int): HTTP error status code
            status_text (str): HTTP error status text

        Returns:
            bytes: HTTP error response
        """
        error_html = f"""
       <!DOCTYPE html>
       <html lang="en">
       <head>
           <meta charset="UTF-8">
           <title>Error {status_code}</title>
       </head>
       <body>
           <h1>Error {status_code}</h1>
           <p>{status_text}</p>
       </body>
       </html>
       """
        return self.create_response(status_code, status_text, error_html, "text/html")

    def create_error_page(self, title, message):
        """
        Create styled error page.

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
               .error-container {{ max-width: 500px; margin: 0 auto; }}
               .error-title {{ color: #e74c3c; font-size: 24px; margin-bottom: 20px; }}
               .error-message {{ color: #666; margin-bottom: 30px; }}
               .btn {{ padding: 10px 20px; background: #3498db; color: white; text-decoration: none; border-radius: 5px; }}
           </style>
       </head>
       <body>
           <div class="error-container">
               <h1 class="error-title">{title}</h1>
               <p class="error-message">{message}</p>
               <a href="/" class="btn">Back to Home</a>
           </div>
       </body>
       </html>
       """

    def create_success_page(self, title, message):
        """
        Create styled success page.

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
               .success-container {{ max-width: 500px; margin: 0 auto; background: white; padding: 40px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
               .success-title {{ color: #27ae60; font-size: 28px; margin-bottom: 20px; }}
               .success-message {{ color: #666; margin-bottom: 30px; font-size: 16px; }}
               .checkmark {{ font-size: 60px; color: #27ae60; margin-bottom: 20px; }}
           </style>
       </head>
       <body>
           <div class="success-container">
               <div class="checkmark">✓</div>
               <h1 class="success-title">{title}</h1>
               <p class="success-message">{message}</p>
           </div>
       </body>
       </html>
       """

    def send_response(self, client_socket, response):
        """
        Send HTTP response to client.

        Sends response data to client socket, handling partial sends
        and potential socket errors gracefully.

        Args:
            client_socket (socket): Client socket connection
            response (bytes): Complete HTTP response data
        """
        try:
            sent = 0
            while sent < len(response):
                bytes_sent = client_socket.send(response[sent:])
                if bytes_sent == 0:
                    break
                sent += bytes_sent
            logger.debug(f"Response sent successfully ({len(response)} bytes)")
        except socket.error as e:
            logger.error(f"Error sending response: {e}")


# Example usage if running file directly
if __name__ == "__main__":
    logger.info("Running custom HTTP server example...")

    # Create server
    server = ParentalControlHTTPServer("127.0.0.1", 8080)

    # Set simple templates for testing
    registration_html = """
   <!DOCTYPE html>
   <html lang="en">
   <head><meta charset="UTF-8"><title>Registration Page</title></head>
   <body>
       <h1>Registration Page</h1>
       <form method="post" action="/register">
           <input name="child_name" placeholder="Child Name" required>
           <button type="submit">Register</button>
       </form>
   </body>
   </html>
   """

    block_html = """
   <!DOCTYPE html>
   <html lang="en">
   <head><meta charset="UTF-8"><title>Site Blocked</title></head>
   <body>
       <h1>Site Blocked</h1>
       <p>Child: {child_name}</p>
       <p>Time: {current_time}</p>
   </body>
   </html>
   """

    server.set_templates(registration_html, block_html)


    def verify_child_example(name):
        """Example verification function for testing."""
        allowed_children = ["child1", "child2", "test"]
        return name in allowed_children


    server.set_verify_callback(verify_child_example)

    # Start server
    try:
        logger.info("Server running on http://127.0.0.1:8080")
        logger.info("Press Ctrl+C to stop")
        server.start_server()
    except KeyboardInterrupt:
        logger.info("Stopping server...")
        server.stop_server()