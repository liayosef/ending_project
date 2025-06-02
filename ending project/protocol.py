import json
import struct
import os
import logging
from cryptography.fernet import Fernet
import base64

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Communication port between parent and child
COMMUNICATION_PORT = 5005


class EncryptionManager:
    """
    Encryption manager for communication - synchronized with parent system.

    Handles encryption and decryption of communication data between parent and child
    systems using Fernet (AES 128-bit + HMAC) encryption.
    """

    def __init__(self, key_file="communication_key.key"):
        """
        Initialize encryption manager with specified key file.

        Args:
            key_file (str): Path to the encryption key file
        """
        self.key_file = key_file
        self.fernet = self._get_or_create_key()

    def _get_or_create_key(self):
        """
        Create or load encryption key for communication.

        Loads existing key from file if available, otherwise generates
        a new Fernet key and saves it securely.

        Returns:
            Fernet: Initialized Fernet encryption object
        """
        if os.path.exists(self.key_file):
            # Load existing key
            with open(self.key_file, 'rb') as f:
                key = f.read()
            logger.info(f"Communication key loaded: {self.key_file}")
        else:
            # Create new key
            key = Fernet.generate_key()
            with open(self.key_file, 'wb') as f:
                f.write(key)

            # Secure file permissions
            try:
                os.chmod(self.key_file, 0o600)
            except:
                pass

            logger.info(f"New communication key created: {self.key_file}")

        return Fernet(key)

    def encrypt_data(self, data):
        """
        Encrypt data for secure transmission.

        Args:
            data (dict|str): Data to encrypt (dict will be JSON serialized)

        Returns:
            str: Base64-encoded encrypted data or None if encryption fails
        """
        try:
            if isinstance(data, dict):
                data_str = json.dumps(data, ensure_ascii=False)
            else:
                data_str = str(data)

            data_bytes = data_str.encode('utf-8')
            encrypted = self.fernet.encrypt(data_bytes)
            return base64.b64encode(encrypted).decode('utf-8')
        except Exception as e:
            logger.error(f"Data encryption error: {e}")
            return None

    def decrypt_data(self, encrypted_data):
        """
        Decrypt received data.

        Args:
            encrypted_data (str): Base64-encoded encrypted data

        Returns:
            dict|str: Decrypted data (JSON parsed to dict if applicable) or None if decryption fails
        """
        try:
            encrypted_bytes = base64.b64decode(encrypted_data.encode('utf-8'))
            decrypted = self.fernet.decrypt(encrypted_bytes)
            data_str = decrypted.decode('utf-8')

            # Attempt to parse as JSON
            try:
                return json.loads(data_str)
            except json.JSONDecodeError:
                return data_str
        except Exception as e:
            logger.error(f"Data decryption error: {e}")
            return None


class Protocol:
    """
    Encrypted communication protocol for parent-child system communication.

    Provides secure message passing with automatic encryption/decryption
    and standardized message types for system operations.
    """

    # Existing message types
    REGISTER_CHILD = "register_child"
    ACK = "ack"
    UPDATE_DOMAINS = "update_domains"
    GET_DOMAINS = "get_domains"
    CHILD_STATUS = "child_status"
    BROWSING_HISTORY = "browsing_history"
    GET_HISTORY = "get_history"
    ERROR = "error"

    # New messages for registration system
    VERIFY_CHILD = "verify_child"
    VERIFY_RESPONSE = "verify_response"

    # Encryption messages
    ENCRYPTED_DATA = "encrypted_data"
    HANDSHAKE = "handshake"

    # Global encryption manager
    _encryption_manager = None

    @classmethod
    def get_encryption_manager(cls):
        """
        Get encryption manager instance (Singleton pattern).

        Returns:
            EncryptionManager: Shared encryption manager instance
        """
        if cls._encryption_manager is None:
            cls._encryption_manager = EncryptionManager()
        return cls._encryption_manager

    @staticmethod
    def send_message(sock, msg_type, data=None, encrypted=True):
        """
        Send message with fixed protocol - encrypted version.

        Sends structured messages over socket with optional encryption.
        Messages are length-prefixed for reliable transmission.

        Args:
            sock (socket): Socket connection to send through
            msg_type (str): Type of message being sent
            data (dict): Message payload data
            encrypted (bool): Whether to encrypt the message

        Raises:
            Exception: If message sending fails
        """
        if data is None:
            data = {}

        # Apply encryption if needed
        if encrypted and msg_type not in [Protocol.ERROR]:
            encryption_manager = Protocol.get_encryption_manager()

            # Encrypt the data
            encrypted_data = encryption_manager.encrypt_data(data)
            if encrypted_data is None:
                # If encryption failed, send unencrypted
                logger.warning("Encryption failed - sending unencrypted")
                encrypted = False
            else:
                # Create encrypted message wrapper
                message = {
                    "type": Protocol.ENCRYPTED_DATA,
                    "original_type": msg_type,
                    "data": encrypted_data,
                    "encrypted": True
                }

        if not encrypted:
            # Regular message (unencrypted)
            message = {
                "type": msg_type,
                "data": data,
                "encrypted": False
            }

        try:
            message_json = json.dumps(message, ensure_ascii=False)
            message_bytes = message_json.encode('utf-8')

            # Send message length followed by message data
            length = struct.pack('!I', len(message_bytes))
            sock.sendall(length + message_bytes)

            # Log message
            if encrypted:
                logger.debug(f"Sent encrypted message: {msg_type}")
            else:
                logger.debug(f"Sent regular message: {msg_type}")

        except Exception as e:
            logger.error(f"Error sending message: {e}")
            raise

    @staticmethod
    def receive_message(sock):
        """
        Receive message with fixed protocol - encrypted version.

        Receives length-prefixed messages and automatically decrypts
        if the message is marked as encrypted.

        Args:
            sock (socket): Socket connection to receive from

        Returns:
            tuple: (message_type, message_data)

        Raises:
            Exception: If message reception or decryption fails
        """
        try:
            # Receive message length
            length_data = sock.recv(4)
            if len(length_data) < 4:
                raise ConnectionError("Connection closed unexpectedly")

            length = struct.unpack('!I', length_data)[0]

            # Receive message data
            message_bytes = b""
            while len(message_bytes) < length:
                chunk = sock.recv(length - len(message_bytes))
                if not chunk:
                    raise ConnectionError("Connection closed unexpectedly")
                message_bytes += chunk

            message_json = message_bytes.decode('utf-8')
            message = json.loads(message_json)

            # Check if message is encrypted
            if message.get("type") == Protocol.ENCRYPTED_DATA and message.get("encrypted", False):
                encryption_manager = Protocol.get_encryption_manager()

                # Decrypt the data
                decrypted_data = encryption_manager.decrypt_data(message["data"])
                if decrypted_data is None:
                    logger.error("Decryption failed")
                    return Protocol.ERROR, {"message": "Decryption failed"}

                original_type = message.get("original_type", "unknown")
                logger.debug(f"Received encrypted message: {original_type}")
                return original_type, decrypted_data
            else:
                # Regular message (unencrypted)
                msg_type = message["type"]
                data = message.get("data", {})
                logger.debug(f"Received regular message: {msg_type}")
                return msg_type, data

        except Exception as e:
            logger.error(f"Error receiving message: {e}")
            raise

    @staticmethod
    def send_handshake(sock):
        """
        Send initial handshake (now encrypted).

        Args:
            sock (socket): Socket connection for handshake
        """
        Protocol.send_message(sock, Protocol.HANDSHAKE,
                              {"version": "1.0", "encryption": "enabled"},
                              encrypted=True)

    @staticmethod
    def test_encryption():
        """
        Test encryption system functionality.

        Performs a round-trip encryption test to verify that the
        encryption system is working correctly.

        Returns:
            bool: True if encryption test passes, False otherwise
        """
        logger.info("Testing communication encryption system...")

        try:
            encryption_manager = Protocol.get_encryption_manager()

            # Simple encryption test
            test_data = {"message": "Hello World! Test", "number": 123}

            encrypted = encryption_manager.encrypt_data(test_data)
            if encrypted is None:
                logger.error("Encryption failed")
                return False

            decrypted = encryption_manager.decrypt_data(encrypted)
            if decrypted != test_data:
                logger.error("Decryption failed")
                return False

            logger.info("Communication encryption works!")
            logger.info(f"Key found at: {encryption_manager.key_file}")
            return True

        except Exception as e:
            logger.error(f"Encryption test error: {e}")
            return False

    @staticmethod
    def sync_encryption_keys():
        """
        Synchronize encryption keys between parent and child.

        Creates shared communication key if it doesn't exist.
        This key must be copied to all child devices.

        Returns:
            bool: True if key synchronization successful, False otherwise
        """
        try:
            # Create shared communication key if not exists
            key_file = "communication_key.key"
            if not os.path.exists(key_file):
                logger.info("Creating shared communication key...")
                key = Fernet.generate_key()
                with open(key_file, 'wb') as f:
                    f.write(key)

                # Secure file permissions
                try:
                    os.chmod(key_file, 0o600)
                except:
                    pass

                logger.info(f"Communication key created: {key_file}")
                logger.warning("Copy this file to all child devices!")
                return True
            else:
                logger.info(f"Communication key exists: {key_file}")
                return True

        except Exception as e:
            logger.error(f"Key synchronization error: {e}")
            return False


# Helper functions for backward compatibility
def send_message(sock, msg_type, data=None):
    """
    Legacy function - now with encryption.

    Args:
        sock (socket): Socket connection
        msg_type (str): Message type
        data (dict): Message data
    """
    return Protocol.send_message(sock, msg_type, data, encrypted=True)


def receive_message(sock):
    """
    Legacy function - now with decryption.

    Args:
        sock (socket): Socket connection

    Returns:
        tuple: (message_type, message_data)
    """
    return Protocol.receive_message(sock)


# Automatic test when loading module
if __name__ == "__main__":
    logger.info("Encrypted communication system")
    success = Protocol.test_encryption()

    if success:
        logger.info("System ready for use!")
        logger.info("Instructions:")
        logger.info("1. Use Protocol.send_message() and Protocol.receive_message()")
        logger.info("2. All communication is automatically encrypted")
        logger.info("3. Key is saved in communication_key.key")
        logger.info("4. Copy the file to all clients!")

        # Synchronize keys
        Protocol.sync_encryption_keys()
    else:
        logger.error("There is a problem with the encryption system")
        logger.info("Check that you have: pip install cryptography")