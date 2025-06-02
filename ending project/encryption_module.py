import os
import json
import logging
from cryptography.fernet import Fernet
import base64

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class SimpleEncryption:
    """
    Simple and secure encryption module that doesn't disrupt existing code.

    Provides AES encryption for text and JSON data using Fernet (AES 128-bit + HMAC).
    Handles key generation, storage, and provides easy-to-use encryption/decryption methods.
    """

    def __init__(self, key_name="parent_system"):
        """
        Initialize encryption system with specified key name.

        Args:
            key_name (str): Name identifier for the encryption key file
        """
        self.key_name = key_name
        self.key_file = f"{key_name}_encryption.key"
        self.fernet = self._get_or_create_key()
        logger.info(f"Encryption module ready: {key_name}")

    def _get_or_create_key(self):
        """
        Create or load encryption key.

        Loads existing key from file if available, otherwise generates
        a new Fernet key and saves it securely to disk.

        Returns:
            Fernet: Initialized Fernet encryption object
        """
        if os.path.exists(self.key_file):
            # Load existing key
            with open(self.key_file, 'rb') as f:
                key = f.read()
            logger.info(f"Encryption key loaded: {self.key_file}")
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

            logger.info(f"New encryption key created: {self.key_file}")

        return Fernet(key)

    def encrypt_text(self, text):
        """
        Encrypt text string.

        Args:
            text (str): Plain text to encrypt

        Returns:
            str: Base64-encoded encrypted text
        """
        if isinstance(text, str):
            text = text.encode('utf-8')

        encrypted = self.fernet.encrypt(text)
        return base64.b64encode(encrypted).decode('utf-8')

    def decrypt_text(self, encrypted_text):
        """
        Decrypt text string.

        Args:
            encrypted_text (str): Base64-encoded encrypted text

        Returns:
            str: Decrypted plain text or None if decryption fails
        """
        try:
            encrypted_bytes = base64.b64decode(encrypted_text.encode('utf-8'))
            decrypted = self.fernet.decrypt(encrypted_bytes)
            return decrypted.decode('utf-8')
        except Exception as e:
            logger.error(f"Decryption error: {e}")
            return None

    def encrypt_json(self, data):
        """
        Encrypt dictionary/list to encrypted JSON.

        Args:
            data (dict|list): Data structure to encrypt

        Returns:
            str: Encrypted JSON string
        """
        json_str = json.dumps(data, ensure_ascii=False, indent=2)
        return self.encrypt_text(json_str)

    def decrypt_json(self, encrypted_text):
        """
        Decrypt JSON to dictionary/list.

        Args:
            encrypted_text (str): Encrypted JSON string

        Returns:
            dict|list: Decrypted data structure or None if decryption fails
        """
        json_str = self.decrypt_text(encrypted_text)
        if json_str:
            try:
                return json.loads(json_str)
            except json.JSONDecodeError as e:
                logger.error(f"JSON decode error: {e}")
        return None


class SafeFileManager:
    """
    Safe file manager with automatic backup functionality.

    Provides secure file operations with automatic backup creation,
    encryption support, and fallback recovery mechanisms.
    """

    def __init__(self, encryption=None):
        """
        Initialize file manager with optional encryption.

        Args:
            encryption (SimpleEncryption): Encryption instance for secure file operations
        """
        self.encryption = encryption

    def safe_save_json(self, filename, data, encrypted=False):
        """
        Safe save with automatic backup.

        Creates backup of existing file before saving new data.
        Supports both encrypted and plain text storage modes.

        Args:
            filename (str): Target filename for saving
            data (dict|list): Data to save
            encrypted (bool): Whether to encrypt the data

        Returns:
            bool: True if save successful, False otherwise
        """
        try:
            # Create backup if file exists
            if os.path.exists(filename):
                backup_name = f"{filename}.backup"
                import shutil
                shutil.copy2(filename, backup_name)
                logger.debug(f"Backup created: {backup_name}")

            # Prepare content
            if encrypted and self.encryption:
                # Encrypted mode
                content = self.encryption.encrypt_json(data)
                with open(f"{filename}.encrypted", 'w', encoding='utf-8') as f:
                    f.write(content)
                logger.info(f"File saved encrypted: {filename}.encrypted")
            else:
                # Regular mode (for now)
                with open(filename, 'w', encoding='utf-8') as f:
                    json.dump(data, f, ensure_ascii=False, indent=2)
                logger.info(f"File saved regular: {filename}")

            return True

        except Exception as e:
            logger.error(f"Error saving {filename}: {e}")

            # Attempt recovery from backup
            backup_name = f"{filename}.backup"
            if os.path.exists(backup_name):
                try:
                    import shutil
                    shutil.copy2(backup_name, filename)
                    logger.info(f"Recovered from backup: {backup_name}")
                except:
                    pass

            return False

    def safe_load_json(self, filename, encrypted=False):
        """
        Safe load with fallback options.

        Attempts to load data from multiple sources in order of preference:
        encrypted file, regular file, backup file.

        Args:
            filename (str): Base filename to load
            encrypted (bool): Whether to attempt encrypted loading

        Returns:
            dict: Loaded data or empty dict if all attempts fail
        """
        files_to_try = []

        if encrypted and self.encryption:
            files_to_try.append((f"{filename}.encrypted", True))

        files_to_try.extend([
            (filename, False),
            (f"{filename}.backup", False)
        ])

        for file_path, is_encrypted in files_to_try:
            if not os.path.exists(file_path):
                continue

            try:
                if is_encrypted:
                    # Encrypted file
                    with open(file_path, 'r', encoding='utf-8') as f:
                        encrypted_content = f.read()
                    data = self.encryption.decrypt_json(encrypted_content)
                    if data is not None:
                        logger.info(f"Encrypted file loaded: {file_path}")
                        return data
                else:
                    # Regular file
                    with open(file_path, 'r', encoding='utf-8') as f:
                        data = json.load(f)
                    logger.info(f"Regular file loaded: {file_path}")
                    return data

            except Exception as e:
                logger.warning(f"Cannot load {file_path}: {e}")
                continue

        logger.error(f"Cannot load {filename}")
        return {}


def test_encryption_safety():
    """
    Test that encryption system works properly.

    Performs comprehensive tests of encryption functionality including
    text encryption, JSON encryption, and file operations.

    Returns:
        bool: True if all tests pass, False otherwise
    """
    logger.info("Testing encryption system...")

    # Test 1: Simple encryption
    crypto = SimpleEncryption("test")

    original = "Hello World! Test message"
    encrypted = crypto.encrypt_text(original)
    decrypted = crypto.decrypt_text(encrypted)

    logger.info(f"Original: {original}")
    logger.info(f"Encrypted: {encrypted[:50]}...")
    logger.info(f"Decrypted: {decrypted}")

    if original == decrypted:
        logger.info("Text encryption works!")
    else:
        logger.error("Problem with text encryption!")
        return False

    # Test 2: JSON encryption
    test_data = {
        "child1": {"blocked_domains": ["facebook.com", "youtube.com"]},
        "child2": {"blocked_domains": ["instagram.com"]}
    }

    encrypted_json = crypto.encrypt_json(test_data)
    decrypted_json = crypto.decrypt_json(encrypted_json)

    if test_data == decrypted_json:
        logger.info("JSON encryption works!")
    else:
        logger.error("Problem with JSON encryption!")
        return False

    # Test 3: Save and load
    file_manager = SafeFileManager(crypto)

    test_filename = "test_safe_file.json"

    # Regular save
    if file_manager.safe_save_json(test_filename, test_data, encrypted=False):
        loaded_data = file_manager.safe_load_json(test_filename, encrypted=False)
        if loaded_data == test_data:
            logger.info("Regular save and load work!")
        else:
            logger.error("Problem with regular save/load!")
            return False

    # Encrypted save
    if file_manager.safe_save_json(test_filename, test_data, encrypted=True):
        loaded_data = file_manager.safe_load_json(test_filename, encrypted=True)
        if loaded_data == test_data:
            logger.info("Encrypted save and load work!")
        else:
            logger.error("Problem with encrypted save/load!")
            return False

    # Cleanup test files
    for f in [test_filename, f"{test_filename}.encrypted", f"{test_filename}.backup"]:
        if os.path.exists(f):
            os.remove(f)

    # Cleanup test key
    if os.path.exists("test_encryption.key"):
        os.remove("test_encryption.key")

    logger.info("All tests passed successfully!")
    logger.info("Safe to start using the encryption system")
    return True


def show_next_step_instructions():
    """
    Detailed instructions for next steps.

    Displays comprehensive instructions for integrating the encryption
    module into the existing system safely.
    """
    instructions = """
Next Step Instructions:

1. Save this code to a new file: encryption_module.py

2. Run safety test:
  python -c "from encryption_module import test_encryption_safety; test_encryption_safety()"

3. If test passes - we're ready for the next step!

4. In the next step we'll add encryption to the existing system
  without breaking anything

WARNING: Don't change anything in the existing code yet!
        This is just preparation for the next step.
"""
    logger.info(instructions)


# Automatic test execution
if __name__ == "__main__":
    test_encryption_safety()
    show_next_step_instructions()