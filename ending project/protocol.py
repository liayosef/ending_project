import json
import struct
import os
from cryptography.fernet import Fernet
import base64

# פורט תקשורת בין הורה לילד
COMMUNICATION_PORT = 5005


class EncryptionManager:
    """מנהל הצפנה לתקשורת"""

    def __init__(self, key_file="communication_key.key"):
        self.key_file = key_file
        self.fernet = self._get_or_create_key()

    def _get_or_create_key(self):
        """יצירה או טעינת מפתח הצפנה לתקשורת"""
        if os.path.exists(self.key_file):
            # טעינת מפתח קיים
            with open(self.key_file, 'rb') as f:
                key = f.read()
            print(f"[🔒] מפתח תקשורת נטען: {self.key_file}")
        else:
            # יצירת מפתח חדש
            key = Fernet.generate_key()
            with open(self.key_file, 'wb') as f:
                f.write(key)

            # הגנה על הקובץ
            try:
                os.chmod(self.key_file, 0o600)
            except:
                pass

            print(f"[🔒] מפתח תקשורת חדש נוצר: {self.key_file}")

        return Fernet(key)

    def encrypt_data(self, data):
        """הצפנת נתונים"""
        try:
            if isinstance(data, dict):
                data_str = json.dumps(data, ensure_ascii=False)
            else:
                data_str = str(data)

            data_bytes = data_str.encode('utf-8')
            encrypted = self.fernet.encrypt(data_bytes)
            return base64.b64encode(encrypted).decode('utf-8')
        except Exception as e:
            print(f"[❌] שגיאה בהצפנת נתונים: {e}")
            return None

    def decrypt_data(self, encrypted_data):
        """פענוח נתונים"""
        try:
            encrypted_bytes = base64.b64decode(encrypted_data.encode('utf-8'))
            decrypted = self.fernet.decrypt(encrypted_bytes)
            data_str = decrypted.decode('utf-8')

            # נסיון לפענח כ-JSON
            try:
                return json.loads(data_str)
            except json.JSONDecodeError:
                return data_str
        except Exception as e:
            print(f"[❌] שגיאה בפענוח נתונים: {e}")
            return None


class Protocol:
    # הודעות קיימות
    REGISTER_CHILD = "register_child"
    ACK = "ack"
    UPDATE_DOMAINS = "update_domains"
    GET_DOMAINS = "get_domains"
    CHILD_STATUS = "child_status"
    BROWSING_HISTORY = "browsing_history"
    GET_HISTORY = "get_history"
    ERROR = "error"

    # הודעות חדשות למערכת רישום
    VERIFY_CHILD = "verify_child"
    VERIFY_RESPONSE = "verify_response"

    # הודעות הצפנה
    ENCRYPTED_DATA = "encrypted_data"
    HANDSHAKE = "handshake"

    # מנהל הצפנה גלובלי
    _encryption_manager = None

    @classmethod
    def get_encryption_manager(cls):
        """קבלת מנהל ההצפנה (Singleton)"""
        if cls._encryption_manager is None:
            cls._encryption_manager = EncryptionManager()
        return cls._encryption_manager

    @staticmethod
    def send_message(sock, msg_type, data=None, encrypted=True):
        """שליחת הודעה עם פרוטוקול קבוע - גרסה מוצפנת"""
        if data is None:
            data = {}

        # אם צריך הצפנה
        if encrypted and msg_type not in [Protocol.HANDSHAKE, Protocol.ERROR]:
            encryption_manager = Protocol.get_encryption_manager()

            # הצפנת הנתונים
            encrypted_data = encryption_manager.encrypt_data(data)
            if encrypted_data is None:
                # אם ההצפנה נכשלה, שלח רגיל
                print("[⚠️] הצפנה נכשלה - שולח רגיל")
                encrypted = False
            else:
                # יצירת הודעה מוצפנת
                message = {
                    "type": Protocol.ENCRYPTED_DATA,
                    "original_type": msg_type,
                    "data": encrypted_data,
                    "encrypted": True
                }

        if not encrypted:
            # הודעה רגילה (לא מוצפנת)
            message = {
                "type": msg_type,
                "data": data,
                "encrypted": False
            }

        try:
            message_json = json.dumps(message, ensure_ascii=False)
            message_bytes = message_json.encode('utf-8')

            # שליחת אורך ההודעה ואז ההודעה עצמה
            length = struct.pack('!I', len(message_bytes))
            sock.sendall(length + message_bytes)

            # הדפסת לוג
            if encrypted:
                print(f"[📤🔒] נשלחה הודעה מוצפנת: {msg_type}")
            else:
                print(f"[📤] נשלחה הודעה רגילה: {msg_type}")

        except Exception as e:
            print(f"[❌] שגיאה בשליחת הודעה: {e}")
            raise

    @staticmethod
    def receive_message(sock):
        """קבלת הודעה עם פרוטוקול קבוע - גרסה מוצפנת"""
        try:
            # קבלת אורך ההודעה
            length_data = sock.recv(4)
            if len(length_data) < 4:
                raise ConnectionError("Connection closed unexpectedly")

            length = struct.unpack('!I', length_data)[0]

            # קבלת ההודעה עצמה
            message_bytes = b""
            while len(message_bytes) < length:
                chunk = sock.recv(length - len(message_bytes))
                if not chunk:
                    raise ConnectionError("Connection closed unexpectedly")
                message_bytes += chunk

            message_json = message_bytes.decode('utf-8')
            message = json.loads(message_json)

            # בדיקה אם ההודעה מוצפנת
            if message.get("type") == Protocol.ENCRYPTED_DATA and message.get("encrypted", False):
                encryption_manager = Protocol.get_encryption_manager()

                # פענוח הנתונים
                decrypted_data = encryption_manager.decrypt_data(message["data"])
                if decrypted_data is None:
                    print("[❌] פענוח נכשל")
                    return Protocol.ERROR, {"message": "Decryption failed"}

                original_type = message.get("original_type", "unknown")
                print(f"[📥🔒] התקבלה הודעה מוצפנת: {original_type}")
                return original_type, decrypted_data
            else:
                # הודעה רגילה (לא מוצפנת)
                msg_type = message["type"]
                data = message.get("data", {})
                print(f"[📥] התקבלה הודעה רגילה: {msg_type}")
                return msg_type, data

        except Exception as e:
            print(f"[❌] שגיאה בקבלת הודעה: {e}")
            raise

    @staticmethod
    def send_handshake(sock):
        """שליחת לחיצת יד ראשונית (לא מוצפנת)"""
        Protocol.send_message(sock, Protocol.HANDSHAKE,
                              {"version": "1.0", "encryption": "enabled"},
                              encrypted=False)

    @staticmethod
    def test_encryption():
        """בדיקת מערכת ההצפנה"""
        print("\n🧪 בודק מערכת הצפנת תקשורת...")

        try:
            encryption_manager = Protocol.get_encryption_manager()

            # בדיקת הצפנה פשוטה
            test_data = {"message": "שלום עולם! 🌍", "number": 123}

            encrypted = encryption_manager.encrypt_data(test_data)
            if encrypted is None:
                print("❌ הצפנה נכשלה")
                return False

            decrypted = encryption_manager.decrypt_data(encrypted)
            if decrypted != test_data:
                print("❌ פענוח נכשל")
                return False

            print("✅ הצפנת תקשורת עובדת!")
            print(f"✅ מפתח נמצא ב: {encryption_manager.key_file}")
            return True

        except Exception as e:
            print(f"❌ שגיאה בבדיקת הצפנה: {e}")
            return False


# פונקציות עזר לתאימות לאחור
def send_message(sock, msg_type, data=None):
    """פונקציה ישנה - עכשיו עם הצפנה"""
    return Protocol.send_message(sock, msg_type, data, encrypted=True)


def receive_message(sock):
    """פונקציה ישנה - עכשיו עם פענוח"""
    return Protocol.receive_message(sock)


# בדיקה אוטומטית כשטוענים את המודול
if __name__ == "__main__":
    print("🔒 מערכת תקשורת מוצפנת")
    success = Protocol.test_encryption()

    if success:
        print("\n✅ המערכת מוכנה לשימוש!")
        print("📋 הוראות:")
        print("1. השתמש ב-Protocol.send_message() ו-Protocol.receive_message()")
        print("2. כל התקשורת מוצפנת אוטומטית")
        print("3. המפתח נשמר ב-communication_key.key")
        print("4. העתק את הקובץ לכל הלקוחות!")
    else:
        print("\n❌ יש בעיה במערכת ההצפנה")
        print("🔧 בדוק שיש לך: pip install cryptography")