import os
import json
import secrets
from cryptography.fernet import Fernet
import base64


class SimpleEncryption:
    """🔒 מודול הצפנה פשוט ובטוח - לא משבש קוד קיים"""

    def __init__(self, key_name="parent_system"):
        self.key_name = key_name
        self.key_file = f"{key_name}_encryption.key"
        self.fernet = self._get_or_create_key()
        print(f"[🔒] מודול הצפנה מוכן: {key_name}")

    def _get_or_create_key(self):
        """יצירה או טעינת מפתח הצפנה"""
        if os.path.exists(self.key_file):
            # טעינת מפתח קיים
            with open(self.key_file, 'rb') as f:
                key = f.read()
            print(f"[🔒] מפתח הצפנה נטען: {self.key_file}")
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

            print(f"[🔒] מפתח הצפנה חדש נוצר: {self.key_file}")

        return Fernet(key)

    def encrypt_text(self, text):
        """הצפנת טקסט"""
        if isinstance(text, str):
            text = text.encode('utf-8')

        encrypted = self.fernet.encrypt(text)
        return base64.b64encode(encrypted).decode('utf-8')

    def decrypt_text(self, encrypted_text):
        """פענוח טקסט"""
        try:
            encrypted_bytes = base64.b64decode(encrypted_text.encode('utf-8'))
            decrypted = self.fernet.decrypt(encrypted_bytes)
            return decrypted.decode('utf-8')
        except Exception as e:
            print(f"[❌] שגיאה בפענוח: {e}")
            return None

    def encrypt_json(self, data):
        """הצפנת מילון/רשימה לJSON מוצפן"""
        json_str = json.dumps(data, ensure_ascii=False, indent=2)
        return self.encrypt_text(json_str)

    def decrypt_json(self, encrypted_text):
        """פענוח JSON למילון/רשימה"""
        json_str = self.decrypt_text(encrypted_text)
        if json_str:
            try:
                return json.loads(json_str)
            except json.JSONDecodeError as e:
                print(f"[❌] שגיאה ב-JSON: {e}")
        return None


class SafeFileManager:
    """💾 מנהל קבצים בטוח - עם גיבוי אוטומטי"""

    def __init__(self, encryption=None):
        self.encryption = encryption

    def safe_save_json(self, filename, data, encrypted=False):
        """שמירה בטוחה עם גיבוי"""
        try:
            # יצירת גיבוי אם הקובץ קיים
            if os.path.exists(filename):
                backup_name = f"{filename}.backup"
                import shutil
                shutil.copy2(filename, backup_name)
                print(f"[💾] גיבוי נוצר: {backup_name}")

            # הכנת התוכן
            if encrypted and self.encryption:
                # מצב מוצפן
                content = self.encryption.encrypt_json(data)
                with open(f"{filename}.encrypted", 'w', encoding='utf-8') as f:
                    f.write(content)
                print(f"[💾] קובץ נשמר מוצפן: {filename}.encrypted")
            else:
                # מצב רגיל (בינתיים)
                with open(filename, 'w', encoding='utf-8') as f:
                    json.dump(data, f, ensure_ascii=False, indent=2)
                print(f"[💾] קובץ נשמר רגיל: {filename}")

            return True

        except Exception as e:
            print(f"[❌] שגיאה בשמירת {filename}: {e}")

            # נסיון שחזור מגיבוי
            backup_name = f"{filename}.backup"
            if os.path.exists(backup_name):
                try:
                    import shutil
                    shutil.copy2(backup_name, filename)
                    print(f"[🔄] שוחזר מגיבוי: {backup_name}")
                except:
                    pass

            return False

    def safe_load_json(self, filename, encrypted=False):
        """טעינה בטוחה עם fallback"""
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
                    # קובץ מוצפן
                    with open(file_path, 'r', encoding='utf-8') as f:
                        encrypted_content = f.read()
                    data = self.encryption.decrypt_json(encrypted_content)
                    if data is not None:
                        print(f"[💾] קובץ מוצפן נטען: {file_path}")
                        return data
                else:
                    # קובץ רגיל
                    with open(file_path, 'r', encoding='utf-8') as f:
                        data = json.load(f)
                    print(f"[💾] קובץ רגיל נטען: {file_path}")
                    return data

            except Exception as e:
                print(f"[⚠️] לא ניתן לטעון {file_path}: {e}")
                continue

        print(f"[❌] לא ניתן לטעון {filename}")
        return {}


# 🧪 בדיקות בטיחות לפני השימוש
def test_encryption_safety():
    """בדיקה שההצפנה עובדת טוב"""
    print("\n🧪 בודק את מערכת ההצפנה...")

    # בדיקה 1: הצפנה פשוטה
    crypto = SimpleEncryption("test")

    original = "שלום עולם! 🌍"
    encrypted = crypto.encrypt_text(original)
    decrypted = crypto.decrypt_text(encrypted)

    print(f"מקורי: {original}")
    print(f"מוצפן: {encrypted[:50]}...")
    print(f"מפוענח: {decrypted}")

    if original == decrypted:
        print("✅ הצפנת טקסט עובדת!")
    else:
        print("❌ בעיה בהצפנת טקסט!")
        return False

    # בדיקה 2: הצפנת JSON
    test_data = {
        "ילד1": {"blocked_domains": ["facebook.com", "youtube.com"]},
        "ילד2": {"blocked_domains": ["instagram.com"]}
    }

    encrypted_json = crypto.encrypt_json(test_data)
    decrypted_json = crypto.decrypt_json(encrypted_json)

    if test_data == decrypted_json:
        print("✅ הצפנת JSON עובדת!")
    else:
        print("❌ בעיה בהצפנת JSON!")
        return False

    # בדיקה 3: שמירה וטעינה
    file_manager = SafeFileManager(crypto)

    test_filename = "test_safe_file.json"

    # שמירה רגילה
    if file_manager.safe_save_json(test_filename, test_data, encrypted=False):
        loaded_data = file_manager.safe_load_json(test_filename, encrypted=False)
        if loaded_data == test_data:
            print("✅ שמירה וטעינה רגילה עובדות!")
        else:
            print("❌ בעיה בשמירה/טעינה רגילה!")
            return False

    # שמירה מוצפנת
    if file_manager.safe_save_json(test_filename, test_data, encrypted=True):
        loaded_data = file_manager.safe_load_json(test_filename, encrypted=True)
        if loaded_data == test_data:
            print("✅ שמירה וטעינה מוצפנת עובדות!")
        else:
            print("❌ בעיה בשמירה/טעינה מוצפנת!")
            return False

    # ניקוי קבצי בדיקה
    for f in [test_filename, f"{test_filename}.encrypted", f"{test_filename}.backup"]:
        if os.path.exists(f):
            os.remove(f)

    # ניקוי מפתח בדיקה
    if os.path.exists("test_encryption.key"):
        os.remove("test_encryption.key")

    print("🎉 כל הבדיקות עברו בהצלחה!")
    print("✅ בטוח להתחיל להשתמש במערכת ההצפנה")
    return True


# 📋 הוראות לשלב הבא
def show_next_step_instructions():
    """הוראות מפורטות לשלב הבא"""
    print("""
📋 הוראות לשלב הבא:

1. 💾 שמור את הקוד הזה בקובץ חדש: encryption_module.py

2. 🧪 הרץ בדיקת בטיחות:
   python -c "from encryption_module import test_encryption_safety; test_encryption_safety()"

3. ✅ אם הבדיקה עברה - אנחנו מוכנים לשלב הבא!

4. 🔄 בשלב הבא נוסיף את ההצפנה למערכת הקיימת
   בלי לשבור שום דבר

⚠️  אל תשנה עדיין שום דבר בקוד הקיים!
    זה רק הכנה לשלב הבא.
""")


# הרצה אוטומטית של בדיקות
if __name__ == "__main__":
    test_encryption_safety()
    show_next_step_instructions()