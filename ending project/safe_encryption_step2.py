# 🛡️ שלב 2: הוספת הצפנה למערכת הקיימת - בזהירות מקסימלית!
#
# נוסיף את ההצפנה לקוד הקיים בלי לשבור כלום
# עם אפשרות לחזור לאחור בכל רגע

from encryption_module import SimpleEncryption, SafeFileManager


class SafeParentServerUpgrade:
    """🔒 שדרוג בטוח למערכת בקרת הורים עם הצפנה"""

    def __init__(self, parent_server_instance):
        """
        מקבל את המופע הקיים של ParentServer ומוסיף לו הצפנה
        ללא שינוי הקוד הקיים!
        """
        # שמירת המופע המקורי
        self.original_server = parent_server_instance

        # הוספת מערכת ההצפנה
        self.encryption = SimpleEncryption("parent_control_system")
        self.file_manager = SafeFileManager(self.encryption)

        # דגל להפעלה/כיבוי של הצפנה
        self.encryption_enabled = False  # מתחילים כבוי לבטיחות

        print("[🔒 UPGRADE] שדרוג הצפנה מוכן - עדיין כבוי לבטיחות")
        print("[🔒 UPGRADE] קרא/י להוראות להפעלה בטוחה")

    def enable_encryption_safely(self):
        """הפעלת הצפנה בבטחה עם גיבויים"""
        print("\n🔒 מתחיל הפעלת הצפנה בטוחה...")

        # שלב 1: יצירת גיבויים של כל הקבצים
        backup_files = [
            'children_data.json',
            'browsing_history.json',
            'users_data.json'
        ]

        for filename in backup_files:
            if os.path.exists(filename):
                backup_name = f"{filename}.pre_encryption_backup"
                try:
                    import shutil
                    shutil.copy2(filename, backup_name)
                    print(f"[💾] גיבוי נוצר: {backup_name}")
                except Exception as e:
                    print(f"[❌] שגיאה בגיבוי {filename}: {e}")
                    print("[🚨] עוצר תהליך - לא בטוח להמשיך!")
                    return False

        # שלב 2: המרה הדרגתית לקבצים מוצפנים
        print("\n🔄 מתחיל המרת קבצים להצפנה...")

        # children_data
        if self._convert_file_to_encrypted('children_data.json'):
            print("✅ children_data הומר להצפנה")
        else:
            print("❌ שגיאה בהמרת children_data")
            return False

        # browsing_history
        if self._convert_file_to_encrypted('browsing_history.json'):
            print("✅ browsing_history הומר להצפנה")
        else:
            print("❌ שגיאה בהמרת browsing_history")
            return False

        # users_data
        if self._convert_file_to_encrypted('users_data.json'):
            print("✅ users_data הומר להצפנה")
        else:
            print("❌ שגיאה בהמרת users_data")
            return False

        # שלב 3: הפעלת מצב הצפנה
        self.encryption_enabled = True
        print("\n🎉 הצפנה הופעלה בהצלחה!")
        print("🔒 כל הקבצים החדשים יישמרו מוצפנים")

        return True

    def _convert_file_to_encrypted(self, filename):
        """המרת קובץ רגיל לקובץ מוצפן"""
        if not os.path.exists(filename):
            print(f"[⚠️] קובץ {filename} לא קיים - מדלג")
            return True

        try:
            # טעינת הקובץ הרגיל
            with open(filename, 'r', encoding='utf-8') as f:
                data = json.load(f)

            # שמירה מוצפנת
            success = self.file_manager.safe_save_json(filename, data, encrypted=True)

            if success:
                print(f"[🔒] {filename} הומר להצפנה")
                return True
            else:
                print(f"[❌] כישלון בהמרת {filename}")
                return False

        except Exception as e:
            print(f"[❌] שגיאה בהמרת {filename}: {e}")
            return False

    def disable_encryption_safely(self):
        """כיבוי הצפנה וחזרה למצב רגיל"""
        print("\n🔓 מכבה הצפנה וחוזר למצב רגיל...")

        self.encryption_enabled = False

        # שחזור מהקבצים הרגילים (אם קיימים)
        backup_files = [
            'children_data.json.pre_encryption_backup',
            'browsing_history.json.pre_encryption_backup',
            'users_data.json.pre_encryption_backup'
        ]

        for backup_file in backup_files:
            if os.path.exists(backup_file):
                original_name = backup_file.replace('.pre_encryption_backup', '')
                try:
                    import shutil
                    shutil.copy2(backup_file, original_name)
                    print(f"[🔄] שוחזר: {original_name}")
                except Exception as e:
                    print(f"[❌] שגיאה בשחזור {original_name}: {e}")

        print("✅ הצפנה בוטלה - המערכת חזרה למצב רגיל")

    # 🔧 מתודות בטוחות שמחליפות את הקיימות
    def safe_save_children_data(self, data=None):
        """שמירת נתוני ילדים - מוצפן או רגיל לפי ההגדרה"""
        if data is None:
            # אם לא ניתנו נתונים, נשתמש בגלובליים
            from parent_server import children_data
            data = {}
            for child, info in children_data.items():
                blocked_domains = info["blocked_domains"]
                if isinstance(blocked_domains, set):
                    blocked_domains = list(blocked_domains)

                data[child] = {
                    "blocked_domains": blocked_domains,
                    "last_seen": info.get("last_seen")
                }

        # שמירה מוצפנת או רגילה
        return self.file_manager.safe_save_json(
            'children_data.json',
            data,
            encrypted=self.encryption_enabled
        )

    def safe_load_children_data(self):
        """טעינת נתוני ילדים - מוצפן או רגיל"""
        return self.file_manager.safe_load_json(
            'children_data.json',
            encrypted=self.encryption_enabled
        )

    def safe_save_browsing_history(self, data=None):
        """שמירת היסטוריית גלישה - מוצפן או רגיל"""
        if data is None:
            from parent_server import browsing_history
            data = browsing_history

        return self.file_manager.safe_save_json(
            'browsing_history.json',
            data,
            encrypted=self.encryption_enabled
        )

    def safe_load_browsing_history(self):
        """טעינת היסטוריית גלישה - מוצפן או רגיל"""
        return self.file_manager.safe_load_json(
            'browsing_history.json',
            encrypted=self.encryption_enabled
        )

    def get_encryption_status(self):
        """מצב ההצפנה הנוכחי"""
        status = {
            "enabled": self.encryption_enabled,
            "files": {
                "children_data_encrypted": os.path.exists('children_data.json.encrypted'),
                "browsing_history_encrypted": os.path.exists('browsing_history.json.encrypted'),
                "children_data_regular": os.path.exists('children_data.json'),
                "browsing_history_regular": os.path.exists('browsing_history.json')
            }
        }
        return status


# 🧪 בדיקות בטיחות לשילוב
def test_integration_safety():
    """בדיקה שהשילוב עם המערכת הקיימת בטוח"""
    print("\n🧪 בודק שילוב בטוח עם המערכת הקיימת...")

    # יצירת נתוני דמה
    test_children_data = {
        "ילד_בדיקה": {
            "blocked_domains": ["test1.com", "test2.com"],
            "last_seen": 1234567890
        }
    }

    test_history = {
        "ילד_בדיקה": [
            {"domain": "test.com", "timestamp": "2024-01-01", "was_blocked": True}
        ]
    }

    # בדיקת השדרוג
    upgrade = SafeParentServerUpgrade(None)  # ללא server אמיתי לבדיקה

    # בדיקה 1: שמירה רגילה
    print("🔍 בודק שמירה רגילה...")
    if upgrade.safe_save_children_data(test_children_data):
        loaded = upgrade.safe_load_children_data()
        if loaded == test_children_data:
            print("✅ שמירה וטעינה רגילה עובדות")
        else:
            print("❌ בעיה בשמירה/טעינה רגילה")
            return False

    # בדיקה 2: הפעלת הצפנה
    print("🔍 בודק הפעלת הצפנה...")
    # יצירת קבצי דמה
    with open('children_data.json', 'w', encoding='utf-8') as f:
        json.dump(test_children_data, f)
    with open('browsing_history.json', 'w', encoding='utf-8') as f:
        json.dump(test_history, f)

    if upgrade.enable_encryption_safely():
        print("✅ הפעלת הצפנה עובדת")

        # בדיקה שהקבצים המוצפנים נוצרו
        if os.path.exists('children_data.json.encrypted'):
            print("✅ קובץ children_data מוצפן נוצר")
        else:
            print("❌ קובץ children_data מוצפן לא נוצר")
            return False
    else:
        print("❌ הפעלת הצפנה נכשלה")
        return False

    # בדיקה 3: טעינה ממצב מוצפן
    print("🔍 בודק טעינה ממצב מוצפן...")
    loaded_encrypted = upgrade.safe_load_children_data()
    if loaded_encrypted == test_children_data:
        print("✅ טעינה ממצב מוצפן עובדת")
    else:
        print("❌ בעיה בטעינה ממצב מוצפן")
        return False

    # בדיקה 4: כיבוי הצפנה וחזרה
    print("🔍 בודק כיבוי הצפנה...")
    upgrade.disable_encryption_safely()
    if not upgrade.encryption_enabled:
        print("✅ כיבוי הצפנה עבד")
    else:
        print("❌ בעיה בכיבוי הצפנה")
        return False

    # ניקוי קבצי בדיקה
    test_files = [
        'children_data.json',
        'children_data.json.encrypted',
        'children_data.json.backup',
        'children_data.json.pre_encryption_backup',
        'browsing_history.json',
        'browsing_history.json.encrypted',
        'browsing_history.json.backup',
        'browsing_history.json.pre_encryption_backup',
        'users_data.json.encrypted',
        'users_data.json.pre_encryption_backup'
    ]

    for f in test_files:
        if os.path.exists(f):
            os.remove(f)

    print("🎉 כל בדיקות השילוב עברו בהצלחה!")
    return True


# 📋 הוראות שימוש מפורטות
def show_usage_instructions():
    """הוראות שימוש מפורטות"""
    print("""
📋 הוראות שימוש בטוח:

🔧 שלב 1: הוספת השדרוג למערכת
---------------------------------------
בקובץ parent_server.py, הוסף בתחילת הקובץ:

from encryption_module import SimpleEncryption, SafeFileManager

ואחרי יצירת parent_server, הוסף:

# הוספת שדרוג הצפנה
from safe_encryption_step2 import SafeParentServerUpgrade
encryption_upgrade = SafeParentServerUpgrade(parent_server)

🔒 שלב 2: הפעלת הצפנה (אופציונלי)
---------------------------------------
# רק אחרי שהכל עובד טוב!
encryption_upgrade.enable_encryption_safely()

🔓 שלב 3: כיבוי הצפנה (במקרה חירום)
---------------------------------------
encryption_upgrade.disable_encryption_safely()

⚠️  זכור/י:
- תמיד יש גיבויים אוטומטיים
- אפשר לכבות ולהפעיל הצפנה בכל רגע
- הקוד הקיים לא משתנה בכלל!
""")


# הרצה אוטומטית
if __name__ == "__main__":
    import os
    import json

    test_integration_safety()
    show_usage_instructions()