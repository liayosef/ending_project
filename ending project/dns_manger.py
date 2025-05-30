import platform
import subprocess
import ctypes
import os
import json
import time
from datetime import datetime


class DNSManager:
    def __init__(self):
        self.system = platform.system()
        self.interface_name = None
        self.master_backup_file = "master_dns_backup.json"  # גיבוי ראשי
        self.session_backup_file = "session_dns_backup.json"  # גיבוי זמני
        self.is_dns_modified = False

    def is_admin(self):
        """בדיקת הרשאות מנהל"""
        try:
            if self.system == "Windows":
                return ctypes.windll.shell32.IsUserAnAdmin()
            else:
                return os.geteuid() == 0
        except:
            return False

    def get_system_default_dns(self):
        """קבלת DNS ברירת המחדל של המערכת (לא מושפע מהפעלות קודמות)"""
        try:
            print("[*] 🔍 מחפש DNS ברירת מחדל של המערכת...")

            # שיטה 1: בדיקת router gateway DNS
            cmd = ['powershell', '-Command', '''
            $gateway = Get-NetRoute -DestinationPrefix "0.0.0.0/0" | Select-Object -First 1 -ExpandProperty NextHop
            $gatewayDNS = @($gateway, "8.8.8.8", "1.1.1.1")
            $gatewayDNS | ForEach-Object { $_ }
            ''']

            result = subprocess.run(cmd, capture_output=True, text=True, encoding='utf-8')
            if result.returncode == 0:
                lines = [line.strip() for line in result.stdout.strip().split('\n') if line.strip()]
                if lines and lines[0] != "127.0.0.1":
                    print(f"[*] 📡 DNS ברירת מחדל מה-Gateway: {lines[0]}")
                    return [lines[0], "8.8.8.8"]  # Gateway + Google DNS כגיבוי

            # שיטה 2: DNS נפוצים כברירת מחדל
            default_dns = ["8.8.8.8", "1.1.1.1"]  # Google + Cloudflare
            print(f"[*] 🌐 משתמש ב-DNS ברירת מחדל: {default_dns}")
            return default_dns

        except Exception as e:
            print(f"[!] שגיאה בקבלת DNS ברירת מחדל: {e}")
            return ["8.8.8.8", "1.1.1.1"]

    def save_master_backup(self):
        """שמירת גיבוי ראשי - רק אם לא קיים או אם DNS לא 127.0.0.1"""
        try:
            # בדוק אם כבר יש גיבוי ראשי תקף
            if os.path.exists(self.master_backup_file):
                with open(self.master_backup_file, 'r', encoding='utf-8') as f:
                    existing_backup = json.load(f)

                # בדוק אם הגיבוי הקיים תקף (לא 127.0.0.1)
                for interface_name, interface_data in existing_backup.get("interfaces", {}).items():
                    dns_servers = interface_data.get("dns_servers", [])
                    if dns_servers and "127.0.0.1" not in dns_servers:
                        print(f"[*] ✅ גיבוי ראשי תקף קיים: {interface_name} -> {dns_servers}")
                        return True

                print("[*] ⚠️ גיבוי ראשי קיים אבל מכיל 127.0.0.1 - יוחלף")

            print("[*] 💾 יוצר גיבוי ראשי חדש...")

            backup_data = {
                "timestamp": datetime.now().isoformat(),
                "interfaces": {},
                "system_default": self.get_system_default_dns()
            }

            # קבלת כל הממשקים הפעילים
            interfaces = self.get_active_interfaces()

            for interface_name in interfaces:
                current_dns = self.get_current_dns_safe(interface_name)

                # שמור רק אם DNS לא 127.0.0.1
                if current_dns and "127.0.0.1" not in current_dns:
                    backup_data["interfaces"][interface_name] = {
                        "dns_servers": current_dns,
                        "timestamp": datetime.now().isoformat()
                    }
                    print(f"[*] 💾 שומר DNS עבור {interface_name}: {current_dns}")
                else:
                    # אם DNS הוא 127.0.0.1, השתמש בברירת מחדל
                    default_dns = self.get_system_default_dns()
                    backup_data["interfaces"][interface_name] = {
                        "dns_servers": default_dns,
                        "timestamp": datetime.now().isoformat(),
                        "note": "מורכב מברירת מחדל (DNS היה 127.0.0.1)"
                    }
                    print(f"[*] 🔄 DNS של {interface_name} היה 127.0.0.1 - שומר ברירת מחדל: {default_dns}")

            # שמירת הגיבוי
            with open(self.master_backup_file, 'w', encoding='utf-8') as f:
                json.dump(backup_data, f, ensure_ascii=False, indent=2)

            print(f"[+] ✅ גיבוי ראשי נשמר ב-{self.master_backup_file}")
            return True

        except Exception as e:
            print(f"[!] ❌ שגיאה בשמירת גיבוי ראשי: {e}")
            return False

    def get_active_interfaces(self):
        """קבלת רשימת ממשקים פעילים"""
        try:
            cmd = ['powershell', '-Command',
                   'Get-NetAdapter | Where-Object {$_.Status -eq "Up" -and $_.Virtual -eq $false} | Select-Object -ExpandProperty Name']
            result = subprocess.run(cmd, capture_output=True, text=True, encoding='utf-8')

            if result.returncode == 0:
                interfaces = [line.strip() for line in result.stdout.strip().split('\n') if line.strip()]
                print(f"[*] 🔍 ממשקים פעילים: {interfaces}")
                return interfaces
        except Exception as e:
            print(f"[!] שגיאה בקבלת ממשקים: {e}")

        # גיבוי - ממשקים נפוצים
        return ['Wi-Fi', 'Ethernet']

    def get_current_dns_safe(self, interface_name):
        """קבלת DNS נוכחי בצורה בטוחה"""
        try:
            cmd = ['powershell', '-Command',
                   f'Get-DnsClientServerAddress -InterfaceAlias "{interface_name}" -AddressFamily IPv4 | Select-Object -ExpandProperty ServerAddresses']
            result = subprocess.run(cmd, capture_output=True, text=True, encoding='utf-8')

            if result.returncode == 0 and result.stdout.strip():
                dns_servers = [line.strip() for line in result.stdout.strip().split('\n')
                               if line.strip() and line.strip() != ""]
                return dns_servers if dns_servers else None
            return None

        except Exception as e:
            print(f"[!] שגיאה בקריאת DNS עבור {interface_name}: {e}")
            return None

    def get_primary_interface(self):
        """מציאת הממשק הראשי (עם חיבור לאינטרנט)"""
        try:
            # חפש ממשק עם default route
            cmd = ['powershell', '-Command', '''
            $defaultRoute = Get-NetRoute -DestinationPrefix "0.0.0.0/0" | Select-Object -First 1
            if ($defaultRoute) {
                $adapter = Get-NetAdapter -InterfaceIndex $defaultRoute.InterfaceIndex
                $adapter.Name
            }
            ''']

            result = subprocess.run(cmd, capture_output=True, text=True, encoding='utf-8')
            if result.returncode == 0 and result.stdout.strip():
                primary_interface = result.stdout.strip()
                print(f"[*] 🌐 ממשק ראשי: {primary_interface}")
                return primary_interface
        except Exception as e:
            print(f"[!] שגיאה במציאת ממשק ראשי: {e}")

        # גיבוי - נסה ממשקים נפוצים
        for interface in ['Wi-Fi', 'Ethernet']:
            if self.get_current_dns_safe(interface):
                print(f"[*] 🔍 משתמש בממשק: {interface}")
                return interface

        return None

    def set_dns(self, interface_name, dns_servers):
        """הגדרת DNS לממשק"""
        try:
            if not dns_servers:
                # אין DNS - חזור להגדרות אוטומטיות
                cmd = ['powershell', '-Command',
                       f'Set-DnsClientServerAddress -InterfaceAlias "{interface_name}" -ResetServerAddresses']
                action = "איפוס להגדרות אוטומטיות"
            else:
                # DNS ספציפי
                if isinstance(dns_servers, str):
                    dns_servers = [dns_servers]

                dns_list = ','.join(f'"{dns}"' for dns in dns_servers)
                cmd = ['powershell', '-Command',
                       f'Set-DnsClientServerAddress -InterfaceAlias "{interface_name}" -ServerAddresses {dns_list}']
                action = f"הגדרה ל-{dns_servers}"

            print(f"[*] 🔧 {action} עבור {interface_name}")
            result = subprocess.run(cmd, capture_output=True, text=True, encoding='utf-8')

            if result.returncode == 0:
                print(f"[+] ✅ DNS עודכן בהצלחה")
                return True
            else:
                print(f"[!] ❌ שגיאה בעדכון DNS: {result.stderr}")
                return False

        except Exception as e:
            print(f"[!] ❌ שגיאה בהגדרת DNS: {e}")
            return False

    def setup_dns_redirect(self):
        """הגדרת DNS לכתובת מקומית"""
        if not self.is_admin():
            print("[!] נדרשות הרשאות מנהל לשינוי הגדרות DNS")
            return False

        if self.system != "Windows":
            print("[!] מערכת הפעלה לא נתמכת")
            return False

        try:
            # 1. שמירת גיבוי ראשי (אם לא קיים)
            self.save_master_backup()

            # 2. מציאת הממשק הראשי
            self.interface_name = self.get_primary_interface()
            if not self.interface_name:
                print("[!] ❌ לא נמצא ממשק רשת מתאים")
                return False

            # 3. הגדרת DNS ל-127.0.0.1
            if self.set_dns(self.interface_name, "127.0.0.1"):
                self.is_dns_modified = True
                print("[+] ✅ DNS הוגדר למחשב המקומי")
                return True
            else:
                return False

        except Exception as e:
            print(f"[!] ❌ שגיאה בהגדרת DNS: {e}")
            return False

    def restore_original_dns(self):
        """שחזור DNS מקורי"""
        print("\n[*] 🔄 מתחיל שחזור DNS מקורי...")

        if not self.is_dns_modified:
            print("[*] ✅ DNS לא שונה - אין צורך בשחזור")
            return True

        success = False

        try:
            # טען גיבוי ראשי
            if not os.path.exists(self.master_backup_file):
                print("[!] ⚠️ לא נמצא גיבוי ראשי - משתמש בברירת מחדל")
                default_dns = self.get_system_default_dns()
                if self.interface_name:
                    success = self.set_dns(self.interface_name, default_dns)
            else:
                with open(self.master_backup_file, 'r', encoding='utf-8') as f:
                    backup_data = json.load(f)

                print(f"[*] 📂 טוען גיבוי מ-{backup_data['timestamp']}")

                # שחזר כל ממשק מהגיבוי
                interfaces_restored = 0
                for interface_name, interface_data in backup_data["interfaces"].items():
                    dns_servers = interface_data["dns_servers"]

                    if self.set_dns(interface_name, dns_servers):
                        interfaces_restored += 1
                        print(f"[+] ✅ שוחזר {interface_name}: {dns_servers}")
                    else:
                        print(f"[!] ❌ כישלון בשחזור {interface_name}")

                if interfaces_restored > 0:
                    success = True
                    print(f"[+] ✅ שוחזרו {interfaces_restored} ממשקים")

                # גיבוי נוסף - שחזור מברירת מחדל אם כלום לא עבד
                if not success:
                    print("[*] 🔄 מנסה שחזור מברירת מחדל...")
                    default_dns = backup_data.get("system_default", ["8.8.8.8", "1.1.1.1"])

                    for interface_name in self.get_active_interfaces():
                        if self.set_dns(interface_name, default_dns):
                            success = True
                            print(f"[+] ✅ שוחזר {interface_name} עם ברירת מחדל")

            # ניקוי נוסף
            if success:
                self.cleanup_after_restore()
                self.is_dns_modified = False
                print("[+] ✅ שחזור DNS הושלם בהצלחה!")
            else:
                print("[!] ❌ שחזור DNS נכשל")
                self.emergency_reset()

        except Exception as e:
            print(f"[!] ❌ שגיאה בשחזור DNS: {e}")
            self.emergency_reset()

        return success

    def cleanup_after_restore(self):
        """ניקוי אחרי שחזור מוצלח"""
        try:
            # ניקוי DNS cache
            print("[*] 🧹 מנקה DNS cache...")
            subprocess.run(['ipconfig', '/flushdns'], capture_output=True)

            # רענון IP (אופציונלי)
            print("[*] 🔄 מרענן הגדרות רשת...")
            subprocess.run(['ipconfig', '/release'], capture_output=True, timeout=5)
            time.sleep(1)
            subprocess.run(['ipconfig', '/renew'], capture_output=True, timeout=10)

            print("[+] ✅ ניקוי הושלם")

        except Exception as e:
            print(f"[!] שגיאה בניקוי: {e}")

    def emergency_reset(self):
        """איפוס חירום"""
        print("[*] 🚨 מבצע איפוס חירום...")

        try:
            # איפוס כל הממשקים להגדרות אוטומטיות
            for interface in self.get_active_interfaces():
                cmd = ['powershell', '-Command',
                       f'Set-DnsClientServerAddress -InterfaceAlias "{interface}" -ResetServerAddresses']
                subprocess.run(cmd, capture_output=True)
                print(f"[*] 🔄 איפוס {interface}")

            # פקודות ניקוי נוספות
            commands = [
                ['ipconfig', '/flushdns'],
                ['ipconfig', '/release'],
                ['ipconfig', '/renew'],
                ['netsh', 'winsock', 'reset']
            ]

            for cmd in commands:
                try:
                    subprocess.run(cmd, capture_output=True, timeout=10)
                    print(f"[*] ✅ {' '.join(cmd)}")
                except:
                    pass

            print("[*] ⚠️ איפוס חירום הושלם - מומלץ להפעיל מחדש את המחשב")

        except Exception as e:
            print(f"[!] שגיאה באיפוס חירום: {e}")

    def cleanup_backup_files(self):
        """ניקוי קבצי גיבוי זמניים (לא הראשי!)"""
        try:
            if os.path.exists(self.session_backup_file):
                os.remove(self.session_backup_file)
                print("[*] 🗑️ קובץ גיבוי זמני נמחק")
        except:
            pass

    def get_status(self):
        """קבלת מצב הDNS הנוכחי"""
        status = {
            "is_modified": self.is_dns_modified,
            "primary_interface": self.interface_name,
            "backup_exists": os.path.exists(self.master_backup_file),
            "current_dns": {}
        }

        for interface in self.get_active_interfaces()[:2]:  # רק 2 הראשונים
            dns = self.get_current_dns_safe(interface)
            if dns:
                status["current_dns"][interface] = dns

        return status


def graceful_dns_shutdown(dns_manager_instance):
    """סגירה נקייה של DNS"""
    print("\n[*] 🔄 מתחיל שחזור DNS...")

    try:
        if dns_manager_instance.restore_dns():
            print("[+] ✅ DNS שוחזר בהצלחה")
            return True
        else:
            print("[!] ❌ כישלון בשחזור DNS")

            choice = input("האם לבצע איפוס חירום? (y/n): ").lower()
            if choice in ['y', 'yes', 'כן']:
                dns_manager_instance.emergency_reset()

            return False

    except Exception as e:
        print(f"[!] שגיאה בשחזור DNS: {e}")
        return False


# דוגמה לשימוש:
if __name__ == "__main__":
    dns_mgr = DNSManager()

    print("=== בדיקת DNS Manager ===")

    # הצג מצב נוכחי
    status = dns_mgr.get_status()
    print(f"מצב: {status}")

    # הגדרת DNS מקומי
    if dns_mgr.setup_dns_redirect():
        print("DNS הוגדר למקומי")

        input("לחץ Enter לשחזור...")

        # שחזור
        dns_mgr.restore_original_dns()
    else:
        print("כישלון בהגדרת DNS")