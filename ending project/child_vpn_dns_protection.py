import subprocess
import socket
import psutil
import time
import logging
import threading
import os
import platform
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


class ChildVPNDNSProtection:
    """VPN and DNS protection for child device"""

    def __init__(self, report_callback=None):
        self.report_callback = report_callback  # Function to report to parent
        self.monitoring_active = False
        self.monitor_thread = None
        self.last_dns_config = []
        self.detected_vpn_processes = []

        # Known VPN process names
        self.vpn_process_names = [
            'nordvpn', 'expressvpn', 'surfshark', 'cyberghost',
            'protonvpn', 'tunnelbear', 'hotspotshield', 'windscribe',
            'openvpn', 'wireguard', 'strongswan', 'l2tp',
            'pptp', 'sstp', 'ikev2', 'softether'
        ]

        # VPN-related files and directories to monitor
        self.vpn_indicators = [
            '/etc/openvpn',
            '/usr/bin/openvpn',
            '/opt/nordvpn',
            '/Applications/ExpressVPN.app',  # macOS
            'C:\\Program Files\\NordVPN',  # Windows
            'C:\\Program Files\\ExpressVPN'  # Windows
        ]

        # Expected DNS servers (should match parent configuration)
        self.expected_dns_servers = [
            "8.8.8.8",  # Google DNS
            "8.8.4.4",  # Google DNS
            "1.1.1.1",  # Cloudflare
            "1.0.0.1",  # Cloudflare
        ]

        # Forbidden DNS servers
        self.forbidden_dns_servers = [
            "9.9.9.9",  # Quad9
            "208.67.222.222",  # OpenDNS
            "176.103.130.130",  # AdGuard
            "185.228.168.9",  # CleanBrowsing
        ]

    def detect_vpn_processes(self) -> Dict[str, any]:
        """
        Detect running VPN processes on the device

        Returns:
            Detection results with found VPN processes
        """
        result = {
            "vpn_processes_found": False,
            "detected_processes": [],
            "vpn_services": [],
            "risk_level": "low"
        }

        try:
            # Check running processes
            for proc in psutil.process_iter(['pid', 'name', 'exe']):
                try:
                    proc_name = proc.info['name'].lower()
                    proc_exe = proc.info.get('exe', '').lower()

                    # Check against known VPN process names
                    for vpn_name in self.vpn_process_names:
                        if vpn_name in proc_name or vpn_name in proc_exe:
                            result["detected_processes"].append({
                                "pid": proc.info['pid'],
                                "name": proc.info['name'],
                                "exe": proc.info.get('exe', 'Unknown'),
                                "vpn_type": vpn_name
                            })
                            result["vpn_processes_found"] = True

                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue

            # Check for VPN services (Windows/Linux)
            vpn_services = self._check_vpn_services()
            result["vpn_services"] = vpn_services

            if vpn_services:
                result["vpn_processes_found"] = True

            # Set risk level
            if result["vpn_processes_found"]:
                result["risk_level"] = "high"
                logger.warning(f"VPN processes detected: {result['detected_processes']}")

                # Store for persistent monitoring
                self.detected_vpn_processes = result["detected_processes"]

        except Exception as e:
            logger.error(f"VPN process detection error: {e}")
            result["risk_level"] = "unknown"

        return result

    def _check_vpn_services(self) -> List[Dict]:
        """Check for VPN services running on the system"""
        vpn_services = []

        try:
            if platform.system() == "Windows":
                # Check Windows services
                services_to_check = [
                    'NordVPN Service', 'ExpressVPN Service', 'SurfsharkService',
                    'CyberGhost 8 Service', 'ProtonVPN Service'
                ]

                for service_name in services_to_check:
                    try:
                        result = subprocess.run([
                            'sc', 'query', service_name
                        ], capture_output=True, text=True, timeout=5)

                        if 'RUNNING' in result.stdout:
                            vpn_services.append({
                                "name": service_name,
                                "status": "running",
                                "type": "windows_service"
                            })
                    except:
                        continue

            elif platform.system() == "Linux":
                # Check systemd services
                try:
                    result = subprocess.run([
                        'systemctl', 'list-units', '--type=service', '--state=running'
                    ], capture_output=True, text=True, timeout=5)

                    for line in result.stdout.split('\n'):
                        for vpn_name in self.vpn_process_names:
                            if vpn_name in line.lower():
                                vpn_services.append({
                                    "name": line.split()[0],
                                    "status": "running",
                                    "type": "systemd_service"
                                })
                except:
                    pass

        except Exception as e:
            logger.error(f"Service check error: {e}")

        return vpn_services

    def detect_vpn_files(self) -> Dict[str, any]:
        """
        Detect VPN-related files and installations

        Returns:
            File detection results
        """
        result = {
            "vpn_files_found": False,
            "detected_files": [],
            "risk_level": "low"
        }

        try:
            for indicator_path in self.vpn_indicators:
                if os.path.exists(indicator_path):
                    result["detected_files"].append(indicator_path)
                    result["vpn_files_found"] = True

            # Check for config files
            config_locations = [
                os.path.expanduser("~/.config/nordvpn"),
                os.path.expanduser("~/.expressvpn"),
                "/etc/wireguard",
                os.path.expanduser("~/AppData/Local/NordVPN"),  # Windows
            ]

            for config_path in config_locations:
                if os.path.exists(config_path):
                    result["detected_files"].append(config_path)
                    result["vpn_files_found"] = True

            if result["vpn_files_found"]:
                result["risk_level"] = "medium"
                logger.warning(f"VPN files detected: {result['detected_files']}")

        except Exception as e:
            logger.error(f"VPN file detection error: {e}")

        return result

    def monitor_dns_configuration(self) -> Dict[str, any]:
        """
        Monitor current DNS configuration

        Returns:
            DNS monitoring results
        """
        result = {
            "dns_modified": False,
            "current_dns": [],
            "forbidden_dns_found": False,
            "dns_changes": [],
            "risk_level": "low"
        }

        try:
            # Get current DNS configuration
            current_dns = self._get_current_dns()
            result["current_dns"] = current_dns

            # Check for changes since last check
            if self.last_dns_config and current_dns != self.last_dns_config:
                result["dns_modified"] = True
                result["dns_changes"] = [
                    f"DNS changed from {self.last_dns_config} to {current_dns}"
                ]
                logger.warning(f"DNS configuration changed: {self.last_dns_config} -> {current_dns}")

            # Check against forbidden DNS servers
            for dns_server in current_dns:
                if dns_server in self.forbidden_dns_servers:
                    result["forbidden_dns_found"] = True
                    result["dns_changes"].append(f"Forbidden DNS server detected: {dns_server}")
                    result["risk_level"] = "high"
                    logger.critical(f"Forbidden DNS server in use: {dns_server}")

            # Check if DNS is not in expected list
            unexpected_dns = [dns for dns in current_dns if dns not in self.expected_dns_servers]
            if unexpected_dns:
                result["dns_modified"] = True
                result["dns_changes"].append(f"Unexpected DNS servers: {unexpected_dns}")
                result["risk_level"] = "medium" if result["risk_level"] == "low" else result["risk_level"]

            # Update last known configuration
            self.last_dns_config = current_dns.copy()

        except Exception as e:
            logger.error(f"DNS monitoring error: {e}")
            result["dns_changes"].append(f"DNS monitoring failed: {e}")

        return result

    def _get_current_dns(self) -> List[str]:
        """Get current DNS servers from system"""
        dns_servers = []

        try:
            if platform.system() == "Windows":
                # Windows DNS detection
                result = subprocess.run([
                    'nslookup', 'google.com'
                ], capture_output=True, text=True, timeout=5)

                for line in result.stdout.split('\n'):
                    if 'Server:' in line:
                        dns_ip = line.split(':')[-1].strip()
                        if self._is_valid_ip(dns_ip):
                            dns_servers.append(dns_ip)

            elif platform.system() == "Linux":
                # Linux DNS detection
                try:
                    with open('/etc/resolv.conf', 'r') as f:
                        for line in f:
                            if line.startswith('nameserver'):
                                dns_ip = line.split()[-1]
                                if self._is_valid_ip(dns_ip):
                                    dns_servers.append(dns_ip)
                except:
                    pass

                # Also check systemd-resolved
                try:
                    result = subprocess.run([
                        'systemd-resolve', '--status'
                    ], capture_output=True, text=True, timeout=5)

                    for line in result.stdout.split('\n'):
                        if 'DNS Servers:' in line:
                            dns_ip = line.split(':')[-1].strip()
                            if self._is_valid_ip(dns_ip):
                                dns_servers.append(dns_ip)
                except:
                    pass

            elif platform.system() == "Darwin":  # macOS
                result = subprocess.run([
                    'scutil', '--dns'
                ], capture_output=True, text=True, timeout=5)

                for line in result.stdout.split('\n'):
                    if 'nameserver[0]' in line:
                        dns_ip = line.split(':')[-1].strip()
                        if self._is_valid_ip(dns_ip):
                            dns_servers.append(dns_ip)

        except Exception as e:
            logger.error(f"DNS detection error: {e}")

        return list(set(dns_servers))  # Remove duplicates

    def _is_valid_ip(self, ip_str: str) -> bool:
        """Check if string is valid IP address"""
        try:
            parts = ip_str.split('.')
            return len(parts) == 4 and all(0 <= int(part) <= 255 for part in parts)
        except:
            return False

    def attempt_dns_restoration(self) -> bool:
        """
        Attempt to restore correct DNS configuration

        Returns:
            True if restoration was attempted/successful
        """
        try:
            logger.info("Attempting to restore DNS configuration...")

            if platform.system() == "Linux":
                # Backup current config
                subprocess.run([
                    'cp', '/etc/resolv.conf', '/etc/resolv.conf.child_backup'
                ], timeout=5)

                # Write correct DNS
                dns_config = "# Restored by Parental Control Child\n"
                for dns_server in self.expected_dns_servers[:2]:
                    dns_config += f"nameserver {dns_server}\n"

                with open('/etc/resolv.conf', 'w') as f:
                    f.write(dns_config)

                logger.info("DNS configuration restored")
                return True

            elif platform.system() == "Windows":
                # Windows DNS restoration (requires admin privileges)
                # This is more complex and may require elevated permissions
                logger.warning("DNS restoration on Windows requires manual intervention")
                return False

        except Exception as e:
            logger.error(f"DNS restoration failed: {e}")
            return False

    def kill_vpn_processes(self) -> Dict[str, any]:
        """
        Attempt to terminate detected VPN processes

        Returns:
            Results of termination attempts
        """
        result = {
            "processes_killed": [],
            "failed_kills": [],
            "success": False
        }

        try:
            for proc_info in self.detected_vpn_processes:
                try:
                    pid = proc_info["pid"]
                    proc = psutil.Process(pid)

                    proc.terminate()  # Try graceful termination first
                    time.sleep(2)

                    if proc.is_running():
                        proc.kill()  # Force kill if still running

                    result["processes_killed"].append(proc_info)
                    logger.info(f"Killed VPN process: {proc_info['name']} (PID: {pid})")

                except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
                    result["failed_kills"].append({
                        "process": proc_info,
                        "error": str(e)
                    })
                    logger.warning(f"Failed to kill VPN process {proc_info['name']}: {e}")

            result["success"] = len(result["processes_killed"]) > 0

        except Exception as e:
            logger.error(f"VPN process termination error: {e}")

        return result

    def comprehensive_security_check(self) -> Dict[str, any]:
        """
        Perform comprehensive security check

        Returns:
            Complete security assessment
        """
        security_result = {
            "timestamp": time.time(),
            "vpn_processes": {},
            "vpn_files": {},
            "dns_status": {},
            "overall_risk": "low",
            "threats_detected": [],
            "actions_needed": [],
            "auto_actions_taken": []
        }

        # Check VPN processes
        security_result["vpn_processes"] = self.detect_vpn_processes()

        # Check VPN files
        security_result["vpn_files"] = self.detect_vpn_files()

        # Check DNS
        security_result["dns_status"] = self.monitor_dns_configuration()

        # Analyze overall risk
        risk_factors = []

        if security_result["vpn_processes"]["vpn_processes_found"]:
            risk_factors.append("VPN processes running")
            security_result["threats_detected"].append("Active VPN detected")
            security_result["actions_needed"].append("Terminate VPN processes")

        if security_result["vpn_files"]["vpn_files_found"]:
            risk_factors.append("VPN files present")
            security_result["threats_detected"].append("VPN software installed")
            security_result["actions_needed"].append("Remove VPN software")

        if security_result["dns_status"]["forbidden_dns_found"]:
            risk_factors.append("Forbidden DNS in use")
            security_result["threats_detected"].append("DNS bypass detected")
            security_result["actions_needed"].append("Restore DNS configuration")

        if security_result["dns_status"]["dns_modified"]:
            risk_factors.append("DNS configuration changed")
            security_result["threats_detected"].append("DNS settings modified")

        # Determine overall risk
        if len(risk_factors) >= 3:
            security_result["overall_risk"] = "critical"
        elif len(risk_factors) >= 2:
            security_result["overall_risk"] = "high"
        elif len(risk_factors) >= 1:
            security_result["overall_risk"] = "medium"

        # Take automatic actions for high/critical risk
        if security_result["overall_risk"] in ["high", "critical"]:
            # Try to kill VPN processes
            if security_result["vpn_processes"]["vpn_processes_found"]:
                kill_result = self.kill_vpn_processes()
                if kill_result["success"]:
                    security_result["auto_actions_taken"].append("Terminated VPN processes")

            # Try to restore DNS
            if security_result["dns_status"]["forbidden_dns_found"]:
                if self.attempt_dns_restoration():
                    security_result["auto_actions_taken"].append("Restored DNS configuration")

        # Report to parent if callback is available
        if self.report_callback and security_result["overall_risk"] != "low":
            try:
                self.report_callback("SECURITY_ALERT", security_result)
            except Exception as e:
                logger.error(f"Failed to report to parent: {e}")

        return security_result

    def start_monitoring(self, check_interval: int = 30):
        """
        Start continuous security monitoring

        Args:
            check_interval: Seconds between security checks
        """
        if self.monitoring_active:
            logger.warning("Security monitoring already active")
            return

        self.monitoring_active = True
        self.monitor_thread = threading.Thread(
            target=self._monitoring_loop,
            args=(check_interval,),
            daemon=True
        )
        self.monitor_thread.start()
        logger.info(f"Started child security monitoring (interval: {check_interval}s)")

    def stop_monitoring(self):
        """Stop security monitoring"""
        self.monitoring_active = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=5)
        logger.info("Stopped child security monitoring")

    def _monitoring_loop(self, check_interval: int):
        """Main monitoring loop"""
        while self.monitoring_active:
            try:
                # Perform comprehensive security check
                security_result = self.comprehensive_security_check()

                if security_result["overall_risk"] != "low":
                    logger.warning(f"🔒 CHILD SECURITY ALERT: Risk level {security_result['overall_risk']}")
                    logger.warning(f"Threats: {security_result['threats_detected']}")

                    if security_result["auto_actions_taken"]:
                        logger.info(f"Auto actions taken: {security_result['auto_actions_taken']}")

                time.sleep(check_interval)

            except Exception as e:
                logger.error(f"Child security monitoring error: {e}")
                time.sleep(check_interval)


# Integration example for child_agent.py
def integrate_with_child_agent():
    """
    Example integration with existing child agent
    """

    # Add this to ChildAgent class __init__:
    """
    def __init__(self):
        # ... existing code ...

        # Initialize security protection
        self.security_protection = ChildVPNDNSProtection(
            report_callback=self.report_security_to_parent
        )
        self.security_protection.start_monitoring(check_interval=30)

        logger.info("Child security protection initialized")
    """

    # Add this method to ChildAgent class:
    """
    def report_security_to_parent(self, alert_type, security_data):
        '''Report security issues to parent server'''
        try:
            message_data = {
                "alert_type": alert_type,
                "security_data": security_data,
                "child_name": self.child_name,
                "timestamp": time.time()
            }

            # Send through existing communication channel
            Protocol.send_message(
                self.parent_socket, 
                "SECURITY_ALERT", 
                message_data
            )

            logger.critical(f"Security alert sent to parent: {alert_type}")

        except Exception as e:
            logger.error(f"Failed to report security to parent: {e}")
    """

    # Add periodic security check method:
    """
    def perform_security_check(self):
        '''Perform manual security check'''
        if hasattr(self, 'security_protection'):
            result = self.security_protection.comprehensive_security_check()
            return result
        return {"overall_risk": "unknown"}
    """


if __name__ == "__main__":
    # Test the protection system
    def test_report_callback(alert_type, data):
        print(f"SECURITY ALERT: {alert_type}")
        print(f"Data: {data}")


    protection = ChildVPNDNSProtection(report_callback=test_report_callback)

    # Run single check
    result = protection.comprehensive_security_check()
    print(f"Security Check Result: {result}")

    # Start monitoring
    protection.start_monitoring(check_interval=10)

    try:
        time.sleep(30)  # Monitor for 30 seconds
    except KeyboardInterrupt:
        pass
    finally:
        protection.stop_monitoring()