import subprocess
import socket
import ipaddress
import time
import logging
import threading
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


class VPNDNSProtection:
    """Simple VPN and DNS change detection for parental control"""

    def __init__(self):
        # Known VPN IP ranges (you can expand this list)
        self.known_vpn_ranges = [
            "185.159.156.0/24",  # NordVPN
            "103.231.88.0/24",  # ExpressVPN
            "198.54.117.0/24",  # Surfshark
            "91.219.215.0/24",  # CyberGhost
            "146.70.124.0/24",  # Private Internet Access
        ]

        # Allowed DNS servers (customize for your needs)
        self.allowed_dns_servers = [
            "8.8.8.8",  # Google DNS
            "8.8.4.4",  # Google DNS
            "1.1.1.1",  # Cloudflare
            "1.0.0.1",  # Cloudflare
            "208.67.222.222",  # OpenDNS (if you want to allow)
        ]

        # Blocked/suspicious DNS servers
        self.blocked_dns_servers = [
            "9.9.9.9",  # Quad9 (often used to bypass)
            "176.103.130.130",  # AdGuard
            "185.228.168.9",  # CleanBrowsing
        ]

        self.monitoring_active = False
        self.monitor_thread = None

    def detect_vpn_usage(self, client_ip: str) -> Dict[str, any]:
        """
        Simple VPN detection based on known IP ranges

        Args:
            client_ip: Client's IP address

        Returns:
            Detection results
        """
        result = {
            "vpn_detected": False,
            "vpn_provider": None,
            "risk_level": "low",
            "action_required": False
        }

        try:
            client_ip_obj = ipaddress.ip_address(client_ip)

            # Check against known VPN ranges
            for vpn_range in self.known_vpn_ranges:
                network = ipaddress.ip_network(vpn_range)
                if client_ip_obj in network:
                    result["vpn_detected"] = True
                    result["risk_level"] = "high"
                    result["action_required"] = True

                    # Try to identify provider
                    if "185.159.156" in vpn_range:
                        result["vpn_provider"] = "NordVPN"
                    elif "103.231.88" in vpn_range:
                        result["vpn_provider"] = "ExpressVPN"
                    elif "198.54.117" in vpn_range:
                        result["vpn_provider"] = "Surfshark"
                    # Add more as needed

                    logger.warning(f"VPN detected from {client_ip} - Provider: {result['vpn_provider']}")
                    break

            # Additional heuristic checks
            if not result["vpn_detected"]:
                # Check for suspicious patterns
                if self._check_suspicious_patterns(client_ip):
                    result["vpn_detected"] = True
                    result["vpn_provider"] = "Unknown"
                    result["risk_level"] = "medium"
                    result["action_required"] = True

        except Exception as e:
            logger.error(f"VPN detection error for {client_ip}: {e}")
            result["risk_level"] = "unknown"

        return result

    def _check_suspicious_patterns(self, client_ip: str) -> bool:
        """Additional heuristic checks for VPN usage"""
        try:
            # Check if IP is from hosting/datacenter ranges (common for VPNs)
            datacenter_indicators = [
                "amazonaws.com",
                "digitalocean.com",
                "vultr.com",
                "linode.com",
                "ovh.com"
            ]

            # Reverse DNS lookup
            try:
                hostname = socket.gethostbyaddr(client_ip)[0]
                for indicator in datacenter_indicators:
                    if indicator in hostname.lower():
                        logger.info(f"Datacenter IP detected: {client_ip} -> {hostname}")
                        return True
            except:
                pass

            return False

        except Exception:
            return False

    def monitor_dns_changes(self) -> Dict[str, any]:
        """
        Monitor current DNS configuration for changes

        Returns:
            DNS monitoring results
        """
        result = {
            "dns_changed": False,
            "current_dns": [],
            "blocked_dns_found": False,
            "action_required": False,
            "issues": []
        }

        try:
            # Method 1: Check /etc/resolv.conf (Linux/Unix)
            current_dns = self._get_system_dns_linux()

            # Method 2: If Windows, check Windows DNS
            if not current_dns:
                current_dns = self._get_system_dns_windows()

            result["current_dns"] = current_dns

            # Check against allowed DNS servers
            for dns_server in current_dns:
                if dns_server not in self.allowed_dns_servers:
                    result["dns_changed"] = True
                    result["issues"].append(f"Unauthorized DNS server: {dns_server}")

                # Check against blocked DNS servers
                if dns_server in self.blocked_dns_servers:
                    result["blocked_dns_found"] = True
                    result["action_required"] = True
                    result["issues"].append(f"Blocked DNS server detected: {dns_server}")
                    logger.warning(f"Blocked DNS server in use: {dns_server}")

            if result["dns_changed"] or result["blocked_dns_found"]:
                logger.warning(f"DNS configuration issue detected: {result['issues']}")

        except Exception as e:
            logger.error(f"DNS monitoring error: {e}")
            result["issues"].append(f"DNS monitoring failed: {e}")

        return result

    def _get_system_dns_linux(self) -> List[str]:
        """Get DNS servers from Linux/Unix system"""
        dns_servers = []

        try:
            with open('/etc/resolv.conf', 'r') as f:
                for line in f:
                    line = line.strip()
                    if line.startswith('nameserver'):
                        dns_ip = line.split()[-1]
                        if self._is_valid_ip(dns_ip):
                            dns_servers.append(dns_ip)
        except:
            pass

        # Also try systemd-resolve
        try:
            result = subprocess.run(
                ['systemd-resolve', '--status'],
                capture_output=True,
                text=True,
                timeout=5
            )

            for line in result.stdout.split('\n'):
                if 'DNS Servers:' in line:
                    dns_ip = line.split(':')[-1].strip()
                    if self._is_valid_ip(dns_ip):
                        dns_servers.append(dns_ip)
        except:
            pass

        return list(set(dns_servers))  # Remove duplicates

    def _get_system_dns_windows(self) -> List[str]:
        """Get DNS servers from Windows system"""
        dns_servers = []

        try:
            result = subprocess.run(
                ['nslookup', 'google.com'],
                capture_output=True,
                text=True,
                timeout=5
            )

            for line in result.stdout.split('\n'):
                if 'Server:' in line:
                    dns_ip = line.split(':')[-1].strip()
                    if self._is_valid_ip(dns_ip):
                        dns_servers.append(dns_ip)
        except:
            pass

        return dns_servers

    def _is_valid_ip(self, ip_str: str) -> bool:
        """Check if string is a valid IP address"""
        try:
            ipaddress.ip_address(ip_str)
            return True
        except:
            return False

    def block_vpn_access(self, client_ip: str) -> bool:
        """
        Block access from detected VPN IP

        Args:
            client_ip: IP to block

        Returns:
            True if successfully blocked
        """
        try:
            # Log the block action
            logger.critical(f"BLOCKING VPN ACCESS from {client_ip}")

            # Add to iptables (Linux) - customize for your system
            try:
                subprocess.run([
                    'iptables', '-A', 'INPUT', '-s', client_ip, '-j', 'DROP'
                ], check=True, timeout=5)
                logger.info(f"Added iptables rule to block {client_ip}")
            except:
                logger.warning("iptables command failed - manual blocking required")

            return True

        except Exception as e:
            logger.error(f"Failed to block VPN access from {client_ip}: {e}")
            return False

    def enforce_dns_settings(self) -> bool:
        """
        Enforce correct DNS settings

        Returns:
            True if DNS settings were corrected
        """
        try:
            logger.info("Enforcing DNS settings...")

            # Backup current resolv.conf
            subprocess.run([
                'cp', '/etc/resolv.conf', '/etc/resolv.conf.backup'
            ], timeout=5)

            # Write correct DNS settings
            dns_config = "# Enforced by Parental Control\n"
            for dns_server in self.allowed_dns_servers[:2]:  # Use first 2
                dns_config += f"nameserver {dns_server}\n"

            with open('/etc/resolv.conf', 'w') as f:
                f.write(dns_config)

            logger.info("DNS settings enforced successfully")
            return True

        except Exception as e:
            logger.error(f"Failed to enforce DNS settings: {e}")
            return False

    def start_monitoring(self, check_interval: int = 30):
        """
        Start continuous monitoring of VPN and DNS

        Args:
            check_interval: Seconds between checks
        """
        if self.monitoring_active:
            logger.warning("Monitoring already active")
            return

        self.monitoring_active = True
        self.monitor_thread = threading.Thread(
            target=self._monitoring_loop,
            args=(check_interval,),
            daemon=True
        )
        self.monitor_thread.start()
        logger.info(f"Started VPN/DNS monitoring (interval: {check_interval}s)")

    def stop_monitoring(self):
        """Stop monitoring"""
        self.monitoring_active = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=5)
        logger.info("Stopped VPN/DNS monitoring")

    def _monitoring_loop(self, check_interval: int):
        """Main monitoring loop"""
        while self.monitoring_active:
            try:
                # Check DNS configuration
                dns_result = self.monitor_dns_changes()

                if dns_result["action_required"]:
                    logger.critical(f"DNS SECURITY ALERT: {dns_result['issues']}")

                    # Attempt to fix DNS
                    if self.enforce_dns_settings():
                        logger.info("DNS settings corrected automatically")
                    else:
                        logger.error("Failed to correct DNS - manual intervention required")

                time.sleep(check_interval)

            except Exception as e:
                logger.error(f"Monitoring loop error: {e}")
                time.sleep(check_interval)

    def check_client_security(self, client_ip: str) -> Dict[str, any]:
        """
        Comprehensive security check for client

        Args:
            client_ip: Client IP to check

        Returns:
            Complete security assessment
        """
        security_result = {
            "client_ip": client_ip,
            "timestamp": time.time(),
            "vpn_check": {},
            "dns_check": {},
            "overall_risk": "low",
            "actions_taken": [],
            "recommendations": []
        }

        # VPN Detection
        security_result["vpn_check"] = self.detect_vpn_usage(client_ip)

        # DNS Check
        security_result["dns_check"] = self.monitor_dns_changes()

        # Determine overall risk
        vpn_risk = security_result["vpn_check"].get("risk_level", "low")
        dns_issues = len(security_result["dns_check"].get("issues", []))

        if vpn_risk == "high" or dns_issues >= 2:
            security_result["overall_risk"] = "high"
        elif vpn_risk == "medium" or dns_issues >= 1:
            security_result["overall_risk"] = "medium"

        # Take automatic actions for high risk
        if security_result["overall_risk"] == "high":
            if security_result["vpn_check"].get("vpn_detected"):
                if self.block_vpn_access(client_ip):
                    security_result["actions_taken"].append("Blocked VPN access")

            if security_result["dns_check"].get("action_required"):
                if self.enforce_dns_settings():
                    security_result["actions_taken"].append("Corrected DNS settings")

        # Generate recommendations
        if security_result["vpn_check"].get("vpn_detected"):
            security_result["recommendations"].append("Monitor for continued VPN usage")

        if security_result["dns_check"].get("dns_changed"):
            security_result["recommendations"].append("Verify DNS configuration manually")

        return security_result


# Integration example for your existing parent_server.py
def integrate_vpn_dns_protection():
    """
    Example of how to integrate with your existing ParentServer class
    """

    # Add this to your ParentServer class __init__ method:
    """
    def __init__(self):
        # ... existing code ...

        # Add VPN/DNS protection
        self.vpn_dns_protection = VPNDNSProtection()
        self.vpn_dns_protection.start_monitoring(check_interval=60)  # Check every minute

        logger.info("VPN/DNS protection initialized")
    """

    # Add this to your handle_child_connection method:
    """
    def handle_child_connection(self, client_socket, address):
        client_ip = address[0]

        # Security check before proceeding
        security_result = self.vpn_dns_protection.check_client_security(client_ip)

        if security_result["overall_risk"] == "high":
            logger.critical(f"HIGH SECURITY RISK from {client_ip}")
            logger.critical(f"VPN detected: {security_result['vpn_check'].get('vpn_detected', False)}")
            logger.critical(f"DNS issues: {security_result['dns_check'].get('issues', [])}")

            # Send security alert to parent interface
            self.send_security_alert(security_result)

            # Close connection
            client_socket.close()
            return

        # Continue with normal connection handling...
        # ... existing code ...
    """

    # Add this method to your ParentServer class:
    """
    def send_security_alert(self, security_result):
        '''Send security alert to parent dashboard'''
        alert_data = {
            "type": "SECURITY_ALERT",
            "timestamp": time.time(),
            "client_ip": security_result["client_ip"],
            "risk_level": security_result["overall_risk"],
            "vpn_detected": security_result["vpn_check"].get("vpn_detected", False),
            "dns_issues": security_result["dns_check"].get("issues", []),
            "actions_taken": security_result["actions_taken"]
        }

        # Add to browsing history or separate security log
        with history_lock:
            if "security_alerts" not in browsing_history:
                browsing_history["security_alerts"] = []

            browsing_history["security_alerts"].append(alert_data)

        logger.critical(f"SECURITY ALERT LOGGED: {alert_data}")
    """


if __name__ == "__main__":
    # Example usage
    protection = VPNDNSProtection()

    # Test VPN detection
    test_ip = "185.159.156.100"  # Known NordVPN range
    vpn_result = protection.detect_vpn_usage(test_ip)
    print(f"VPN Detection Result: {vpn_result}")

    # Test DNS monitoring
    dns_result = protection.monitor_dns_changes()
    print(f"DNS Monitoring Result: {dns_result}")

    # Start monitoring
    protection.start_monitoring(check_interval=30)

    try:
        time.sleep(10)  # Monitor for 10 seconds
    except KeyboardInterrupt:
        pass
    finally:
        protection.stop_monitoring()