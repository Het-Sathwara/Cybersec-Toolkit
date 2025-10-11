#!/usr/bin/env python3
"""
A comprehensive cybersecurity toolkit for security analysis and testing.
"""

import hashlib
import socket
import threading
import time
import os
import re
import json
import base64
import subprocess
import platform
from datetime import datetime
from cryptography.fernet import Fernet
import getpass

class AdvancedPasswordChecker:
    """Advanced password strength checker with entropy analysis"""
    
    def __init__(self):
        self.common_passwords = [
            'password', '123456', 'admin', 'qwerty', 'letmein',
            'welcome', 'monkey', '1234567890', 'password123',
            'iloveyou', 'welcome123', 'login', 'abc123', 'master'
        ]
        self.breach_database = [
            'password', '123456', 'password123', 'admin', 'qwerty',
            'welcome', 'monkey', 'dragon', 'master', 'hello'
        ]
    
    def check_strength(self, password):
        """Advanced password strength analysis"""
        score = 0
        feedback = []
        vulnerabilities = []
        
        # Length analysis
        if len(password) >= 8:
            score += 20
        else:
            feedback.append("Use at least 8 characters")
        
        if len(password) >= 12:
            score += 10
        if len(password) >= 16:
            score += 5
        
        # Character variety checks
        if re.search(r'[a-z]', password):
            score += 10
        else:
            feedback.append("Include lowercase letters")
            
        if re.search(r'[A-Z]', password):
            score += 10
        else:
            feedback.append("Include uppercase letters")
            
        if re.search(r'[0-9]', password):
            score += 10
        else:
            feedback.append("Include numbers")
            
        if re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            score += 10
        else:
            feedback.append("Include special characters")
        
        # Advanced pattern analysis
        if re.search(r'(.)\1{2,}', password):
            score -= 15
            vulnerabilities.append("Repeated characters detected")
        
        if re.search(r'(012|123|234|345|456|567|678|789)', password):
            score -= 10
            vulnerabilities.append("Sequential numbers detected")
        
        if re.search(r'(qwe|wer|ert|rty|tyu|yui|uio|iop)', password):
            score -= 10
            vulnerabilities.append("Keyboard patterns detected")
        
        # Breach database check
        if password.lower() in self.breach_database:
            score -= 40
            vulnerabilities.append("Password found in breach database")
        
        # Entropy calculation
        entropy = self._calculate_entropy(password)
        if entropy < 30:
            score -= 20
            vulnerabilities.append("Low entropy - easily guessable")
        
        return score, feedback, vulnerabilities, entropy
    
    def _calculate_entropy(self, password):
        """Calculate password entropy"""
        import math
        charset_size = 0
        if re.search(r'[a-z]', password):
            charset_size += 26
        if re.search(r'[A-Z]', password):
            charset_size += 26
        if re.search(r'[0-9]', password):
            charset_size += 10
        if re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            charset_size += 32
        
        return len(password) * math.log2(charset_size) if charset_size > 0 else 0

class VulnerabilityScanner:
    """Network vulnerability scanner"""
    
    def __init__(self):
        self.common_vulnerabilities = {
            21: "FTP - Potential data exposure",
            22: "SSH - Brute force attacks",
            23: "Telnet - Unencrypted communication",
            25: "SMTP - Email spoofing",
            53: "DNS - Cache poisoning",
            80: "HTTP - XSS, CSRF attacks",
            110: "POP3 - Credential theft",
            143: "IMAP - Email access",
            443: "HTTPS - Certificate issues",
            993: "IMAPS - Email security",
            995: "POP3S - Email security"
        }
    
    def scan_vulnerabilities(self, host, ports):
        """Scan for common vulnerabilities"""
        results = []
        print(f"Scanning {host} for vulnerabilities...")
        
        for port in ports:
            if self._is_port_open(host, port):
                vulnerability = self.common_vulnerabilities.get(port, "Unknown service")
                risk_level = self._assess_risk_level(port)
                results.append({
                    'port': port,
                    'service': self._get_service_name(port),
                    'vulnerability': vulnerability,
                    'risk_level': risk_level,
                    'recommendations': self._get_recommendations(port)
                })
                print(f"Port {port}: {vulnerability} ({risk_level})")
        
        return results
    
    def _is_port_open(self, host, port, timeout=1):
        """Check if port is open"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((host, port))
            sock.close()
            return result == 0
        except:
            return False
    
    def _get_service_name(self, port):
        """Get service name for port"""
        services = {
            21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
            80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS",
            993: "IMAPS", 995: "POP3S"
        }
        return services.get(port, "Unknown")
    
    def _assess_risk_level(self, port):
        """Assess risk level for port"""
        high_risk = [21, 23, 25, 110, 143]
        medium_risk = [22, 53, 80, 993, 995]
        
        if port in high_risk:
            return "HIGH"
        elif port in medium_risk:
            return "MEDIUM"
        else:
            return "LOW"
    
    def _get_recommendations(self, port):
        """Get security recommendations for port"""
        recommendations = {
            21: "Disable anonymous FTP, use SFTP instead",
            22: "Use key-based authentication, disable root login",
            23: "Disable telnet, use SSH",
            25: "Configure SPF, DKIM, DMARC records",
            53: "Use DNSSEC, secure DNS server",
            80: "Redirect to HTTPS, implement security headers",
            110: "Use POP3S with encryption",
            143: "Use IMAPS with encryption",
            443: "Ensure valid SSL certificate",
            993: "Verify IMAPS configuration",
            995: "Verify POP3S configuration"
        }
        return recommendations.get(port, "Review service configuration")

class NetworkMonitor:
    """Network traffic monitoring and analysis"""
    
    def __init__(self):
        self.connections = []
        self.suspicious_activities = []
    
    def get_active_connections(self):
        """Get active network connections using alternative methods"""
        try:
            # Try using ss command first (modern replacement for netstat)
            result = subprocess.run(['ss', '-tuln'], capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                connections = []
                for line in result.stdout.split('\n'):
                    if 'tcp' in line.lower() or 'udp' in line.lower():
                        connections.append(line.strip())
                return connections
            
            # Fallback to /proc/net/tcp and /proc/net/udp
            connections = []
            try:
                with open('/proc/net/tcp', 'r') as f:
                    for line in f:
                        if line.strip():
                            connections.append(f"TCP: {line.strip()}")
                with open('/proc/net/udp', 'r') as f:
                    for line in f:
                        if line.strip():
                            connections.append(f"UDP: {line.strip()}")
                return connections
            except:
                return ["Network monitoring not available on this system"]
                
        except Exception as e:
            return [f"Network monitoring error: {str(e)}"]
    
    def analyze_connections(self, connections):
        """Analyze connections for suspicious activity"""
        suspicious = []
        
        for conn in connections:
            # Check for suspicious ports
            if ':6666' in conn or ':6667' in conn:  # IRC ports
                suspicious.append("IRC connection detected")
            if ':1337' in conn:  # Common backdoor port
                suspicious.append("Suspicious port 1337 detected")
            if ':31337' in conn:  # Elite port
                suspicious.append("Suspicious port 31337 detected")
        
        return suspicious

class DigitalForensics:
    """Digital forensics tools"""
    
    def __init__(self):
        self.deleted_files = []
        self.system_info = {}
    
    def get_system_info(self):
        """Gather system information for forensics"""
        info = {
            'timestamp': datetime.now().isoformat(),
            'platform': platform.system(),
            'platform_version': platform.version(),
            'architecture': platform.architecture(),
            'processor': platform.processor(),
            'hostname': platform.node(),
            'python_version': platform.python_version()
        }
        return info
    
    def analyze_file_metadata(self, filepath):
        """Analyze file metadata"""
        try:
            stat = os.stat(filepath)
            metadata = {
                'size': stat.st_size,
                'created': datetime.fromtimestamp(stat.st_ctime).isoformat(),
                'modified': datetime.fromtimestamp(stat.st_mtime).isoformat(),
                'accessed': datetime.fromtimestamp(stat.st_atime).isoformat(),
                'permissions': oct(stat.st_mode)[-3:]
            }
            return metadata
        except Exception as e:
            return {'error': str(e)}

class FileEncryptor:
    """File encryption/decryption"""
    
    def __init__(self):
        self.key = None
    
    def generate_key(self):
        """Generate a new encryption key"""
        self.key = Fernet.generate_key()
        return self.key
    
    def save_key(self, filename="secret.key"):
        """Save encryption key to file"""
        if self.key:
            with open(filename, 'wb') as key_file:
                key_file.write(self.key)
            print(f"Key saved to {filename}")
    
    def load_key(self, filename="secret.key"):
        """Load encryption key from file"""
        try:
            with open(filename, 'rb') as key_file:
                self.key = key_file.read()
            print(f"Key loaded from {filename}")
            return True
        except FileNotFoundError:
            print(f"Key file {filename} not found")
            return False
    
    def encrypt_file(self, filename):
        """Encrypt a file"""
        if not self.key:
            print("No key available. Generate or load a key first.")
            return False
        
        try:
            fernet = Fernet(self.key)
            with open(filename, 'rb') as file:
                original_data = file.read()
            
            encrypted_data = fernet.encrypt(original_data)
            
            with open(filename + '.encrypted', 'wb') as file:
                file.write(encrypted_data)
            
            print(f"File encrypted: {filename}.encrypted")
            return True
        except Exception as e:
            print(f"Encryption failed: {e}")
            return False
    
    def decrypt_file(self, filename):
        """Decrypt a file"""
        if not self.key:
            print("No key available. Load a key first.")
            return False
        
        try:
            fernet = Fernet(self.key)
            with open(filename, 'rb') as file:
                encrypted_data = file.read()
            
            decrypted_data = fernet.decrypt(encrypted_data)
            
            output_filename = filename.replace('.encrypted', '.decrypted')
            with open(output_filename, 'wb') as file:
                file.write(decrypted_data)
            
            print(f"File decrypted: {output_filename}")
            return True
        except Exception as e:
            print(f"Decryption failed: {e}")
            return False

class NetworkScanner:
    """Network port scanner"""
    
    def __init__(self):
        self.open_ports = []
    
    def scan_port(self, host, port, timeout=1):
        """Scan a single port"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((host, port))
            sock.close()
            return result == 0
        except:
            return False
    
    def scan_ports(self, host, ports, timeout=1):
        """Scan multiple ports"""
        print(f"Scanning {host}...")
        open_ports = []
        
        for port in ports:
            if self.scan_port(host, port, timeout):
                open_ports.append(port)
                print(f"Port {port}: OPEN")
            else:
                print(f"Port {port}: CLOSED")
        
        return open_ports

class HashGenerator:
    """Generate hashes for text and files"""
    
    @staticmethod
    def hash_text(text, algorithm='sha256'):
        """Generate hash for text"""
        if algorithm == 'md5':
            return hashlib.md5(text.encode()).hexdigest()
        elif algorithm == 'sha1':
            return hashlib.sha1(text.encode()).hexdigest()
        elif algorithm == 'sha256':
            return hashlib.sha256(text.encode()).hexdigest()
        elif algorithm == 'sha512':
            return hashlib.sha512(text.encode()).hexdigest()
        else:
            return "Unsupported algorithm"
    
    @staticmethod
    def hash_file(filename, algorithm='sha256'):
        """Generate hash for file"""
        try:
            hash_obj = hashlib.new(algorithm)
            with open(filename, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hash_obj.update(chunk)
            return hash_obj.hexdigest()
        except FileNotFoundError:
            return "File not found"
        except Exception as e:
            return f"Error: {e}"

class CyberSecurityToolkit:
    """Professional cybersecurity toolkit"""
    
    def __init__(self):
        self.password_checker = AdvancedPasswordChecker()
        self.vulnerability_scanner = VulnerabilityScanner()
        self.network_monitor = NetworkMonitor()
        self.forensics = DigitalForensics()
        self.file_encryptor = FileEncryptor()
        self.network_scanner = NetworkScanner()
        self.hash_generator = HashGenerator()
    
    def show_menu(self):
        """Display main menu"""
        print("\n" + "="*60)
        print("    CYBERSECURITY TOOLKIT")
        print("="*60)
        print("1. Advanced Password Analysis")
        print("2. Vulnerability Scanner")
        print("3. Network Monitoring")
        print("4. Digital Forensics")
        print("5. File Encryption/Decryption")
        print("6. Network Port Scanner")
        print("7. Hash Generator")
        print("8. Security Report Generator")
        print("9. Exit")
        print("="*60)
    
    def advanced_password_menu(self):
        """Advanced password analysis interface"""
        print("\n--- Advanced Password Analysis ---")
        password = getpass.getpass("Enter password to analyze: ")
        
        score, feedback, vulnerabilities, entropy = self.password_checker.check_strength(password)
        
        print(f"\nPassword Analysis Results:")
        print(f"Strength Score: {score}/100")
        print(f"Entropy: {entropy:.2f} bits")
        
        if score >= 80:
            print("Status: STRONG")
        elif score >= 60:
            print("Status: MODERATE")
        else:
            print("Status: WEAK")
        
        if vulnerabilities:
            print("\nSecurity Vulnerabilities:")
            for vuln in vulnerabilities:
                print(f"  - {vuln}")
        
        if feedback:
            print("\nRecommendations:")
            for suggestion in feedback:
                print(f"  - {suggestion}")
    
    def vulnerability_scanner_menu(self):
        """Vulnerability scanner interface"""
        print("\n--- Vulnerability Scanner ---")
        host = input("Enter host to scan (default: localhost): ") or "localhost"
        
        print("Select scan type:")
        print("1. Common ports scan")
        print("2. Full vulnerability scan")
        print("3. Custom ports")
        
        choice = input("Select option: ")
        
        if choice == '1':
            ports = [21, 22, 23, 25, 53, 80, 110, 443, 993, 995]
            results = self.vulnerability_scanner.scan_vulnerabilities(host, ports)
            self._display_vulnerability_results(results)
        
        elif choice == '2':
            ports = list(range(1, 1025))  # Well-known ports
            print("Running full scan (this may take a while)...")
            results = self.vulnerability_scanner.scan_vulnerabilities(host, ports)
            self._display_vulnerability_results(results)
        
        elif choice == '3':
            try:
                port_input = input("Enter ports (comma-separated): ")
                ports = [int(p.strip()) for p in port_input.split(',')]
                results = self.vulnerability_scanner.scan_vulnerabilities(host, ports)
                self._display_vulnerability_results(results)
            except ValueError:
                print("Invalid port numbers")
    
    def _display_vulnerability_results(self, results):
        """Display vulnerability scan results"""
        if not results:
            print("No vulnerabilities found.")
            return
        
        print(f"\nVulnerability Scan Results:")
        for result in results:
            print(f"\nPort {result['port']} ({result['service']}):")
            print(f"  Risk Level: {result['risk_level']}")
            print(f"  Issue: {result['vulnerability']}")
            print(f"  Recommendation: {result['recommendations']}")
    
    def network_monitor_menu(self):
        """Network monitoring interface"""
        print("\n--- Network Monitoring ---")
        print("Getting active connections...")
        
        connections = self.network_monitor.get_active_connections()
        print(f"\nActive Connections ({len(connections)}):")
        for conn in connections[:10]:  # Show first 10
            print(f"  {conn}")
        
        if len(connections) > 10:
            print(f"  ... and {len(connections) - 10} more")
        
        suspicious = self.network_monitor.analyze_connections(connections)
        if suspicious:
            print(f"\nSuspicious Activity Detected:")
            for activity in suspicious:
                print(f"  - {activity}")
        else:
            print("\nNo suspicious activity detected.")
    
    def forensics_menu(self):
        """Digital forensics interface"""
        print("\n--- Digital Forensics ---")
        print("1. System Information")
        print("2. File Metadata Analysis")
        print("3. Back to main menu")
        
        choice = input("Select option: ")
        
        if choice == '1':
            info = self.forensics.get_system_info()
            print(f"\nSystem Information:")
            for key, value in info.items():
                print(f"  {key}: {value}")
        
        elif choice == '2':
            filepath = input("Enter file path: ")
            if os.path.exists(filepath):
                metadata = self.forensics.analyze_file_metadata(filepath)
                print(f"\nFile Metadata:")
                for key, value in metadata.items():
                    print(f"  {key}: {value}")
            else:
                print("File not found.")
    
    def encryption_menu(self):
        """File encryption interface"""
        print("\n--- File Encryption/Decryption ---")
        print("1. Generate new key")
        print("2. Load existing key")
        print("3. Encrypt file")
        print("4. Decrypt file")
        print("5. Back to main menu")
        
        choice = input("Select option: ")
        
        if choice == '1':
            key = self.file_encryptor.generate_key()
            self.file_encryptor.save_key()
            print("New encryption key generated and saved!")
        
        elif choice == '2':
            filename = input("Enter key filename (default: secret.key): ") or "secret.key"
            self.file_encryptor.load_key(filename)
        
        elif choice == '3':
            filename = input("Enter filename to encrypt: ")
            self.file_encryptor.encrypt_file(filename)
        
        elif choice == '4':
            filename = input("Enter encrypted filename: ")
            self.file_encryptor.decrypt_file(filename)
    
    def scanner_menu(self):
        """Network scanner interface"""
        print("\n--- Network Port Scanner ---")
        host = input("Enter host to scan (default: localhost): ") or "localhost"
        
        print("Select scan type:")
        print("1. Common ports (21,22,23,25,53,80,110,443,993,995)")
        print("2. Custom port range")
        print("3. Single port")
        
        choice = input("Select option: ")
        
        if choice == '1':
            ports = [21, 22, 23, 25, 53, 80, 110, 443, 993, 995]
            self.network_scanner.scan_ports(host, ports)
        
        elif choice == '2':
            try:
                start = int(input("Start port: "))
                end = int(input("End port: "))
                if start < 1 or end < 1 or start > 65535 or end > 65535:
                    print("Port numbers must be between 1 and 65535")
                    return
                if start > end:
                    print("Start port must be less than or equal to end port")
                    return
                ports = list(range(start, end + 1))
                self.network_scanner.scan_ports(host, ports)
            except ValueError:
                print("Invalid port number. Please enter a valid integer.")
                return
        
        elif choice == '3':
            try:
                port = int(input("Port number: "))
                if port < 1 or port > 65535:
                    print("Port number must be between 1 and 65535")
                    return
                self.network_scanner.scan_ports(host, [port])
            except ValueError:
                print("Invalid port number. Please enter a valid integer.")
                return
    
    def hash_menu(self):
        """Hash generator interface"""
        print("\n--- Hash Generator ---")
        print("1. Hash text")
        print("2. Hash file")
        print("3. Back to main menu")
        
        choice = input("Select option: ")
        
        if choice == '1':
            text = input("Enter text to hash: ")
            print("\nAvailable algorithms: md5, sha1, sha256, sha512")
            algorithm = input("Enter algorithm (default: sha256): ") or "sha256"
            
            hash_value = self.hash_generator.hash_text(text, algorithm)
            print(f"\n{algorithm.upper()} hash: {hash_value}")
        
        elif choice == '2':
            filename = input("Enter filename: ")
            print("\nAvailable algorithms: md5, sha1, sha256, sha512")
            algorithm = input("Enter algorithm (default: sha256): ") or "sha256"
            
            hash_value = self.hash_generator.hash_file(filename, algorithm)
            print(f"\n{algorithm.upper()} hash: {hash_value}")
    
    def security_report_menu(self):
        """Generate comprehensive security report"""
        print("\n--- Security Report Generator ---")
        print("Generating comprehensive security report...")
        
        report = {
            'timestamp': datetime.now().isoformat(),
            'system_info': self.forensics.get_system_info(),
            'network_connections': len(self.network_monitor.get_active_connections()),
            'recommendations': [
                "Enable two-factor authentication",
                "Keep software updated",
                "Use strong, unique passwords",
                "Enable firewall protection",
                "Regular security scans"
            ]
        }
        
        print(f"\nSecurity Report Generated:")
        print(f"Timestamp: {report['timestamp']}")
        print(f"System: {report['system_info']['platform']}")
        print(f"Active Connections: {report['network_connections']}")
        print(f"Recommendations: {len(report['recommendations'])}")
        
        # Save report to file
        with open('security_report.json', 'w') as f:
            json.dump(report, f, indent=2)
        print("Report saved to security_report.json")
    
    def run(self):
        """Main application loop"""
        while True:
            try:
                self.show_menu()
                choice = input("\nSelect an option (1-9): ")
                
                if choice == '1':
                    self.advanced_password_menu()
                elif choice == '2':
                    self.vulnerability_scanner_menu()
                elif choice == '3':
                    self.network_monitor_menu()
                elif choice == '4':
                    self.forensics_menu()
                elif choice == '5':
                    self.encryption_menu()
                elif choice == '6':
                    self.scanner_menu()
                elif choice == '7':
                    self.hash_menu()
                elif choice == '8':
                    self.security_report_menu()
                elif choice == '9':
                    print("\nGoodbye! Stay secure!")
                    break
                else:
                    print("Invalid option. Please try again.")
                
                input("\nPress Enter to continue...")
                
            except KeyboardInterrupt:
                print("\n\nExiting...")
                break
            except EOFError:
                print("\n\nExiting...")
                break

if __name__ == "__main__":
    toolkit = CyberSecurityToolkit()
    toolkit.run()