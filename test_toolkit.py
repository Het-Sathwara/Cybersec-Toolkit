#!/usr/bin/env python3
"""
Professional Cybersecurity Toolkit - Test Suite
Comprehensive testing for all professional features
"""

import os
import tempfile
import time
from cybersecurity_toolkit import CyberSecurityToolkit

def test_advanced_password_checker():
    """Test advanced password analysis"""
    print("=" * 60)
    print("TESTING ADVANCED PASSWORD CHECKER")
    print("=" * 60)
    
    toolkit = CyberSecurityToolkit()
    
    test_cases = [
        ("password123", "Common weak password"),
        ("MyStr0ng!P@ssw0rd", "Strong password"),
        ("123456", "Very weak password"),
        ("qwerty", "Keyboard pattern"),
        ("", "Empty password"),
        ("ThisIsAVeryLongPasswordWithNumbers123AndSymbols!@#", "Very strong password")
    ]
    
    for password, description in test_cases:
        print(f"\nTesting: {description}")
        print(f"Password: {'*' * len(password) if password else '(empty)'}")
        
        score, feedback, vulnerabilities, entropy = toolkit.password_checker.check_strength(password)
        print(f"Score: {score}/100")
        print(f"Entropy: {entropy:.2f} bits")
        
        if score >= 80:
            status = "STRONG"
        elif score >= 60:
            status = "MODERATE"
        else:
            status = "WEAK"
        print(f"Status: {status}")
        
        if vulnerabilities:
            print("Vulnerabilities:")
            for vuln in vulnerabilities:
                print(f"  - {vuln}")
        
        if feedback:
            print("Suggestions:")
            for suggestion in feedback:
                print(f"  - {suggestion}")

def test_vulnerability_scanner():
    """Test vulnerability scanner"""
    print("\n" + "=" * 60)
    print("TESTING VULNERABILITY SCANNER")
    print("=" * 60)
    
    toolkit = CyberSecurityToolkit()
    
    print("Scanning localhost for common vulnerabilities...")
    ports = [22, 80, 443, 8080, 3000]
    results = toolkit.vulnerability_scanner.scan_vulnerabilities("localhost", ports)
    
    if results:
        print(f"\nVulnerability Scan Results:")
        for result in results:
            print(f"\nPort {result['port']} ({result['service']}):")
            print(f"  Risk Level: {result['risk_level']}")
            print(f"  Issue: {result['vulnerability']}")
            print(f"  Recommendation: {result['recommendations']}")
    else:
        print("No vulnerabilities found in tested ports.")

def test_network_monitor():
    """Test network monitoring"""
    print("\n" + "=" * 60)
    print("TESTING NETWORK MONITOR")
    print("=" * 60)
    
    toolkit = CyberSecurityToolkit()
    
    print("Getting active network connections...")
    connections = toolkit.network_monitor.get_active_connections()
    
    print(f"Found {len(connections)} active connections")
    if connections:
        print("Sample connections:")
        for conn in connections[:5]:
            print(f"  {conn}")
        
        if len(connections) > 5:
            print(f"  ... and {len(connections) - 5} more")
    
    print("\nAnalyzing connections for suspicious activity...")
    suspicious = toolkit.network_monitor.analyze_connections(connections)
    
    if suspicious:
        print(f"Suspicious Activity Detected:")
        for activity in suspicious:
            print(f"  - {activity}")
    else:
        print("No suspicious activity detected.")

def test_digital_forensics():
    """Test digital forensics tools"""
    print("\n" + "=" * 60)
    print("TESTING DIGITAL FORENSICS")
    print("=" * 60)
    
    toolkit = CyberSecurityToolkit()
    
    print("Gathering system information...")
    system_info = toolkit.forensics.get_system_info()
    
    print("System Information:")
    for key, value in system_info.items():
        print(f"  {key}: {value}")
    
    # Test file metadata analysis
    print("\nTesting file metadata analysis...")
    test_file = "forensics_test.txt"
    with open(test_file, 'w') as f:
        f.write("This is a test file for forensics analysis.")
    
    metadata = toolkit.forensics.analyze_file_metadata(test_file)
    
    if 'error' not in metadata:
        print("File Metadata:")
        for key, value in metadata.items():
            print(f"  {key}: {value}")
    else:
        print(f"Metadata analysis failed: {metadata['error']}")
    
    # Cleanup
    if os.path.exists(test_file):
        os.remove(test_file)
        print(f"Cleaned up: {test_file}")

def test_file_encryption():
    """Test file encryption/decryption"""
    print("\n" + "=" * 60)
    print("TESTING FILE ENCRYPTION/DECRYPTION")
    print("=" * 60)
    
    toolkit = CyberSecurityToolkit()
    
    # Create a temporary test file
    test_content = "This is sensitive data that needs to be encrypted!\nLine 2: More confidential information.\nLine 3: Top secret data here."
    test_file = "encryption_test.txt"
    
    print(f"Creating test file: {test_file}")
    with open(test_file, 'w') as f:
        f.write(test_content)
    
    print(f"Original content:\n{test_content}")
    
    # Generate key
    print("\nGenerating encryption key...")
    key = toolkit.file_encryptor.generate_key()
    print(f"Key generated: {key[:20]}...")
    
    # Save key
    toolkit.file_encryptor.save_key("test_key.key")
    print("Key saved to test_key.key")
    
    # Encrypt file
    print(f"\nEncrypting {test_file}...")
    if toolkit.file_encryptor.encrypt_file(test_file):
        print("File encrypted successfully!")
        
        # Check encrypted file exists
        encrypted_file = test_file + '.encrypted'
        if os.path.exists(encrypted_file):
            print(f"Encrypted file created: {encrypted_file}")
            with open(encrypted_file, 'rb') as f:
                encrypted_content = f.read()
            print(f"Encrypted content (first 50 bytes): {encrypted_content[:50]}")
        
        # Test decryption
        print(f"\nTesting decryption...")
        # Create new encryptor instance and load key
        decryptor = toolkit.file_encryptor
        if decryptor.load_key("test_key.key"):
            if decryptor.decrypt_file(encrypted_file):
                print("File decrypted successfully!")
                
                # Check decrypted content
                decrypted_file = encrypted_file.replace('.encrypted', '.decrypted')
                if os.path.exists(decrypted_file):
                    with open(decrypted_file, 'r') as f:
                        decrypted_content = f.read()
                    print(f"Decrypted content:\n{decrypted_content}")
                    
                    # Verify content matches
                    if decrypted_content == test_content:
                        print("Content verification: PASSED")
                    else:
                        print("Content verification: FAILED")
    
    # Cleanup
    cleanup_files = [test_file, test_file + '.encrypted', test_file + '.decrypted', 'test_key.key']
    for file in cleanup_files:
        if os.path.exists(file):
            os.remove(file)
            print(f"Cleaned up: {file}")

def test_network_scanner():
    """Test network scanner"""
    print("\n" + "=" * 60)
    print("TESTING NETWORK SCANNER")
    print("=" * 60)
    
    toolkit = CyberSecurityToolkit()
    
    # Test scanning localhost
    print("Scanning localhost for common ports...")
    common_ports = [22, 80, 443, 8080, 3000, 5000]
    open_ports = toolkit.network_scanner.scan_ports("localhost", common_ports)
    
    print(f"\nScan results:")
    if open_ports:
        print(f"Open ports found: {open_ports}")
    else:
        print("No open ports found in the tested range")
    
    # Test individual port scanning
    print(f"\nTesting individual port scanning...")
    test_ports = [22, 80, 443]
    for port in test_ports:
        is_open = toolkit.network_scanner.scan_port("localhost", port, timeout=0.5)
        status = "OPEN" if is_open else "CLOSED"
        print(f"Port {port}: {status}")

def test_hash_generator():
    """Test hash generator"""
    print("\n" + "=" * 60)
    print("TESTING HASH GENERATOR")
    print("=" * 60)
    
    toolkit = CyberSecurityToolkit()
    
    # Test text hashing
    test_text = "Hello, Cybersecurity World! This is a test string."
    print(f"Text to hash: {test_text}")
    
    algorithms = ['md5', 'sha1', 'sha256', 'sha512']
    for algo in algorithms:
        hash_value = toolkit.hash_generator.hash_text(test_text, algo)
        print(f"{algo.upper()}: {hash_value}")
    
    # Test file hashing
    print(f"\nTesting file hashing...")
    test_file = "test_file.txt"
    if os.path.exists(test_file):
        print(f"Hashing file: {test_file}")
        for algo in algorithms:
            hash_value = toolkit.hash_generator.hash_file(test_file, algo)
            print(f"{algo.upper()}: {hash_value}")
    else:
        print(f"Test file {test_file} not found")

def test_security_report():
    """Test security report generation"""
    print("\n" + "=" * 60)
    print("TESTING SECURITY REPORT GENERATOR")
    print("=" * 60)
    
    toolkit = CyberSecurityToolkit()
    
    print("Generating comprehensive security report...")
    
    # Simulate report generation
    report = {
        'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
        'system_info': toolkit.forensics.get_system_info(),
        'network_connections': len(toolkit.network_monitor.get_active_connections()),
        'recommendations': [
            "Enable two-factor authentication",
            "Keep software updated",
            "Use strong, unique passwords",
            "Enable firewall protection",
            "Regular security scans"
        ]
    }
    
    print(f"Security Report Generated:")
    print(f"  Timestamp: {report['timestamp']}")
    print(f"  System: {report['system_info']['platform']}")
    print(f"  Active Connections: {report['network_connections']}")
    print(f"  Recommendations: {len(report['recommendations'])}")
    
    # Save report
    import json
    with open('test_security_report.json', 'w') as f:
        json.dump(report, f, indent=2)
    print("Report saved to test_security_report.json")

def run_all_tests():
    """Run all professional toolkit tests"""
    print("PROFESSIONAL CYBERSECURITY TOOLKIT - COMPREHENSIVE TEST SUITE")
    print("=" * 60)
    print("This test suite validates all professional functionality.")
    print("=" * 60)
    
    start_time = time.time()
    
    try:
        test_advanced_password_checker()
        test_vulnerability_scanner()
        test_network_monitor()
        test_digital_forensics()
        test_file_encryption()
        test_network_scanner()
        test_hash_generator()
        test_security_report()
        
        end_time = time.time()
        duration = end_time - start_time
        
        print("\n" + "=" * 60)
        print("PROFESSIONAL TEST SUITE COMPLETED")
        print("=" * 60)
        print(f"Total execution time: {duration:.2f} seconds")
        print("All professional tests completed successfully!")
        
    except Exception as e:
        print(f"\nTest suite failed with error: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    run_all_tests()