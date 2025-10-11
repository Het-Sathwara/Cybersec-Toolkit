# Professional Cybersecurity Toolkit

A comprehensive Python-based cybersecurity toolkit for security analysis, testing, and professional security assessments.

## Features

### Core Security Tools
- **Advanced Password Analysis**: Multi-factor password strength analysis with entropy calculation and vulnerability detection
- **File Encryption/Decryption**: Encrypt and decrypt files using strong Fernet encryption
- **Network Port Scanner**: Scan local or remote hosts for open ports with comprehensive reporting
- **Hash Generator**: Generate MD5, SHA1, SHA256, and SHA512 hashes for text and files

### Professional Security Features
- **Vulnerability Scanner**: Comprehensive network vulnerability assessment with risk analysis
- **Network Monitoring**: Real-time network traffic analysis and connection monitoring
- **Digital Forensics**: System information gathering and file metadata analysis
- **Security Report Generator**: Professional JSON security assessment reports

## Installation

1. Install Python 3.6 or higher
2. Install required dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## Usage

### Professional Toolkit
Run the main cybersecurity toolkit:
```bash
python cybersecurity_toolkit.py
```

### Testing
Run comprehensive tests:
```bash
python test_toolkit.py
```

## Tools Overview

### Core Security Tools

#### 1. Advanced Password Analysis
- Multi-factor password strength analysis
- Entropy calculation for password complexity
- Vulnerability detection (patterns, sequences, breaches)
- Comprehensive feedback and recommendations
- Breach database checking

#### 2. File Encryption/Decryption
- Generate encryption keys
- Encrypt files with strong Fernet encryption
- Decrypt files using saved keys
- Keys are saved to `secret.key` by default

#### 3. Network Port Scanner
- Scan common ports (21, 22, 23, 25, 53, 80, 110, 443, 993, 995)
- Custom port ranges
- Single port scanning
- Works on localhost or remote hosts

#### 4. Hash Generator
- Generate hashes for text input
- Generate hashes for files
- Supports MD5, SHA1, SHA256, and SHA512 algorithms

### Professional Security Features

#### 5. Vulnerability Scanner
- Comprehensive network vulnerability assessment
- Risk level analysis for open ports
- Security recommendations for each vulnerability
- Service identification and threat analysis

#### 6. Network Monitoring
- Real-time network connection monitoring
- Suspicious activity detection
- Port-based threat identification
- Connection analysis and reporting

#### 7. Digital Forensics
- System information gathering
- File metadata analysis
- Timestamp and permission analysis
- Forensic data collection

#### 8. Security Report Generator
- Comprehensive security assessment
- Automated report generation
- JSON format output
- System and network security analysis

## Key Features

- **Professional Interface**: Clean, enterprise-ready command-line interface
- **Comprehensive Testing**: Full test suite with automated validation
- **Cross-Platform**: Works on Linux, Windows, and macOS
- **Modular Design**: Each tool can be used independently
- **Security-First**: Built with security best practices in mind

## Security Notes

- This toolkit is for educational and professional security testing purposes
- Always use strong, unique passwords
- Keep encryption keys secure
- Only scan networks you own or have permission to scan
- Use hashes to verify file integrity
- Follow responsible disclosure practices

## Requirements

- Python 3.6+
- cryptography library

## Installation

```bash
# Clone or download the project
cd cybersecurity-toolkit

# Install dependencies
pip install -r requirements.txt

# Run the toolkit
python cybersecurity_toolkit.py
```

## License

This project is for educational and professional purposes. Use responsibly and ethically.
