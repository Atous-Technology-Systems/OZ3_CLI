# ATOUS OWASP Pentest Suite

![Version](https://img.shields.io/badge/version-2.0.0--improved-blue)
![License](https://img.shields.io/badge/license-MIT-green)

## 🛡️ Overview

ATOUS OWASP Pentest Suite is a comprehensive, automated security testing tool designed for conducting authorized penetration testing and security assessments. The suite implements security checks based on OWASP Top 10 vulnerabilities and provides a structured approach to identifying security weaknesses in web applications and APIs.

## ⚠️ Legal Disclaimer

This script is created for **educational and authorized testing purposes only**. Using this tool on systems without explicit permission is illegal. The author is not responsible for any misuse or damage caused by this tool.

## 🔑 Key Features

- 🔍 **Reconnaissance & Port Scanning**
  - Comprehensive Nmap scanning with service detection
  - Configurable timing and timeout settings
  - Detailed port and service analysis

- 💉 **Injection Testing**
  - SQL Injection (SQLi) detection
  - Cross-Site Scripting (XSS) testing
  - Sanitized and safe payload testing

- 🚫 **Access Control Testing**
  - Insecure Direct Object Reference (IDOR) detection
  - Authentication bypass attempts
  - Privilege escalation checks

- 🌐 **API Security Testing**
  - Automated OWASP ZAP integration
  - OpenAPI/Swagger specification scanning
  - API endpoint security validation

- 🔌 **WebSocket Security**
  - Connection security testing
  - Message injection testing
  - WebSocket protocol vulnerabilities

- 🔒 **HTTP Security Headers**
  - Security header presence validation
  - Missing header detection
  - Best practices compliance checking

## 🛠️ Requirements

- **Operating System**: Linux
- **Shell**: Bash
- **Required Tools**:
  - nmap
  - curl
  - docker
- **Optional Tools**:
  - websocat
  - jq

## 📦 Installation

1. Clone the repository or download the script
2. Make the script executable:
   ```bash
   chmod +x owasp_improved.sh
   ```
3. Ensure all dependencies are installed:
   ```bash
   # On Debian/Ubuntu
   sudo apt-get install nmap curl docker.io
   
   # Optional tools
   sudo apt-get install jq
   # websocat can be installed from its GitHub repository
   ```

## 🚀 Usage

### Interactive Mode (Default)
```bash
./owasp_improved.sh
```

### Non-Interactive Mode
```bash
./owasp_improved.sh -n -t localhost -p 8080
```

### Using Environment Variables
```bash
TARGET_HOST=localhost TARGET_PORT=8080 ./owasp_improved.sh -n
```

### Debug Mode
```bash
./owasp_improved.sh -d -t example.com -p 443
```

## ⚙️ Command Line Options

| Option | Description |
|--------|-------------|
| `-h, --help` | Show help message |
| `-v, --version` | Show version |
| `-q, --quiet` | Quiet mode (errors only) |
| `-d, --debug` | Debug mode (verbose) |
| `-n, --non-interactive` | Non-interactive mode |
| `-t, --target HOST` | Set target host |
| `-p, --port PORT` | Set target port |
| `--timeout SECONDS` | Set operation timeout |
| `--timing TIMING` | Set Nmap timing (T0-T5) |
| `--report-dir DIR` | Set report directory |

## 🌍 Environment Variables

| Variable | Description |
|----------|-------------|
| `TARGET_HOST` | Target host |
| `TARGET_PORT` | Target port |
| `TIMEOUT` | Timeout in seconds |
| `NMAP_TIMING` | Nmap timing |
| `INJECTION_ENDPOINT` | Endpoint for injection testing |
| `IDOR_ENDPOINT` | Endpoint for IDOR testing |
| `OPENAPI_URL` | OpenAPI documentation URL |
| `WS_URL` | WebSocket URL |

## 📊 Reports and Logs

The suite generates comprehensive reports and logs:
- **Security Report**: Detailed findings in Markdown format
- **Scan Logs**: Detailed operation logs
- **ZAP Reports**: When using the OWASP ZAP integration
- All outputs are saved in the specified report directory

## 🛡️ Security Features

1. **Input Validation**
   - Thorough sanitization of all inputs
   - Protection against command injection
   - Safe handling of user-provided parameters

2. **Safe Execution**
   - Controlled timeouts for all operations
   - Secure file permissions
   - Protected output handling

3. **Error Handling**
   - Graceful failure management
   - Detailed error logging
   - User-friendly error messages

## 🔄 Modules

1. **Reconnaissance Module**
   - Port scanning
   - Service detection
   - Version identification

2. **Injection Testing Module**
   - SQLi detection
   - XSS identification
   - Safe payload testing

3. **Access Control Module**
   - IDOR testing
   - Authentication checks
   - Authorization validation

4. **API Security Module**
   - ZAP integration
   - Automated scanning
   - Vulnerability detection

5. **WebSocket Module**
   - Protocol testing
   - Security validation
   - Connection testing

6. **HTTP Headers Module**
   - Security header checks
   - Configuration validation
   - Best practices verification

## 🤝 Contributing

Contributions are welcome! Please feel free to submit pull requests.

## 📝 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 👥 Author

- **Atous Technology Systems**
- Version: 2.0.0-improved
- Date: 2025-06-22

## 📚 Documentation and Resources

For more information about the vulnerabilities tested, refer to:
- [OWASP Top 10](https://owasp.org/www-project-top-10/)
- [OWASP API Security Top 10](https://owasp.org/www-project-api-security/)
- [OWASP WebSocket Security](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client_Side_Testing/10-Testing_WebSockets)

---

Remember to always conduct security testing responsibly and only on systems you have permission to test.
