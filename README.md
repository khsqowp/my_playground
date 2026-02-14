# 개인 통합 라이프스타일 플랫폼

88Motorcycle은 블로그, 포트폴리오, 학습 아카이브, 데이터 관리, 자동화를 하나로 통합한 라이프스타일 플랫폼입니다.
개발, 보안, 바이크 라이프 등 다양한 관심사를 기록하고 공유하며, 개인 데이터를 체계적으로 관리할 수 있습니다.

## 🚀 주요 기능

### 1. 콘텐츠 관리 (CMS)
- **블로그 (Blog)**: 기술, 일상, 바이크 등 다양한 주제의 글 게시. 마크다운 에디터, 태그, 카테고리, 시리즈 지원.
- **포트폴리오 (Portfolio)**: 프로젝트 쇼케이스. 기술 스택, 갤러리, 링크 관리.
- **아카이브 (Archive)**: 학습 노트, 메모, 퀴즈 등 지식 관리.

### 2. 데이터 및 자동화
- **데이터 컬렉션**: 스키마 없는 JSON 데이터를 유연하게 저장 및 관리 (NoSQL-like).
- **자동화 (Automation)**: 웹훅(Webhook) 연동, AI 설정 관리.

### 3. 사용자 경험
- **공개/비공개 모드**: 로그인 없이 접근 가능한 공개 영역과 관리자 전용 영역 분리.
- **반응형 디자인**: 모바일 친화적인 UI/UX.
- **다크 모드**: 시스템 설정 또는 사용자 선택에 따른 테마 지원.

---

## 🛠 아키텍처 및 기술 스택

이 프로젝트는 **Next.js 15 App Router**를 기반으로 한 풀스택 애플리케이션입니다.

- **Frontend**: Next.js 15, React 19, Tailwind CSS, Shadcn UI
- **Backend**: Next.js Server Actions & Route Handlers
- **Database**: PostgreSQL (pgvector 지원)
- **ORM**: Prisma
- **Auth**: NextAuth.js v5 (Credentials Provider)
- **Container**: Docker (Node.js + PostgreSQL Monolith)

### 모놀리식 컨테이너 (Monolith Container)
배포 편의성을 위해 **PostgreSQL 데이터베이스와 웹 애플리케이션을 하나의 Docker 컨테이너**로 통합했습니다.
- `Dockerfile.monolith`: PostgreSQL 설치 및 Next.js 빌드 통합 이미지
- `scripts/start-monolith.sh`: 컨테이너 시작 시 DB 초기화 및 앱 실행 자동화

---

## 💻 설치 및 실행 가이드

### 필수 요구사항
- Docker Desktop (또는 Docker Engine)
- Git

### 1. 프로젝트 클론
```bash
git clone https://github.com/YOUR_REPO/88motorcycle-web.git
cd 88motorcycle-web
```

### 2. 환경 변수 설정 (.env)
`.env` 파일은 보안상 저장소에 포함되지 않습니다. 아래 내용을 참고하여 프로젝트 루트에 `.env` 파일을 생성하세요.
```properties
# Database
DATABASE_URL="postgresql://postgres:postgres@localhost:5432/88motorcycle"

# NextAuth
NEXTAUTH_URL="http://localhost:3000"
NEXTAUTH_SECRET="your-secret-key-at-least-32-chars" # openssl rand -base64 32

# Admin Account (Initial Setup)
ADMIN_EMAIL="admin@88motorcycle.com"
ADMIN_PASSWORD="changeme"
```

### 3. 실행 (Docker Compose)
단일 컨테이너로 실행하기 위해 다음 명령어를 사용합니다.
```bash
docker-compose -f docker-compose.monolith.yml up -d --build
```
- 최초 실행 시 데이터베이스 초기화 및 시딩(Seed) 작업으로 인해 **약 30초 정도 소요**될 수 있습니다.

### 4. 접속
- **웹 서비스**: [http://localhost:3000](http://localhost:3000)
- **관리자 로그인**: 설정한 `ADMIN_EMAIL` / `ADMIN_PASSWORD` 사용

---

## 📂 폴더 구조 및 주요 파일

```
.
├── .env                    # 환경 변수 (직접 생성 필요)
├── Dockerfile.monolith     # 단일 컨테이너 빌드 파일
├── docker-compose.monolith.yml # 단일 컨테이너 실행 설정
├── drafts/                 # 글 초안 (옵션)
├── next.config.ts          # Next.js 설정
├── package.json            # 의존성 관리
├── prisma/
│   ├── schema.prisma       # DB 스키마 정의 (PostgreSQL)
│   └── seed.ts             # 초기 데이터 생성 스크립트
├── public/                 # 정적 파일 (이미지, 업로드 등)
├── scripts/
│   └── start-monolith.sh   # 컨테이너 시작 스크립트
└── src/
    ├── app/                # App Router 페이지 및 API
    ├── components/         # UI 컴포넌트
    ├── lib/                # 유틸리티 및 라이브러리 설정
    └── types/              # TypeScript 타입 정의
```

## ⚠️ 주의사항
- **데이터 보존**: 데이터베이스 파일은 `monolith_data` 도커 볼륨에 영구 저장됩니다. 컨테이너를 삭제해도 데이터는 유지되지만, 볼륨을 삭제(`docker volume rm ...`)하면 데이터가 유실됩니다.
- **포트 충돌**: 로컬에 이미 PostgreSQL(5432)이나 Node.js(3000)가 실행 중이라면 충돌할 수 있습니다. 필요시 `docker-compose.monolith.yml`에서 포트 매핑을 수정하세요.
