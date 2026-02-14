import { PrismaClient } from "@prisma/client";
import bcrypt from "bcryptjs";

const prisma = new PrismaClient();

async function main() {
  console.log("🌱 시드 데이터 생성 시작...\n");

  // ==================== 관리자 계정 ====================
  const adminEmail = process.env.ADMIN_EMAIL || "admin@88motorcycle.com";
  const adminPassword = process.env.ADMIN_PASSWORD || "changeme";
  const hashedPassword = await bcrypt.hash(adminPassword, 12);

  const admin = await prisma.user.upsert({
    where: { email: adminEmail },
    update: {},
    create: {
      email: adminEmail,
      password: hashedPassword,
      name: "관리자",
      role: "OWNER",
    },
  });
  console.log(`✅ 관리자: ${admin.email}`);

  // ==================== 카테고리 ====================
  const categoryData = [
    { name: "개발", slug: "development", color: "#3B82F6" },
    { name: "보안", slug: "security", color: "#EF4444" },
    { name: "DevOps", slug: "devops", color: "#10B981" },
    { name: "모터사이클", slug: "motorcycle", color: "#F59E0B" },
    { name: "학습 노트", slug: "study-notes", color: "#8B5CF6" },
    { name: "일상", slug: "daily", color: "#EC4899" },
    { name: "프로젝트", slug: "projects", color: "#06B6D4" },
    { name: "기타", slug: "misc", color: "#6B7280" },
  ];

  const categories: Record<string, string> = {};
  for (const cat of categoryData) {
    const created = await prisma.category.upsert({
      where: { slug: cat.slug },
      update: { name: cat.name, color: cat.color },
      create: cat,
    });
    categories[cat.slug] = created.id;
  }
  console.log(`✅ 카테고리 ${categoryData.length}개 생성`);

  // ==================== 태그 ====================
  const tagNames = [
    "React", "Next.js", "TypeScript", "Python", "Docker",
    "Linux", "네트워크", "데이터베이스", "API", "CI/CD",
    "보안", "클라우드", "AWS", "알고리즘", "면접준비",
    "바이크", "투어링", "정비", "리뷰",
  ];

  const tags: Record<string, string> = {};
  for (const name of tagNames) {
    const tag = await prisma.tag.upsert({
      where: { name },
      update: {},
      create: { name },
    });
    tags[name] = tag.id;
  }
  console.log(`✅ 태그 ${tagNames.length}개 생성`);

  // ==================== 시리즈 ====================
  const seriesData = [
    { name: "Next.js 15 마스터하기", description: "Next.js 15의 새로운 기능과 패턴을 학습합니다" },
    { name: "보안 실무 가이드", description: "실무에서 자주 마주치는 보안 이슈와 대응법" },
    { name: "바이크 투어 일지", description: "전국 바이크 투어 기록" },
  ];

  const series: Record<string, string> = {};
  for (const s of seriesData) {
    const created = await prisma.series.upsert({
      where: { name: s.name },
      update: {},
      create: s,
    });
    series[s.name] = created.id;
  }
  console.log(`✅ 시리즈 ${seriesData.length}개 생성`);

  // ==================== 블로그 글 ====================
  const posts = [
    {
      title: "Next.js 15 App Router 완벽 가이드",
      slug: "nextjs-15-app-router-guide",
      content: `# Next.js 15 App Router 완벽 가이드

## 소개
Next.js 15에서 크게 변화한 App Router에 대해 깊이 있게 알아봅니다.

## Server Components
React Server Components는 서버에서만 실행되는 컴포넌트입니다.

\`\`\`tsx
// app/page.tsx - Server Component (기본값)
export default async function Page() {
  const data = await fetch('https://api.example.com/data');
  return <div>{JSON.stringify(data)}</div>;
}
\`\`\`

## Client Components
클라이언트 상호작용이 필요한 경우 \`"use client"\` 지시어를 사용합니다.

\`\`\`tsx
"use client";
import { useState } from 'react';

export default function Counter() {
  const [count, setCount] = useState(0);
  return <button onClick={() => setCount(c => c + 1)}>{count}</button>;
}
\`\`\`

## 라우팅 구조
- \`app/page.tsx\` → \`/\`
- \`app/blog/page.tsx\` → \`/blog\`
- \`app/blog/[slug]/page.tsx\` → \`/blog/:slug\`

## 결론
App Router는 서버 우선 접근 방식으로 성능과 개발 경험 모두를 개선합니다.`,
      excerpt: "Next.js 15 App Router의 Server Components, Client Components, 그리고 새로운 라우팅 패턴을 알아봅니다.",
      published: true,
      visibility: "PUBLIC",
      categorySlug: "development",
      tagNames: ["Next.js", "React", "TypeScript"],
      seriesName: "Next.js 15 마스터하기",
      seriesOrder: 1,
      viewCount: 342,
      daysAgo: 15,
    },
    {
      title: "TypeScript 5.x 새로운 기능 총정리",
      slug: "typescript-5x-new-features",
      content: `# TypeScript 5.x 새로운 기능 총정리

## Decorators (Stage 3)
TC39 Decorators가 정식 지원됩니다.

\`\`\`typescript
function logged(target: any, context: ClassMethodDecoratorContext) {
  return function (...args: any[]) {
    console.log(\`Calling \${String(context.name)}\`);
    return target.apply(this, args);
  };
}

class Calculator {
  @logged
  add(a: number, b: number) { return a + b; }
}
\`\`\`

## const Type Parameters
\`const\` 타입 파라미터로 리터럴 타입 추론이 가능합니다.

\`\`\`typescript
function createConfig<const T>(config: T): T {
  return config;
}

const config = createConfig({ theme: "dark", lang: "ko" });
// type: { readonly theme: "dark"; readonly lang: "ko" }
\`\`\`

## satisfies 연산자
타입 체크와 타입 추론을 동시에 할 수 있습니다.

\`\`\`typescript
type Color = "red" | "green" | "blue";

const palette = {
  red: [255, 0, 0],
  green: "#00ff00",
} satisfies Record<string, Color | number[]>;
\`\`\``,
      excerpt: "TypeScript 5.x에서 추가된 Decorators, const Type Parameters, satisfies 연산자 등을 정리합니다.",
      published: true,
      visibility: "PUBLIC",
      categorySlug: "development",
      tagNames: ["TypeScript"],
      viewCount: 218,
      daysAgo: 12,
    },
    {
      title: "Docker Compose로 개발 환경 구축하기",
      slug: "docker-compose-dev-environment",
      content: `# Docker Compose로 개발 환경 구축하기

## 왜 Docker Compose인가?
팀원 간 개발 환경 차이를 없애고, 인프라를 코드로 관리할 수 있습니다.

## docker-compose.yml 작성

\`\`\`yaml
version: '3.8'
services:
  app:
    build: .
    ports:
      - "3000:3000"
    volumes:
      - .:/app
      - /app/node_modules
    environment:
      DATABASE_URL: mysql://root:password@db:3306/myapp
    depends_on:
      - db

  db:
    image: mysql:8.0
    environment:
      MYSQL_ROOT_PASSWORD: password
      MYSQL_DATABASE: myapp
    ports:
      - "3306:3306"
    volumes:
      - db_data:/var/lib/mysql

volumes:
  db_data:
\`\`\`

## 실행 및 관리
\`\`\`bash
docker-compose up -d      # 백그라운드 실행
docker-compose logs -f    # 로그 확인
docker-compose down -v    # 종료 및 볼륨 삭제
\`\`\``,
      excerpt: "Docker Compose를 사용해 MySQL + Next.js 개발 환경을 구축하는 방법을 소개합니다.",
      published: true,
      visibility: "PUBLIC",
      categorySlug: "devops",
      tagNames: ["Docker", "CI/CD"],
      viewCount: 156,
      daysAgo: 10,
    },
    {
      title: "SQL Injection 공격 원리와 방어법",
      slug: "sql-injection-defense",
      content: `# SQL Injection 공격 원리와 방어법

## SQL Injection이란?
사용자 입력을 통해 SQL 쿼리를 조작하는 공격 기법입니다.

## 공격 예시
\`\`\`sql
-- 정상 쿼리
SELECT * FROM users WHERE email = 'user@example.com' AND password = 'pass123';

-- 주입된 쿼리
SELECT * FROM users WHERE email = '' OR 1=1 --' AND password = '';
\`\`\`

## 방어 방법

### 1. Prepared Statements (권장)
\`\`\`python
cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
\`\`\`

### 2. ORM 사용
\`\`\`typescript
// Prisma (안전)
const user = await prisma.user.findUnique({
  where: { email: userInput }
});
\`\`\`

### 3. 입력 검증
- 화이트리스트 기반 검증
- 특수문자 이스케이프
- 입력 길이 제한

## 결론
Prepared Statement + ORM 사용이 가장 효과적입니다.`,
      excerpt: "SQL Injection의 기본 원리를 이해하고 실무에서 효과적으로 방어하는 방법을 알아봅니다.",
      published: true,
      visibility: "PUBLIC",
      categorySlug: "security",
      tagNames: ["보안", "데이터베이스"],
      seriesName: "보안 실무 가이드",
      seriesOrder: 1,
      viewCount: 489,
      daysAgo: 8,
    },
    {
      title: "XSS 취약점 완전 정복",
      slug: "xss-vulnerability-guide",
      content: `# XSS 취약점 완전 정복

## XSS(Cross-Site Scripting) 유형

### 1. Stored XSS
데이터베이스에 저장되어 다른 사용자에게 실행됩니다.

### 2. Reflected XSS
URL 파라미터를 통해 즉시 실행됩니다.

### 3. DOM-based XSS
클라이언트 측 JavaScript에서 발생합니다.

## 방어 전략
- HTML Entity 인코딩
- CSP (Content Security Policy) 헤더 설정
- HttpOnly 쿠키 사용
- DOMPurify 라이브러리 활용

\`\`\`typescript
import DOMPurify from 'dompurify';
const clean = DOMPurify.sanitize(dirtyHtml);
\`\`\``,
      excerpt: "Stored, Reflected, DOM-based XSS의 차이를 이해하고 방어 전략을 수립합니다.",
      published: true,
      visibility: "PUBLIC",
      categorySlug: "security",
      tagNames: ["보안"],
      seriesName: "보안 실무 가이드",
      seriesOrder: 2,
      viewCount: 312,
      daysAgo: 5,
    },
    {
      title: "2024 가을 강원도 투어 후기",
      slug: "2024-fall-gangwon-tour",
      content: `# 2024 가을 강원도 투어 후기

## 코스
서울 → 양평 → 원주 → 평창 → 정선 → 태백 → 영월 → 서울

## 1일차: 서울 → 평창
아침 6시 출발. 양평까지는 도로가 쾌적했고, 원주를 지나 평창으로 진입하면서 단풍이 절정이었습니다.

### 하이라이트
- 평창 대관령 양떡목장 인근 와인딩 로드
- 양평 두물머리 일출

## 2일차: 평창 → 태백
정선 아우라지를 거쳐 태백으로. 해발 1,000m 이상의 고갯길에서 체감 온도가 많이 떨어졌습니다.

### 장비
- 재킷: 클로버 3계절 라이딩 재킷
- 장갑: 겨울용으로 교체 필요

## 정리
총 주행거리: 약 520km
연비: 약 22km/L
추천 시기: 10월 중순 (단풍 절정)`,
      excerpt: "가을 단풍 시즌, 강원도 대관령-정선-태백을 거치는 2박 3일 바이크 투어 기록.",
      published: true,
      visibility: "PUBLIC",
      categorySlug: "motorcycle",
      tagNames: ["바이크", "투어링"],
      seriesName: "바이크 투어 일지",
      seriesOrder: 1,
      viewCount: 87,
      daysAgo: 20,
    },
    {
      title: "Prisma ORM 쿼리 최적화 팁",
      slug: "prisma-query-optimization",
      content: `# Prisma ORM 쿼리 최적화 팁

## N+1 문제 해결
\`include\`를 사용하여 관련 데이터를 한 번에 가져옵니다.

\`\`\`typescript
const posts = await prisma.post.findMany({
  include: {
    author: true,
    tags: { include: { tag: true } },
  },
});
\`\`\`

## Select로 필요한 필드만 가져오기
\`\`\`typescript
const users = await prisma.user.findMany({
  select: { id: true, name: true, email: true },
});
\`\`\`

## 배치 작업
\`createMany\`와 트랜잭션을 활용합니다.

\`\`\`typescript
await prisma.$transaction([
  prisma.post.deleteMany({ where: { published: false } }),
  prisma.tag.deleteMany({ where: { posts: { none: {} } } }),
]);
\`\`\``,
      excerpt: "Prisma에서 N+1 문제 해결, 필드 선택, 배치 작업 등 실무 쿼리 최적화 팁을 공유합니다.",
      published: true,
      visibility: "PUBLIC",
      categorySlug: "development",
      tagNames: ["TypeScript", "데이터베이스"],
      viewCount: 195,
      daysAgo: 3,
    },
    {
      title: "AWS EC2 + Docker로 서비스 배포하기",
      slug: "aws-ec2-docker-deploy",
      content: `# AWS EC2 + Docker로 서비스 배포

## 초기 설정
EC2 인스턴스를 생성하고 Docker를 설치합니다.

\`\`\`bash
sudo yum update -y
sudo yum install docker -y
sudo systemctl start docker
sudo usermod -aG docker ec2-user
\`\`\`

## GitHub Actions CI/CD
\`\`\`yaml
name: Deploy
on:
  push:
    branches: [main]
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Build & Push
        run: |
          docker build -t myapp .
          docker push myregistry/myapp
\`\`\`

이 글은 아직 작성 중입니다...`,
      excerpt: "AWS EC2와 Docker를 사용해 웹 서비스를 배포하는 과정을 단계별로 설명합니다.",
      published: false,
      visibility: "PRIVATE",
      categorySlug: "devops",
      tagNames: ["Docker", "AWS", "CI/CD"],
      viewCount: 0,
      daysAgo: 1,
    },
  ];

  for (const post of posts) {
    const existing = await prisma.post.findUnique({ where: { slug: post.slug } });
    if (existing) continue;

    const tagIds = [];
    for (const tagName of (post.tagNames || [])) {
      if (tags[tagName]) tagIds.push(tags[tagName]);
    }

    await prisma.post.create({
      data: {
        title: post.title,
        slug: post.slug,
        content: post.content,
        excerpt: post.excerpt || null,
        published: post.published,
        visibility: post.visibility as any,
        authorId: admin.id,
        categoryId: post.categorySlug ? categories[post.categorySlug] : null,
        seriesId: post.seriesName ? series[post.seriesName] : null,
        seriesOrder: post.seriesOrder || null,
        viewCount: post.viewCount || 0,
        createdAt: new Date(Date.now() - (post.daysAgo || 0) * 86400000),
        tags: tagIds.length > 0 ? {
          create: tagIds.map((tagId) => ({ tag: { connect: { id: tagId } } })),
        } : undefined,
      },
    });
  }
  console.log(`✅ 블로그 글 ${posts.length}개 생성`);

  // ==================== 노트 ====================
  const notes = [
    {
      title: "HTTP 상태 코드 정리",
      content: `# HTTP 상태 코드 정리

## 2xx 성공
- **200** OK: 성공
- **201** Created: 리소스 생성 성공
- **204** No Content: 성공이지만 응답 본문 없음

## 3xx 리다이렉션
- **301** Moved Permanently: 영구 이동
- **302** Found: 임시 이동
- **304** Not Modified: 캐시 유효

## 4xx 클라이언트 오류
- **400** Bad Request: 잘못된 요청
- **401** Unauthorized: 인증 필요
- **403** Forbidden: 권한 없음
- **404** Not Found: 리소스 없음
- **429** Too Many Requests: 요청 과다

## 5xx 서버 오류
- **500** Internal Server Error
- **502** Bad Gateway
- **503** Service Unavailable`,
      categorySlug: "development",
      tagNames: ["API", "네트워크"],
      daysAgo: 25,
    },
    {
      title: "리눅스 필수 명령어 모음",
      content: `# 리눅스 필수 명령어

## 파일 관리
| 명령어 | 설명 |
|--------|------|
| \`ls -la\` | 상세 목록 |
| \`cp -r\` | 재귀 복사 |
| \`mv\` | 이동/이름변경 |
| \`chmod 755\` | 권한 변경 |
| \`chown\` | 소유자 변경 |

## 프로세스
| 명령어 | 설명 |
|--------|------|
| \`ps aux\` | 전체 프로세스 |
| \`top / htop\` | 실시간 모니터링 |
| \`kill -9 PID\` | 강제 종료 |
| \`nohup\` | 백그라운드 실행 |

## 네트워크
| 명령어 | 설명 |
|--------|------|
| \`netstat -tulpn\` | 포트 확인 |
| \`curl -v\` | HTTP 요청 |
| \`ssh -i key.pem\` | SSH 접속 |
| \`scp\` | 원격 파일 복사 |`,
      categorySlug: "development",
      tagNames: ["Linux"],
      daysAgo: 18,
    },
    {
      title: "Git 브랜치 전략 - Git Flow vs Trunk-Based",
      content: `# Git 브랜치 전략

## Git Flow
- main / develop / feature / release / hotfix
- 장점: 명확한 릴리스 관리
- 단점: 복잡함, 머지 충돌 빈번

## Trunk-Based Development
- 하나의 main 브랜치에 직접 커밋
- Feature Flag로 기능 제어
- 장점: 단순함, CI/CD 친화적
- 단점: Feature Flag 관리 필요

## 추천
- 소규모 팀: Trunk-Based
- 대규모 팀 / 릴리스 관리 필요: Git Flow`,
      categorySlug: "devops",
      tagNames: ["CI/CD"],
      daysAgo: 7,
    },
    {
      title: "OAuth 2.0 인증 흐름",
      content: `# OAuth 2.0 인증 흐름

## Authorization Code Grant (가장 안전)
1. 사용자 → 인증 서버 (로그인 페이지)
2. 인증 서버 → 클라이언트 (Authorization Code)
3. 클라이언트 → 인증 서버 (Code + Client Secret)
4. 인증 서버 → 클라이언트 (Access Token)

## PKCE (모바일/SPA용)
Code Verifier와 Code Challenge를 사용하여 Client Secret 없이 안전하게 인증

## Refresh Token
Access Token 만료 시 새 토큰 발급
- Access Token: 짧은 수명 (15분~1시간)
- Refresh Token: 긴 수명 (7일~30일)`,
      categorySlug: "security",
      tagNames: ["보안", "API"],
      daysAgo: 4,
    },
    {
      title: "Python 알고리즘 패턴 정리",
      content: `# 알고리즘 패턴

## 투 포인터
\`\`\`python
def two_sum(nums, target):
    left, right = 0, len(nums) - 1
    while left < right:
        s = nums[left] + nums[right]
        if s == target: return [left, right]
        elif s < target: left += 1
        else: right -= 1
\`\`\`

## 슬라이딩 윈도우
\`\`\`python
def max_subarray(nums, k):
    window = sum(nums[:k])
    result = window
    for i in range(k, len(nums)):
        window += nums[i] - nums[i - k]
        result = max(result, window)
    return result
\`\`\`

## BFS / DFS
\`\`\`python
from collections import deque

def bfs(graph, start):
    visited = set([start])
    queue = deque([start])
    while queue:
        node = queue.popleft()
        for neighbor in graph[node]:
            if neighbor not in visited:
                visited.add(neighbor)
                queue.append(neighbor)
\`\`\``,
      categorySlug: "study-notes",
      tagNames: ["Python", "알고리즘"],
      daysAgo: 2,
    },
  ];

  for (const note of notes) {
    const tagIds = (note.tagNames || []).map((n) => tags[n]).filter(Boolean);

    await prisma.note.create({
      data: {
        title: note.title,
        content: note.content,
        authorId: admin.id,
        categoryId: note.categorySlug ? categories[note.categorySlug] : null,
        createdAt: new Date(Date.now() - (note.daysAgo || 0) * 86400000),
        tags: tagIds.length > 0 ? {
          create: tagIds.map((tagId) => ({ tag: { connect: { id: tagId } } })),
        } : undefined,
      },
    });
  }
  console.log(`✅ 노트 ${notes.length}개 생성`);

  // ==================== 메모 ====================
  const memos = [
    { content: "내일 미팅 준비: 보안 진단 결과 보고서 정리하기", categoryTag: "업무", pinned: true, daysAgo: 0 },
    { content: "Tailwind CSS v4 릴리스 확인 → 새 프로젝트에 적용 고려", categoryTag: "개발", pinned: false, daysAgo: 1 },
    { content: "바이크 오일 교환 예약 (3,000km 도달)", categoryTag: "바이크", pinned: true, daysAgo: 2 },
    { content: "Next.js middleware에서 rate limiting 구현 방법 조사", categoryTag: "개발", pinned: false, daysAgo: 3 },
    { content: "Docker multi-stage build로 이미지 크기 절반 줄이기 성공! 1.2GB → 580MB", categoryTag: "개발", pinned: false, daysAgo: 4 },
    { content: "OWASP Top 10 2025 변경사항 확인하기", categoryTag: "보안", pinned: false, daysAgo: 5 },
    { content: "주말 투어 코스: 서울 → 남이섬 → 춘천 (왕복 약 200km)", categoryTag: "바이크", pinned: false, daysAgo: 6 },
    { content: "Prisma $queryRaw 사용 시 SQL Injection 주의! 반드시 Prisma.sql 사용할 것", categoryTag: "개발", pinned: true, daysAgo: 7 },
    { content: "면접 준비: 시스템 디자인 - URL Shortener, Rate Limiter", categoryTag: "면접", pinned: false, daysAgo: 9 },
    { content: "GitHub Actions self-hosted runner 설정 완료. EC2 비용 절감 효과 확인 필요", categoryTag: "DevOps", pinned: false, daysAgo: 11 },
    { content: "React 19 useOptimistic, useFormStatus 사용법 정리 필요", categoryTag: "개발", pinned: false, daysAgo: 13 },
    { content: "SSL 인증서 갱신 알림 설정 (Let's Encrypt 90일)", categoryTag: "보안", pinned: false, daysAgo: 14 },
  ];

  for (const memo of memos) {
    await prisma.memo.create({
      data: {
        content: memo.content,
        categoryTag: memo.categoryTag,
        pinned: memo.pinned,
        authorId: admin.id,
        createdAt: new Date(Date.now() - memo.daysAgo * 86400000),
      },
    });
  }
  console.log(`✅ 메모 ${memos.length}개 생성`);

  // ==================== 퀴즈 ====================
  const quizSets = [
    {
      title: "네트워크 기초 퀴즈",
      description: "OSI 7계층, TCP/IP, HTTP 기초 지식을 테스트합니다",
      questions: [
        { question: "OSI 7계층의 4번째 계층은?", answer: "전송 계층 (Transport Layer)", hint: "TCP, UDP가 속하는 계층" },
        { question: "HTTP 기본 포트 번호는?", answer: "80", hint: "HTTPS는 443" },
        { question: "TCP와 UDP의 가장 큰 차이는?", answer: "TCP는 연결 지향적(신뢰성), UDP는 비연결형(속도)", hint: "핸드셰이크 여부" },
        { question: "DNS의 역할은?", answer: "도메인 이름을 IP 주소로 변환", hint: "Domain Name System" },
        { question: "서브넷 마스크 255.255.255.0의 CIDR 표기는?", answer: "/24", hint: "255는 8비트" },
      ],
    },
    {
      title: "정보보안 기초 퀴즈",
      description: "OWASP, 암호화, 인증 관련 기초 문제",
      questions: [
        { question: "OWASP Top 10에서 1순위 취약점은? (2021)", answer: "Broken Access Control", hint: "접근 제어 관련" },
        { question: "대칭키 암호화의 예시 알고리즘은?", answer: "AES (Advanced Encryption Standard)", hint: "같은 키로 암호화/복호화" },
        { question: "JWT의 세 부분은?", answer: "Header, Payload, Signature", hint: "점(.)으로 구분" },
        { question: "CSRF 공격을 방어하는 대표적인 방법은?", answer: "CSRF Token 사용", hint: "요청마다 고유한 토큰" },
        { question: "bcrypt의 특징은?", answer: "솔트(salt)를 자동 생성하여 해싱, 연산량 조절 가능", hint: "패스워드 해싱에 사용" },
      ],
    },
  ];

  for (const quiz of quizSets) {
    const existing = await prisma.quizSet.findFirst({ where: { title: quiz.title } });
    if (existing) continue;

    await prisma.quizSet.create({
      data: {
        title: quiz.title,
        description: quiz.description,
        authorId: admin.id,
        questions: {
          create: quiz.questions.map((q, i) => ({
            question: q.question,
            answer: q.answer,
            hint: q.hint,
            order: i + 1,
          })),
        },
      },
    });
  }
  console.log(`✅ 퀴즈 세트 ${quizSets.length}개 생성`);

  // ==================== 외부 링크 ====================
  const links = [
    { title: "GitHub", url: "https://github.com", icon: "github", order: 1 },
    { title: "Notion", url: "https://notion.so", icon: "book-open", order: 2 },
    { title: "Vercel", url: "https://vercel.com", icon: "triangle", order: 3 },
    { title: "AWS Console", url: "https://console.aws.amazon.com", icon: "cloud", order: 4 },
    { title: "ChatGPT", url: "https://chat.openai.com", icon: "bot", order: 5 },
  ];

  for (const link of links) {
    const existing = await prisma.externalLink.findFirst({ where: { url: link.url, userId: admin.id } });
    if (existing) continue;

    await prisma.externalLink.create({
      data: { ...link, userId: admin.id },
    });
  }
  console.log(`✅ 외부 링크 ${links.length}개 생성`);

  // ==================== 활동 로그 ====================
  const activities = [
    { action: "CREATE", target: "post", daysAgo: 0 },
    { action: "UPDATE", target: "post", daysAgo: 0 },
    { action: "CREATE", target: "note", daysAgo: 1 },
    { action: "CREATE", target: "memo", daysAgo: 1 },
    { action: "CREATE", target: "post", daysAgo: 2 },
    { action: "DELETE", target: "memo", daysAgo: 3 },
    { action: "CREATE", target: "quiz", daysAgo: 4 },
    { action: "UPDATE", target: "settings", daysAgo: 5 },
    { action: "CREATE", target: "post", daysAgo: 6 },
    { action: "CREATE", target: "note", daysAgo: 7 },
  ];

  for (const act of activities) {
    await prisma.activityLog.create({
      data: {
        action: act.action,
        target: act.target,
        userId: admin.id,
        createdAt: new Date(Date.now() - act.daysAgo * 86400000),
      },
    });
  }
  console.log(`✅ 활동 로그 ${activities.length}개 생성`);

  // ==================== 시스템 설정 ====================
  const settings = [
    { key: "site_name", value: "88Motorcycle" },
    { key: "site_description", value: "개인 통합 플랫폼 - 데이터 허브, 블로그, 아카이브, 자동화" },
    { key: "posts_per_page", value: "10" },
  ];

  for (const setting of settings) {
    await prisma.systemSetting.upsert({
      where: { key: setting.key },
      update: { value: setting.value },
      create: setting,
    });
  }
  console.log(`✅ 시스템 설정 ${settings.length}개 생성`);

  console.log("\n🎉 시드 데이터 생성 완료!");
}

main()
  .then(async () => {
    await prisma.$disconnect();
  })
  .catch(async (e) => {
    console.error(e);
    await prisma.$disconnect();
    process.exit(1);
  });
