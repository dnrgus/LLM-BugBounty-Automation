# Support matrix (v5.0)

What v5.0 supports end to end, and what it deliberately does not (v5.0 개발 계획서 8.2). Requests outside this matrix are deferred by default (plan section 10).

| 영역 | v5.0 지원 | 지원하지 않음 |
|---|---|---|
| LLM / RAG / Agent | prompt injection, indirect injection, system prompt / data leakage, tool/agent misuse 계열 testcase를 fake/OpenAI 호환/HTTP/SSE/WebSocket/browser target에 실행, canary + negative control + 반복 재현 | 모든 모델/정책 우회 보장 |
| Web / API | GET/HEAD/OPTIONS 실행, POST/PUT/PATCH/DELETE inventory + 정책 gate(dry_run 기본), tester 소유 계정 두 개로 read-only object access 비교 | 파괴적 exploit 자동화, 상태 변경 method의 object 비교 자동화, id 열거/추측 |
| Static — Python | Flask/FastAPI route/auth/dataflow, 프로젝트 전체 interprocedural (module-level 함수, import alias) | class method receiver 타입 추론, sanitizer 인식 |
| Static — JS/TS | Express/Next.js/NestJS route, NestJS `@UseGuards`, 함수 내부 dataflow, body schema 추론 | 함수 간/파일 간 dataflow (WP-05 미구현), 모듈 별칭 sink (`childProcess.exec`) |
| Static — 기타 언어 | Django `path()`, Spring/Rails/Gin 등은 탐지 신호만 | Java/Spring, PHP, Go, .NET, Rails AST/dataflow |
| Judge | canary/regex/refusal 규칙 기반 1차 + opt-in semantic 2차, 충돌·저신뢰 시 `needs_review` | LLM 판단만으로 confirmed |
| Evidence | raw/sanitized 분리, SHA-256 manifest, redaction, report 시 재검증 | 법적/조직별 제출 형식 자동 대응 |
| Interface | 로컬 CLI (`scan`, `validate`, `reproduce`, `report`, `benchmark`, `release-check` 등) | SaaS, 대시보드, 멀티유저/팀 계정, 중앙 서버 |
