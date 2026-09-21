# LLM-BugBounty-Automation

허가된 LLM, RAG, AI Agent, 웹 기반 AI 서비스를 반복 가능하고 증거 중심으로 점검하기 위한 보안 테스트 자동화 프로젝트입니다.

이 저장소의 기본 원칙은 **Scope first**, **Policy aware**, **Evidence driven**, **Reproducible**입니다. 허가되지 않은 대상이나 프로그램 정책에서 금지한 행위는 실행 전에 차단하는 것을 목표로 합니다.

현재 구현된 범위:

- `doctor`, `fingerprint`, `validate-scope`, `sample-run` CLI
- Scope + Program Policy 실행 게이트
- deny 우선 URL/domain 정책, subdomain 명시 허용, redirect 재검증, request budget enforcement
- Capability 기반 YAML 테스트케이스 로딩
- 외부 서비스 없이 테스트 가능한 Fake LLM, Fake Agent, Fake RAG Target
- Run, Target, Testcase, Prompt, Request, Response, Trace/Event, Judgement, Finding, Evidence, Reproduction, Report 저장 모델
- SQLite 저장소와 Trace ordering 검증
- OWASP GenAI, OWASP Agentic, MITRE ATLAS 기반 coverage matrix
- 테스트케이스 schema validation, capability/policy 기반 selector, prompt rendering
- Executor session/checkpoint, timeout, retry, idempotency key, trace export
- Reproducer repeat attempts, negative controls, confirmed/unstable/rejected 상태 전이
- deterministic judge, judge benchmark, raw/sanitized evidence, redaction log, Markdown/JSON report
- Tool Doctor version snapshot, Promptfoo/Garak/PyRIT output normalization
- Mutation Engine 전략 변형, lineage, hash dedup, 전략별 통계
- PyRIT adaptive redteam 결과 기반 Adaptive Mutation Plan 생성 (multi-turn 성공 시나리오를 후속 mutation lineage로 연계)
- PyRIT 기반 Adaptive Mutation을 기존 Executor/Judge Ensemble/Reproducer 파이프라인에 그대로 유입해 Finding/Evidence/Report 생성
- Subfinder/httpx/Katana/ffuf 결과를 Asset/Endpoint로 정규화하고 Scope Policy로 재검증하는 Recon 파이프라인
- Nuclei/Dalfox 결과를 NormalizedResult(FindingCandidate)로, TruffleHog 결과를 SecretFinding으로 정규화 (원본 secret 값은 절대 저장/출력하지 않고 도구가 제공한 redacted 값만 사용)
- Recon Endpoint를 AI API/Chat/RAG/Agent로 분류하는 offline 휴리스틱 Classifier
- RAG Test Harness: controlled/injection 문서 corpus, chunking, deterministic retrieval, retrieval trace, RAG corpus hash를 Environment Fingerprint에 포함
- Finding Dedup/Root Cause Clustering: category+seed testcase 기반 exact dedup과 제목 유사도 기반 heuristic dedup, root_cause_key는 run 간에도 안정적이라 동일 원인 재발을 연결 가능. `sample-run`/`adaptive-run`이 root cause cluster report를 자동 생성
- Full Orchestrator: `scan --profile {quick,llm,agent,rag,web,full}`이 scope/policy → recon → classify → scan → judge → reproduce → dedup → report를 프로필별 설정(judges/executor/reproduction/mutation/target)으로 end-to-end 연결. `full` 프로필은 LLM/Agent/RAG scan과 PyRIT adaptive 결과를 하나의 root cause cluster로 통합
- Hardening: 외부 도구 출력의 score 필드 타입 변경(예: 숫자 → 문자열 라벨)이 파서를 crash시키지 않고 graceful하게 처리, Evidence Sanitizer에 AWS access key/PEM private key 패턴 추가, clean install(`pip install -e ".[dev]"` → `pytest` → `scan --profile full`)을 별도 venv에서 검증
- 실제 Target Adapter: `--target openai`(OpenAI 호환 Chat Completions API)와 `--target-config`(YAML로 설정하는 자체 스키마 REST API, `CustomHTTPAdapter`)로 실제 요청 전송. 세션별 multi-turn 대화 이력 유지, `Target*Error` 타입 체계(연결 실패/인증 실패/429/5xx/응답 파싱 실패)로 실패 원인 구분, `httpx.MockTransport` 기반 hermetic 테스트로 실제 네트워크 없이 검증(+ 로컬 mock 서버로 진짜 end-to-end 실행도 확인). API 키는 환경변수로만 주입 (커밋되지 않음)
- Attack Budget: request/token/cost/runtime 예산과 카테고리별(per-suite) 예산을 프로필(`config/pipeline.yaml`)에 선언하면 `scan`/`sample-run`이 예산 소진 시 자동으로 중단. 연속된 target 오류(`repeated_target_errors`)도 크래시 대신 graceful하게 중단하고 결과에 사유를 남김

## 빠른 시작

```bash
python -m pip install -e ".[dev]"
python main.py doctor
python main.py validate-scope --url https://ai.example.com/api/chat
python main.py sample-run

# Fake Agent Target으로 샘플 실행
python main.py sample-run --target fake-agent
pytest
```

`sample-run`은 번들된 Fake LLM Target만 사용합니다. 외부 네트워크나 실제 LLM API를 호출하지 않습니다.

## 저장소 구조

```text
config/        파이프라인, 모델, 도구, 로깅, Scope 예시
core/          orchestrator, Full Orchestrator, pipeline profile, 데이터 모델, fingerprint
scope/         Scope와 Program Policy 검사
targets/       Target Adapter 계약과 Fake Target
adapters/      LLM/Recon/Discovery 외부 도구 어댑터
attacks/       Mutation Engine과 PyRIT Adaptive Planner
recon/         Subfinder/httpx/Katana/ffuf 기반 Asset/Endpoint 파이프라인, AI Endpoint Classifier
rag_harness/   Controlled RAG corpus, chunking, retrieval harness
findings/      Finding dedup, root-cause clustering, cluster report
testcase/      YAML 테스트케이스 스키마, 로더, 기본 suite
executor/      세션 실행기와 Approval Gate
traces/        Trace export helper
judges/        rule, canary, regex, ensemble judge
storage/       SQLite 저장소와 artifact helper
reporting/     Evidence redaction과 report 생성
tests/         단위 및 통합 테스트
```

## 안전 모델

모든 실행은 다음 두 단계를 통과해야 합니다.

1. Scope validation: domain과 URL pattern 검사
2. Program Policy validation: 허용된 테스트 유형, request budget, concurrency, 고위험 action 정책 검사

Scope 정책은 deny 규칙을 allow 규칙보다 먼저 적용합니다. Subdomain은 `allow_subdomains: true`가 명시된 경우에만 허용됩니다. Redirect target은 다시 Scope 검사를 거치며, 범위 밖이면 실행하지 않고 record-only decision으로 남깁니다.

고위험 action은 기본적으로 block 또는 simulate 처리합니다. Raw evidence, 로컬 실행 산출물, private report, credential, `.env` 파일은 커밋되지 않도록 `.gitignore`에 포함되어 있습니다.

## 현재 명령

```bash
# 로컬 런타임과 선택 도구 설치 상태 확인
python main.py doctor

# URL이 Scope/Policy를 통과하는지 확인
python main.py validate-scope --url https://ai.example.com/api/chat

# 오프라인 Fake Target 기반 샘플 실행
python main.py sample-run

# 실제 OpenAI 호환 API 대상 실행 (실제 네트워크 요청! scope.yaml에 해당 도메인이
# 허용돼 있어야 하고, 대상 프로그램의 서면 허가가 있어야만 사용할 것)
export OPENAI_API_KEY=sk-...
python main.py sample-run --target openai --scope config/my-scope.yaml

# 자체 REST 스키마 API 대상 실행 (config/targets/*.example.yaml 참고, 코드 작성 불필요)
cp config/targets/custom-http.example.yaml config/targets/my-target.yaml
# my-target.yaml의 base_url/request/response_text_path를 실제 스펙에 맞게 수정
export TARGET_API_KEY=...
python main.py sample-run --target-config config/targets/my-target.yaml --scope config/my-scope.yaml

# 재현성 fingerprint 생성
python main.py fingerprint

# Target capability 기준 coverage matrix 확인
python main.py coverage --target fake-rag

# Judge baseline benchmark 실행
python main.py judge-benchmark

# 외부 도구 상태 점검 및 lock 파일 생성
python main.py doctor --json --write-lock

# Promptfoo/Garak 결과 정규화
python main.py normalize-tool-output --tool promptfoo --input tests/fixtures/tools/promptfoo-results.json

# Prompt mutation 생성
python main.py mutate --testcase-id LLM-TOOL-001 --strategy json_wrap --var RESOURCE "admin console"

# PyRIT adaptive redteam 결과 정규화
python main.py normalize-tool-output --tool pyrit --input tests/fixtures/tools/pyrit-results.json

# PyRIT 성공 시나리오 기반 Adaptive Mutation Plan 생성 (오프라인 미리보기, 실행 없음)
python main.py adaptive-plan --input tests/fixtures/tools/pyrit-results.json

# PyRIT 기반 Adaptive Mutation을 Executor/Judge/Reproducer 경로로 실행해 Finding까지 생성
python main.py adaptive-run --input tests/fixtures/tools/pyrit-results.json

# Nuclei/Dalfox 결과 정규화 (FindingCandidate)
python main.py normalize-tool-output --tool nuclei --input tests/fixtures/tools/nuclei-results.jsonl
python main.py normalize-tool-output --tool dalfox --input tests/fixtures/tools/dalfox-results.json

# TruffleHog 결과 정규화 (SecretFinding, redacted 값만 노출)
python main.py normalize-tool-output --tool trufflehog --input tests/fixtures/tools/trufflehog-results.jsonl

# Subfinder/httpx/Katana/ffuf 결과로 Asset/Endpoint map 생성 및 Scope 재검증
python main.py recon \
  --subfinder-input tests/fixtures/tools/subfinder-results.jsonl \
  --httpx-input tests/fixtures/tools/httpx-results.jsonl \
  --katana-input tests/fixtures/tools/katana-results.jsonl \
  --ffuf-input tests/fixtures/tools/ffuf-results.json

# RAG Test Harness: controlled/injection 문서 retrieval과 canary 유출을 Judge/Reproducer로 검증
python main.py sample-run --target fake-rag

# Full Orchestrator: scope/policy -> recon -> classify -> scan -> judge -> reproduce -> dedup -> report
# (인자를 생략하면 번들 fixture로 로컬에서 바로 end-to-end 실행됨)
python main.py scan --profile full

# 단일 프로필만 빠르게 실행하고 싶을 때
python main.py scan --profile web
python main.py scan --profile agent
```

## 산출물

`sample-run`은 다음 산출물을 로컬에 생성합니다.

- `evidence/raw/`: 원본 요청/응답 Evidence
- `evidence/sanitized/`: redaction 적용 Evidence와 redaction log
- `reports/shareable/`: 제출용 Markdown/JSON report, `{run_id}_root_cause_clusters.json` (findings가 있을 때만 생성)

위 경로는 기본적으로 `.gitignore` 대상입니다.

## v0.1.0-mvp1 Release Gate

```bash
pytest
python main.py judge-benchmark
python main.py sample-run --target fake-llm
git status --short
```

## v1.0.0 Release Gate

```bash
# clean install (별도 venv 권장)
python -m venv .venv && . .venv/bin/activate
python -m pip install -e ".[dev]"

pytest
python main.py doctor
python main.py judge-benchmark
python main.py sample-run
python main.py sample-run --target fake-agent
python main.py sample-run --target fake-rag
python main.py scan --profile full
git status --short
```

### v1.0.0 완료 범위

- Phase 0~16 전체: core model/storage, scope+policy, target adapter, testcase/coverage,
  executor/trace/approval gate, judge ensemble/benchmark, reproducer/control, evidence/report,
  tool doctor + Promptfoo/Garak/PyRIT, mutation engine, recon, web/secret scanner, AI endpoint
  classifier + RAG harness, finding dedup/root cause, full orchestrator
- Hardening: 외부 도구 출력 파싱이 예상치 못한 필드 타입에서도 crash하지 않고 graceful하게 처리,
  Evidence Sanitizer 패턴 보강, clean install부터 `scan --profile full`까지 별도 venv에서 검증

### 알려진 제한사항 (Known Limitations)

- 실제 Target Adapter는 OpenAI 호환 API(`--target openai`)와 자체 REST 스키마(`--target-config`, `CustomHTTPAdapter`)까지만 있음. 브라우저 자동화가 필요한 웹 챗봇 UI, WebSocket 기반 API, MCP/Tool 호출을 하는 Agent용 Adapter는 아직 없음 (`targets/base.py`의 계약을 구현하면 추가 가능 — `targets/http_target.py`가 참고 예시)
- Capability는 target config에 수동으로 선언해야 함 (`capabilities: {chat: true, ...}`). 실제로 대상에 probe를 보내 자동 감지하는 Capability Probe는 아직 없음
- Promptfoo/Garak/PyRIT/Nuclei/Dalfox/TruffleHog는 실제 CLI를 직접 실행하지 않고, 각 도구가 생성한 JSON/JSONL 출력 파일을 정규화하는 방식만 지원 (Adapter-first 설계 원칙에 따름)
- RAG retrieval은 실제 embedding/vector store가 아니라 오프라인 재현성을 위한 결정론적 Jaccard 토큰 overlap으로 근사됨
- Root Cause Clustering은 단일 패스 greedy 그룹핑이며 pgvector 기반 semantic clustering은 v2 계획 (설계서 22절)
- Judge는 rule/regex/canary만 구현되어 있고, `llm`/`full` 프로필 설정에 남아있는 `semantic` judge 항목은 아직 미구현 (해당 이름을 사용하는 judge 요청은 조용히 no-op 처리됨)

## 마일스톤

설계서 기준 실행 가능한 마일스톤은 다음과 같습니다.

- `v0.1.0-mvp1`: core validation loop, evidence, basic reporting
- `v0.2.0-llm-redteam`: Promptfoo/Garak/Mutation/PyRIT 통합
- `v0.3.0-discovery`: recon, web security tools, AI discovery, RAG harness 통합
- `v1.0.0`: 안정화된 첫 릴리스 (full orchestrator, dedup/root cause, hardening)

## 개발 흐름

각 Phase는 테스트가 통과하고 샘플 실행이 가능한 상태에서 커밋합니다. 실행 가능한 마일스톤에만 tag를 생성합니다.

권장 브랜치 흐름:

```bash
git switch -c feat/target-adapters
pytest
git commit -m "feat: add target adapters and fake targets"
git push -u origin feat/target-adapters
```

Phase 작업은 `feat/*` 브랜치에서 진행하고, 검증 후 `main`에 병합합니다.
