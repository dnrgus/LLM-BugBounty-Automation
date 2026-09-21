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
core/          orchestrator, 데이터 모델, fingerprint
scope/         Scope와 Program Policy 검사
targets/       Target Adapter 계약과 Fake Target
adapters/      LLM/Recon/Discovery 외부 도구 어댑터
attacks/       Mutation Engine과 PyRIT Adaptive Planner
recon/         Subfinder/httpx/Katana/ffuf 기반 Asset/Endpoint 파이프라인
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

# Subfinder/httpx/Katana/ffuf 결과로 Asset/Endpoint map 생성 및 Scope 재검증
python main.py recon \
  --subfinder-input tests/fixtures/tools/subfinder-results.jsonl \
  --httpx-input tests/fixtures/tools/httpx-results.jsonl \
  --katana-input tests/fixtures/tools/katana-results.jsonl \
  --ffuf-input tests/fixtures/tools/ffuf-results.json
```

## 산출물

`sample-run`은 다음 산출물을 로컬에 생성합니다.

- `evidence/raw/`: 원본 요청/응답 Evidence
- `evidence/sanitized/`: redaction 적용 Evidence와 redaction log
- `reports/shareable/`: 제출용 Markdown/JSON report

위 경로는 기본적으로 `.gitignore` 대상입니다.

## v0.1.0-mvp1 Release Gate

```bash
pytest
python main.py judge-benchmark
python main.py sample-run --target fake-llm
git status --short
```

## 마일스톤

설계서 기준 실행 가능한 마일스톤은 다음과 같습니다.

- `v0.1.0-mvp1`: core validation loop, evidence, basic reporting
- `v0.2.0-llm-redteam`: Promptfoo/Garak/Mutation/PyRIT 통합
- `v0.3.0-discovery`: recon, web security tools, AI discovery, RAG harness 통합
- `v1.0.0`: 안정화된 첫 릴리스

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
