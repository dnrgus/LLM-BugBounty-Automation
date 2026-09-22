# LLM-BugBounty-Automation

[![CI](https://github.com/dnrgus/LLM-BugBounty-Automation/actions/workflows/ci.yml/badge.svg)](https://github.com/dnrgus/LLM-BugBounty-Automation/actions/workflows/ci.yml)

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
- Capability Probe: `profile` 명령이 target config에 선언된 capability를 실제 probe 요청(Scope/Policy 게이트와 Executor를 그대로 통과)으로 검증 — 예: `sessions: true`라고 선언했지만 실제로는 turn 간 상태를 기억 못 하는 target을 잡아냄. Executor에 session override(`session_id`)를 추가해 서로 다른 Trace가 같은 target-side 세션을 공유하도록 지원
- `reproduce <finding-id>`: 저장된 finding을 실제 target에 다시 재현(프로그램이 패치했는지 확인하는 용도). `--minimize`로 성공한 prompt를 segment 단위로 제거하며 재현이 유지되는 최소 형태까지 축소하는 Minimal PoC 생성, 결과를 evidence로 저장
- Adapter Contract Test: 5종 Target Adapter(Fake LLM/Agent/RAG, OpenAI-compatible, CustomHTTP) 전체가 metadata/capabilities/healthcheck/send/trace/reset_session 계약을 동일하게 만족하는지 하나의 테스트 스위트로 검증
- GitHub Actions CI: push/PR마다 `ruff`(버그성 규칙만) → `pytest` → `doctor`/`judge-benchmark`/`sample-run`×3/`scan --profile full` smoke → raw evidence/private report 미포함 확인까지 자동 실행 (Python 3.11/3.12 매트릭스)
- Session Strategy: testcase가 `session_strategy: shared_suite|persistent`를 선언하면 같은 run(또는 같은 target)의 동일 category testcase들이 하나의 target-side 세션을 실제로 공유 (멀티턴/상태 누적 테스트용)

**v3.0 Universal Bug Bounty Architecture 마이그레이션 진행 중** (URL-only/Source-only/Hybrid 대상까지 하나의 Core로 처리하는 확장 — 기존 기능은 전부 보존):

- AttackSurface 모델: LIVE(Discovery)와 SOURCE(정적분석) 결과가 서로 의존하지 않고 합류하는 공통 중간표현(`AttackSurfaceItem`). 같은 (method, path) endpoint나 (name, position) parameter는 자동 merge, static+live 동시 관측 시 confidence 상승, 충돌하는 메타데이터는 덮어쓰지 않고 `provenance`에 양쪽 다 보존
- SOURCE MODE (`audit <path>`): 소스 트리를 정적 분석해 언어/프레임워크 감지, route(Flask/FastAPI/Express/Django, Next.js Pages/App Router) 추출, input source(request.args/json/body 등)·위험 sink(eval/os.system/pickle.loads/SQL 문자열 조합 등)·secret(AWS key/PEM/generic API key, 값 자체는 절대 저장 안 함)·LLM/RAG/Agent SDK 연동 패턴까지 탐지. Python/JS/TS는 AST 기반(v3.2.0, 아래 참고)이고 나머지는 정규식 기반
- LIVE MODE (`discover <url>`): URL만 갖고 있는 대상을 안전하게 passive crawl — GET/HEAD만 사용하고 공격 payload는 절대 전송하지 않음. 페이지 fingerprint(status/title/서버 헤더), form/인증 힌트(password form, set-cookie, www-authenticate), JS에서 추출한 API path·WebSocket URL·노출된 source map, AI/LLM 관련 키워드 힌트를 `AttackSurfaceItem`으로 수집. 발견된 링크/스크립트도 전부 다시 Scope/Policy 검증을 통과해야 fetch됨 (동일 출처 여부가 아니라 Scope 설정이 유일한 기준)
- Auto Profiler (`discover --classify` / `--auto-profile`): LIVE MODE 결과를 web/api/graphql/llm/rag/agent/websocket 후보로 분류. `--auto-profile`은 그중 llm/api 후보를 기존 Capability Probe(`core/profiler.py`)로 연결해 실제로 찔러봄 — 스키마를 모르는 블랙박스 엔드포인트라 몇 가지 흔한 요청/응답 형태를 순서대로 시도하는 best-effort이며, 모든 시도는 다시 한 번 독립적으로 Scope/Policy 검증을 통과해야 함
- Pack Selector (`discover --select-packs`): 분류된 target 능력(web/api/graphql/llm/rag/agent/websocket) × Policy(`testing.*` 카테고리 허용 여부) × Budget(예상 요청 비용 대비 잔여 예산)을 기준으로 어떤 Attack Pack을 실행할지 결정. 적용 대상이 아니거나, 정책이 막거나, 예산이 부족한 경우도 전부 이유와 함께 기록 (discovery의 `skipped_out_of_scope`와 동일한 투명성 원칙)
- Pack 실행 연결 (`discover --run-packs`): 선택된 Pack을 실제로 연결. `testcase_suite` 계열 Pack(llm_core/rag_injection/agent_tool_abuse)은 카테고리를 합쳐 기존 scan 파이프라인(Executor→JudgeEnsemble→Reproducer)으로 한 번에 실행 — `--pack-target`으로 대상 지정. 외부 툴 계열 Pack(web_scan/nuclei, api_fuzz/dalfox, secret_scan/trufflehog)은 이 프로젝트가 지금까지 그래왔듯 바이너리를 직접 실행하지 않고, `--nuclei-results` / `--dalfox-results` / `--trufflehog-results`로 이미 만들어진 결과 파일을 넘겨야 실행됨 — 툴이 설치 안 됐는지, 설치는 됐는데 결과 파일이 없는지를 구분해서 이유를 기록
- HYBRID MODE (`correlate <source_path> <url>`): SOURCE 정적분석과 LIVE discovery를 같은 대상에 대해 함께 실행하고, U2의 AttackSurfaceItem merge 규칙으로 합류 — 소스에서 발견된 route가 실제로 LIVE에서도 관측되면 confidence가 올라가고 `source_type: "merged"`로 양쪽 provenance를 함께 기록 ("정적 root cause + 실제 도달 가능성"이 둘 다 확인된 경우). LIVE에서 관측되지 않은 SOURCE 전용 발견(예: admin 전용 sink)은 그대로 낮은 확신도로 남음
- Scenario Engine (`run-scenario`): 기존 단일 testcase 기반 Executor 경로와 나란히 동작하는 multi-turn/cross-session 공격 워크플로우 실행기. 각 step은 자신만의 `session_ref`를 가질 수 있어 "세션 A에서 정보를 흘리고, 세션 B에서 그걸 다시 물어본다" 같은 cross-session 시나리오를 표현 가능. `{{PREV_RESPONSE}}` / `{{STEP:id}}`로 이전 step의 응답을 다음 step 프롬프트에 템플릿으로 삽입
- Universal Manifest (`adapter: universal`): 기존 `openai_compatible`/`custom_http` target.yaml 스키마는 그대로 두고, 세 번째 어댑터 종류로 Auth(none/bearer/api_key/basic) × Interaction(chat_completions의 실제 messages 배열 / custom_json 템플릿) × Session(stateful 여부)을 독립적으로 조립하는 `CompatibilityAdapter` 추가. `config/targets/universal.example.yaml` 참고 — 기존 `sample-run`/`scan`/`run-scenario` 등 모든 CLI 명령이 그대로 사용 가능
- Event 모델 + 범용 WebSocket 전송 (`adapter: websocket`): 스트리밍 대상을 위한 네 번째 어댑터 종류. START/TOKEN/RETRIEVAL/TOOL_CALL/FINAL/ERROR 형식 Event 모델로 임의의 WS 프레임 형식(설정 가능한 `type_field`/`text_field`/`*_types`)을 해석해 하나의 TargetResponse로 합침. `config/targets/websocket.example.yaml` 참고 — Scope/Policy 엔진도 `ws://`/`wss://` 스킴을 인식하도록 함께 확장
- Plugin SDK + Browser 어댑터 (`adapter: browser`): `targets/config.py`를 건드리지 않고도 새 adapter 종류를 등록할 수 있는 plugin registry(`plugins/registry.py`, 내장 plugin 또는 `llmbb.target_adapters` entry point로 서드파티 plugin도 등록 가능). API가 전혀 없는 채팅 UI를 위한 Playwright 기반 브라우저 자동화 어댑터가 기본 내장 plugin으로 등록되어 있음 — Playwright는 선택 설치(`pip install playwright && playwright install chromium`)이며, 설치 안 된 상태에서도 모듈 로드 자체는 항상 정상 동작하고 실제 사용 시점에만 명확한 에러 발생

**v3.1.0 Operational Pipeline 진행 중** (기능 모음을 하나의 실전 운용 파이프라인으로 연결):

- Scan Orchestrator 통합 (P3.1-1, `scan <url>`): LIVE MODE 분석의 단일 진입점. 기존에는 `discover --classify --auto-profile --select-packs --run-packs`를 따로 조합해야 했던 것을, `scan <url>` 한 번으로 discover → classify → (선택) auto-profile → pack 선택 → pack 실행(testcase_suite는 Executor/Judge/Reproducer로, 외부 툴은 결과 파일이 있을 때만) → finding dedup/root cause cluster → report까지 연결. `--profile`을 생략하면 `quick`으로 기본 동작하며, URL을 생략하면 기존 fixture 기반 `--profile` 파이프라인이 그대로(동작 변경 없이) 실행됨
- Scenario → Finding Lifecycle 연결 (P3.1-2): `run-scenario`가 flag된 각 step을 `reproduction_spec(type=scenario)`을 가진 일반 Finding으로 승격 — scenario 전체(steps/prompts/session_ref)를 spec에 그대로 스냅샷하므로 `reproduce <finding-id>`가 원본 `--scenarios` YAML 없이도 나중에 재현 가능. 재현 시 전체 scenario를 다시 실행하고(step 하나만 격리하면 이전 step이 만든 상태가 사라짐), flag된 step의 prompt만 canary-neutralized/benign 버전으로 바꾼 control replay와 비교하는 control-vs-attack 검증을 거침
- External ToolRunner 실행 계층 (P3.1-3, `tools/runner.py`): Nuclei/Dalfox가 로컬에 설치돼 있고 결과 파일이 안 주어졌다면(`scan <url>` / `discover --run-packs`), 더 이상 "설치는 됐지만 결과 파일 없음"으로만 멈추지 않고 Policy/Scope 통과한 URL에 대해 실제로 실행 — `subprocess`는 항상 `shell=False`(argv 리스트, 셸 문자열 없음), timeout 시 프로세스를 kill, 실행한 버전을 기록. TruffleHog는 URL fetch 모드가 없어(파일시스템 스캔 전용) 이번 단계에서는 여전히 결과 파일 방식만 지원. 미설치 툴은 여전히 scan 전체를 깨지 않고 `skipped_tool_not_installed`로 기록

**v3.2.0 Source Intelligence 진행 중** (SOURCE MODE를 패턴 매칭에서 구조 이해로 승격):

- Python AST 파서 (P3.2-1, `source/parsers/python.py`): Flask/FastAPI route를 표준 `ast` 모듈로 파싱해 method/path/handler/file/line을 추출 — 기존 정규식 추출기와 달리 `methods=[...]` kwarg를 실제로 읽어서 method를 정확히 판별. 파싱 실패(SyntaxError) 시 해당 파일만 기존 정규식 추출기로 자동 fallback
- JavaScript/TypeScript AST 파서 (P3.2-2, `source/parsers/javascript.py`, 선택 설치 `pip install '.[jsts]'`): tree-sitter로 Express(`app.get/post/put/delete/patch`)와 Next.js API route(Pages Router `pages/api/**`, App Router `app/**/route.ts`의 `export function GET/POST/...`)를 추출, 동적 세그먼트(`[id]` → `:id`, `[...slug]` → `*slug`)도 변환. tree-sitter 미설치 시에도 모듈 로드는 항상 정상 동작하고 해당 파일만 정규식 fallback으로 처리(Playwright와 동일한 optional-dependency 패턴)
- Source/Sink Lightweight Dataflow (P3.2-3, `source/dataflow/python.py`): request.args/json/form/cookies/headers 같은 실제 소스에서 SQL(`execute`/`query`)·명령 실행(`os.system`/`subprocess.*`)·역직렬화(`pickle`/`yaml.load`)·템플릿 인젝션(`render_template_string`)·파일 접근(`open`)·SSRF(`requests.*`/`httpx.*`)·LLM prompt sink(`ChatCompletion.create` 등, list/dict 리터럴 내부까지 추적)로 실제로 도달하는지를 함수 단위 + 1-hop interprocedural로 추적. 단순 정규식 매치(기존 `_find_sinks`)와 별도로 `asset_type: dataflow`로 file/line 근거가 있는 구체적 증거만 별도 표시
- Auth/AI Source Intelligence (P3.2-4, `source/auth/python.py`, `source/ai/python.py`): route handler에 `@login_required`/`jwt_required`/`Depends(get_current_user)` 같은 auth guard가 있는지 탐지 — 단, "guard가 안 보임"을 "인증이 없다"로 단정하지 않고 `asset_type: auth`의 evidence-backed candidate(`detected: false` + 명시적 note)로만 출력 (미들웨어/프레임워크 기본값일 수 있음). LLM/RAG/Agent 파일 단위 시그널도 `dynamic_validation_hint` 필드(예: "prompt_injection/system_prompt_leak testcase로 canary 기반 negative control과 비교해서 검증")를 포함해 정적 후보 → 동적 검증으로 이어지는 다음 단계를 명시

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

# Target capability probe (선언된 capability를 실제 요청으로 검증)
python main.py profile --target-config config/targets/my-target.yaml --scope config/my-scope.yaml

# 저장된 finding을 실제 target에 다시 재현 (프로그램이 패치했는지 확인) + Minimal PoC 생성
python main.py reproduce finding_XXXXXXXXXXXX --target-config config/targets/my-target.yaml \
  --scope config/my-scope.yaml --minimize

# SOURCE MODE: 소스코드 정적 분석 (route/input/sink/secret/LLM 연동 탐지)
python main.py audit ./my-service-source

# LIVE MODE: URL만으로 passive discovery (GET/HEAD만 사용, 공격 payload 없음)
python main.py discover https://target.example.com --scope config/my-scope.yaml --max-pages 20

# Auto Profiler: discovery 결과를 web/api/graphql/llm/rag/agent/websocket으로 분류 + Capability Probe 연결
python main.py discover https://target.example.com --scope config/my-scope.yaml --classify --auto-profile

# Pack Selector: 분류 결과 + policy + (선택) budget 기준으로 어떤 Attack Pack을 실행할지 결정
python main.py discover https://target.example.com --scope config/my-scope.yaml --select-packs --pack-budget-requests 200

# Pack 실행: 선택된 Pack을 실제로 연결 (testcase_suite는 --pack-target으로 실행, 외부 툴은 결과 파일이 있어야 실행)
python main.py discover https://target.example.com --scope config/my-scope.yaml --run-packs \
  --pack-target openai --pack-target-config config/targets/my-target.yaml \
  --trufflehog-results trufflehog-output.jsonl

# HYBRID MODE: SOURCE 정적분석 + LIVE discovery를 같은 대상에 대해 상관관계 분석
python main.py correlate ./my-service-source https://target.example.com --scope config/my-scope.yaml

# Scenario Engine: multi-turn/cross-session 시나리오 실행 (scenario/suites/*.yaml)
python main.py run-scenario --scenarios scenario/suites/basic.yaml --target fake-llm

# Browser 어댑터 (API 없는 채팅 UI): 먼저 pip install playwright && playwright install chromium
python main.py sample-run --target openai --target-config config/targets/browser.example.yaml \
  --scope config/my-scope.yaml

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

# LIVE MODE scan (v3.1.0 P3.1-1 Scan Orchestrator): scan에 URL을 주면
# discover -> classify -> select-packs -> run-packs 를 한 번에 연결해서 실행
# (기존 discover --classify --auto-profile --select-packs --run-packs 조합과 동일한 결과)
python main.py scan https://target.example.com --scope config/my-scope.yaml \
  --pack-target openai --pack-target-config config/targets/my-target.yaml
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

- 실제 Target Adapter는 OpenAI 호환 API(`--target openai`)와 자체 REST 스키마(`--target-config`, `CustomHTTPAdapter`)까지만 있음. **브라우저 자동화가 필요한 웹 챗봇 UI, WebSocket 기반 API, MCP/Tool 호출을 하는 Agent용 Adapter는 의도적으로 만들지 않음** — 실전형 v2.0 설계서 자체가 "브라우저 자동화에 의존한 모든 UI 조작"을 v1 비목표로 명시했고, WebSocket/Agent-MCP는 실제 대상의 구체적인 프로토콜/스키마 없이 범용으로 만들면 검증 안 된 채 깨지기 쉬워서 실제 타겟이 정해지면 그때 `targets/base.py` 계약(`targets/http_target.py`가 참고 예시)으로 추가하는 게 안전함
- 스트리밍 응답(SSE/chunked) 미지원 — Executor는 완전한 응답 한 번을 기다렸다가 Judge에 넘기는 동기 모델이라, 스트리밍을 지원하려면 Trace/Judge 파이프라인 전체에 걸친 구조 변경이 필요함
- Capability는 target config에 선언(`capabilities: {chat: true, ...}`)하는 게 기본이며, `profile` 명령이 실제 probe 요청으로 선언과 실제 동작(현재는 multi-turn 기억 여부)의 불일치를 검증. rag/tools/mcp 같은 항목은 한 번의 probe로 안전하게 자동 판별하기 어려워 여전히 선언 기반
- Session Strategy: testcase에 `session_strategy: per_testcase|shared_suite|persistent`를 선언 가능. `shared_suite`는 같은 run 안에서 같은 category의 testcase들이 세션을 공유(멀티턴/상태 누적 테스트용), `persistent`는 run이 달라져도 같은 target+category면 세션을 재사용. `cross_session_pair`(A/B 세션 비교)는 우리 실행 모델(testcase 1개 = 실행 1번)에 잘 안 맞아 미구현
- Promptfoo/Garak/PyRIT는 여전히 실제 CLI를 직접 실행하지 않고 각 도구가 생성한 JSON/JSONL 출력 파일을 정규화하는 방식만 지원. Nuclei/Dalfox는 P3.1-3부터 `tools/runner.py`를 통해 설치돼 있고 결과 파일이 없으면 실제로 실행됨(Policy/Scope 통과 필수, `shell=False`). TruffleHog는 URL fetch 모드가 없어(파일시스템 스캔 전용, `tools/trufflehog.py`) 여전히 결과 파일 방식만 지원
- RAG retrieval은 실제 embedding/vector store가 아니라 오프라인 재현성을 위한 결정론적 Jaccard 토큰 overlap으로 근사됨
- Root Cause Clustering은 단일 패스 greedy 그룹핑이며 pgvector 기반 semantic clustering은 v2 계획 (설계서 22절)
- Judge는 rule/regex/canary만 구현되어 있고, `llm`/`full` 프로필 설정에 남아있는 `semantic` judge 항목은 아직 미구현 (해당 이름을 사용하는 judge 요청은 조용히 no-op 처리됨)
- Attack Budget의 cost_usd는 provider별 가격표가 없어 실제 비용 데이터가 주어질 때만 집계되고, 기본적으로는 항상 0으로 유지되어 `estimated_cost_usd` 상한이 사실상 강제되지 않음

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
