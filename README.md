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

**v3.3.0 Static -> Dynamic Validation** (완료, `v3.3.0` 태그):

- Static/Live Entity Resolver (P3.3-1, `correlation/resolver.py`): SOURCE의 route와 LIVE에서 관측된 endpoint를 `attack_surface/merge.py`의 정확 일치(exact method+path)보다 안정적으로 매칭 — path parameter를 표기법(Flask `<int:id>`, FastAPI `{id}`, `:id`/`*slug`) 관계없이 하나의 canonical `{param}` 토큰으로 정규화하고, 라이브 쪽의 숫자/UUID 같은 concrete 세그먼트도 같은 토큰으로 정규화해서 매칭. `/v1` 같은 version prefix와 리버스 프록시 prefix(suffix match)도 더 낮은 confidence로 허용. LIVE MODE는 안전을 위해 항상 GET으로만 probe하므로 discovery가 관측한 method는 "실제 허용 메소드"가 아니라 "probe에 쓴 메소드"로 취급 — source가 non-GET을 선언해도 매칭은 되지만 confidence가 낮아지고 근거(`basis`)에 명시됨. 모든 매칭 결과는 confidence 0.6 미만이면 `review_required: true`로 표시되어 자동 공격 대상에서 제외됨 (기존 `correlate` 명령/`merge_items()`의 exact-match 동작은 그대로 유지, 이 resolver는 추가된 상위 레이어)
- Validation Plan Generator (P3.3-2, `validation/planner.py`, `validation/templates/categories.yaml`): SOURCE MODE가 만든 모든 static candidate(endpoint/dataflow/auth/llm·rag·agent/secret/function/parameter)를 `executable`(실행 가능한 기존 파이프라인이 있음)/`review_only`(검증 경로는 있지만 사람 판단·컨텍스트 필요)/`unsupported`(이 finding 유형엔 동적 검증 개념 자체가 적용 안 됨) 중 하나로 분류하고 이유를 남김. RCE/파일접근/역직렬화/템플릿 인젝션 같은 destructive sink는 항상 `requires_approval: true`로 자동 실행 대상에서 제외. auth guard가 감지된 endpoint는 인증 컨텍스트가 주어지지 않으면 `review_only`로 강등. LLM/RAG/Agent capability hint는 같은 파일 안에 live로 확인된 endpoint가 있어야만 (기존 testcase_suite pack으로) `executable`이 됨
- Dynamic Validator + Correlated Finding (P3.3-3, `validation/executor.py`, `findings/correlation.py`): "executable"로 분류된 llm/rag/agent capability hint를 실제로 해당 testcase_suite pack(Executor→JudgeEnsemble→Reproducer, 기존 control-vs-attack 로직 그대로 재사용)으로 실행하고, 결과 Finding의 `reproduction_spec`에 `origin: [static, dynamic]`과 원본 static candidate id/entity match 근거를 덧붙여 저장 — static-only 후보와 동적으로 검증된 후보가 구분됨. endpoint/dataflow/auth 등 아직 실행기가 없는 유형은 "not_run"으로 명확히 표시(가짜 executor를 만들지 않음)
- Hybrid CLI 완성 (P3.3-4, `scan <url> --source <path>`): SOURCE audit + LIVE discovery + entity resolution(P3.3-1) + validation planning(P3.3-2) + dynamic validation(P3.3-3)을 한 명령으로 연결. 결과를 `static_findings`(source-only)/`live_findings`(discovery)/`entity_matches`/`validation_plans`/`correlated_findings`(실제 동적 근거가 있는 Finding)로 명확히 구분해서 보고. 같은 static candidate에 매칭되는 live endpoint가 여러 개(예: 페이지 fingerprint + form action)라도 동적 검증은 후보당 한 번만 실행 (duplicate suppression). 기존 `scan <url>`(source 없이)과 `scan --profile`(url 없이) 동작은 완전히 그대로 유지

**v3.4.0 Production Hardening** (완료, `v3.4.0` 태그):

- Checkpoint / Resume (P3.4-1, `core/checkpoint.py`, `storage/run_state.py`): `sample-run --resume-run-id <id>`처럼 `resume_run_id`를 넘기면 그 run_id로 이미 완료된 testcase는 다시 target에 보내지 않고 건너뜀. policy/target/profile/선택된 testcase 내용(hash 포함)으로 만든 config fingerprint가 이전 실행과 다르면 `ConfigFingerprintMismatchError`로 즉시 거부(다른 설정으로 같은 run_id를 재개하는 위험한 상황 차단). `resume_run_id`를 안 주면(기본값) 완전히 기존 동작 그대로 — 매 호출마다 새 run_id 발급. `Run` insert가 idempotent(`insert or ignore`)해져서 같은 run_id를 여러 번 insert해도 에러 없음
- Cancellation / Backpressure (P3.4-2, `core/cancel.py`): `sample-run` 실행 중 Ctrl-C를 누르면 `CancellationToken`이 세팅되고, 다음 testcase로 넘어가기 전(또는 target 호출 직전)에 협조적으로 확인해서 중단 — 진행 중인 요청을 강제로 끊지 않고 안전하게 멈춤. `resume_run_id`와 함께 쓰면 취소된 run은 `run_state`에 `cancelled`로 기록되고 나중에 그대로 재개 가능(`cancelled`도 재개 가능한 상태). `tools/runner.py`의 외부 툴 실행도 이제 timeout뿐 아니라 명시적 cancel로도 자식 프로세스를 즉시 kill. `Executor`는 scope.yaml의 `limits.concurrency`를 실제로 읽어 동시 실행 수를 제한하는 `BoundedConcurrency`(세마포어)를 적용 — 지금은 순차 실행이라 당장 동작에 영향은 없지만 향후 동시 실행 경로가 생기면 그대로 적용됨
- Artifact Integrity / Redaction (P3.4-3, `reporting/integrity.py`): `sample-run`/`scan` 등 모든 실행이 끝날 때마다 그 run의 모든 Evidence 파일(raw+sanitized)을 다시 SHA-256으로 해싱해서 기록된 값과 비교하는 manifest(`{run_id}_manifest.json`)를 생성 — 기록 이후 파일이 바뀌었거나 삭제됐으면 `tamper_detected: true`로 표시(조용히 신뢰하지 않음). `Evidence`에 `raw_path`/`raw_sha256`를 추가해서 raw→sanitized provenance를 DB에도 남김(기존 호출부는 그대로 동작, 전부 추가된 선택 필드). 기존에 이미 있던 `reporting/evidence.py`(raw/sanitized 분리)·`reporting/sanitizer.py`(secret/cookie/token redaction)는 그대로 재사용 — roadmap이 제안한 `evidence/integrity.py` 경로 대신 `reporting/integrity.py`를 쓴 이유는 `evidence/`가 이미 raw/sanitized 산출물이 쌓이는 런타임 디렉터리라서 Python 패키지명과 충돌하기 때문
- Large Target / Performance (P3.4-4): `correlation/resolver.py`의 entity resolution을 O(source × live) 전체 스캔에서 canonical path/버전-제거 경로/마지막 path segment로 인덱싱한 O(source + live)로 변경(정확히 동일한 confidence/basis 결과 유지, 기존 테스트 전부 그대로 통과). `findings/dedup.py`의 exact-key 매칭도 매 finding마다 버킷 전체를 스캔하던 것을 dict 조회 O(1)로 변경(가장 흔한 경우인 "같은 seed testcase의 mutation/adaptive 변종"에 적용, title-similarity fallback은 여전히 선형 — v2로 계획된 영역). `live/discovery.py`의 크롤 큐(`to_visit`)에 `max_queue_size`(기본 1000) cap과 중복 큐잉 방지를 추가 — 링크가 극단적으로 많은 페이지가 있어도 메모리가 무한정 늘어나지 않고, `list.pop(0)`이 매번 처리하는 리스트 크기도 큐 cap으로 제한됨

**v4.1.0 Dynamic Validation Expansion** (완료, `v4.1.0` 태그 — v3.3.0이 llm/rag/agent에만 만들었던 실제 동적 검증기를 endpoint/auth/dataflow까지 확장):

- Validation Contract (4.1-A, `validation/contract.py`): 검증 생명주기를 8단계 상태 머신(`ValidationStatus`: PLANNED/EXECUTABLE/RUNNING/BLOCKED/CONFIRMED/REJECTED/UNSTABLE/REVIEW_ONLY)과 명시적 transition table로 통일. `CONFIRMED`/`REJECTED`/`UNSTABLE`는 의도적으로 기존 `core.models.FindingStatus`와 문자열 값이 동일 — 이름만 비슷한 게 아니라 실제로 호환됨을 테스트로 증명. `validation/legacy_adapter.py`가 v3.3.0의 `ValidationPlan`/`DynamicValidationOutcome`을 그대로 감싸서(수정 없이) 이 새 contract로 노출
- Endpoint Validator (4.1-B, `validation/endpoint_validator.py`): 후보 endpoint에 안전한 메소드(GET/HEAD/OPTIONS, 선언된 메소드 중 안전한 것만 추가)로만 probe. 매 redirect hop마다 Policy로 다시 검증하고 out-of-scope 대상은 절대 따라가지 않음
- Auth Validator (4.1-C, `validation/auth_validator.py`): 명시적으로 제공된 fixture/env/browser-session 인증 컨텍스트 두 개(control/probe)로 같은 요청을 보내 응답 구조(정렬된 JSON key 집합, 원본 body는 절대 저장 안 함)를 비교. 자격증명 추측/탈취는 절대 하지 않으며, 응답이 모호하면 항상 `review_only`/`unstable` — 절대 자동으로 `confirmed` 처리하지 않음
- Dataflow Validator (4.1-D, `validation/dataflow_validator.py`): 정적으로 추적된 source→sink 후보에 무해한 correlation token을 주입해 응답에 반사(reflect)되는지만 확인 — sink의 실제 payload/동작은 절대 실행하지 않음. `os_command`/`sql_injection`/`deserialization` 등 destructive sink 유형이나 request body가 필요한 주입 위치는 아예 요청을 보내지 않고 `review_only`
- Finding/Reproducer/Report 연결 (4.1-E, `validation/finding_adapter.py`): `Finding`에 `origin`/`static_candidate_id`/`validation_task_ids`/`validation_status` 4개 필드 추가(전부 optional, 기존 호출부 영향 없음). Endpoint Validator는 "executable" 분류에서 자동 실행되고(CONFIRMED = 도달 가능 확인, 취약점 단정 아님), Auth/Dataflow Validator는 호출자가 실제 컨텍스트(인증 컨텍스트 쌍/주입 위치)를 명시적으로 제공할 때만 실행(planner가 이 둘을 항상 `review_only`로 유지하는 설계와 일치). `findings/dedup.py`는 이런 validation-origin finding을 `validator_type + candidate + target entity`로 dedup(재검증마다 바뀌는 랜덤 task id 대신 결정론적 키). Report는 static_candidate가 있는 finding에만 정적 근거/동적 검증/제한사항 섹션을 추가
- Release Hardening (4.1-F): 기존 438개 회귀 스위트 + 새 74개 테스트 전부 pass(총 512), llm/rag/agent 동작은 전혀 변경 없이 그대로, 모든 신규 validator가 Policy 게이트를 먼저 통과. **알려진 범위**: endpoint validator는 `scan <url> --source <path>` HYBRID CLI에 아직 자동 연결되지 않음(라이브러리 레벨 dispatch는 완성/테스트됨) — CLI 자동 실행 확장은 회귀 위험을 이 하드닝 단계에서 새로 만들지 않기 위해 의도적으로 다음 단계로 미룸

**v4.2.0 Source Intelligence Expansion** (완료, `v4.2.0` 태그 — v4.0.0까지 "Dataflow/Auth/AI source intelligence는 Python 전용"이었던 제한을 JS/TS까지 확장):

- SourceFact/LanguageSourceAnalyzer Contract (4.2-A, `source/contract.py`): `trace_dataflow`/`find_auth_guards`를 언어별로 등록하는 레지스트리 — 기존에 `source/analyzers.py`가 "python이면 X, 아니면 무시"로 하드코딩했던 것을 대체. Python 백엔드는 이 레지스트리를 통해 그대로 등록(동작 변화 없음), 새 언어는 등록만 하면 바로 연결됨
- JS/TS AST Adapter (4.2-B, `source/parsers/jsts_ast.py`): 기존 `source/parsers/javascript.py`에 인라인돼 있던 tree-sitter 언어 로딩/파싱 로직을 `parse_tree()` 공용 헬퍼로 추출 — NestJS 라우트 추출과 JS/TS dataflow/auth 백엔드가 같은 파싱 단계를 재사용
- NestJS Framework Analyzer (4.2-C, `source/frameworks/nestjs.py`): `@Controller('prefix')` 클래스 데코레이터 + `@Get()/@Post()/...` 메소드 데코레이터로 라우트 추출. NestJS 데코레이터는 대상의 AST 자식이 아니라 형제 노드라서(`export` 키워드가 그 사이에 끼어있음) `.named_children`으로 걸러야 하는 함정을 발견/수정
- JS/TS Dataflow + Auth (4.2-D, `source/dataflow/javascript.py`, `source/auth/javascript.py`): Express/NestJS의 `req.query/body/params/cookies/headers`에서 실제 위험 호출(`child_process.exec`, `eval`, `fs.readFileSync` 등)까지 도달하는지 함수 단위로 추적(v1은 1-hop interprocedural 없이 함수 경계를 넘지 않음, Python 버전보다 좁은 범위로 의도적으로 제한). NestJS `@UseGuards(...)`는 이름 기반 추측이 아니라 실제 프레임워크 매커니즘이라 Python 휴리스틱보다 약간 더 높은 confidence(0.7)로 보고
- AI/RAG/Agent SDK Detection for JS/TS (4.2-E, `source/ai/python.py`): RAG/Agent 패턴은 이미 언어에 무관한 대소문자 무시 substring 매치라 추가 변경 없이 JS/TS도 인식됐음을 확인. LLM SDK 패턴만 Python의 `import X`/`from X import` 문법에 편향돼 있어서 JS `require('openai')`/ESM `import ... from '@anthropic-ai/sdk'` 인식을 추가
- Release Hardening (4.2-F): 기존 512개 회귀 스위트 + 새 43개 테스트 전부 pass(총 555), Python 경로는 레지스트리 리팩터링 전후로 동작 완전히 동일함을 통합 테스트로 확인. **알려진 범위**: JS/TS dataflow tracer는 Python 버전과 달리 1-hop interprocedural이 없음(같은 파일의 다른 함수로 전달된 tainted 값은 추적 안 됨) — 의도적으로 좁힌 v1 범위, 필요해지면 이후 확장

**v4.3.0 Runtime Coverage Expansion** (완료, `v4.3.0` 태그 — 스트리밍 응답 미지원이었던 known limitation을 해소하고, Judge가 최종 텍스트뿐 아니라 Event 스트림도 쓸 수 있게 확장):

- EventStream Contract (4.3-A, `targets/base.py`): 기존 `TargetAdapter`에 `events()`를 *선택적으로* 추가하는 `StreamingTargetAdapter` — 기존 `send()`는 절대 대체하지 않음(Backward-compatible). `supports_streaming(target)`으로 호출자가 먼저 확인 가능. v3.0.0 시절부터 이미 있던 `events/models.py`(Event/EventType: START/TOKEN/RETRIEVAL/TOOL_CALL/FINAL/ERROR)와 `events/websocket_target.py`를 발견하고 그 위에 이 contract를 형식화함
- HTTP SSE Target (4.3-B, `events/sse_target.py`): Server-Sent-Events/chunked-JSON 스트리밍 대상을 위한 범용 어댑터 — 기존 WebSocket 어댑터와 같은 패턴으로 `send()`가 자신의 `events()` 위에서 동작. `adapter: sse`로 target.yaml에서 선택(`config/targets/sse.example.yaml`)
- WebSocket Event 통합 (4.3-C, `events/websocket_target.py`): 기존 어댑터도 `events()`를 구현하도록 리팩터링 — `send()`가 프레임 해석 루프를 중복 구현하던 것을 자신의 `events()`를 소비하는 방식으로 변경, 두 전송 방식이 실제로 하나의 contract로 통일됨을 증명
- Browser/Agent Trace (4.3-D, `plugins/browser.py`): Playwright 기반 DOM 폴링을 한 번의 고정 대기 대신 주기적 polling으로 바꿔, 응답 텍스트가 늘어날 때마다 TOKEN 이벤트를 방출하고 안정화되면 조기 종료. **정직하게 범위를 제한**: 진짜 push 기반 스트림이 아니라 "마지막 poll 이후 텍스트가 늘어났다"는 재구성일 뿐이라고 docstring에 명시
- Judge Event-Compatibility (4.3-E, `judges/signals.py`): 새 `StreamingAnomalyJudge` — 스트림 중간 error 이벤트, 또는 스트리밍된 토큰 내용이 최종 응답에서 사라진 경우(retraction/correction 신호)를 탐지. 기존 Judge는 전혀 재작성하지 않음(로드맵 헌장이 명시적으로 금지). `JudgeEnsemble.judge()`가 선택적 `trace_events` 파라미터를 받고, 이 judge가 목록에 있고 실제로 trace_events가 주어졌을 때만 `evaluate_events()`를 호출 — 기본 활성화 목록에는 없음(opt-in)
- Release Hardening (4.3-F): 기존 555개 회귀 스위트 + 새 23개 테스트 전부 pass(총 578). **알려진 범위**: browser adapter의 events()는 진짜 스트림이 아니라 DOM polling 재구성; StreamingAnomalyJudge는 opt-in만 가능(기본 활성화 안 됨); SSE/WS 어댑터는 `--target-config` YAML 경로로만 선택 가능(기존 websocket과 동일하게, `scan`/`sample-run`의 `--target` 단축 옵션에는 아직 없음)

**v4.4.0 Accuracy & Benchmark** (완료, `v4.4.0` 태그 — v4.1-v4.4 로드맵의 마지막 버전. SOURCE MODE가 실제로 알려진 취약점을 얼마나 잘 찾는지 측정하고 CI에서 그 정확도를 게이트로 검증):

- Ground Truth Schema (4.4-A, `benchmarks/ground_truth.py`, `benchmarks/corpus/*.ground_truth.yaml`): 벤치마크 fixture가 포함하는 것으로 알려진 취약점을 `asset_type`/`file`/`sink_type`/`secret_type`(line은 선택)으로 문서화. `sample_app`(prompt injection, os command injection, 같은 하드코딩 키에 대한 secret 패턴 2개 매치)과 `express_app`(destructuring된 `exec()` 호출 — 실제로는 `os_command`가 아니라 `code_execution`으로 분류되는 것을 관찰된 그대로 문서화, 조용히 "고쳐서" 적지 않음)
- Metric Engine (4.4-B, `benchmarks/metrics.py`): precision/recall/FPR/FNR/F1. 이 컨텍스트에는 "true negative" 공간이 없어서 FPR은 "예측한 finding 중 틀린 비율"로 정의(보안 벤치마킹 관례, 고전적 정의와 다름을 명시). `aggregate_accuracy_metrics`는 rate 평균이 아니라 원시 count를 합산
- Matching & Scoring (4.4-C, `benchmarks/matcher.py`): ground truth가 실제로 다루는 asset_type만 false positive 후보로 취급 — parameter/endpoint/llm 같은 정상 신호는 취약점 주장이 아니므로 절대 false positive로 벌점받지 않음
- CI Quality Gate (4.4-D, `python main.py quality-gate`): 코퍼스의 모든 fixture에 대해 SOURCE MODE를 실행하고 집계한 precision/recall이 기준(기본 0.85/0.85, 현재 실제 점수는 1.0/1.0) 밑으로 떨어지면 실패. `.github/workflows/ci.yml`에 새 단계로 연결. **덧붙여 발견/수정한 버그**: CI가 지금까지 `pip install -e ".[dev]"`만 실행해서 `jsts`(tree-sitter) extra가 한 번도 설치되지 않았음 — v3.2.0/v4.2.0 이후로 tree-sitter 의존 테스트 파일 6개가 CI에서 계속 조용히 skip되고 있었음(`pytest.importorskip`가 파일당 skip 1개로 집계되어 눈치채기 어려웠음). CI 설치 커맨드를 정확히 재현한 격리된 venv로 확인 후 `.[dev,jsts]`로 수정
- Confidence Calibration (4.4-E, `benchmarks/calibration.py`): AttackSurfaceItem의 confidence가 실제로 정확도를 반영하는지 분석하는 리포팅 도구일 뿐, confidence 값 자체를 바꾸지 않음. true positive들이 평균적으로 false positive보다 높은 confidence를 갖는지만 확인
- Release Hardening (4.4-F): 기존 578개 회귀 스위트 + 새 24개 테스트 전부 pass(총 602). **알려진 범위**: ground truth 코퍼스가 fixture 2개/finding 5개뿐이라 confidence calibration이 통계적으로 의미 있으려면 더 커져야 함; quality-gate는 SOURCE MODE 정적 결과만 검증하고 실제 동적 Finding의 reproduction-rate는 검증 안 함(라이브 대상이 필요하기 때문)

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
config/        파이프라인, 모델, 도구, 로깅, Scope 예시 (config/scope.ci.yaml은 CI LIVE/HYBRID smoke 전용)
core/          orchestrator(scan/live/hybrid pipeline), checkpoint/resume, cancel, 데이터 모델, fingerprint
scope/         Scope와 Program Policy 검사
targets/       Target Adapter 계약과 Fake Target (+ universal/websocket/browser plugin)
adapters/      LLM/Recon/Discovery 외부 도구 결과 정규화 어댑터
attacks/       Mutation Engine과 PyRIT Adaptive Planner
tools/         외부 바이너리(nuclei/dalfox) 실제 실행 계층 (Policy/Scope 게이트, shell=False)
recon/         Subfinder/httpx/Katana/ffuf 기반 Asset/Endpoint 파이프라인, AI Endpoint Classifier
live/          LIVE MODE discovery, 분류, auto-profile
source/        SOURCE MODE static analysis -- parsers/(Python AST, JS/TS tree-sitter), frameworks/
               (Express, Next.js), sources/·sinks/·dataflow/(taint tracing), auth/, ai/
correlation/   Static/Live entity resolver (경로 canonicalization, confidence, review_required)
validation/    static candidate -> executable/review_only/unsupported 분류, 실제 동적 검증 실행기
attack_surface/ AttackSurfaceItem 공통 모델과 merge 규칙
hybrid/        SOURCE + LIVE correlate (exact-match, U8)
scenario/      multi-turn/cross-session 시나리오 실행기, finding 승격, 재현
rag_harness/   Controlled RAG corpus, chunking, retrieval harness
findings/      Finding dedup, root-cause clustering, external-tool/scenario finding 승격
packs/         Attack Pack 정의, 선택, 실행
testcase/      YAML 테스트케이스 스키마, 로더, 기본 suite
executor/      세션 실행기, Approval Gate, cancellation/backpressure
traces/        Trace export helper
judges/        rule, canary, regex, ensemble judge
storage/       SQLite 저장소, run_state(resume), artifact helper
reporting/     Evidence redaction, integrity manifest, report 생성
tests/         단위 및 통합 테스트
```

## 안전 모델

모든 실행은 다음 두 단계를 통과해야 합니다.

1. Scope validation: domain과 URL pattern 검사
2. Program Policy validation: 허용된 테스트 유형, request budget, concurrency, 고위험 action 정책 검사

Scope 정책은 deny 규칙을 allow 규칙보다 먼저 적용합니다. Subdomain은 `allow_subdomains: true`가 명시된 경우에만 허용됩니다. Redirect target은 다시 Scope 검사를 거치며, 범위 밖이면 실행하지 않고 record-only decision으로 남깁니다.

고위험 action은 기본적으로 block 또는 simulate 처리합니다. Raw evidence, 로컬 실행 산출물, private report, credential, `.env` 파일은 커밋되지 않도록 `.gitignore`에 포함되어 있습니다.

v3.4.0부터 추가된 안전 장치:

- destructive 가능성이 있는 dataflow sink(RCE/파일 접근/역직렬화/템플릿 인젝션)는 `validation/planner.py`가 항상 `requires_approval: true`로 표시하고 절대 자동으로 `executable` 분류하지 않습니다.
- Ctrl-C/명시적 cancel은 진행 중인 요청을 강제로 끊지 않고, 다음 안전한 지점(다음 testcase 시작 전, subprocess spawn 직전)에서만 협조적으로 중단합니다 — 진행 중인 evidence/checkpoint 기록은 항상 끝까지 완료됩니다.
- 모든 run의 Evidence 파일은 report 시점에 다시 SHA-256으로 재검증되어, 기록 이후 변경되거나 삭제된 파일은 `tamper_detected: true`로 표시됩니다(조용히 신뢰하지 않음).

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

# HYBRID MODE scan (v3.3.0 P3.3-4 Hybrid CLI 완성): URL과 소스 경로를 함께 주면
# SOURCE audit + LIVE discovery + entity resolution + validation planning + dynamic
# validation을 한 명령으로 연결 (static_findings/live_findings/correlated_findings로 구분해 보고)
python main.py scan https://target.example.com --source ./target-source \
  --scope config/my-scope.yaml --pack-target openai --pack-target-config config/targets/my-target.yaml
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

## v4.0.0 Release Gate

로드맵 문서(`개발로드맵 v3.1 -> v5.0`) 기준 "실전 완성판" 게이트입니다. v3.0.0 이후 URL-only(LIVE)/Source-only(SOURCE)/Both(HYBRID) 세 입력 모두 discovery/audit부터 report까지 끊기지 않고, 재현 가능하며, 안전하게 실패하는 것이 v4.0.0의 완성 기준입니다.

```bash
# clean install (별도 venv 권장)
python -m venv .venv && . .venv/bin/activate
python -m pip install -e ".[dev]"      # JS/TS AST까지 검증하려면 -e ".[dev,jsts]"

pytest
python main.py doctor
python main.py judge-benchmark
python main.py sample-run
python main.py scan --profile full            # SOURCE 없이도 동작하는 fixture 기반 경로
python main.py audit tests/fixtures/source/sample_app   # SOURCE MODE
# LIVE/HYBRID는 실제 도달 가능한 URL이 필요 -- CI는 로컬 http.server로 검증 (.github/workflows/ci.yml)
git status --short
```

### v4.0.0 완료 범위

- **LIVE**: URL 입력 → discovery → auto-profile → pack 선택/실행 → judge → reproduce → evidence → report가 `scan <url>` 한 명령으로 완주 (P3.1-1~P3.1-4)
- **SOURCE**: Python(AST)/JS·TS(tree-sitter, optional) route/dataflow/auth/AI 후보 + evidence가 `audit <path>`로 생성 (P3.2-1~P3.2-4)
- **HYBRID**: SOURCE/LIVE entity 매칭(confidence + review_required) → validation planning(executable/review_only/unsupported) → 실제 동적 검증 → correlated finding이 `scan <url> --source <path>` 한 명령으로 완주 (P3.3-1~P3.3-4)
- **Scenario**: multi-turn/cross-session finding이 `reproduce <finding-id>`로 재현 가능 (P3.1-2)
- **External Tools**: nuclei/dalfox는 Policy/Scope 게이트를 통과한 뒤 실제 실행 + 버전 기록, 미설치 시 graceful skip (P3.1-3)
- **Operations**: resume(`--resume-run-id`)/cancel(SIGINT)/timeout/checkpoint (P3.4-1, P3.4-2)
- **Evidence**: raw/sanitized 분리 + run별 SHA-256 integrity manifest + tamper detection (P3.4-3)
- **Regression**: 기존 175개 baseline을 포함한 전체 테스트 스위트가 100% pass (v3.0.0의 296 → 현재 438)
- **CI**: lint + unit + regression + integration + LIVE/SOURCE/HYBRID smoke가 모두 `.github/workflows/ci.yml`에서 실행됨
- **Documentation**: README quickstart, 안전 모델(threat/safety model), 알려진 제한사항 — 모두 이 문서에 포함

### v4.0.0 알려진 제한사항 (Known Limitations)

v1.0.0 이후 새로 생긴/여전히 남은 제한사항입니다 (v1.0.0 절의 기존 목록도 대부분 계속 유효).

- **동적 검증 실행기는 llm/rag/agent만 존재**: `validation/executor.py`는 capability hint(llm/rag/agent)가 같은 파일의 live-매칭된 endpoint와 연결될 때만 기존 testcase_suite pack으로 실제 검증. endpoint 자체(generic)·dataflow·auth 후보는 실제로 검증할 executor가 아직 없어 항상 `review_only`/`unsupported`로만 분류됨 — 가짜 executor를 만들지 않기로 한 의도적 결정
- **Dataflow/Auth/AI source intelligence는 Python 전용**: JS/TS는 route/call 추출(P3.2-2)까지는 있지만 taint tracing(P3.2-3)과 auth guard 탐지(P3.2-4)는 아직 Python만 지원
- **TruffleHog는 URL fetch 모드 없음**: 파일시스템 스캔 전용이라 live pack 실행에는 연결되지 않고 결과 파일 방식만 지원 (`tools/trufflehog.py`)
- **Auth guard 탐지는 candidate일 뿐 확정이 아님**: 알려진 decorator/FastAPI Depends 패턴을 못 찾았다고 "인증 없음"으로 단정하지 않음 (미들웨어/프레임워크 기본값일 수 있음) — 항상 사람 검토 필요
- Bounded queue(`discover`의 `max_queue_size`)는 메모리 상한만 보장하며, 대형 target에서 SQLite 쓰기 자체를 배치/스트리밍하는 것은 아직 안 함 (각 insert가 독립 connection)
- **Concurrency limit은 아직 실질적 효과 없음**: `Executor`가 scope.yaml의 `limits.concurrency`를 실제로 세마포어로 적용하지만, 현재 파이프라인 자체가 순차 실행이라 동시 실행 경로가 생기기 전까지는 no-op
- v1.0.0 절에 있던 항목 중 계속 유효: 실제 Target Adapter 범위(OpenAI 호환/CustomHTTP/Universal/WebSocket/Browser는 있지만 MCP Agent adapter는 없음), 스트리밍 응답(SSE/chunked) 미지원, RAG retrieval이 실제 임베딩이 아닌 Jaccard 근사, semantic judge 미구현, `cost_usd` 예산이 실제 가격표 없이는 항상 0

## v4.1.0 Release Gate

구현계획서(`v4.1-v4.4 구체적 구현계획서`) 기준 "Dynamic Validation Expansion" 게이트입니다. v4.0.0까지 llm/rag/agent에만 있던 실제 동적 검증기(가짜 executor 없이 실제로 무언가를 실행해보는 것)를 endpoint/auth/dataflow로 확장하고, 그 결과가 Finding/Reproducer/Report까지 실제로 도달하는 것이 v4.1.0의 완성 기준입니다.

```bash
pytest   # 512 passed
ruff check .
python main.py doctor
python main.py judge-benchmark
```

### v4.1.0 완료 범위

- **Validation Contract**: `ValidationTask`/`ValidationResult`/`ValidationStatus`(8-state) + 기존 v3.3.0 `ValidationPlan`/`DynamicValidationOutcome`을 감싸는 legacy adapter (4.1-A)
- **Endpoint Validator**: 안전한 메소드만 probe, redirect hop마다 재검증 (4.1-B)
- **Auth Validator**: 명시적으로 제공된 컨텍스트 쌍의 응답 구조 비교, 절대 자격증명 추측/탈취 없음 (4.1-C)
- **Dataflow Validator**: correlation token 반사 여부만 확인, destructive sink는 요청 자체를 보내지 않음 (4.1-D)
- **Finding/Report 통합**: Finding의 새 provenance 필드(전부 optional), validator-origin finding의 결정론적 dedup key, Report의 정적 근거/동적 검증/제한사항 섹션 (4.1-E)
- **Regression**: 기존 438개 baseline을 포함한 전체 테스트 스위트가 100% pass (v4.0.0의 438 → 현재 512, 신규 74개)
- **CI**: 기존 `.github/workflows/ci.yml`(lint + unit + regression + integration + LIVE/SOURCE/HYBRID smoke)이 변경 없이 그대로 통과

### v4.1.0 알려진 제한사항 (Known Limitations)

v4.0.0 절의 기존 목록도 대부분 계속 유효하며, 이번에 새로 생긴/여전히 남은 항목만 추가합니다.

- **Endpoint/Auth/Dataflow validator는 아직 `scan <url> --source <path>` CLI에 자동 연결되지 않음**: `validation/executor.py`의 `run_endpoint_validation`/`run_auth_validation`/`run_dataflow_validation`은 라이브러리 레벨에서 완성/테스트됐지만(`tests/test_validation_dispatch.py`), `core/orchestrator.py`의 `run_hybrid_scan_pipeline`은 여전히 llm/rag/agent capability hint만 자동 실행함 — endpoint를 CLI에 자동 연결하면 기존 `test_hybrid_scan_dynamically_validates_...`류 테스트의 `dynamic_validation_runs` 개수 단정이 깨지므로, 이번 하드닝 단계에서 회귀 위험을 새로 만들지 않기 위해 의도적으로 다음 단계로 미룸
- **Auth/Dataflow validator는 호출자가 컨텍스트를 직접 준비해야 함**: `AuthContext` 쌍(실제 fixture/env/browser-session 자격증명)이나 `DataflowInjectionPoint`(주입 위치)를 자동으로 추론/생성하지 않음 — 이 프로젝트가 자격증명을 추측하거나 탈취하지 않는다는 안전 원칙에 따른 의도적 설계
- v4.0.0 절에 있던 "동적 검증 실행기는 llm/rag/agent만 존재" 항목은 이번 버전으로 endpoint까지는 실행기가 생겼지만, auth/dataflow는 여전히 컨텍스트 없이는 자동 실행되지 않으므로 완전히 해소된 것은 아님(위 두 항목 참고)

## v4.2.0 Release Gate

구현계획서 기준 "Source Intelligence Expansion" 게이트입니다. v4.0.0까지 Python 전용이었던 dataflow tracing/auth guard 탐지를 JS/TS까지 확장하고, NestJS 라우트 추출과 JS/TS AI SDK 탐지를 추가하는 것이 v4.2.0의 완성 기준입니다.

```bash
pytest   # 555 passed
ruff check .
python main.py doctor
python main.py judge-benchmark
python main.py audit tests/fixtures/source/sample_app   # 여전히 동작 (regression)
```

### v4.2.0 완료 범위

- **SourceFact Contract**: `LanguageSourceAnalyzer` 레지스트리, python 백엔드가 이를 통해 등록(동작 변화 없음) (4.2-A)
- **JS/TS AST Adapter**: 공용 `parse_tree()` 헬퍼로 tree-sitter 파싱 로직 중복 제거 (4.2-B)
- **NestJS Framework Analyzer**: `@Controller`/`@Get()` 등 데코레이터 기반 라우트 추출 (4.2-C)
- **JS/TS Dataflow + Auth**: Express/NestJS `req.*` → 위험 호출 추적(1-hop interprocedural 없음), `@UseGuards(...)` 탐지 (4.2-D)
- **AI/RAG/Agent SDK Detection for JS/TS**: `require`/ESM import 문법 인식 추가 (4.2-E)
- **Regression**: 기존 512개 baseline을 포함한 전체 테스트 스위트가 100% pass (v4.1.0의 512 → 현재 555, 신규 43개)
- **CI**: 기존 `.github/workflows/ci.yml`이 변경 없이 그대로 통과

### v4.2.0 알려진 제한사항 (Known Limitations)

v4.1.0 절의 기존 목록도 대부분 계속 유효하며, 이번에 새로 생긴/여전히 남은 항목만 추가합니다.

- **JS/TS dataflow tracer는 1-hop interprocedural이 없음**: `source/dataflow/javascript.py`는 함수 경계를 넘어 전파되는 taint를 추적하지 않음(같은 파일의 다른 함수로 전달된 tainted 값은 놓침) — Python 버전(`source/dataflow/python.py`)은 이 기능이 있음. 의도적으로 좁힌 v1 범위이며, 필요해지면 이후 확장 대상
- **Flask/FastAPI 이외 Python 프레임워크나 Django/Spring/Rails/Gin 등은 여전히 route/dataflow/auth AST 지원이 없음**: `source/ingestion.py`의 `_FRAMEWORK_SIGNATURES`는 이들을 감지만 하고(매니페스트 파일 기반), 실제 route/dataflow 추출은 Python(Flask/FastAPI)과 JS/TS(Express/Next.js/NestJS)로 한정됨
- v4.1.0 절에 있던 항목들 계속 유효 (endpoint validator가 HYBRID CLI에 자동 연결되지 않음, auth/dataflow validator가 호출자 컨텍스트 필요)

## v4.3.0 Release Gate

"Runtime Coverage Expansion" 게이트입니다. v4.2.0까지 없던 SSE/WebSocket 스트리밍 대상 지원을 하나의 EventStream contract로 통일하고, Judge가 최종 텍스트 이외에 Event 스트림도 근거로 쓸 수 있게 여는 것이 v4.3.0의 완성 기준입니다.

```bash
pytest   # 578 passed
ruff check .
python main.py doctor
python main.py judge-benchmark
```

### v4.3.0 완료 범위

- **EventStream Contract**: `StreamingTargetAdapter`(선택적 `events()`), `supports_streaming()` (4.3-A)
- **HTTP SSE Target**: `adapter: sse`, `send()`가 `events()` 위에서 동작 (4.3-B)
- **WebSocket Event 통합**: 기존 어댑터도 같은 `events()` contract 구현 (4.3-C)
- **Browser/Agent Trace**: DOM polling 기반 TOKEN/FINAL 이벤트, 조기 종료 (4.3-D)
- **Judge Event-Compatibility**: `StreamingAnomalyJudge`(opt-in), 기존 Judge 전혀 재작성 없음 (4.3-E)
- **Regression**: 기존 555개 baseline을 포함한 전체 테스트 스위트가 100% pass (v4.2.0의 555 → 현재 578, 신규 23개)
- **CI**: 기존 `.github/workflows/ci.yml`이 변경 없이 그대로 통과

### v4.3.0 알려진 제한사항 (Known Limitations)

v4.2.0 절의 기존 목록도 대부분 계속 유효하며, 이번에 새로 생긴/여전히 남은 항목만 추가합니다.

- **Browser adapter의 `events()`는 진짜 스트림이 아님**: Playwright DOM polling으로 "지난 poll 이후 텍스트가 늘어났다"를 재구성한 것 — WebSocket/SSE처럼 실제 push 기반 이벤트가 아님. 토큰 경계도 실제 생성 시점과 무관하게 poll 주기에 따라 달라짐
- **StreamingAnomalyJudge는 기본 비활성화**: `JudgeEnsemble.default()`의 활성화 목록에 없음 — testcase가 `judges: [..., streaming_anomaly]`로 명시적으로 opt-in해야 동작 (Feature flag first 원칙)
- **SSE/WebSocket 대상은 `--target-config` YAML로만 선택 가능**: `scan`/`sample-run`의 `--target openai|fake-llm|...` 단축 옵션에는 아직 없음 — 기존 websocket 어댑터도 v4.3.0 이전부터 동일한 제약이었음
- v4.2.0 절에 있던 항목들 계속 유효

## v4.4.0 Release Gate

"Accuracy & Benchmark" 게이트입니다 — v4.1.0-v4.4.0 로드맵의 마지막 버전. SOURCE MODE가 실제로 알려진 취약점을 정확히 찾아내는지 ground truth 코퍼스로 측정하고, 그 정확도를 CI 게이트로 검증하는 것이 v4.4.0의 완성 기준입니다.

```bash
pytest   # 602 passed
ruff check .
python main.py doctor
python main.py judge-benchmark
python main.py quality-gate   # precision/recall 1.0/1.0 (기준 0.85/0.85)
```

### v4.4.0 완료 범위

- **Ground Truth Schema**: `benchmarks/corpus/*.ground_truth.yaml`, 2개 fixture/5개 documented finding (4.4-A)
- **Metric Engine**: precision/recall/FPR/FNR/F1, raw count 기반 집계 (4.4-B)
- **Matching & Scoring**: ground truth가 다루는 asset_type만 false positive 후보 (4.4-C)
- **CI Quality Gate**: `python main.py quality-gate`, `.github/workflows/ci.yml`에 연결 + `jsts` extra 미설치로 6개 테스트 파일이 CI에서 조용히 skip되던 버그 발견/수정 (4.4-D)
- **Confidence Calibration**: TP/FP 평균 confidence 비교 리포팅, 값 자체는 변경 안 함 (4.4-E)
- **Regression**: 기존 578개 baseline을 포함한 전체 테스트 스위트가 100% pass (v4.3.0의 578 → 현재 602, 신규 24개)
- **CI**: `.github/workflows/ci.yml`에 `quality-gate` 단계 추가 + `jsts` extra 설치 버그 수정

### v4.4.0 알려진 제한사항 (Known Limitations)

v4.3.0 절의 기존 목록도 대부분 계속 유효하며, 이번에 새로 생긴/여전히 남은 항목만 추가합니다.

- **Ground truth 코퍼스가 아직 작음**: fixture 2개, finding 5개뿐 — confidence calibration이 통계적으로 의미 있으려면 코퍼스가 훨씬 커져야 함(4.4-E의 `is_well_calibrated`은 지금은 "비교할 게 없으면 true" 규칙에 자주 해당)
- **FPR/FNR은 보안 벤치마킹 관례 정의**: 고전적인 true-negative 기반 FPR이 아니라 "예측한 finding 중 틀린 비율"(`benchmarks/metrics.py` docstring 참고) — 이 프로젝트의 static-analysis-vs-ground-truth 컨텍스트에는 무한한 true negative 공간이 없기 때문
- **quality-gate는 SOURCE MODE 정적 결과만 검증**: 실제 동적 Finding의 reproduction-rate/live 정확도는 검증하지 않음 — 라이브 대상이 필요해서 CI의 결정론적/네트워크 없는 실행 원칙과 맞지 않음
- v4.3.0 절에 있던 항목들 계속 유효

## v4.5.0 Release Gate

"API/Auth 검증 연결" 게이트입니다 — v5.0 개발 계획서의 첫 버전(WP-01~WP-03). 후보는 찾지만 실제 검증 경로가 끊기던 문제를 CLI 한 흐름(`scan -> validate -> reproduce -> report`)으로 연결하는 것이 완성 기준입니다.

```bash
pytest   # 640 passed
ruff check .
python main.py scan --source tests/fixtures/source/rest_api_app --artifact runs/artifacts/scan.json
python main.py validate --artifact runs/artifacts/scan.json --base-url https://<허가된 대상> \
    --auth-contexts config/my-auth.yaml --key-field owner
python main.py reproduce <finding-id> --auth-contexts config/my-auth.yaml --attempts 3
python main.py report --run-id <validate run_id>
```

### v4.5.0 완료 범위

- **HTTP method/body 모델 (WP-01)**: `source/endpoints.py` endpoint inventory — route x 실제 method(POST/PUT/PATCH/DELETE 포함), path/query param, body format(json/form/multipart)과 field 추론(Flask, FastAPI pydantic, Express). 캡처 요청(HAR/JSON)이 있으면 추론보다 우선. `audit` 출력에 `endpoint_inventory` 추가
- **상태 변경 요청 정책 gate (WP-01)**: `PolicyEngine.decide_method` — read-only는 실행, 상태 변경은 기본 `dry_run`(계획/기록만, 전송 안 함) / `review_required` / `allowed`(`testing.state_changing_requests`). DELETE는 `destructive_actions: true`도 필요하고 blocked_actions의 `delete`면 차단. 상태 변경 body는 캡처/사용자 제공 예시 없이는 절대 합성하지 않음
- **Auth context / object 비교 (WP-02)**: 테스터 본인 소유 테스트 계정만 YAML로 선언(`config/auth_contexts.example.yaml`), 자격증명은 `${ENV}` 참조만 허용(리터럴 거부, evidence/report에 기록 안 함). read-only 요청만, 테스터가 선언한 자기 객체 id만 요청. 응답은 status/구조/key field **hash**만 fingerprint로 저장. 계정 2개 미만이면 요청 없이 `needs_review` + 이유 기록
- **`FindingStatus.NEEDS_REVIEW`** 추가(additive)
- **Validator CLI 연결 (WP-03)**: `scan --source`(url 없이) → scan artifact, `validate`, `reproduce <id>`(object access finding 재실행/횟수/결과 저장), `report`(finding별 md/json: 상태, 판정 근거, evidence 경로+SHA-256, 재현 기록, 재현 절차, 제한사항)
- **CI**: validate/report smoke 추가

### v4.5.0 알려진 제한사항 (Known Limitations)

- 상태 변경 method의 object 비교는 자동화하지 않음(항상 `needs_review`)
- path param 값은 테스터가 `owned_objects`로 선언한 값만 사용 — 선언이 없으면 해당 요청은 계획만 기록
- body 추론은 handler 본문 기반 — JS/TS는 route 호출부터 다음 route까지의 구간 휴리스틱, 다른 파일에서 import한 handler는 미해석(WP-05 범위)
- `scan <url>`(LIVE/HYBRID) 경로는 변경 없음; `--source`만 단독으로 줄 때의 동작만 새 artifact 모드로 바뀜(이전엔 `--source`가 무시되고 fixture 파이프라인이 실행됐음)

## v4.6.0 Release Gate

"분석 정확도와 Judge 보강" 게이트입니다 (v5.0 개발 계획서 WP-04, WP-06).

```bash
pytest   # 667 passed
ruff check .
python main.py quality-gate   # 3개 fixture, 8/8 TP, FP 0
python main.py sample-run --semantic-judge-config config/semantic_judge.example.yaml   # 선택 사항
```

### v4.6.0 완료 범위

- **Python interprocedural dataflow (WP-04)**: `source/interprocedural/python.py` — 프로젝트 전체 call graph(같은 파일 함수, `from x import f`, module alias), 함수별 taint summary(param→sink, param→return)로 route → service → sink N-hop 추적. FastAPI route param은 source(Depends 제외). `max_depth`/`max_nodes`/`time_budget_s` cap, 초과 시 graceful 중단 + `audit` 출력의 `interprocedural` 통계. 각 chain에 `call_path`/`hops`/`route`/auth guard 정보 연결, sink family 표준화(sql/command/template/url_fetch/file/deserialization/llm_prompt). 다중 파일 fixture `layered_flask_app`을 ground truth에 고정
- **Semantic judge 보조 (WP-06)**: `judges/semantic.py` — 기존 deterministic judge가 1차, semantic judge는 2차(opt-in). 두 판정 충돌, 또는 동의하더라도 confidence가 기준 미만이면 `needs_review`. semantic 단독으로는 절대 confirmed가 되지 않음. evidence에 `judge_layers`(deterministic / semantic / final) 3층과 model·prompt version·prompt SHA-256 기록. judge 호출 실패 시 abstain(실행 중단 없음)

### v4.6.0 알려진 제한사항 (Known Limitations)

- **WP-05(JS/TS 함수 간 dataflow)는 이번 버전에서 구현하지 않음**: JS/TS는 기존과 같이 함수 내부(single-scope) 추적만 지원. Express middleware → handler → service, Next.js server action, NestJS controller → service 흐름은 미지원
- Python interprocedural: class method 호출(`self.repo.find(x)`)은 receiver 타입 추론 없이 명시적으로 끊김(추측하지 않음), sanitizer 인식 없음
- Semantic judge는 기본 비활성, `sample-run` 경로에만 연결됨

## v5.0.0 Release Gate — 기능 동결

v5.0.0은 "더 이상 기능을 추가하지 않아도 된다"는 기준선입니다. 지원 범위와 미지원 범위를 문서로 구분하고, 그 범위 안에서 탐지 → 안전 검증 → 재현 → 증거 → 보고를 끝까지 수행합니다. 이후 개선은 실제 허가된 대상에서 반복 확인된 실패만 5.0.x 패치로 반영합니다.

```bash
pytest                        # 702 passed
pytest -m "p0 or p1" tests/regression
python main.py release-check  # G1-G10 모두 통과해야 exit 0 (offline)
python main.py benchmark --baseline benchmarks/baselines/baseline.json
```

| Gate | 계획서 8.3 항목 | 점검 방법 (`release-check`) |
|---|---|---|
| G1 | 샘플 프로젝트 end-to-end 실행 | `scan --source` → `sample-run` → `validate` → `report` → `reproduce` |
| G2 | scope 밖 대상 실행 전 차단 | 모든 validator에서 scope 밖 요청 0건 |
| G3 | 상태 변경 요청은 정책 없이 자동 실행 안 됨 | 기본 정책에서 POST/PUT/PATCH/DELETE 전송 0건 |
| G4 | LLM finding 대표 세트 재현 | fake-llm/fake-rag confirmed finding 재현 성공 |
| G5 | Auth/BOLA 비교가 테스트 계정 환경에서 동작 | 소유권 검사 있음 → rejected, 없음 → confirmed, 계정 1개 → needs_review |
| G6 | Python/JS-TS dataflow regression | quality-gate + benchmark baseline 회귀 0건 |
| G7 | evidence hash 검증 및 redaction | hash 검증, 자격증명/canary redaction, 변조 감지 |
| G8 | report에 근거·재현 절차 누락 없음 | 필수 필드(`core/contract.py`) 모두 채워짐 |
| G9 | known limitation 문서 | `docs/KNOWN_LIMITATIONS.md`, `docs/SUPPORT_MATRIX.md` |
| G10 | benchmark 결과와 데이터셋 범위 명시 | v4.7.0 절의 표 + 외부 앱 미포함 명시 |

### v5.0.0 문서

- `docs/CLI.md` — 전체 명령/옵션, exit code(0/1/2/3/130), finding 상태 (parser에서 생성, 테스트로 동기화 강제)
- `docs/SCHEMAS.md` — 고정된 schema 버전, scope/policy 키, evidence 디렉터리 구조와 manifest, report 필수 필드, 재현 기록
- `docs/SUPPORT_MATRIX.md` — v5.0 지원/미지원 범위
- `docs/KNOWN_LIMITATIONS.md` — 통합된 알려진 제한사항

### v5.0.1 패치 (재점검에서 발견)

- **SQLite 연결 누수**: `SQLiteStore.connect()`가 commit만 하고 연결을 닫지 않아 호출마다 연결이 남았음(Windows에서는 DB 파일 잠금 원인). commit/rollback 후 항상 닫도록 수정
- **외부 도구 프로세스 pipe 누수**: timeout/취소로 kill한 도구의 stdout/stderr pipe가 닫히지 않았음. kill 후 `communicate()`로 정리
- **재현 기록의 버전 오표기**: editable 설치 메타데이터가 오래되면 `package_version`이 `0.1.0`으로 기록됐음. 소스 트리의 `pyproject.toml`을 우선 사용

### v5.0.0 이후 운영 원칙

| 상황 | 처리 | 예시 버전 |
|---|---|---|
| crash / scope / integrity 버그 | 즉시 수정 | 5.0.1 |
| 반복 미탐/오탐 | 재현 케이스를 benchmark에 추가한 뒤 탐지 로직 수정 | 5.0.2 |
| report/evidence 품질 | schema 호환 유지하며 보완 | 5.0.3 |
| 새 framework 요청 | 실전 반복 필요성 없으면 보류 | 미정 |
| 대규모 구조 변경 | 5.x에 억지로 넣지 않음 | 6.0 검토 |

실전 테스트 기록은 Target / Expected / Observed / Outcome(TP·FP·FN·Blocked·Error) / Root Cause / Fix Decision / Regression 항목으로 남기고, 수정 시 `benchmarks/datasets/manifest.yaml`에 케이스를 추가합니다.

## v4.7.0 Release Gate

"실전 Benchmark와 안정화" 게이트입니다 (v5.0 개발 계획서 WP-07, WP-08). 이 단계부터는 기능 추가보다 측정 결과를 우선합니다.

```bash
pytest   # 689 passed
pytest -m "p0 or p1" tests/regression   # P0/P1 회귀 스위트
python main.py benchmark --baseline benchmarks/baselines/baseline.json   # 회귀 시 exit 1
```

### v4.7.0 benchmark 결과 (데이터셋 범위와 함께)

데이터셋 `benchmarks/datasets/manifest.yaml`(v5-benchmark): 저장소 내장 fixture 5개 + offline fake LLM/RAG/agent target 3개. **외부 실제 취약 앱은 포함되어 있지 않습니다** — `kind: external`(`path_env`)로 로컬에 clone한 앱을 등록할 수 있고, 등록하지 않으면 `skipped`로 보고됩니다.

| 구분 | target | ground truth | TP | FP | FN | precision | recall |
|---|---|---|---|---|---|---|---|
| overall (holdout 제외) | 7 | 14 | 12 | 0 | 2 | 1.00 | 0.86 |
| holdout | 1 | 2 | 1 | 0 | 1 | 1.00 | 0.50 |

- 미탐 원인: `dataflow_cut` 2건(Python class method 호출, JS/TS 함수 간 호출), `policy_blocked` 1건(scope 예시가 `tool_abuse: false`)
- 안정성(품질과 별도 집계): ok 8 / error 0 / timeout 0 / skipped 0
- 숫자는 작은 자체 데이터셋 기준이라 일반 성능을 뜻하지 않습니다

### v4.7.0 완료 범위

- **Benchmark dataset (WP-07)**: 버전마다 같은 manifest를 재실행, target별/그룹별/holdout TP·FP·FN과 데이터셋 크기, 미탐 원인 taxonomy(unsupported_framework, dataflow_cut, auth_context_missing, validator_limitation, judge_false_negative, policy_blocked), LLM target의 재현 시도/성공 횟수, 커밋된 baseline 대비 회귀 게이트(CI)
- **안정성/회귀 (WP-08)**: target별 timeout과 crash 격리(한 target 실패가 나머지를 멈추지 않음). 비정상 입력(깊은 중첩, 바이너리, 잘못된 UTF-8, 거대 파일, symlink loop)은 파일 단위로 격리되고 `interprocedural.file_errors`에 기록. `report`가 evidence hash를 재검증해 변조된 근거를 표시하고 인용하지 않음. `pytest -m p0/p1` 이름 있는 회귀 스위트를 CI 단계로 추가

### v4.7.0 알려진 제한사항 (Known Limitations)

- JS/TS sink 별칭 미해석: `const childProcess = require('child_process'); childProcess.exec(x)`처럼 모듈을 다른 이름에 담으면 sink로 인식하지 않음(benchmark 작성 중 발견, 미수정)
- timeout된 분석 thread는 강제 종료할 수 없어 백그라운드에 남음(보고 후 다음 target 진행)
- v4.6.0 제한사항 계속 유효

## 마일스톤

설계서 기준 실행 가능한 마일스톤은 다음과 같습니다.

- `v0.1.0-mvp1`: core validation loop, evidence, basic reporting
- `v0.2.0-llm-redteam`: Promptfoo/Garak/Mutation/PyRIT 통합
- `v0.3.0-discovery`: recon, web security tools, AI discovery, RAG harness 통합
- `v1.0.0`: 안정화된 첫 릴리스 (full orchestrator, dedup/root cause, hardening)
- `v3.0.0`: Universal Architecture (URL-only/Source-only/Hybrid 대상 공통 Core, U0~U12)
- `v3.1.0`: Operational Pipeline (`scan <url>` 단일 진입점, scenario finding, external tool runner)
- `v3.2.0`: Source Intelligence (Python/JS·TS AST, dataflow, auth/AI source intelligence)
- `v3.3.0`: Static -> Dynamic Validation (entity resolver, validation planner, dynamic validator, `scan <url> --source <path>`)
- `v3.4.0`: Production Hardening (checkpoint/resume, cancellation, evidence integrity, large-target 성능)
- `v4.0.0`: 실전 완성판 — 로드맵이 권장하는 최종 목표 (URL/Source/Both 세 입력 모두 end-to-end)
- `v4.1.0`: Dynamic Validation Expansion (validation contract, endpoint/auth/dataflow validator, Finding/Reproducer/Report 통합)
- `v4.2.0`: Source Intelligence Expansion (LanguageSourceAnalyzer contract, NestJS 라우트, JS/TS dataflow/auth/AI SDK 탐지)
- `v4.3.0`: Runtime Coverage Expansion (EventStream contract, HTTP SSE target, WebSocket/Browser event 통합, Judge event-compatibility)
- `v4.4.0`: Accuracy & Benchmark (ground truth schema, metric engine, matching/scoring, CI quality gate, confidence calibration) — v4.1.0-v4.4.0 로드맵 완결
- `v4.5.0`: API/Auth 검증 연결 (HTTP method/body inventory + 상태 변경 정책 gate, tester-owned auth context 비교, scan -> validate -> reproduce -> report CLI)
- `v4.6.0`: 분석 정확도와 Judge 보강 (Python interprocedural dataflow + caps, semantic judge 보조 layer / needs_review) — JS/TS 함수 간 추적은 제한사항
- `v4.7.0`: 실전 Benchmark와 안정화 (dataset manifest + baseline 회귀 게이트, 미탐 원인 분류, crash/timeout 격리, evidence 재검증, P0/P1 회귀 스위트)
- `v5.0.0`: 기능 동결 — 고정된 계약(schema/exit code/finding 상태/report 필드), 재현 환경 기록, 문서(CLI/schema/지원 matrix/제한사항), offline release gate `release-check` G1-G10
- `v5.0.1`: 재점검 패치 — SQLite 연결/외부 도구 pipe 리소스 누수, 재현 기록 버전 오표기 수정

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
