"""P3.2-4 Auth/LLM/RAG Source Intelligence (roadmap v3.2.0 Source Intelligence)."""

from pathlib import Path

from source.ai.python import find_ai_capability_hints
from source.auth.python import find_auth_guards


def test_auth_present_flask_login_decorator_is_detected() -> None:
    text = (
        "from flask_login import login_required\n\n"
        "@app.route('/api/admin')\n"
        "@login_required\n"
        "def admin():\n"
        "    return 'ok'\n"
    )
    hints = find_auth_guards(Path("app.py"), text, {"admin"})
    assert len(hints) == 1
    assert hints[0].detected is True
    assert "login_required" in hints[0].guard_names
    assert hints[0].confidence > 0.5


def test_auth_missing_route_is_reported_as_a_candidate_not_a_confirmed_absence() -> None:
    text = "@app.route('/api/chat')\ndef chat():\n    return 'ok'\n"
    hints = find_auth_guards(Path("app.py"), text, {"chat"})
    assert len(hints) == 1
    assert hints[0].detected is False
    assert hints[0].guard_names == []
    assert "NOT proof" in hints[0].note


def test_fastapi_depends_auth_dependency_is_detected() -> None:
    text = (
        "@app.get('/api/profile')\n"
        "def profile(user = Depends(get_current_user)):\n"
        "    return user\n"
    )
    hints = find_auth_guards(Path("app.py"), text, {"profile"})
    assert hints[0].detected is True
    assert "get_current_user" in hints[0].guard_names


def test_non_route_functions_are_never_reported() -> None:
    text = "def helper():\n    return 1\n"
    assert find_auth_guards(Path("app.py"), text, {"some_other_route_handler"}) == []
    assert find_auth_guards(Path("app.py"), text, set()) == []  # no known route handlers at all


def test_llm_sdk_usage_produces_a_capability_hint_with_a_dynamic_validation_hint() -> None:
    text = "import openai\nopenai.ChatCompletion.create(model='gpt-4')\n"
    hints = find_ai_capability_hints("app.py", text)
    kinds = {hint.kind for hint in hints}
    assert kinds == {"llm"}
    assert hints[0].dynamic_validation_hint
    assert "prompt_injection" in hints[0].dynamic_validation_hint


def test_rag_and_agent_signals_are_each_reported_separately() -> None:
    text = "from langchain.vectorstores import FAISS\n@tool\ndef search(): ...\n"
    hints = find_ai_capability_hints("app.py", text)
    kinds = {hint.kind for hint in hints}
    assert kinds == {"rag", "agent"}


def test_plain_file_with_no_ai_signals_produces_no_hints() -> None:
    text = "def add(a, b):\n    return a + b\n"
    assert find_ai_capability_hints("app.py", text) == []


def test_js_require_openai_produces_an_llm_capability_hint() -> None:
    text = "const OpenAI = require('openai');\nconst client = new OpenAI();\n"
    hints = find_ai_capability_hints("app.js", text)
    kinds = {hint.kind for hint in hints}
    assert kinds == {"llm"}


def test_ts_esm_import_anthropic_sdk_produces_an_llm_capability_hint() -> None:
    text = "import Anthropic from '@anthropic-ai/sdk';\nconst client = new Anthropic();\n"
    hints = find_ai_capability_hints("app.ts", text)
    kinds = {hint.kind for hint in hints}
    assert kinds == {"llm"}


def test_js_langchain_import_produces_a_rag_capability_hint() -> None:
    text = "import { OpenAIEmbeddings } from '@langchain/openai';\n"
    hints = find_ai_capability_hints("app.ts", text)
    kinds = {hint.kind for hint in hints}
    assert "rag" in kinds


def test_js_tool_calls_field_produces_an_agent_capability_hint() -> None:
    text = "const response = await client.chat.completions.create({ tools: [], tool_calls: [] });\n"
    hints = find_ai_capability_hints("app.js", text)
    kinds = {hint.kind for hint in hints}
    assert "agent" in kinds
    assert "llm" in kinds
