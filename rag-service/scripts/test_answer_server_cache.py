"""Unit tests for server-side answer cache helpers."""
import os
import sys
import tempfile
import types
from pathlib import Path

cache_dir = tempfile.TemporaryDirectory()
os.environ["ANSWER_CACHE_ROOT"] = cache_dir.name
os.environ["ENABLE_ANSWER_CACHE"] = "1"
os.environ["ANSWER_CACHE_TTL_SECONDS"] = "3600"

sys.path.insert(0, os.path.dirname(__file__))


class FakeFastAPI:
    def __init__(self, *args, **kwargs) -> None:
        pass

    def get(self, *args, **kwargs):
        return lambda fn: fn

    def post(self, *args, **kwargs):
        return lambda fn: fn

    def delete(self, *args, **kwargs):
        return lambda fn: fn


class FakeHTTPException(Exception):
    def __init__(self, status_code: int, detail) -> None:
        self.status_code = status_code
        self.detail = detail


for mod in [
    "fastapi",
    "fastapi.responses",
    "pydantic",
    "qdrant_client",
    "requests",
    "answer",
    "index_pdfs",
    "settings",
]:
    parts = mod.split(".")
    parent = None
    for i, part in enumerate(parts):
        full = ".".join(parts[: i + 1])
        if full not in sys.modules:
            module = types.ModuleType(full)
            sys.modules[full] = module
            if parent is not None:
                setattr(parent, part, module)
        parent = sys.modules[full]

sys.modules["fastapi"].FastAPI = FakeFastAPI  # type: ignore[attr-defined]
sys.modules["fastapi"].File = lambda *args, **kwargs: None  # type: ignore[attr-defined]
sys.modules["fastapi"].Form = lambda *args, **kwargs: None  # type: ignore[attr-defined]
sys.modules["fastapi"].Header = lambda *args, **kwargs: None  # type: ignore[attr-defined]
sys.modules["fastapi"].HTTPException = FakeHTTPException  # type: ignore[attr-defined]
sys.modules["fastapi"].UploadFile = object  # type: ignore[attr-defined]
sys.modules["fastapi.responses"].HTMLResponse = object  # type: ignore[attr-defined]
sys.modules["fastapi.responses"].StreamingResponse = object  # type: ignore[attr-defined]
sys.modules["pydantic"].BaseModel = object  # type: ignore[attr-defined]
sys.modules["qdrant_client"].QdrantClient = object  # type: ignore[attr-defined]
sys.modules["answer"].build_prompt = lambda *args, **kwargs: ""  # type: ignore[attr-defined]
sys.modules["answer"].call_gemini = lambda *args, **kwargs: ("", [])  # type: ignore[attr-defined]
sys.modules["answer"].retrieve = lambda *args, **kwargs: []  # type: ignore[attr-defined]
sys.modules["answer"].stream_gemini = lambda *args, **kwargs: iter(())  # type: ignore[attr-defined]
sys.modules["index_pdfs"].SUPPORTED_EXTENSIONS = {".txt"}  # type: ignore[attr-defined]
sys.modules["index_pdfs"].collection_for_project = lambda project: f"{project}_docs"  # type: ignore[attr-defined]
sys.modules["settings"].get_data_root = lambda: Path(cache_dir.name)  # type: ignore[attr-defined]
sys.modules["settings"].set_data_root = lambda path: Path(path)  # type: ignore[attr-defined]

from web import (  # noqa: E402
    _answer_cache_key,
    _answer_cache_stats,
    _clear_answer_cache,
    _read_answer_cache,
    _sse_event,
    _write_answer_cache,
)


def test_answer_cache_key_changes_with_context_text() -> None:
    first = [{"source": "a.txt", "locator": "document", "page": None, "text": "alpha"}]
    second = [{"source": "a.txt", "locator": "document", "page": None, "text": "beta"}]

    assert _answer_cache_key("inbox", "q", 12, False, first) != _answer_cache_key("inbox", "q", 12, False, second)
    print("test_answer_cache_key_changes_with_context_text PASSED")


def test_answer_cache_roundtrip() -> None:
    contexts = [{"source": "a.txt", "locator": "document", "page": None, "text": "alpha"}]
    key = _answer_cache_key("inbox", "q", 12, False, contexts)

    _write_answer_cache(key, {"answer": "cached answer", "web_sources": []})
    cached = _read_answer_cache(key)

    assert cached is not None
    assert cached["answer"] == "cached answer"
    print("test_answer_cache_roundtrip PASSED")


def test_answer_cache_stats_and_project_clear() -> None:
    inbox_key = _answer_cache_key("inbox", "q1", 12, False, [])
    docs_key = _answer_cache_key("docs", "q2", 12, False, [])
    _write_answer_cache(inbox_key, {"project": "inbox", "answer": "a", "web_sources": []})
    _write_answer_cache(docs_key, {"project": "docs", "answer": "b", "web_sources": []})

    stats = _answer_cache_stats("inbox")
    assert stats["count"] >= 1
    assert stats["total_bytes"] > 0

    result = _clear_answer_cache("inbox")
    assert result["removed"] >= 1
    assert _read_answer_cache(inbox_key) is None
    assert _read_answer_cache(docs_key) is not None
    print("test_answer_cache_stats_and_project_clear PASSED")


def test_sse_event_formats_single_json_event() -> None:
    event = _sse_event({"type": "token", "text": "안녕하세요"})

    assert event.startswith("data: ")
    assert event.endswith("\n\n")
    assert '"type": "token"' in event
    assert "안녕하세요" in event
    print("test_sse_event_formats_single_json_event PASSED")


if __name__ == "__main__":
    test_answer_cache_key_changes_with_context_text()
    test_answer_cache_roundtrip()
    test_answer_cache_stats_and_project_clear()
    test_sse_event_formats_single_json_event()
    cache_dir.cleanup()
    print("\nAll tests PASSED")
