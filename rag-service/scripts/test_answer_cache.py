"""Unit tests for answer.py embedding cache helpers."""
import os
import sys
import types

sys.path.insert(0, os.path.dirname(__file__))


class FakeTextEmbedding:
    created: list[str] = []

    def __init__(self, model_name: str) -> None:
        self.model_name = model_name
        self.created.append(model_name)


for mod in ["fastembed", "qdrant_client", "qdrant_client.models", "requests", "index_pdfs"]:
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

sys.modules["fastembed"].TextEmbedding = FakeTextEmbedding  # type: ignore[attr-defined]
sys.modules["fastembed"].SparseTextEmbedding = object  # type: ignore[attr-defined]
sys.modules["qdrant_client"].QdrantClient = object  # type: ignore[attr-defined]
sys.modules["qdrant_client.models"].Fusion = object  # type: ignore[attr-defined]
sys.modules["qdrant_client.models"].FusionQuery = object  # type: ignore[attr-defined]
sys.modules["qdrant_client.models"].Prefetch = object  # type: ignore[attr-defined]
sys.modules["qdrant_client.models"].SparseVector = object  # type: ignore[attr-defined]
sys.modules["index_pdfs"].collection_for_project = lambda project: f"{project}_docs"  # type: ignore[attr-defined]

from answer import _get_dense_embedder, query_terms, rerank_score  # noqa: E402


def test_dense_embedder_reuses_same_model() -> None:
    first = _get_dense_embedder("model-a")
    second = _get_dense_embedder("model-a")

    assert first is second
    assert FakeTextEmbedding.created == ["model-a"]
    print("test_dense_embedder_reuses_same_model PASSED")


def test_dense_embedder_separates_model_names() -> None:
    first = _get_dense_embedder("model-b")
    second = _get_dense_embedder("model-c")

    assert first is not second
    assert FakeTextEmbedding.created[-2:] == ["model-b", "model-c"]
    print("test_dense_embedder_separates_model_names PASSED")


def test_public_key_query_expands_algorithm_terms() -> None:
    terms = query_terms("공개키 암호의 종류는?")

    assert "공개키" in terms
    assert "rsa" in terms
    assert "elgamal" in terms
    assert "ecc" in terms
    print("test_public_key_query_expands_algorithm_terms PASSED")


def test_public_key_algorithm_context_scores_higher_than_generic_context() -> None:
    terms = query_terms("공개키 암호의 종류는?")
    algorithm_context = "공개키 암호 방식에는 RSA, ElGamal, ECC 타원곡선 암호 등이 있다."
    generic_context = "공개키 암호는 비대칭키 암호라고도 하며 하이브리드 암호시스템과 함께 사용된다."

    assert rerank_score(0.1, algorithm_context, terms) > rerank_score(0.1, generic_context, terms)
    print("test_public_key_algorithm_context_scores_higher_than_generic_context PASSED")


if __name__ == "__main__":
    test_dense_embedder_reuses_same_model()
    test_dense_embedder_separates_model_names()
    test_public_key_query_expands_algorithm_terms()
    test_public_key_algorithm_context_scores_higher_than_generic_context()
    print("\nAll tests PASSED")
