"""Unit tests for index batching helpers."""
import os
import sys
import types

sys.path.insert(0, os.path.dirname(__file__))


for mod in [
    "fitz",
    "olefile",
    "openpyxl",
    "pytesseract",
    "docx",
    "fastembed",
    "faster_whisper",
    "pptx",
    "qdrant_client",
    "qdrant_client.models",
    "tqdm",
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

sys.modules["docx"].Document = object  # type: ignore[attr-defined]
sys.modules["fastembed"].SparseTextEmbedding = object  # type: ignore[attr-defined]
sys.modules["fastembed"].TextEmbedding = object  # type: ignore[attr-defined]
sys.modules["faster_whisper"].WhisperModel = object  # type: ignore[attr-defined]
sys.modules["pptx"].Presentation = object  # type: ignore[attr-defined]
sys.modules["qdrant_client"].QdrantClient = object  # type: ignore[attr-defined]
for name in [
    "Distance",
    "FieldCondition",
    "Filter",
    "MatchValue",
    "PointStruct",
    "SparseVector",
    "SparseVectorParams",
    "VectorParams",
]:
    setattr(sys.modules["qdrant_client.models"], name, object)
sys.modules["tqdm"].tqdm = lambda iterable, **kwargs: iterable  # type: ignore[attr-defined]

from index_pdfs import chunk_text, clean_text, iter_batches  # noqa: E402


def test_iter_batches_splits_remainder() -> None:
    batches = list(iter_batches([1, 2, 3, 4, 5], 2))

    assert batches == [[1, 2], [3, 4], [5]]
    print("test_iter_batches_splits_remainder PASSED")


def test_iter_batches_rejects_non_positive_size() -> None:
    try:
        list(iter_batches([1], 0))
    except ValueError:
        print("test_iter_batches_rejects_non_positive_size PASSED")
        return

    raise AssertionError("iter_batches should reject non-positive batch_size")


def test_clean_text_preserves_line_boundaries() -> None:
    text = clean_text(" 공개키 암호 \n\n RSA   방식 \n ECC 방식 ")

    assert text == "공개키 암호\nRSA 방식\nECC 방식"
    print("test_clean_text_preserves_line_boundaries PASSED")


def test_chunk_text_keeps_heading_with_body() -> None:
    chunks = list(chunk_text("공개키 암호\nRSA 방식 설명입니다.\nECC 방식 설명입니다.", 40, 10))

    assert chunks
    assert "공개키 암호\nRSA 방식 설명입니다." in chunks[0]
    assert any("ECC 방식 설명입니다." in chunk for chunk in chunks)
    print("test_chunk_text_keeps_heading_with_body PASSED")


def test_chunk_text_rejects_invalid_overlap() -> None:
    try:
        list(chunk_text("text", 10, 10))
    except ValueError:
        print("test_chunk_text_rejects_invalid_overlap PASSED")
        return

    raise AssertionError("chunk_text should reject size <= overlap")


def test_chunk_text_splits_long_units() -> None:
    chunks = list(chunk_text("가" * 35, 12, 3))

    assert len(chunks) > 1
    assert all(len(chunk) <= 12 for chunk in chunks)
    print("test_chunk_text_splits_long_units PASSED")


if __name__ == "__main__":
    test_iter_batches_splits_remainder()
    test_iter_batches_rejects_non_positive_size()
    test_clean_text_preserves_line_boundaries()
    test_chunk_text_keeps_heading_with_body()
    test_chunk_text_rejects_invalid_overlap()
    test_chunk_text_splits_long_units()
    print("\nAll tests PASSED")
