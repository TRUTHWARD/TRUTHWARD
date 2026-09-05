# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from io import BytesIO
from time import monotonic
from typing import Any, Callable
import warnings


OCR_PDF_MIME_TYPE = "application/pdf"
OCR_IMAGE_MIME_TYPES = {
    "image/bmp",
    "image/jpeg",
    "image/png",
    "image/tiff",
    "image/webp",
}
OCR_RESOURCE_PROFILE = "ocr-tool.v1"
MAX_OCR_INPUT_BYTES = 10 * 1024 * 1024
MAX_OCR_PAGES = 25
MAX_OCR_PAGE_PIXELS = 24_000_000
MAX_OCR_TOTAL_PIXELS = 48_000_000
MAX_OCR_LINES = 10_000
MAX_OCR_TEXT_CHARS = 2 * 1024 * 1024
OCR_EXECUTION_TIMEOUT_SECONDS = 30.0
OCR_MEMORY_BUDGET_BYTES = 256 * 1024 * 1024


class OcrAdapterError(ValueError):
    """Safe failure raised by the controlled OCR Tool adapter."""


@dataclass(frozen=True, slots=True)
class OcrPageText:
    page_number: int
    text: str
    confidence: float
    line_count: int


@dataclass(frozen=True, slots=True)
class OcrDocumentResult:
    text: str
    confidence: float
    page_count: int
    line_count: int
    pages: tuple[OcrPageText, ...]
    adapter: str


class OcrDocumentAdapter(ABC):
    """Tool contract for OCR execution only; policy and persistence stay in Service."""

    @abstractmethod
    def extract_text(self, payload: bytes, *, mime_type: str) -> OcrDocumentResult:
        raise NotImplementedError


class RapidOcrDocumentAdapter(OcrDocumentAdapter):
    """Local ONNX OCR adapter for images and image-based PDF pages."""

    def __init__(
        self,
        engine_factory: Callable[[], Any] | None = None,
        *,
        timeout_seconds: float = OCR_EXECUTION_TIMEOUT_SECONDS,
    ) -> None:
        if timeout_seconds <= 0:
            raise ValueError("OCR timeout must be positive")
        self._engine_factory = engine_factory
        self._engine_instance: Any | None = None
        self.timeout_seconds = float(timeout_seconds)

    def extract_text(self, payload: bytes, *, mime_type: str) -> OcrDocumentResult:
        if not payload:
            raise OcrAdapterError("OCR_INPUT_INVALID: OCR source is empty")
        if len(payload) > MAX_OCR_INPUT_BYTES:
            raise OcrAdapterError(
                f"OCR_INPUT_TOO_LARGE: OCR source exceeds {MAX_OCR_INPUT_BYTES} byte limit"
            )
        canonical_mime = (mime_type or "").split(";")[0].strip().lower()
        if canonical_mime == OCR_PDF_MIME_TYPE:
            images = self._render_pdf(payload)
        elif canonical_mime in OCR_IMAGE_MIME_TYPES:
            images = self._load_images(payload)
        else:
            raise OcrAdapterError("OCR_INPUT_UNSUPPORTED: OCR supports PDF, PNG, JPEG, TIFF, BMP, and WebP")

        pages: list[OcrPageText] = []
        all_scores: list[float] = []
        total_pixels = 0
        total_lines = 0
        total_text_chars = 0
        deadline = monotonic() + self.timeout_seconds
        try:
            for page_number, image in enumerate(images, start=1):
                try:
                    if monotonic() > deadline:
                        raise OcrAdapterError(
                            f"OCR_TIMEOUT: OCR exceeded {self.timeout_seconds:g} second limit"
                        )
                    width, height = image.size
                    page_pixels = _checked_pixel_count(width, height)
                    if page_pixels > MAX_OCR_PAGE_PIXELS:
                        raise OcrAdapterError("OCR_INPUT_TOO_LARGE: rendered page exceeds safe pixel limit")
                    total_pixels += page_pixels
                    if total_pixels > MAX_OCR_TOTAL_PIXELS:
                        raise OcrAdapterError("OCR_INPUT_TOO_LARGE: OCR document exceeds total pixel limit")
                    result = self._engine()(image)
                    if monotonic() > deadline:
                        raise OcrAdapterError(
                            f"OCR_TIMEOUT: OCR exceeded {self.timeout_seconds:g} second limit"
                        )
                    normalized_texts = [
                        _normalize_ocr_text(str(item))
                        for item in (getattr(result, "txts", None) or ())
                    ]
                    texts = tuple(item for item in normalized_texts if item)
                    total_lines += len(texts)
                    if total_lines > MAX_OCR_LINES:
                        raise OcrAdapterError(
                            f"OCR_RESOURCE_EXHAUSTED: OCR output exceeds {MAX_OCR_LINES} line limit"
                        )
                    total_text_chars += sum(len(item) for item in texts)
                    if total_text_chars > MAX_OCR_TEXT_CHARS:
                        raise OcrAdapterError(
                            f"OCR_RESOURCE_EXHAUSTED: OCR output exceeds {MAX_OCR_TEXT_CHARS} character limit"
                        )
                    scores = tuple(float(item) for item in (getattr(result, "scores", None) or ()))
                    page_scores = [max(0.0, min(1.0, score)) for score in scores[: len(texts)]]
                    if len(page_scores) < len(texts):
                        page_scores.extend([0.0] * (len(texts) - len(page_scores)))
                    page_text = "\n".join(texts).strip()
                    page_confidence = sum(page_scores) / len(page_scores) if page_scores else 0.0
                    pages.append(
                        OcrPageText(
                            page_number=page_number,
                            text=page_text,
                            confidence=round(page_confidence, 6),
                            line_count=len(texts),
                        )
                    )
                    all_scores.extend(page_scores)
                finally:
                    close_image = getattr(image, "close", None)
                    if callable(close_image):
                        close_image()
        except OcrAdapterError:
            raise
        except Exception as exc:
            raise OcrAdapterError("OCR_EXECUTION_FAILED: controlled OCR inference failed") from exc
        finally:
            close_images = getattr(images, "close", None)
            if callable(close_images):
                close_images()

        text = "\n\n".join(page.text for page in pages if page.text).strip()
        if not text:
            raise OcrAdapterError("OCR_NO_TEXT: OCR completed but found no text")
        confidence = sum(all_scores) / len(all_scores) if all_scores else 0.0
        return OcrDocumentResult(
            text=text,
            confidence=round(confidence, 6),
            page_count=len(pages),
            line_count=sum(page.line_count for page in pages),
            pages=tuple(pages),
            adapter="rapidocr-onnxruntime",
        )

    def _engine(self) -> Any:
        if self._engine_instance is not None:
            return self._engine_instance
        if self._engine_factory is not None:
            self._engine_instance = self._engine_factory()
            return self._engine_instance
        try:
            from rapidocr import RapidOCR
        except ImportError as exc:
            raise OcrAdapterError(
                "OCR_TOOL_UNAVAILABLE: OCR requires the declared rapidocr and onnxruntime dependencies"
            ) from exc
        self._engine_instance = RapidOCR()
        return self._engine_instance

    def _render_pdf(self, payload: bytes) -> Any:
        try:
            import pypdfium2 as pdfium
        except ImportError as exc:
            raise OcrAdapterError("OCR_TOOL_UNAVAILABLE: PDF OCR requires the declared pypdfium2 dependency") from exc

        def iter_pages() -> Any:
            document: Any | None = None
            try:
                document = pdfium.PdfDocument(payload)
                if len(document) > MAX_OCR_PAGES:
                    raise OcrAdapterError(f"OCR_INPUT_TOO_LARGE: PDF exceeds {MAX_OCR_PAGES} page limit")
                for page in document:
                    bitmap: Any | None = None
                    image: Any | None = None
                    try:
                        bitmap = page.render(scale=2.0)
                        image = bitmap.to_pil()
                        width, height = image.size
                        if _checked_pixel_count(width, height) > MAX_OCR_PAGE_PIXELS:
                            raise OcrAdapterError(
                                "OCR_INPUT_TOO_LARGE: rendered page exceeds safe pixel limit"
                            )
                        converted = image.convert("RGB")
                    finally:
                        if image is not None:
                            image.close()
                        if bitmap is not None:
                            bitmap.close()
                        page.close()
                    yield converted
            except OcrAdapterError:
                raise
            except Exception as exc:
                raise OcrAdapterError("OCR_EXECUTION_FAILED: PDF rendering for OCR failed") from exc
            finally:
                if document is not None:
                    document.close()

        return iter_pages()

    def _load_images(self, payload: bytes) -> Any:
        try:
            from PIL import Image, ImageSequence
        except ImportError as exc:
            raise OcrAdapterError("OCR_TOOL_UNAVAILABLE: image OCR requires the declared Pillow dependency") from exc

        def iter_frames() -> Any:
            source: Any | None = None
            try:
                with warnings.catch_warnings():
                    warnings.simplefilter("error", Image.DecompressionBombWarning)
                    source = Image.open(BytesIO(payload))
                for frame_number, frame in enumerate(ImageSequence.Iterator(source), start=1):
                    if frame_number > MAX_OCR_PAGES:
                        raise OcrAdapterError(
                            f"OCR_INPUT_TOO_LARGE: image exceeds {MAX_OCR_PAGES} frame limit"
                        )
                    width, height = frame.size
                    if _checked_pixel_count(width, height) > MAX_OCR_PAGE_PIXELS:
                        raise OcrAdapterError(
                            "OCR_INPUT_TOO_LARGE: image frame exceeds safe pixel limit"
                        )
                    yield frame.convert("RGB")
            except OcrAdapterError:
                raise
            except (Image.DecompressionBombError, Image.DecompressionBombWarning) as exc:
                raise OcrAdapterError("OCR_INPUT_TOO_LARGE: image exceeds safe pixel limit") from exc
            except Exception as exc:
                raise OcrAdapterError("OCR_EXECUTION_FAILED: image decoding for OCR failed") from exc
            finally:
                if source is not None:
                    source.close()

        return iter_frames()


def ocr_resource_limit_snapshot() -> dict[str, int | float | str]:
    return {
        "profile": OCR_RESOURCE_PROFILE,
        "maxBytes": MAX_OCR_INPUT_BYTES,
        "maxPages": MAX_OCR_PAGES,
        "maxPagePixels": MAX_OCR_PAGE_PIXELS,
        "maxTotalPixels": MAX_OCR_TOTAL_PIXELS,
        "maxLines": MAX_OCR_LINES,
        "maxTextChars": MAX_OCR_TEXT_CHARS,
        "timeoutSeconds": OCR_EXECUTION_TIMEOUT_SECONDS,
        "memoryBudgetBytes": OCR_MEMORY_BUDGET_BYTES,
    }


def _checked_pixel_count(width: Any, height: Any) -> int:
    try:
        normalized_width = int(width)
        normalized_height = int(height)
    except (TypeError, ValueError) as exc:
        raise OcrAdapterError("OCR_INPUT_INVALID: image dimensions are invalid") from exc
    if normalized_width <= 0 or normalized_height <= 0:
        raise OcrAdapterError("OCR_INPUT_INVALID: image dimensions are invalid")
    return normalized_width * normalized_height


def _normalize_ocr_text(value: str) -> str:
    return "".join(
        character
        for character in value.replace("\r\n", "\n").replace("\r", "\n")
        if character in {"\n", "\t"} or not (ord(character) < 32 or 127 <= ord(character) <= 159)
    ).strip()


def ocr_document_adapter() -> OcrDocumentAdapter:
    return RapidOcrDocumentAdapter()
