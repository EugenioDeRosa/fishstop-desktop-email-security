"""Local QR inspection in a bounded child process. Destinations are never opened."""
from __future__ import annotations

import io
import multiprocessing
import re
import time
from urllib.parse import urlsplit

QR_REQUEST = re.compile(
    r"\b(?:scan\w*|scansion\w*|inquadra\w*|escanea\w*)\b.{0,120}"
    r"\b(?:qr|codice|code|c[oó]digo)\b", re.I | re.S)
MAX_BYTES = 12 * 1024 * 1024
MAX_TOTAL_BYTES = 24 * 1024 * 1024
MAX_PIXELS = 8_000_000
MAX_PAGES = 4
TIMEOUT = 6.0


def qr_request(text: str) -> str:
    match = QR_REQUEST.search(str(text or ""))
    return match.group(0) if match else ""


def _inspect(raw: bytes, content_type: str) -> dict:
    import zxingcpp
    from PIL import Image
    Image.MAX_IMAGE_PIXELS = MAX_PIXELS
    result = {"status": "complete", "analysis_complete": True, "urls": [], "text": "", "pages_scanned": 0}
    deadline = time.monotonic() + 4

    def decode(image):
        if len(result["urls"]) >= 4:
            return
        if image.width * image.height > MAX_PIXELS:
            raise ValueError("Image pixel limit exceeded")
        for barcode in zxingcpp.read_barcodes(image, formats=zxingcpp.BarcodeFormat.QRCode):
            value = barcode.text
            if len(value) > 2048:
                continue
            try:
                parsed = urlsplit(value)
                if parsed.scheme in {"https", "http"} and parsed.hostname and value not in result["urls"]:
                    result["urls"].append(value)
            except ValueError:
                pass
            if len(result["urls"]) >= 4:
                break

    if content_type == "application/pdf" or raw.startswith(b"%PDF"):
        import pypdfium2
        with pypdfium2.PdfDocument(raw) as document:
            for index in range(min(len(document), MAX_PAGES)):
                if time.monotonic() >= deadline:
                    result.update(status="partial", analysis_complete=False)
                    break
                page = document[index]
                try:
                    textpage = page.get_textpage()
                    try:
                        result["text"] = (result["text"] + " " + textpage.get_text_range(count=min(1600, textpage.count_chars())))[:1600]
                    finally:
                        textpage.close()
                    width, height = page.get_size()
                    if width <= 0 or height <= 0:
                        raise ValueError("Invalid PDF page dimensions")
                    scale = min(3.0, (MAX_PIXELS / (width * height)) ** .5)
                    bitmap = page.render(scale=scale)
                    try:
                        decode(bitmap.to_pil())
                    finally:
                        bitmap.close()
                    result["pages_scanned"] += 1
                finally:
                    page.close()
            if len(document) > MAX_PAGES:
                result.update(status="partial", analysis_complete=False)
    else:
        with Image.open(io.BytesIO(raw)) as image:
            decode(image)
    return result


def _worker(connection, items):
    try:
        for index, raw, content_type in items:
            try:
                result = _inspect(raw, content_type)
            except Exception:
                result = {"status": "unavailable", "analysis_complete": False, "urls": [], "text": ""}
            connection.send((index, result))
    finally:
        connection.close()


def inspect_requested_qr(items: list[tuple[int, bytes, str]]) -> dict:
    """One worker per email; unavailable/timeout is neutral, never a clean result."""
    unavailable = {index: {"status": "unavailable", "analysis_complete": False, "urls": [], "text": ""}
                   for index, _, _ in items}
    eligible = []
    total = 0
    for item in items[:6]:
        if len(item[1]) <= MAX_BYTES and total + len(item[1]) <= MAX_TOTAL_BYTES:
            eligible.append(item)
            total += len(item[1])
    if not eligible:
        return unavailable
    context = multiprocessing.get_context("spawn")
    receiver, sender = context.Pipe(duplex=False)
    process = context.Process(target=_worker, args=(sender, eligible), daemon=True)
    deadline = time.monotonic() + TIMEOUT
    try:
        process.start()
        sender.close()
        for _ in eligible:
            if not receiver.poll(max(0, deadline - time.monotonic())):
                break
            index, result = receiver.recv()
            unavailable[index] = result
    except (OSError, EOFError, RuntimeError):
        pass
    finally:
        receiver.close()
        sender.close()
        if process.pid:
            process.join(timeout=.1)
            if process.is_alive():
                process.terminate()
                process.join(timeout=.3)
            if process.is_alive():
                process.kill()
                process.join(timeout=.3)
            process.close()
    return unavailable
