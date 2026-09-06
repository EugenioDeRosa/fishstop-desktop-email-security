"""
analyzer/constants.py - Costanti condivise per l'analisi statica delle email.

Contiene:
  - KNOWN_BRANDS       : database di domini brand noti per il lookalike check
  - _HOMOGLYPH_MAP     : mappa omoglifi Unicode -> ASCII
  - MAGIC_BYTES        : firme binarie per l'identificazione reale degli allegati
  - CONTENT_TYPE_TO_EXT: mapping Content-Type MIME -> estensioni attese
"""

# Domini di brand noti - usati come riferimento per il lookalike check.
# Ampliabile con i brand rilevanti per il contesto aziendale.
KNOWN_BRANDS: list[str] = [
    "paypal.com", "amazon.com", "amazon.it", "apple.com", "microsoft.com",
    "google.com", "gmail.com", "outlook.com", "live.com", "hotmail.com",
    "facebook.com", "instagram.com", "linkedin.com", "twitter.com", "x.com",
    "dropbox.com", "icloud.com", "chase.com", "wellsfargo.com", "bankofamerica.com",
    "intesasanpaolo.com", "unicredit.it", "poste.it", "postepay.it",
    "netflix.com", "spotify.com", "ebay.com", "dhl.com", "fedex.com",
    "ups.com", "brt.it", "gls-italy.com",
]

# Caratteri Unicode omoglifi -> ASCII equivalente
# (sottoinsieme rilevante per phishing; non serve un mapping completo)
HOMOGLYPH_MAP: dict[str, str] = {
    # Cyrillic characters frequently abused in IDN homograph attacks.
    "\u0430": "a", "\u0435": "e", "\u043e": "o", "\u0440": "p", "\u0441": "c", "\u0445": "x",
    "\u0501": "d",
    # Latin lookalikes that are not ordinary accented letters in common languages.
    "\u0131": "i", "\u013a": "l", "\u1e37": "l", "\u0261": "g", "\u028f": "y", "\u028b": "v",
}

# Magic Bytes database (Gary Kessler / File Signatures)
MAGIC_BYTES: dict[str, list[bytes]] = {
    "pdf":  [b"%PDF"],
    "zip":  [b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08"],
    "docx": [b"PK\x03\x04"],
    "xlsx": [b"PK\x03\x04"],
    "pptx": [b"PK\x03\x04"],
    "exe":  [b"MZ"],
    "elf":  [b"\x7fELF"],
    "png":  [b"\x89PNG\r\n\x1a\n"],
    "jpg":  [b"\xff\xd8\xff"],
    "gif":  [b"GIF87a", b"GIF89a"],
    "bmp":  [b"BM"],
    "tiff": [b"II*\x00", b"MM\x00*"],
    "rar":  [b"Rar!\x1a\x07"],
    "7z":   [b"7z\xbc\xaf\x27\x1c"],
    "gz":   [b"\x1f\x8b"],
    "bz2":  [b"BZh"],
    "doc":  [b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"],
    "xls":  [b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"],
    "ppt":  [b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"],
    "rtf":  [b"{\\rtf"],
    "html": [b"<!DOCTYPE", b"<html"],
    "xml":  [b"<?xml"],
    "js":   [],
    "bat":  [],
    "ps1":  [],
    "sh":   [b"#!/"],
}

CONTENT_TYPE_TO_EXT: dict[str, list[str]] = {
    "application/pdf":       ["pdf"],
    "application/zip":       ["zip", "docx", "xlsx", "pptx"],
    "application/msword":    ["doc"],
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document": ["docx"],
    "application/vnd.ms-excel": ["xls"],
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet": ["xlsx"],
    "application/vnd.ms-powerpoint": ["ppt"],
    "application/vnd.openxmlformats-officedocument.presentationml.presentation": ["pptx"],
    "application/x-rar-compressed": ["rar"],
    "application/x-7z-compressed":  ["7z"],
    "application/gzip":      ["gz"],
    "application/x-bzip2":  ["bz2"],
    "application/octet-stream": [],
    "image/png":  ["png"],
    "image/jpeg": ["jpg"],
    "image/gif":  ["gif"],
    "image/bmp":  ["bmp"],
    "image/tiff": ["tiff"],
    "text/html":  ["html"],
    "text/xml":   ["xml"],
    "application/rtf": ["rtf"],
}

# File types that can directly execute code, launch another resource, or mount
# attacker-controlled content when opened. These are risky delivery formats even
# when filename, declared MIME type, and magic bytes agree with each other.
DANGEROUS_ATTACHMENT_EXTENSIONS: frozenset[str] = frozenset({
    "exe", "dll", "scr", "com", "msi", "msp", "cpl", "sys", "ocx", "pif",
    "lnk", "url", "scf", "reg",
    "js", "jse", "mjs", "vbs", "vbe", "wsf", "wsh", "hta",
    "ps1", "psm1", "psd1", "bat", "cmd",
    "sh", "bash", "zsh", "fish", "py", "pyw", "pl", "rb", "jar",
    "iso", "img", "vhd", "vhdx",
    "apk", "appx", "appxbundle", "msix", "msixbundle", "deb", "rpm", "dmg", "pkg",
})

DANGEROUS_ATTACHMENT_MIME_TYPES: frozenset[str] = frozenset({
    "application/javascript",
    "application/java-archive",
    "application/vnd.microsoft.portable-executable",
    "application/x-bat",
    "application/x-dosexec",
    "application/x-executable",
    "application/x-java-archive",
    "application/x-ms-shortcut",
    "application/x-msdownload",
    "application/x-msdos-program",
    "application/x-powershell",
    "application/x-sh",
    "application/x-shellscript",
    "text/javascript",
    "text/x-powershell",
    "text/x-python",
    "text/x-script.python",
    "text/x-shellscript",
})

DANGEROUS_MAGIC_FORMATS: frozenset[str] = frozenset({"exe", "elf", "sh"})

# A benign-looking penultimate extension is a common disguise for a dangerous
# final extension, for example invoice.pdf.exe.
DECOY_ATTACHMENT_EXTENSIONS: frozenset[str] = frozenset({
    "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx",
    "jpg", "jpeg", "png", "gif", "txt", "rtf", "csv",
})
