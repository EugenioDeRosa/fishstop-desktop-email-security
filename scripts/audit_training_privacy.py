"""Read-only dataset checks. Reports contain counts/hashes, never message text."""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import re

RESERVED = (".example", ".invalid", ".test", ".localhost")


def audit(directory):
    directory = Path(directory)
    expected_path = directory / "dataset_hashes.json"
    expected = json.loads(expected_path.read_text(encoding="utf-8")) if expected_path.exists() else {}
    result = {"scope": directory.name, "files": {}, "limitations": [
        "Heuristics are candidate detection, not an anonymity certification.",
        "Synthetic markers and local manifests do not independently prove authorship or training execution.",
        "No model-weight extraction or memorization attack was performed."]}
    for split in ("train", "validation", "test"):
        path = directory / f"{split}.jsonl"
        if not path.exists():
            continue
        counts = Counter()
        iban_candidates = set()
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        for line in path.read_text(encoding="utf-8").splitlines():
            record = json.loads(line)
            counts["records"] += 1
            counts["marked_synthetic"] += record.get("synthetic") is True
            text = json.dumps(record, ensure_ascii=False)
            addresses = re.findall(r"[\w.+-]+@([\w.-]+\.[A-Za-z]{2,})", text)
            def reserved(host):
                return host.endswith(RESERVED) or host in {"example.com", "example.net", "example.org"} or any(host.endswith('.'+h) for h in ("example.com", "example.net", "example.org"))
            counts["records_with_nonreserved_email_candidate"] += any(not reserved(host.lower()) for host in addresses)
            counts["records_with_secret_pattern"] += bool(re.search(r"(?:GOCSPX-[\w-]{15,}|hf_[A-Za-z0-9]{25,}|ghp_[A-Za-z0-9]{30,}|-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----)", text))
            iban_values = re.findall(r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b", text)
            iban_candidates.update(iban_values)
            counts["records_with_iban_candidate"] += bool(iban_values)
            counts["records_with_phone_candidate"] += bool(re.search(r"(?<!\w)\+\d[\d ()-]{8,}\d", text))
        valid_iban = 0
        for value in iban_candidates:
            digits = "".join(str(ord(c) - 55) if c.isalpha() else c for c in value[4:] + value[:4])
            valid_iban += int(digits) % 97 == 1
        result["files"][path.name] = {"sha256": digest, "matches_manifest": expected.get(path.name) == digest if path.name in expected else None,
                                    "unique_iban_candidates": len(iban_candidates), "checksum_valid_iban_candidates": valid_iban, **counts}
    archive = directory / f"fishstop-dataset-{directory.name.removeprefix('fishstop-')}.zip"
    if archive.exists():
        result["dataset_zip_sha256"] = hashlib.sha256(archive.read_bytes()).hexdigest()
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("directory")
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    destination = Path(args.output)
    destination.parent.mkdir(parents=True, exist_ok=True)
    result = audit(args.directory)
    destination.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2))
