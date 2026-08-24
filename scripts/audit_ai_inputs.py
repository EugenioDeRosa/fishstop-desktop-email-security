"""Print the exact normalized EML text sent to FishStop AI analysis."""

from __future__ import annotations

import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
ENGINE_ROOT = PROJECT_ROOT / "src-python"
if str(ENGINE_ROOT) not in sys.path:
    sys.path.insert(0, str(ENGINE_ROOT))

from main import analyze  # noqa: E402


DEFAULT_INPUT_DIR = Path(
    "/Users/eugenio/Università/Tesi_Master/FishSTOP/data/raw/EMAIL MALEVOLE"
)
DEFAULT_FILES = [
    "apertura link 2 .eml",
    "apertura link.eml",
    "domainlookalike.eml",
    "fattura falsa.eml",
    "impersonificazione microsoft.eml",
    "operazione bancaria 2.eml",
    "operazione bancaria 3.eml",
    "operazione bancaria.eml",
    "pdf malevolo .eml",
    "ricatto .eml",
    "spam 2 .eml",
    "spam.eml",
]


def main() -> None:
    for filename in DEFAULT_FILES:
        report = analyze(str(DEFAULT_INPUT_DIR / filename))
        print(f"\n{'=' * 88}\nFILE: {filename}")
        print(f"SUBJECT: {report.get('subject') or '-'}")
        print(f"FROM: {report.get('from_') or '-'}")
        print(
            "AI CONTEXT: "
            f"{report.get('body_context')} | source={report.get('body_source')} | "
            f"removed: quoted={report.get('body_ai_removed_quoted_lines', 0)}, "
            f"thread/header={report.get('body_ai_removed_header_lines', 0)}, "
            f"footer={report.get('body_ai_removed_tail_lines', 0)}"
        )
        print("\nBODY_FOR_AI:\n")
        print(report.get("body_for_ai") or "[empty]")


if __name__ == "__main__":
    main()
