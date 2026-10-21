"""Paired local inference experiment. Private inputs/results must stay outside Git."""
import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import statistics
import sys
import time


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--eml", action="append", default=[], help="Private EML path; repeat for multiple inputs")
    parser.add_argument("--synthetic", action="store_true", help="Include long boundary cases built in memory")
    parser.add_argument("--endpoint", default="http://127.0.0.1:11435/api/chat")
    parser.add_argument("--model", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--repeats", type=int, default=1)
    parser.add_argument("--context", type=int, default=4096)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    args.output = args.output.resolve()
    if root == args.output or root in args.output.parents:
        import subprocess
        if subprocess.run(["git", "check-ignore", "--quiet", str(args.output)], cwd=root).returncode:
            parser.error("Results inside the repository must be in a Git-ignored directory.")
    os.environ.update(OLLAMA_MODEL=args.model, OLLAMA_CHAT_ENDPOINT=args.endpoint,
                      OLLAMA_NUM_CTX=str(args.context), OLLAMA_NUM_THREAD="8", OLLAMA_KEEP_ALIVE="2m",
                      FISHSTOP_LLM_PROVIDER="ollama", OLLAMA_SINGLE_PASS="0", FISHSTOP_ANALYSIS_MODE="balanced")
    sys.path.insert(0, str(root / "src-python"))
    import requests
    from fishstop_engine.analyzer.soc_analyzer import EmlSOCAnalyzer
    from fishstop_engine.analyzer import llm_context_analyzer as llm
    session = requests.Session()
    session.trust_env = False
    base = args.endpoint.rsplit("/", 1)[0]
    cases = []
    for path in args.eml:
        p = Path(path)
        soc = EmlSOCAnalyzer().analyze(str(p))
        soc["local_only"] = True
        cases.append({"id": p.name, "sha256": hashlib.sha256(p.read_bytes()).hexdigest(), "soc": soc})
    if args.synthetic:
        # Fixed descriptive filler, varied paragraph IDs; no model-generated dataset.
        filler = "\n\n".join(
            f"Exhibit {i}: The hall contains windows and seating. The exhibition describes regional architecture, materials and lighting. "
            "The catalogue records the dimensions, historical uses and renovation dates of each room."
            for i in range(32))
        for name, ending, expected_action, expected_risk in [
            ("late-secret-request", "Reply with the security code you just received so we can verify your account.", "provide_credentials", "phishing"),
            ("benign-security-warning", "Security notice: never reply with your password or security code. We will never ask you to disclose it. No action is required.", "informational", "benign"),
            ("implicit-narrative-lure", "You have inherited an unexpected fortune from a stranger. Your allocated account and guaranteed funds are waiting; the process must remain confidential.", None, "phishing"),
        ]:
            cases.append({"id": name, "expected_action": expected_action, "expected_risk": expected_risk,
                          "soc": {"subject": "Exhibition bulletin", "from_": "Bulletin <notice@example.test>",
                                  "body_for_ai": filler + "\n\n" + ending, "body_for_identity": filler + "\n\n" + ending,
                                  "links": [], "attachments": [], "local_only": True}})
    args.output.parent.mkdir(parents=True, exist_ok=True)
    result = {"metadata": {"model": args.model, "context": args.context, "threads": 8,
                          "scope": "Local AI pipeline only; no reputation/brand network enrichment. Identical warmup before every timed run. No claim of production accuracy.",
                          "request_timeout": llm.OLLAMA_REQUEST_TIMEOUT, "pipeline_timeout": llm.OLLAMA_PIPELINE_TIMEOUT,
                          "prompt_version": llm.PROMPT_VERSION, "num_predict": llm.OLLAMA_NUM_PREDICT,
                          "extractor_sha256": hashlib.sha256((root / "src-python/fishstop_engine/analyzer/long_email.py").read_bytes()).hexdigest()}, "runs": []}

    def save():
        args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")

    try:
        for repeat in range(args.repeats):
            for case in cases:
                for enabled in ([False, True] if repeat % 2 == 0 else [True, False]):
                    mode = "extract" if enabled else "baseline"
                    print(json.dumps({"start": case["id"], "mode": mode, "repeat": repeat + 1}), flush=True)
                    # Match runtime/model context and clear previous email's prompt
                    # cache by unloading first; common load is outside the timer.
                    warm_started = time.monotonic()
                    session.post(base + "/generate", json={"model": args.model, "keep_alive": 0}, timeout=30).raise_for_status()
                    session.post(args.endpoint, json={"model": args.model, "messages": [], "stream": False,
                                 "keep_alive": "2m", "options": {"num_ctx": args.context, "num_thread": 8}}, timeout=90).raise_for_status()
                    warm_seconds = time.monotonic() - warm_started
                    llm.LONG_EMAIL_EXTRACTION = enabled
                    started = time.monotonic()
                    final, progress = {}, []
                    try:
                        for event in llm.stream_phi4_email_analysis(copy.deepcopy(case["soc"]), model=args.model):
                            if event.get("status") == "progress":
                                progress.append({"stage": event.get("stage"), "seconds": round(time.monotonic() - started, 3)})
                            if event.get("status") in {"ok", "error", "cancelled"}:
                                final = event
                    except Exception as exc:
                        final = {"status": "error", "message": f"{type(exc).__name__}: {exc}"}
                    row = {"case": case["id"], "source_sha256": case.get("sha256"), "mode": mode, "repeat": repeat + 1,
                           "expected_action": case.get("expected_action"), "expected_risk": case.get("expected_risk"),
                           "seconds": round(time.monotonic() - started, 3), "warmup_seconds": round(warm_seconds, 3),
                           "progress": progress, "result": final}
                    result["runs"].append(row)
                    save()
                    analysis = final.get("analysis") or {}
                    print(json.dumps({"done": case["id"], "mode": mode, "seconds": row["seconds"], "status": final.get("status"),
                                      "verdict": analysis.get("final_verdict"), "action": analysis.get("requested_action"),
                                      "risk": analysis.get("ai_content_assessment"), "performance": final.get("performance")}), flush=True)
    finally:
        session.post(base + "/generate", json={"model": args.model, "keep_alive": 0}, timeout=30)
    comparisons = []
    for case in cases:
        rows = [r for r in result["runs"] if r["case"] == case["id"]]
        times = {mode: [r["seconds"] for r in rows if r["mode"] == mode and r["result"].get("status") == "ok"] for mode in ("baseline", "extract")}
        pairs = []
        for repeat in range(1, args.repeats + 1):
            pair = {r["mode"]: r for r in rows if r["repeat"] == repeat}
            if set(pair) != {"baseline", "extract"}:
                continue
            before, after = pair["baseline"]["result"], pair["extract"]["result"]
            fields = ["final_verdict", "requested_action", "action_channel", "ai_content_assessment", "content_risk"]
            pairs.append({"repeat": repeat, "both_complete": before.get("status") == after.get("status") == "ok",
                          "analysis_fields": {key: [before.get("analysis", {}).get(key), after.get("analysis", {}).get(key)] for key in fields}})
        comparisons.append({"case": case["id"], "median_success_seconds": {m: statistics.median(t) for m, t in times.items() if t},
                            "errors": {m: sum(r["result"].get("status") != "ok" for r in rows if r["mode"] == m) for m in times}, "pairs": pairs})
    result["comparisons"] = comparisons
    save()
    print(json.dumps(comparisons), flush=True)


if __name__ == "__main__":
    main()
