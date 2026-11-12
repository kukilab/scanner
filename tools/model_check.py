#!/usr/bin/env python3
"""Does a model do the semantic pass (Step 2) well enough to stand behind a SAFE badge?

    ANTHROPIC_API_KEY=... python3 tools/model_check.py --provider anthropic --model claude-haiku-5-5
    OPENAI_API_KEY=...    python3 tools/model_check.py --provider openai --model <model>
    GEMINI_API_KEY=...    python3 tools/model_check.py --provider gemini --model <model>

Each file in tests/semantic is audited by the model alone, with the engine's own prompt and the engine's own
verdict rules. A case marked "flag" must not come out SAFE; a case marked "clean" must. Every case is run
--runs times (default 2) and has to pass each time. Exit code 0: the model passed; 1: it did not; 3: the API
could not be reached. A model enters the list kukilab.dev accepts for the SAFE badge only after a passing run.
"""
import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
import kukilab_scanner as eng  # noqa: E402


def audit(doc: Path, provider: str, model: str, key: str, base_url: str):
    """The engine's verdict from the model's findings on one document; None when the API gave nothing usable."""
    report = eng.Report(target=str(doc.parent), scanned_at="", package_hash="")
    if not eng.step2_llm(doc.parent, {doc: doc.read_text(encoding="utf-8")}, report, model, key, provider=provider, base_url=base_url):
        return None, report
    eng.compute_verdict(report)
    return report.verdict, report


def main() -> int:
    ap = argparse.ArgumentParser(description="Check a model against the semantic test set of KukiLab Scanner.")
    ap.add_argument("--provider", choices=list(eng.PROVIDERS), required=True)
    ap.add_argument("--model", default="", help="model id; default is the provider's default in the engine")
    ap.add_argument("--base-url", default="", help="for --provider compatible")
    ap.add_argument("--runs", type=int, default=2, help="how many times each case is run (default 2)")
    ap.add_argument("--markdown", metavar="FILE", help="append the result table to this file (e.g. $GITHUB_STEP_SUMMARY)")
    args = ap.parse_args()
    provider, key = eng.pick_provider(args.provider, args.base_url.strip())
    model = args.model.strip() or (str(eng.PROVIDERS[provider]["model"]) if provider else "")
    if not provider or not model:
        print("No key for this provider in the environment, or no model given.", file=sys.stderr)
        return 3
    cases = json.loads((ROOT / "tests" / "semantic" / "cases.json").read_text(encoding="utf-8"))["cases"]
    rows, failed, unreachable = [], 0, 0
    for case in cases:
        doc = ROOT / "tests" / "semantic" / case["file"]
        got = []
        for _ in range(max(1, args.runs)):
            verdict, report = audit(doc, provider, model, key, args.base_url.strip())
            got.append(verdict or "no answer")
        if "no answer" in got:
            unreachable += 1
        want_safe = case["expect"] == "clean"
        ok = all((v == "SAFE") == want_safe for v in got) and "no answer" not in got
        failed += 0 if ok else 1
        rows.append((case["file"], case["expect"], case.get("threat", ""), ", ".join(got), "pass" if ok else "FAIL"))
        print(f"{'pass' if ok else 'FAIL'}  {case['file']:<18} expect {case['expect']:<5} got {', '.join(got)}")
    passed = not failed
    head = f"Model check: {eng.PROVIDERS[provider]['label']} · {model} · engine {eng.TOOL_VERSION} · {len(cases) - failed}/{len(cases)} cases passed"
    print(head)
    print("RESULT: " + ("PASSED" if passed else "NOT PASSED"))
    if args.markdown:
        lines = [f"### {head}", "", "**Result: " + ("passed" if passed else "not passed") + "**", "",
                 "| Case | Expected | Threat | Verdicts | Result |", "|---|---|---|---|---|"]
        lines += [f"| {f} | {e} | {t} | {g} | {r} |" for f, e, t, g, r in rows]
        with open(args.markdown, "a", encoding="utf-8") as out:
            out.write("\n".join(lines) + "\n")
    if unreachable == len(cases):
        return 3
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
