"""Fixed confirmation boundary for the existing Noteri qualification workflow."""
import argparse
import json
from pathlib import Path
import noteri_qualification_receipt as pipeline

CONFIRM = "PROBE-NOTERI-CONTROL-PLANE"

def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--confirm")
    parser.add_argument("--rules-root", type=Path, required=True)
    parser.add_argument("--rules-sha", required=True)
    args = parser.parse_args()
    try:
        pipeline.require(args.confirm == CONFIRM, "confirmation_required")
        return pipeline.launch(args.rules_root, args.rules_sha)
    except Exception as exc:
        print(json.dumps({"ready": False, "hml_verified": False,
            "code": str(exc) if isinstance(exc, pipeline.Blocked) else type(exc).__name__}))
        return 2

if __name__ == "__main__":
    raise SystemExit(main())
