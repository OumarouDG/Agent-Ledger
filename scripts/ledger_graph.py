"""Write the provenance graph as one self-contained, offline HTML page. Read-only.

    python scripts/pull_audit_from_cloudwatch.py audit.jsonl
    python scripts/ledger_graph.py audit.jsonl --out agentledger-graph.html
    python scripts/ledger_graph.py audit.jsonl --workflow wf_001 --pr 3
    python scripts/ledger_graph.py --synthetic --out synthetic-graph.html

The page needs no server, no network and no AWS login. Statuses come from ledger.evidence,
ledger.chain and ledger.metrics; this script and the page decide nothing about evidence.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import audit_timeline as tl  # noqa: E402
from ledger import build_graph  # noqa: E402
from ledger.sample import LABEL, sample_declarations, sample_events  # noqa: E402
from ledger.visualize import build_view, render_html  # noqa: E402


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("path", nargs="?", default="gateway-audit.jsonl")
    ap.add_argument("--out", default="agentledger-graph.html")
    ap.add_argument("--workflow")
    ap.add_argument("--pr", type=int)
    ap.add_argument("--declarations", metavar="FILE")
    ap.add_argument("--synthetic", action="store_true", help="invented A->B->C sample, bannered")
    args = ap.parse_args(argv)
    label = None
    try:
        if args.synthetic:
            events, decls, label = sample_events(), sample_declarations(), LABEL
        else:
            with open(args.path, encoding="utf-8") as f:
                events, bad = tl.load(f)
            for n, text in bad:
                print(f"WARNING: line {n} is not valid JSON: {text!r}", file=sys.stderr)
            decls = []
            if args.declarations:
                from ledger_report import load_declarations
                decls = load_declarations(args.declarations)
        g = build_graph(events, decls)
        view = build_view(g, synthetic_label=label, workflow=args.workflow, pr=args.pr)
        Path(args.out).write_text(render_html(view), encoding="utf-8")
    except (OSError, ValueError, KeyError, ImportError) as e:
        print(f"failed: {type(e).__name__}: {e}", file=sys.stderr)
        return 2
    print(f"wrote {args.out}: {len(view['nodes'])} nodes, {len(view['edges'])} edges, "
          f"{len(view['chains'])} deliverable chain(s)" + (" [SYNTHETIC]" if label else ""))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
