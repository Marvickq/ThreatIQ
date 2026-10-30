"""Compare retrieval arms on the labelled synthetic set in rag_dataset.py, using a throwaway SQLite database.

    python -m eval.rag_eval            # real embeddings (needs NVIDIA_API_KEY); keyword-only arms run regardless
    python -m eval.rag_eval --stub     # local stub embedder: checks plumbing ONLY, says nothing about model quality

Arms:  baseline      = the previous algorithm (exact indicator match only)
       keyword_exact = exact + keyword (no embeddings)
       hybrid        = exact + keyword + semantic, fused (the shipped pipeline)

Never touches the configured database: DATABASE_URL is overridden before the app is imported.
"""
import argparse
import json
import os
import statistics
import tempfile
import time
from datetime import timedelta
from pathlib import Path

TMP = Path(tempfile.mkdtemp(prefix="rag_eval_"))
os.environ["DATABASE_URL"] = f"sqlite:///{(TMP / 'eval.db').as_posix()}"
os.environ["SCHEDULER_ENABLED"] = "false"

from sqlmodel import Session, select  # noqa: E402

from app.ai.embedding_client import EmbeddingClient  # noqa: E402
from app.config import get_settings  # noqa: E402
from app.database import engine  # noqa: E402
from app.migrations import run_migrations  # noqa: E402
from app.models import Organization, ReviewDecision, SecurityAlert, utcnow  # noqa: E402
from app.services import embedding_service, indicators, retrieval_service  # noqa: E402
from eval import rag_dataset as ds  # noqa: E402
from eval.stub_embedder import start_stub  # noqa: E402

K = 5


# ------------------------------------------------------------------------------ corpus
def build(session: Session) -> tuple[Organization, dict[str, str], dict[str, str], str]:
    """Returns (org, alert_id -> family, query_id -> family, other_org_alert_id)."""
    org = Organization(name="Eval Org", slug="eval-org", allow_external_enrichment=True)
    other = Organization(name="Other Org", slug="other-org", allow_external_enrichment=True)
    session.add(org); session.add(other); session.flush()
    family_of: dict[str, str] = {}

    def add(o, title, desc, days, decision, note, family, demo=False):
        a = SecurityAlert(organization_id=o.id, title=title, description=desc, severity="high", source="eval", status="resolved" if decision else "new",
                          is_demo=demo, created_at=utcnow() - timedelta(days=days))
        session.add(a); session.flush(); indicators.store(session, a)
        if decision:
            session.add(ReviewDecision(organization_id=o.id, alert_id=a.id, decision=decision, reviewer_note=note, created_at=a.created_at + timedelta(hours=2)))
        if family:
            family_of[a.id] = family
        return a

    for fam, rows in ds.HISTORY.items():
        for t, d, days, dec, note in rows:
            add(org, t, d, days, dec, note, fam)
    for t, d, days, dec, note in ds.NOISE:
        add(org, t, d, days, dec, note, None)
    t, d, days, dec, note = ds.STALE
    add(org, t, d, days, dec, note, None)  # stale: relevant by family but must be filtered, so it is not in the relevant set
    leak = add(other, "Log4j JNDI exploit attempt", "jndi:ldap://198.51.100.7/a CVE-2021-44228 against web01.", 2, "true_positive", "other tenant", "log4shell")
    queries: dict[str, str] = {}
    for t, d, fam, _ in ds.QUERIES:
        q = add(org, t, d, 0, None, "", None)
        queries[q.id] = fam or ""
    session.commit()
    return org, family_of, queries, leak.id


# ------------------------------------------------------------------------------ metrics
def baseline_ids(session, alert) -> list[str]:
    exact = retrieval_service._exact_matches(session, alert)
    strong = lambda terms: sum(1 for t, _ in terms if t in retrieval_service.STRONG_TYPES)
    return [a for a, _ in sorted(exact.items(), key=lambda kv: (-(len(kv[1]) * 2 + strong(kv[1])), kv[0]))][:K]


def score(runs: dict[str, list[str]], relevant: dict[str, set[str]]) -> dict:
    p, r, rr, hits, empty_ok, false_ret = [], [], [], 0, 0, 0
    pos_q = 0
    for qid, got in runs.items():
        rel = relevant[qid]
        if not rel:
            if not got:
                empty_ok += 1
            false_ret += len(got)
            continue
        pos_q += 1
        tp = [g for g in got if g in rel]
        p.append(len(tp) / len(got) if got else 0.0)
        r.append(len(tp) / len(rel))
        rank = next((i + 1 for i, g in enumerate(got) if g in rel), None)
        rr.append(1 / rank if rank else 0.0)
        hits += 1 if rank else 0
    return {"precision@5": round(statistics.mean(p), 3), "recall@5": round(statistics.mean(r), 3), "mrr": round(statistics.mean(rr), 3),
            "hit_rate": round(hits / pos_q, 3), "no_history_queries_empty": empty_ok, "irrelevant_returned_for_no_history": false_ret}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--stub", action="store_true", help="use a local stub embedder (plumbing check only)")
    ap.add_argument("--price-per-mtok", type=float, default=None, help="USD per million input tokens, if you want a cost estimate")
    args = ap.parse_args()

    settings = get_settings()
    if args.stub:
        settings.nvidia_base_url, settings.nvidia_api_key = start_stub(), "stub-key"
        print("!! STUB EMBEDDER: results below test plumbing only and say NOTHING about nvidia/nemotron-3.5-embed-1b quality.\n")
    run_migrations(engine)
    client = EmbeddingClient(settings)

    with Session(engine) as session:
        org, family_of, queries, leak_id = build(session)
        relevant = {qid: {a for a, f in family_of.items() if f == fam and a != leak_id} if fam else set() for qid, fam in queries.items()}
        alerts = {qid: session.get(SecurityAlert, qid) for qid in queries}
        arms: dict[str, dict[str, list[str]]] = {"baseline": {}, "keyword_exact": {}}
        lat: dict[str, list[float]] = {"baseline": [], "keyword_exact": [], "hybrid": []}
        for qid, a in alerts.items():
            t = time.perf_counter(); arms["baseline"][qid] = baseline_ids(session, a); lat["baseline"].append((time.perf_counter() - t) * 1000)
            t = time.perf_counter(); arms["keyword_exact"][qid] = [i.id for i in retrieval_service.retrieve(session, a).items]; lat["keyword_exact"].append((time.perf_counter() - t) * 1000)

        report: dict = {"corpus": {"historical": len(family_of) - 1, "queries": len(queries)}, "stub_embedder": args.stub}
        ok, why = embedding_service.allowed(session, org.id)
        if ok:
            all_ids = list(session.exec(select(SecurityAlert).where(SecurityAlert.organization_id == org.id, SecurityAlert.id.notin_(list(queries)))).all())
            t = time.perf_counter(); res = embedding_service.index_alerts(session, all_ids, client)
            report["indexing"] = {"alerts": len(all_ids), "indexed": res.indexed, "failed": res.failed, "error": res.error, "seconds": round(time.perf_counter() - t, 2)}
            arms["hybrid"] = {}
            notes = []
            for qid, a in alerts.items():
                t = time.perf_counter(); r = retrieval_service.retrieve(session, a, client); lat["hybrid"].append((time.perf_counter() - t) * 1000)
                arms["hybrid"][qid] = [i.id for i in r.items]; notes += r.notes
            report["hybrid_notes"] = sorted(set(notes))
            report["embedding_usage"] = {"api_calls": client.calls, "input_chars": client.input_chars, "approx_tokens": client.input_chars // 4}
            if args.price_per_mtok is not None:
                report["embedding_usage"]["est_cost_usd"] = round(client.input_chars / 4 / 1e6 * args.price_per_mtok, 6)
        else:
            report["hybrid"] = f"NOT RUN: {why}"

        report["metrics"] = {name: score(runs, relevant) for name, runs in arms.items()}
        report["latency_ms_median"] = {n: round(statistics.median(v), 1) for n, v in lat.items() if v}
        report["tenant_isolation"] = {"other_org_alert_ever_returned": any(leak_id in got for runs in arms.values() for got in runs.values())}
        report["stale_item_returned_by_arm"] = {
            n: sum(1 for got in runs.values() for g in got if session.get(SecurityAlert, g).description.startswith("198.51.100.200")) for n, runs in arms.items()
        }
        report["per_query_misses"] = {
            n: [ds.QUERIES[list(queries).index(q)][0] for q in queries if relevant[q] and not (set(runs[q]) & relevant[q])] for n, runs in arms.items()
        }
    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
