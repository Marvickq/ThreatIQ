# Retrieval-augmented analysis (RAG)

```
Alert -> normalised text -> embedding -> hybrid retrieval -> security filtering + ranking -> Nebius LLM
      -> citation validation -> assessment -> human review
```

Everything after "Nebius LLM" is the pre-existing pipeline (`investigation_service`, `ai/response_parser.py`, audit log, review decisions). This adds retrieval in front of it; it replaces nothing.

## Stages

| Stage | Where | Notes |
|---|---|---|
| Normalise | `embedding_service.alert_text` | Fixed field order: title, source/severity, entity, indicators, description (bounded to 6,000 chars). No ids or timestamps, so identical alerts hash identically and are never re-embedded. |
| Embed | `ai/embedding_client.py` | `POST {NVIDIA_BASE_URL}/embeddings`, model `nvidia/nemotron-3.5-embed-1b`. Vectors are 2048-dim, truncated to `EMBEDDING_DIMENSIONS` (1024) and re-normalised (the model supports Matryoshka truncation). Documents use `input_type=passage`, the alert being analysed uses `query`. |
| Exact | `retrieval_service._exact_matches` | Pre-existing indicator matching (CVE, IP, domain, URL, hashes). Always runs, always ranks first. |
| Keyword | `retrieval_service._keyword_matches` | PostgreSQL: `to_tsquery`/`ts_rank_cd` on a GIN index. SQLite: IDF-weighted scan of the 500 most recent alerts. Needs >= 3 shared content words and >= 25 % of the alert's words. |
| Semantic | `retrieval_service._semantic_matches` | PostgreSQL + pgvector: HNSW cosine search (`embedding_vec`). Otherwise an in-process cosine scan of up to `RAG_CANDIDATE_LIMIT` stored vectors. Matches below `RAG_MIN_SIMILARITY` are dropped. |
| Fuse + filter | `retrieval_service._build` | Reciprocal rank fusion over the three lists; drop cases older than `RAG_MAX_AGE_DAYS` unless they share a strong indicator; recency decay (half-life 180 days, floor 0.5); x1.2 for cases with a human decision. Strong exact matches always sort above text-similarity-only matches. |
| Generate | `investigation_service` | Prompt v3. Each case carries `retrieved_by`, `case_created_at`, `reliability`, the analyst decision and its date. The package has a `retrieval` block (mode, limitations). |
| Validate | `ai/response_parser.py` (unchanged) | Every citation must be a `(source_type, source_id)` in the package, else the output is rejected. |

Analyst decisions are used as evidence: a matched case's latest decision (and a truncated reviewer note) is supplied as data, labelled `analyst_decided`. Notes are untrusted text like everything else retrieved.

Threat intelligence is unchanged: CISA KEV and NVD are looked up per CVE in the alert and stored as `evidence_items`. They are **not** searched semantically (no KEV/NVD corpus is indexed).

## Safety properties

- **Tenant isolation:** every retrieval query filters `organization_id` (and joins re-check it on the alert row). Real and demo alerts never retrieve each other.
- **Untrusted content:** retrieved text is placed only inside the `EVIDENCE` block, with end markers neutralised; the system prompt says it is data, not instructions.
- **Data egress:** alert text is sent to NVIDIA only when `NVIDIA_API_KEY` is set **and** the organization has *External enrichment* enabled (the same switch that governs NVD/VirusTotal). Otherwise nothing is sent and retrieval is keyword + exact.
- **Failure handling:** no key, org not allowed, timeout, 401/429/5xx, malformed response, un-indexed corpus, or a failing SQL stage each degrade to the remaining stages. The reason is recorded in `retrieval.limitations`, shown to the model, and the model is told not to treat missing cases as evidence. Nothing is fabricated; citations still must resolve to stored rows.
- **Audit:** a `retrieval_completed` event stores mode, per-stage candidate counts and the number of cases supplied. It never stores alert text or vectors.
- **Read path:** `GET /alerts/{id}/related-incidents` makes no outbound call, so it shows exact + keyword only. The cases the model saw are the stored `evidence_items`.

## Setup

1. Set `NVIDIA_API_KEY` (see `backend/.env.example`). Enable *External enrichment* for the organization.
2. Migrate (automatic at start-up, or `alembic upgrade head`). Migration `0006` creates `alert_embeddings`; on PostgreSQL it also creates the GIN full-text index and, **if the server offers pgvector**, enables the extension and adds `embedding_vec vector(1024)` with an HNSW index. On Supabase the extension is available; the migration runs `CREATE EXTENSION IF NOT EXISTS vector`.
3. Embed existing alerts: `python -m app.cli embed-backfill <org-slug> [--limit 500]`. New alerts are embedded when they are first analysed; an alert is only searchable by *later* analyses after it has been embedded, so backfill matters.

## Limitations

- **SQLite has no vector index.** Local development uses a brute-force cosine scan over stored JSON vectors (fine for thousands, not for millions). Full-text on SQLite is a bounded Python scan, not an index. Production-scale semantic search needs PostgreSQL + pgvector.
- Changing `EMBEDDING_DIMENSIONS` needs a new migration (the column is `vector(1024)`) and a re-embed. Mixing models in one column is not supported; rows are keyed by model, and a different model finds nothing until re-embedded.
- No reranker. One should only be added if `eval/rag_eval.py` on real data shows a meaningful gain.
- Corpus freshness is manual (backfill) plus analysis-time indexing; there is no background indexer.
- Hosted NVIDIA API is a "Preview" under NVIDIA's API Trial Terms; pricing, rate limits and batch limits were **not** published in the docs consulted. The `input_type` values for text (`query`/`passage`) follow the OpenAI-compatible NIM convention and must be confirmed with a real key (see Evaluation).
- Case outcomes are only as good as past human decisions; a wrong past decision is retrieved as readily as a right one.

## Evaluation

`python -m eval.rag_eval` builds a throwaway SQLite database from a small **synthetic** labelled set (`eval/rag_dataset.py`: 32 family-labelled historical alerts, 5 noise alerts, 1 stale alert, a second tenant, 12 queries including a no-history query) and compares:

- `baseline` - the previous exact-indicator-only retrieval,
- `keyword_exact` - exact + keyword,
- `hybrid` - the shipped pipeline.

It reports precision@5, recall@5, MRR, hit rate, empty-result behaviour, tenant leakage, stale-case leakage, per-stage latency and embedding usage. `--stub` runs a local fake embedder: it validates plumbing only and **says nothing about NVIDIA model quality**. Citation validity and unsupported-conclusion rates require LLM calls and are measured separately (see the report that accompanied this change for what was and was not run).

The set is small and written by the implementer; treat results as a regression check, not a benchmark. Re-run it on a sample of your own labelled alerts before tuning `RAG_MIN_SIMILARITY` or deciding on a reranker.
