# Moraa — RAG / vector-store attacks (OWASP LLM08)

> Distinct from prompt injection (`offensive-ai-security` skill owns session-scoped indirect
> injection). This doc owns the **storage/retrieval layer itself** — bugs that need no injection
> payload at all because the flaw is in how embeddings are stored, scoped, and searched. Trigger:
> shared knowledge base, document-upload-feeds-chatbot feature, or a directly reachable vector-DB
> port (Chroma `:8000`, Weaviate `:8080`, Qdrant `:6333`, Milvus `:19530`, pgvector on Postgres).

## Technique 1 — persistent corpus poisoning (survives across sessions/users)
Proof bar is stronger than one-shot injection: the payload must reach a **different, clean
session** via **semantic retrieval on an unrelated query** — not just "my own document gets
summarized when I reopen it."
1. Upload a doc with on-topic filler (repeats the target topic's common query vocabulary so the
   chunk's embedding sits close to many real queries) + a hidden instruction (white-on-white text
   or metadata field).
2. Wait for ingestion, confirm indexed.
3. From a **second session/account**, ask a plain question about the common topic — not naming
   your document.
4. OOB callback fires or injected behavior appears in that second session = persistent poisoning.
   Only reproduces when you ask about your own doc = session-scoped, not this class.

## Technique 2 — cross-tenant vector-store IDOR
App-layer tenant checks (`tenant_id` gate in the chat API) often aren't enforced **in the vector
DB itself**:
```bash
curl -s http://T:8000/api/v1/heartbeat                # Chroma — reachability
curl -s http://T:6333/collections                       # Qdrant — lists ALL collections, no auth
curl -s -X POST http://T:8080/v1/graphql \
  -d '{"query":"{Get{Document(limit:5){content _additional{id}}}}"}'   # Weaviate, no tenant filter
```
200 + real content, zero creds = unauthenticated full corpus read, **Critical standalone**.
If the DB requires auth but the app's own API exposes a raw doc-ID or client-controlled
`namespace`/`tenant_id`: `GET /api/knowledge/document/00042` (try sibling IDs),
`POST /api/chat {"query":"...","namespace":"tenant-B"}`. Proof bar: response content must be
independently verifiable as belonging to a different real tenant — compare against your own
account's control query first.

## Technique 3 — source-text/metadata leakage (lowest effort, highest yield)
RAG implementations almost universally store the original chunk text as metadata next to the
vector. Any "similar results"/"sources used" block, or a leftover `/similar`/`/search`/
`/embeddings/query` debug endpoint, is exposing that raw text. Don't confuse this with true
embedding inversion (needs a trained decoder + query access to the embedding model — treat any
"I inverted the embedding" claim as Informational unless a working decoder is demonstrated).

## Technique 4 — retrieval hijack ("SEO poisoning" for RAG)
No gradient access needed: craft a chunk that repeats a topic's query vocabulary far more densely
than real content, confirm it out-competes genuine docs in top-k across 3+ differently-phrased
queries. Not a standalone finding — score by what the LLM does with the hijacked context
(misinformation, chained instruction per Technique 1, steer toward attacker link).

## False-positive gate
1. Second-session rule for poisoning claims — a re-ask by the uploading session doesn't count.
2. Verifiable cross-tenant artifact, checked against a same-account control (not "looks different").
3. Don't write a metadata leak up as "embedding inversion" — different remediation, different severity.
4. Retrieval-hijack alone is Medium at best — needs the downstream chain to go higher.

## Severity
| Finding | Severity |
|---|---|
| Unauthenticated vector-DB API, full corpus | Critical |
| Cross-tenant retrieval, verified artifact | High–Critical |
| Persistent poisoning reaching a second clean session | High–Critical (chain-dependent) |
| Source-text/metadata leak, own-tenant only | Low–Medium |
| Retrieval-hijack, no chain | Medium (Informational without one) |

## Bridge
`offensive-ai-security` skill (session-scoped prompt injection, base false-positive gate this
extends), `idor-access-control.md` (vector-store leak is IDOR at the retrieval layer, same
verifiable-artifact standard), `cloud.md` (managed vector-DB API keys leak via JS bundles same as
any other cloud key).
