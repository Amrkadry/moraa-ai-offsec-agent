# Moraa — ReDoS (Regular Expression Denial of Service)

> HackTricks `regular-expression-denial-of-service-redos`. We have a CONFIRMED finding in this class
> (Werkzeug `ETags.from_header` — quadratic backtracking via `If-None-Match`, CWE-1333/400) —
> this doc formalizes that hunting method. Cross-ref [[rce-scenarios]] (DoS is the ceiling, not RCE).

## The vulnerable pattern (spot it by reading the regex, or by probing blind)
Catastrophic/quadratic backtracking comes from **ambiguous repetition** — a quantifier over a group
that itself can match the same characters multiple overlapping ways:
```
(a+)+$        (a*)*         (a|a)*        (a|aa)*        ([a-zA-Z]+)*    (\d+)+
```
Any user-controlled string parsed against a hand-rolled regex in a hot path (header parsing, input
validation, URL routing, template/markdown rendering, log-line matching) is a candidate.

## Where to look (the classes that keep shipping this)
- **HTTP header parsers** — `ETag`/`If-Match`/`If-None-Match`, `Range`, `Accept-Language`,
  content-type/charset parsing, cookie parsing — anywhere a header VALUE is validated with a regex
  before use (our Werkzeug finding: `If-None-Match` parsed by a quadratic ETag-list regex).
- **Input validators** — email/URL/phone/username "format" regexes on signup/profile forms.
- **Markdown/template renderers** — link/emphasis/autolink regexes.
- **Search/filter query parsers.**
- **Log processors / WAF rules** — ironically, WAF signature regexes are a classic ReDoS target too.

## Detect — blind timing probe, no source needed
Send inputs of increasing length built to trigger backtracking, watch response time scale
**exponentially/quadratically**, not linearly:
```bash
for n in 10 20 30 40; do
  payload=$(python3 -c "print('a'*$n + '!')")   # 'a'*n matches the greedy group, trailing char forces backtrack
  time curl -s -H "If-None-Match: \"$payload\"" https://target/ -o /dev/null
done
```
A linear parser: response time flat. A vulnerable quadratic/exponential regex: time roughly doubles
or worse per +10 chars — confirm with a clear before/after delta (our Werkzeug PoC: largest legitimate
response was milliseconds; the crafted payload pushed it to seconds, scaling predictably with length).

## Confirm safely (don't take down production)
- Start SMALL (n=10,20,30) and stop as soon as you see the scaling trend — you don't need to fully
  hang the server to prove it, a clear super-linear curve across 3-4 points is enough.
- Prefer testing against a local/staging instance of the SAME open-source component if the target is
  self-hosted OSS (Werkzeug, a specific npm/pip package) — reproduce the timing curve locally, then
  do ONE confirming request against the real target at a moderate size.
- Never sustain the attack (no repeated large payloads, no concurrent floods) — a single confirming
  request per size step is enough for the report.

## Source-available shortcut
If you have the source (self-hosted OSS, a leaked bundle, decompiled app), grep for hand-rolled regex
near header/input parsing and paste candidates into a backtracking checker (`safe-regex` npm,
`redos-detector`, or simply reason about nested quantifiers manually). This is how the Werkzeug bug
was found — read `ETags.from_header`, spotted the ambiguous group, then built the timing PoC to prove it live.

## Report
CWE-1333 (Inefficient Regular Expression Complexity) / CWE-400 (Uncontrolled Resource Consumption).
Show the timing table (payload size → response time) as the evidence — that IS the PoC for ReDoS, no
crash or 500 needed. Severity: Medium typically (single-request DoS of one worker/thread); High if it
can exhaust a small worker pool with few requests (state the math). Remediation: replace the regex
with a non-backtracking engine (RE2, or Rust `regex` crate) or rewrite to remove ambiguous nesting,
and add a length cap on the input before it reaches the regex.
