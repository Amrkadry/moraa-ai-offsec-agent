# PoC discipline — why your "clean negative" is usually a broken harness

> Why this doc exists: the most expensive failure in this methodology is not a missed bug, it is a
> **false negative you believed**. A PoC that silently never ran, a fixture that was never created,
> a tool that died on startup, an OOB canary nobody polled — each produces the same output as a
> genuinely secure target: nothing. Every clean negative in `findings/CLEAN-*.md` is a claim that
> the control held, and that claim is only as good as the proof that your harness fires at all.
> This doc is the set of rules that stop a dead harness from being recorded as a secure target.
> Cross-ref [[controls-and-oracles]] (fire a control that must produce the opposite result),
> [[validate]] (where a verdict becomes durable), [[loadout]] (install-time smoke test),
> [[engagement-ceiling]] ("structurally blocked" vs "I did not look hard enough").

---

## 0. The rule: no negative without a positive control

**A test that has never produced a positive result has not been tested.** Before you record any
negative, make the same harness fire on something you *know* is vulnerable. If it cannot produce a
hit on a planted positive, its silence on the target means nothing.

```bash
# the pattern, for any detector you are about to trust
run_detector ./known_vulnerable_fixture   # MUST report a hit  -> harness is alive
run_detector ./known_clean_fixture        # MUST report nothing -> harness is not just echoing
run_detector "$TARGET"                    # only NOW is this result meaningful
```

Record the positive-control result in the verdict file. A `CLEAN-*.md` without one is an untested
assertion wearing a verdict's clothes.

---

## 1. A PoC that needs a fixture must create it

This is the single most common cause of a false negative in this library's own history. A PoC that
reads a file, a directory, a database or a config **must create that input itself**, every run, in
a temp location it owns. If the input is assumed to pre-exist:

- on your machine it exists (you made it once, by hand, weeks ago) and the PoC passes;
- on a clean checkout it does not, and the PoC errors — or worse, reports "no finding";
- you conclude the target is fine.

```python
# WRONG — assumes the directory exists; on a fresh clone this raises, or silently yields nothing
listfile = REPO / "fixtures" / "dns" / "hosts.txt"
listfile.write_text(payload)

# RIGHT — the test creates what it needs, and says so
listfile = REPO / "fixtures" / "dns" / "hosts.txt"
listfile.parent.mkdir(parents=True, exist_ok=True)   # a PoC that needs a fixture creates it
listfile.write_text(payload)
```

```bash
# prove it: delete every generated input and run from scratch. This is the only honest test.
git clean -xdn                 # review what is untracked/generated
rm -rf ./fixtures/generated/   # or whatever your harness writes
<run the whole suite>          # must still pass
```

If the suite only passes on *your* box, you do not have a PoC — you have a local ritual.

---

## 2. Prove with an artifact, not with stdout

`stdout` is the least reliable proof surface there is: it is swallowed by pipes, truncated by
tooling, buffered away on crash, and trivially faked by an `echo` left in a script. Make the PoC
write a **file** whose existence and content can only result from the vulnerability firing.

```bash
# weak: the only evidence is a line of text that anything could have printed
./poc.sh && echo "VULNERABLE"

# strong: the artifact IS the proof, and it is timestamped, sized and hashable
./poc.sh --out ./evidence/readfile.bin
test -s ./evidence/readfile.bin || { echo "PoC produced no artifact — treat as NO RESULT"; exit 2; }
sha256sum ./evidence/readfile.bin
head -c 200 ./evidence/readfile.bin        # content only the target could have supplied
```

Pick an artifact that is unforgeable by your own harness: file content read from the target, a
response body with a server-generated id, a row the target wrote. "Status code 200" is not an
artifact ([[validate]]).

---

## 3. Distinguish "no result" from "negative" — three exit states, not two

Most harnesses collapse failure into "no finding". Give yours three outcomes and make the middle
one loud:

| Exit | Meaning | What you may record |
|---|---|---|
| `0` | fired, control held | a **negative** — eligible for `CLEAN-*.md` |
| `1` | fired, found the issue | a **positive** — go to [[validate]] |
| `2` | **did not fire** (no artifact, tool missing, auth dead, timeout) | **nothing.** Re-run; never record. |

```bash
# make the harness refuse to be ambiguous
command -v ffuf >/dev/null || { echo "[!] ffuf missing — NO RESULT"; exit 2; }
test -n "${SESSION:-}"      || { echo "[!] no session — NO RESULT"; exit 2; }
# liveness: prove the session is actually authenticated before trusting any 401/403 below
code=$(curl -s -o /dev/null -w '%{http_code}' https://app.acme.example/api/me -H "Cookie: $SESSION")
[ "$code" = "200" ] || { echo "[!] session dead (/api/me -> $code) — NO RESULT"; exit 2; }
```

> A dead session turns every authorization test into a uniform 401/403 and reads exactly like a
> perfectly-fenced application. Re-validate the session **before and after** every authz sweep.

---

## 4. Assert readiness; never sleep and hope

`sleep 5` is a guess that silently becomes wrong on a slower box, a cold container or a throttled
network — and when it is wrong the PoC reports nothing. Poll for the condition instead, with a
bounded timeout and a non-zero exit when it never arrives.

```bash
# WRONG
docker run -d --name app acme/app:1.2.3 && sleep 5 && ./poc.sh

# RIGHT — wait for the actual readiness signal, fail loudly if it never comes
docker run -d --name app acme/app:1.2.3
for i in $(seq 1 60); do
  curl -fsS http://127.0.0.1:8080/healthz >/dev/null 2>&1 && break
  [ "$i" = 60 ] && { echo "[!] app never became ready — NO RESULT"; exit 2; }
  sleep 1
done
./poc.sh
```

The same applies to OOB: do not conclude "no interaction" until you have **polled** the collaborator
and seen your own positive control land ([[controls-and-oracles]]).

```bash
# plant a control interaction you KNOW should fire, then poll once for both
curl -s "http://control.<your-collab-id>.oastify.com/canary" -o /dev/null   # must appear
# ... fire the real probe ...
# then poll: control present + probe absent = real negative
#            control absent                 = your OOB channel is broken -> NO RESULT
```

---

## 5. Language and runtime traps that produce silent no-ops

| Trap | Symptom | Fix |
|---|---|---|
| ES module loaded as a script | "cannot use import outside a module", or nothing at all | `"type":"module"` in `package.json`, or a `.mjs` extension |
| Library resolves its server build in a test runner | browser-only sink never executes, PoC "passes" | `--conditions browser` (or the runner's equivalent) so the browser entrypoint loads |
| Python `-c` with an unescaped quote in a shell wrapper | the snippet silently truncates | write the script to a file and run it with `python3 -I <file>` |
| Interpreter picks up a planted module from CWD | your `json`/`os` import is the target's file | run with `python3 -I`, keep PoCs **outside** the extracted/untrusted directory |
| `set -e` absent | a failed step is skipped and the last command's `0` is reported as success | `set -euo pipefail` at the top of every PoC |
| CRLF line endings on a shell script | `bad interpreter: /bin/bash^M` | enforce `eol=lf` via `.gitattributes` |
| Shell glob eaten by the URL | `curl 'http://h/[a-z]'` never sends a request and looks like a WAF block | `curl -g`, or quote/encode the brackets |

---

## 6. Before you write `CLEAN-<slug>.md`

Answer all five in the verdict file. If you cannot, the result is **no result**:

1. **What positive control fired?** Name it and show its output.
2. **Was the identity live at the end?** Re-checked `/api/me` after the sweep, not before.
3. **Did the harness produce an artifact on the positive case?** Path, size, hash.
4. **Was every input created by the run?** Or did something pre-exist on your machine only?
5. **What would change this verdict?** The re-open condition — a new primitive, a second
   identity, a working session on another tier ([[engagement-ceiling]]).

> A clean negative is a real deliverable and worth writing down — it stops the next run re-treading
> closed ground. But it is a *claim about the target*, and an untested harness makes it a claim
> about your tooling instead. The five answers above are what make it the former.
