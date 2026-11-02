# Moraa — Delegating work to GLM (and the model-tier question)

> **Tier 2 — operator layer.** This doc describes *one* working setup, published as a
> reference rather than a requirement. Yours will differ; nothing in the methodology
> depends on it. See [CUSTOMIZATION.md](CUSTOMIZATION.md).

> Settled 2026-09-29 after a full audit of the agent + delegation wiring. This doc exists so the
> question stops being re-derived every session.

## The verdict: a subagent CANNOT run on GLM

This is architecture, not a missing config toggle.

- All six agents pin a **Claude-only** `model:` — `bughunter`, `chain-builder`, `cloud-offensive`,
  `pentest` = `opus`; `recon`, `validator` = `sonnet`. The agent frontmatter schema has **no**
  provider or baseURL field.
- The Agent tool's `model` parameter accepts only `fable | opus | sonnet | haiku`.
- **No router or proxy exists.** `ANTHROPIC_BASE_URL` and `ANTHROPIC_AUTH_TOKEN` appear in no
  settings file (`settings.json`, `settings.local.json`, `.claude.json`, `session-env/`, `state/`).
  There is no LiteLLM / claude-code-router remapping a Claude alias to a z.ai endpoint.

So `Agent(bughunter, model: "glm-...")` is rejected, and `Agent(bughunter, model: "opus")` always
reaches Anthropic. **Do not plan work that assumes a GLM-powered subagent.**

## What DOES work: shell-out delegation

The agent's own reasoning stays on Claude; only *labor* runs on GLM.

```bash
pi -p --provider zai --model glm-5.3-flash --thinking max "<task>"
```

Preferred entry point is the `pi-delegate` skill. Lane rationale: `glm-5.3-flash` has 1M context, is
reasoning-capable, and at $0.15/$0.50 per M tokens is ~9x cheaper than `glm-5.3`.

**The split that makes this safe:** Claude researches, verifies, judges and reviews; GLM drafts,
formats, refactors and bulk-processes. Delegate labor, never judgment. This applies to methodology
docs too, not just code.

**REVIEW GATE — non-negotiable.** Before accepting any GLM output, re-read it in full against the
original requirement: *does this serve the goal*, not *does it run*. Off-target, incomplete or noisy
goes back with what is wrong. Log the confirmation in the tracker.

Every task handed to GLM states the **exact requirement, the expected output shape, and acceptance
criteria** — GLM is much weaker at inferring an unstated contract.

## Lane status (audited 2026-09-29)

| Lane | State | Notes |
|---|---|---|
| **Pi -> zai** | **LIVE**, authenticated | Default provider `zai`, default model `glm-5.3`; 7 models cached. The primary lane. |
| ZCode -> zai | **DEAD** | `~/.zcode/cli/config.json` does not exist. Signing into the ZCode desktop app does **not** authenticate its CLI — it fails with `Model provider is missing an API key: zai`. Fix the config or stop routing here. |
| `~/.claude/glm/glm.py` | Fallback only | Hand-rolled stdlib client against `api.z.ai/api/anthropic`. `config.json` has an **empty** `api_key`; needs `GLM_API_KEY` exported. Superseded by the delegate skills. |

**There is no lane config file on disk** — neither `~/.config/delegate-skills/config.json` nor
`<git-root>/.delegate/config.json` exists. The fleet is prose/memory-driven, so `--lane` dials are
unavailable and **every delegate call must pass model and thinking flags explicitly.**

Flag note: `--thinking max` is Pi's own reasoning dial, not a fleet-lane `effort` dial —
`pi-delegate` exposes `provider, model, timeout, readOnly` only. `omp-delegate` is the one that maps
lane `effort` onto `--thinking` (`off|auto|low|medium|high|max`).

## Model tiering on the Claude side

Separate question, and the one you actually control. Mechanical/high-volume work (content and param
fuzzing, subdomain resolution, JS-bundle grepping, wordlist enumeration, dorking sweeps) runs fine on
`sonnet` — which is why `recon` and `validator` are pinned there. Reasoning-heavy work (business-logic
chains, authz methodology, chaining A->B, exploit construction, writing findings) stays on `opus`.
When orchestrating several agents on one target, split cheap recon/fuzz/validation from expensive
exploitation/chaining rather than running everything on the top tier.

## Addendum (2026-10-01): a shell-only agent CAN now run a Burp-backed hunt

The verdict above is unchanged and still true: **a subagent cannot BE a GLM model** — agent
frontmatter pins Claude-only models and there is no router/proxy; delegation stays shell-out.
What changed is narrower: the **Burp tool surface is no longer Claude-only**. `scripts/burp_bridge.py`
is a stdlib-only MCP client exposed as a CLI, so a shell-only delegated agent (pi/GLM, aider,
codex) can drive Repeater, Collaborator and the authenticated proxy history itself — `ping` first,
then `list` / `schema` / `call`. Usage, exit codes and the Collaborator/proxy-history traps:
[[burp-mcp]] § "Driving Burp from a shell-only agent". Hand the run a filled-in
`delegation-hunt-brief.md` — that template encodes the scope confirmation, the do-not-redo
pre-flight, the auth-state rules (a dead second account BLOCKS two-account IDOR, never faked) and
the closing output contract such a run must answer to.
