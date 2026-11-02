# Security, scope and responsible use

## What this project is

Methodology — documentation and triage tooling for **authorized** offensive security work. It
encodes how to look for a class of vulnerability, how to prove one, and how to tell a real finding
from a scanner artefact.

## What this project is not

- **Not an exploit kit.** There are no weaponised exploits, no RCE payloads aimed at named
  software, no botnet or C2 tooling, and no mass-targeting automation.
- **Not a scanner.** Nothing here crawls the internet looking for victims. The scripts are recon,
  parsing and triage helpers that act on a scope *you* supply.
- **Not a source of undisclosed vulnerabilities.** No unreported finding against any real system
  appears in this repository. See "Sanitization" below.

## Acceptable use

Use this only against:

- systems you own;
- systems you are contractually engaged to test, within the agreed rules of engagement;
- bug-bounty programs, within the published scope you have read, using your own test accounts;
- CTF, lab and training environments.

Unauthorized testing is illegal in most jurisdictions. The author accepts no liability for misuse.
If you are unsure whether you are authorized, you are not.

The methodology itself enforces some of this: `SKILL.md` requires scope confirmation before any
host is touched, and `engagements/_TEMPLATE/ENGAGEMENT.md` has an authorization note as a required
field, not an optional one.

## Sanitization

Many docs teach from a real measured case. Before publication, every host, domain, product name,
cookie name and identifier in those examples was replaced with a fictional placeholder
(`acme.example` and relatives — the README has the full mapping). The measurements and reasoning
are real; the names are not.

Specifically **not** in this repository:

- live engagement folders, credentials, cookies, tokens, session material or loot;
- any confirmed-but-unreported vulnerability against a real system;
- any real client, program or host name;
- anything that would let a reader identify a target from an example.

Secret-shaped strings in `tests/fixtures/` are deliberately non-functional: AWS's published
documentation key `AKIAIOSFODNN7EXAMPLE`, obvious `EXAMPLE` placeholders, and RFC 2606
(`.example`, `.invalid`) / RFC 5737 (`203.0.113.0/24`) reserved values. There are no live secrets
to find. If you believe you have found one, report it as below rather than opening a public issue.

## Reporting a problem with this repository

Found a leaked secret, a surviving client-identifying example, or anything else that should not be
public? Please **do not open a public issue.** Use GitHub's private vulnerability reporting on this
repo, or contact the maintainer directly, and allow a reasonable window for removal.

For a security problem in *another* product that you found while using this methodology: report it
to that vendor or program, not here. `reporting.md` covers how to write it up.
