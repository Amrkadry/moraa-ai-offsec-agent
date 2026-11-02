# Engagement — <TARGET>

> Copy this whole `_TEMPLATE` folder to `engagements/<target>/` and fill it in.
> Then tell Claude: "start engagement on <target>" (redhunt loads auth.json + this file).

## Authorization
- Authorized by: <name / ticket / program>
- Type: [ ] bug bounty  [ ] internal pentest  [ ] CPTS lab  [ ] CTF
- Window: <start> – <end>
- Rules of engagement / constraints: <no DoS, no social eng, rate limits, prod vs staging…>

## Scope
- In scope: (also mirror into auth.json "scope")
  - <*.target.com>
  - <10.10.10.0/24>
- Out of scope:
  - <...>

## Target intel
- Tech stack / known assets:
- Crown jewels (what causes most damage if compromised):
  1.
  2.
- Provided creds / starting point: see auth.json
- Notes / docs dropped in: docs/

## Goals
- [ ] <e.g. reach Domain Admin>
- [ ] <e.g. find IDOR in orders API>
- [ ] Report deliverable

## Folder map
findings/  coverage.md  recon/  loot/  pivot/  report/  docs/  auth.json
