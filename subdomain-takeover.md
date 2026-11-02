# Moraa — Subdomain takeover

> Load when recon (`recon.md`) turns up a CNAME/NS pointing at a third-party service. Severity is
> High-Critical when the claimed host inherits the parent's cookie scope, CSP allowlist, OAuth
> `redirect_uri` allowlist, SAML entity ID, or mail SPF/DKIM — that's where the real impact is,
> not the takeover itself.

## 1. Resolve every subdomain — CNAME first, then NS

```bash
while read -r sub; do
  cname=$(dig +short CNAME "$sub" | head -n1)
  [ -n "$cname" ] && printf '%s\tCNAME\t%s\n' "$sub" "$cname"
done < recon/subs.txt > recon/resolved.tsv

# NS delegation (rarer, far more dangerous — you get ALL records under the subdomain)
while read -r sub; do
  ns=$(dig +short NS "$sub")
  [ -n "$ns" ] && printf '%s\tNS\t%s\n' "$sub" "$(echo "$ns" | tr '\n' ',')"
done < recon/subs.txt >> recon/resolved.tsv

# cleanest signal: CNAME target itself doesn't resolve
awk -F'\t' '$2=="CNAME"{print $3}' recon/resolved.tsv | while read -r t; do
  dig +short "$t" >/dev/null 2>&1 || echo "$t (NXDOMAIN target)"
done
```

## 2. Match the HTTP fingerprint (don't trust the CNAME alone)

```bash
curl -sk -H "Host: lost.target.com" https://lost.target.com/ | grep -F "<fingerprint string>"
```

| Service | CNAME pattern | Fingerprint substring |
|---|---|---|
| GitHub Pages | `*.github.io` | `There isn't a GitHub Pages site here.` |
| Heroku | `*.herokuapp.com`, `*.herokudns.com` | `No such app` / `There's nothing here, yet.` |
| AWS S3 (website) | `*.s3-website-*.amazonaws.com`, `*.s3.amazonaws.com` | `NoSuchBucket` |
| Azure App Service | `*.azurewebsites.net` | `404 Web Site not found.` |
| Azure Storage/CDN | `*.blob.core.windows.net`, `*.azureedge.net` | NXDOMAIN / Bad Request |
| Netlify | `*.netlify.app` | `Not Found - Request ID` |
| Vercel | `*.vercel.app`, `cname.vercel-dns.com` | `404: NOT_FOUND` (edge-case: verify ownership first) |
| Shopify | `*.myshopify.com` | `Sorry, this shop is currently unavailable.` |
| Surge.sh | `*.surge.sh` | `project not found` |
| Ghost | `*.ghost.io` | `The thing you were looking for is no longer here` |
| Pantheon | `*.pantheonsite.io` | `The gods are wise, but do not know of the site which you seek.` |
| Bitbucket | `*.bitbucket.io` | `Repository not found` |
| Fastly | `*.fastly.net` | `Fastly error: unknown domain` (edge-case) |
| Google Cloud Storage | `*.storage.googleapis.com` | `NoSuchBucket` |
| Statuspage/Zendesk/Helpscout | various | vendor-specific 404 — check current fingerprint DB |

Full ~50-service fingerprint DB (with `http_status`/`edge-case` notes): `can-i-take-over-xyz`
project or `subjack`/`nuclei -tags takeover` template set — pull fresh, providers change pages.

## 3. Confirm before reporting (false-positive rate here is notorious)

The trap: unclaimed *to you* ≠ unclaimed period — the legit owner may hold it in an account you
can't see (paused Heroku app, suspended-not-deleted S3 bucket).

```
1. Attempt to register the resource (create a Heroku app/S3 bucket with the exact name the CNAME
   expects). "Name taken" with no fingerprint on the live site = false positive, someone has it.
2. On successful claim: serve ONE static, clearly-labelled proof page. Re-fetch the subdomain over
   HTTPS — your content must come back.
3. Screenshot + curl response into the report.
```

Never: serve a login form or anything phishing-shaped, run any script on the claimed page, hold
the resource past triage, or use a takeover to intercept real traffic "for research."

## 4. NS takeover (rare, much bigger blast radius)

A subdomain that delegates DNS to a third-party provider (`sub.target.com NS ns1.dnsmadeeasy.com`)
where the zone is unclaimed on that provider → you control **every record** under the subdomain,
not just one hostname.

```bash
for ns in $(dig +short NS sub.target.com); do dig @"$ns" sub.target.com SOA; done
```
`REFUSED`/`SERVFAIL` from every listed nameserver, on a provider that lets anyone create
arbitrary-named zones (DNSMadeEasy, EasyDNS, NS1 historically) = the takeover primitive.

## 5. Tooling shortcuts (automate §1-2, not required)

```bash
subjack -w recon/subs.txt -t 100 -timeout 30 -ssl -c fingerprints.json -v
nuclei -l recon/subs.txt -tags takeover
```

## 6. Severity & report

Impact is entirely about what the parent domain shares with the claimed host: session cookies
scoped to `*.target.com`? CSP `script-src` allowlists the vendor domain? OAuth `redirect_uri`
registered against it? Mail SPF/DKIM includes it? State exactly which of those apply — that's
what turns "I claimed an S3 bucket" into Critical vs. Low.

Include: vulnerable subdomain, DNS resolution path, provider + service, HTTP response with
fingerprint, the proof-page screenshot/curl, concrete shared-trust impact, remediation (delete
the dangling record or re-claim the resource). Release the claimed resource after triage.
