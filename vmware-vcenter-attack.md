# Moraa — VMware vCenter / Workspace ONE / Aria external attack matrix

> Trigger: banner "VMware vCenter Server", `/ui`/`/ui/login`, `/websso/SAML2/Metadata`, `/sdk`,
> `/mob`, cert SAN `vcenter`/`vsphere`/`vcsa`, Workspace ONE `/SAAS/*`, Aria/vRealize
> `/vco`/`/lcm/api/v1`. **External/internet-exposed only** — internal-network vCenter reached via
> a foothold routes through `pivoting.md`/`active-directory.md` instead. Patching cycles for
> hypervisor management are slow; the 2021-era trifecta below still pays in 2026.

## Fingerprint
```bash
curl -sk "https://$T/sdk/vimServiceVersions.xml"
curl -sk "https://$T/ui/login" | grep -oE 'build[^"]{0,40}'
curl -sk "https://$T/api/appliance/system/version"          # vSphere 7+ REST
echo | openssl s_client -connect "$T:443" -servername "$T" 2>/dev/null | openssl x509 -noout -text | grep -A1 "Subject Alt"
```
Map build → version → VMSA advisory (support.broadcom.com/security-advisories).

## CVE matrix (pre-auth, network-reachable — cross-check CISA KEV before grading severity)
| CVE | Product | Vector | Status |
|---|---|---|---|
| CVE-2024-37085 | ESXi AD-joined | `ESX Admins` group auto-admin bypass, no join-time check | ransomware-favorite (Storm-0506/Black Basta) |
| CVE-2023-34048 | vCenter 7/8 | DCERPC pre-auth OOB write → RCE | exploited 2021-2023 as 0-day by UNC3886 |
| CVE-2023-20887 | Aria Ops for Networks | pre-auth Thrift cmd injection → root | KEV |
| CVE-2022-22954 | Workspace ONE Access | pre-auth FreeMarker SSTI → RCE | mass-exploited within 48h of disclosure |
| CVE-2022-22972 | Workspace ONE/Identity Mgr | Host-header auth bypass → admin session | CISA Emergency Directive 22-03 |
| CVE-2021-22005 | vCenter 6.7/7.0 | Analytics pre-auth file upload → RCE | KEV |
| CVE-2021-21985 | vCenter (vSAN plugin, on by default) | reflection+SSRF chain → RCE | KEV |
| CVE-2021-21972 | vCenter (vRealize plugin, bundled default) | `uploadova` pre-auth file upload → RCE | canonical, heavily scanned |
| CVE-2020-3992/CVE-2021-21974 | ESXi OpenSLP :427 | pre-auth UAF/heap overflow | ESXiArgs ransomware campaign (2023, 2yr post-patch) |

## Detection-only probes (do NOT execute file-upload/RCE PoCs without explicit sign-off)
```bash
# CVE-2021-21972 — 405 exists+vulnerable / 404 patched / 401 patched
curl -sk -o /dev/null -w "%{http_code}\n" "https://$T/ui/vropspluginui/rest/services/uploadova"

# CVE-2022-22954 — Stage A baseline only, no execution
curl -sk -o /tmp/wone_baseline.txt -w "%{http_code}\n" \
  "https://$T/catalog-portal/ui/oauth/verify?error=&deviceUdid=probe"
# Stage B (execution — sign-off required): unique canary, body-diff against Stage-A baseline,
# confirmed RCE only if $CANARY echoes back AND uid= output absent from baseline.
```

## SSO / vmdir enumeration
```bash
curl -sk "https://$T/websso/SAML2/Metadata/vsphere.local" | xmllint --format -
ldapsearch -x -H "ldap://$T:389" -b ""   -s base   # anon bind attempt if 389/636 exposed
```

## Managed Object Browser (MOB) — frequently leaks
```bash
curl -skI "https://$T/mob"    # 200 unauth = full vSphere tree browsable (VMs/hosts/datastores/sessions)
```

## Post-cred vSphere REST + datastore pull
```bash
curl -sk -X POST -u 'user@vsphere.local:<pw>' "https://$T/api/session"     # → session token
curl -sk -H "vmware-api-session-id: <token>" "https://$T/api/vcenter/vm"
curl -sk -H "vmware-api-session-id: <token>" "https://$T/folder?dsName=datastore1&dcPath=Datacenter"  # VMDK/snapshot pull — huge, often contains cloud-init creds
```

## Default creds (low lockout threshold — often 3 attempts → 60s-to-permanent lockout, ONE try only)
`administrator@vsphere.local` / set-at-install · `root`/`vmware` (legacy appliance) · Aria
`admin`/`vmware` (legacy). Use only breach-corpora creds, never blind guesses.

## Workspace ONE / Aria specific paths
```
/SAAS/auth/saml/response  /SAAS/jersey/manager/api/health  /catalog-portal/services/airwatch/identifiers
/suite-api/api/versions   /csp/gateway/am/api/about        /vco/api/about
```

## Severity guidance
Internet-exposed + current patch = Informational (attack-surface note). Internet-exposed +
missing patch with public RCE, or + default admin password = **Critical** (virtualization-plane
compromise, not app-level). MOB anonymously reachable = High. `/sdk` reachable, version only = Medium.

## Bridge
`enterprise-vpn-attack.md` (VPN breach → vCenter is the natural internal pivot, only if scope
permits going internal), `auth-oauth.md` § SAML (Workspace ONE/vCenter SSO SP metadata →
XSW/sig-stripping), `m365-entra-attack.md` (vCenter SSO sometimes federates to Entra).
