# Moraa — AWS deep-dive (privesc chains + per-service attack surface)

> Load once you're in AWS specifically and `cloud.md`'s overview isn't deep enough. Same safety
> rule: enumerate & prove, don't create/delete at scale; persistence techniques below are
> **describe-the-capability, do not execute against a live client estate**.

## 1. Full IAM shadow-admin vector table (beyond `cloud.md`'s core 8)

| Permission | Gives you |
|---|---|
| `iam:CreateLoginProfile` / `UpdateLoginProfile` | Set a console password on a user that has none (or reset one) → log into the AWS console as them |
| `iam:AddUserToGroup` | Add yourself to an admin group directly |
| `iam:SetDefaultPolicyVersion` | Revert a policy to an old, more-permissive version instead of authoring a new one |
| `iam:CreateVirtualMFADevice` + `EnableMFADevice` | Register your OWN virtual MFA on a user — bypasses `aws:MultiFactorAuthPresent` conditions gating sensitive actions; generate the 2 consecutive TOTP codes needed to enable it with `oathtool --base32 --totp <seed>` |
| `iam:UpdateAccessKey` | Reactivate a disabled access key you can see |
| `iam:CreateServiceSpecificCredential` | Mint CodeCommit git creds for a user — pivot into their repos (may contain more creds) |
| `iam:UploadSSHPublicKey` | Push your own SSH key onto a user → `git clone` their CodeCommit repos over SSH |
| `iam:DeactivateMFADevice` / `ResyncMFADevice` | Strip or desync a user's MFA, defeating MFA-conditioned policies |

```bash
enumerate-iam.py --access-key AKIA... --secret-key ...   # brute your own effective perms, no logging noise
```

## 2. Lambda privesc + persistence (have `iam:PassRole`+`lambda:*`, or code-update rights)

**Privesc** — beyond the basic PassRole+CreateFunction combo already in `cloud.md`:
- **Env-var RCE**: `lambda:UpdateFunctionConfiguration` to set a runtime-specific hijack var (Python `PYTHONSTARTUP` pointing at your code path baked into the deployment package, Node `NODE_OPTIONS=--require /path/evil.js`, Ruby `RUBYOPT`) — code runs on next invocation without touching the handler.
- **Layer injection**: publish a malicious Lambda layer whose init code runs on import, attach it to the target function — persistent across handler updates.
- **Function URL abuse**: `lambda:CreateFunctionUrlConfig` on a function you can already invoke turns it into a direct public HTTPS endpoint, bypassing API Gateway auth entirely if the function itself has none.
- **Network-isolated exfil**: if the target function runs in a VPC with no internet egress but holds a role with broad access, deploy your own throwaway function using the *same role* (via PassRole) that just calls `sts get-caller-identity`/reads a secret and writes it to a table/log you can read — bypasses the network isolation, not the IAM boundary.

**Persistence** (capability only — never execute live): layer backdoor (malicious code fires on every invocation via import), extension backdoor (Lambda Extensions API runs alongside the handler), **weighted-alias backdoor** (publish a backdoor version, alias 99% traffic to the clean version / 1% to the backdoor — stealthy, low detection rate), async self-recursive-invoke loop, EventBridge cron-triggered backdoor, execution-wrapper script (`AWS_LAMBDA_EXEC_WRAPPER` runs before the runtime starts), runtime-version pinning (stops an update from silently breaking a layer-based backdoor's compatibility).

## 3. EKS — the payout is usually IRSA, not the pod

```bash
aws eks list-clusters && aws eks update-kubeconfig --name <cluster>
kubectl auth can-i --list                                        # what can you already do
kubectl get sa -A -o yaml | grep -A2 "eks.amazonaws.com/role-arn" # find IRSA-annotated SAs
```
**IAM Roles for Service Accounts (IRSA) abuse** — the highest-value EKS bug: if you can create a
Pod/ServiceAccount in-namespace, annotate your own SA with a role ARN you've found (even one you
don't own) and see if the trust policy's `sub`/`aud` condition is scoped loosely enough (e.g. by
namespace only, not by exact SA name) to let you assume it:
```yaml
apiVersion: v1
kind: ServiceAccount
metadata: {name: sa, annotations: {eks.amazonaws.com/role-arn: arn:aws:iam::ACCT:role/ClusterAdmin}}
```
then run a pod with that `serviceAccountName` and `aws sts get-caller-identity` inside it.
Also: privileged-pod → node filesystem/kubelet-creds access (see `k8s.md`), Secrets dump
(`kubectl get secrets -A -o json`), node-to-node lateral movement across the cluster's flat VPC
network, cross-cluster movement if two EKS clusters share a VPC, and known VPC-CNI CVEs for
pod-to-host escape — check the installed CNI version against the CVE feed.

## 4. ECS — task role theft is the fast path

```bash
aws ecs list-clusters && aws ecs list-tasks --cluster C && aws ecs describe-tasks --cluster C --tasks T
aws ecs describe-task-definition --task-definition TD   # env vars + Secrets Manager/SSM ARN refs in plain sight
```
- **ECS Exec** (`ecs:ExecuteCommand`, if enabled or you can enable it): `aws ecs execute-command
  --cluster C --task T --container CT --interactive --command "/bin/sh"` = direct shell in the
  container, then read the task-role creds off the local metadata endpoint (`169.254.170.2` +
  `$AWS_CONTAINER_CREDENTIALS_RELATIVE_URI`, headerless).
- **Malicious task-definition registration** + `ecs:UpdateService` to swap the running service
  onto it, or a standalone `run-task` — runs your container with the task's IAM role attached.
- **ECR image injection**: if you can push to the referenced ECR repo, backdoor the image the
  task definition already points at instead of touching the task def.
- **VPC pivot**: tasks on the same VPC/subnet as internal-only services — port-scan from inside
  a task you control.
- **CloudWatch Logs mining**: `aws logs filter-log-events` across the task's log group for
  secrets accidentally logged (stack traces, debug env dumps).
- **Autoscaling cost-attack**: `application-autoscaling:RegisterScalableTarget` to blow out
  min/max task count — a billing-DoS angle worth naming in a report if the perm is unintentionally
  broad, not something to actually execute.

## 5. Cognito

- **Identity Pool credential harvesting**: authenticate to the User Pool → exchange the ID token
  for temporary AWS creds via the linked Identity Pool (`cognito-identity:GetCredentialsForIdentity`)
  — check what the **unauthenticated** role (if the pool allows guest access) can already do; it's
  frequently over-permissioned because devs assume "unauthenticated" means "low value."
- **Lambda trigger attack surface**: PreSignUp/PostAuthentication/PreTokenGeneration triggers run
  with attacker-influenced input at signup/login time — if you can reach or modify the trigger
  function, or if it trusts unvalidated custom attributes, that's an auth-bypass/priv-esc path.
- **Group-based privesc**: `cognito-idp:AdminAddUserToGroup` (if held) to add yourself to an
  admin-mapped group — group membership often maps directly to an IAM role via the Identity Pool's
  role-mapping rules.
- MFA: check `SMS_MFA` (SIM-swap/interception risk, not a direct bug) vs `SOFTWARE_TOKEN_MFA`
  before claiming an MFA weakness; a disabled MFA requirement on a pool with admin users is the
  actual finding, not "SMS exists."

## 6. API Gateway

- **Usage-plan self-add** (`apigateway:UpdateUsagePlan` + a key) bypasses rate limiting on a
  metered/paid API.
- **Lambda-backend pivot**: `GET /restapis/{id}/resources/{rid}/methods/{m}/integration` — an
  `AWS_PROXY` type integration's URI contains the full Lambda function ARN; attack that function
  directly (see §2) rather than the gateway.
- **Stage-variable leak**: `${stageVariables.x}` values often carry DB hosts/API keys used in
  integration URIs — dump them via `get-stage`.
- **Authorizer bypass**: try the protected route with **no** `Authorization` header at all first
  (misconfigured authorizers sometimes only fire on a non-empty header); for a Lambda authorizer,
  check whether its response is cached (`authorizerResultTtlInSeconds`) — a stale cached ALLOW for
  a since-revoked token is a real bypass window, not theoretical.
- **Hidden-resource discovery**: recursively walk `get-resources` — undocumented `/admin`, `/debug`,
  `/internal` paths often exist in the deployed API but not the public docs.

## 7. Secrets Manager / SSM Parameter Store / KMS

```bash
aws secretsmanager list-secrets --query 'SecretList[].Name'
for s in $(aws secretsmanager list-secrets --query 'SecretList[].Name' --output text); do
  aws secretsmanager get-secret-value --secret-id "$s" --query SecretString --output text; done
aws ssm get-parameters-by-path --path / --recursive --with-decryption --query 'Parameters[].{N:Name,V:Value}'
```
KMS: `kms:Encrypt`/`Decrypt` on a key you can reach = decrypt anything already encrypted under it;
`kms:CreateKey`/`ScheduleKeyDeletion` abuse is a destructive/DoS angle — describe, don't execute.

## 8. SNS / SQS

- **Cross-account topic/queue policy abuse**: a `Principal: "*"` or overly broad account condition
  in the resource policy is a direct cross-account read/publish primitive — check with
  `get-topic-attributes`/`get-queue-attributes` before assuming same-account-only.
- **Queue peek without dequeue**: `receive-message` without a matching `delete-message` doesn't
  remove it (just hides it for the visibility timeout) — safe to read without disrupting production
  processing, the right way to prove impact minimally.
- **Dead-letter-queue mining**: DLQ messages are the ones that *failed* processing — often contain
  full request payloads plus the error that reveals *why* (stack trace, validation detail = a
  free info-disclosure/logic-map for the app behind the queue).
- **Fanout injection**: SNS→Lambda or SNS→SQS→Lambda chains mean a forged message you can publish
  reaches application code exactly like a legitimate event — treat topic-publish rights as an
  injection primitive into whatever consumes the topic.

## 9. Metadata SSRF — nuances beyond `ssrf.md`'s core table

- **IMDSv2 IPv6 bypass**: the metadata service is also reachable over link-local IPv6 —
  `curl -g -6 "http://[fe80::1%25eth0]/latest/meta-data/"` — worth trying when an app's SSRF
  filter only blocks the IPv4 `169.254.169.254` literal.
  Also try the routable IMDSv2 IPv6 address `fd00:ec2::254` some platforms expose.
- **SSRF-with-header-control → IMDSv2 anyway**: if the SSRF lets you set arbitrary request
  headers (not just the URL), you can still do the `PUT .../api/token` dance server-side and
  chain the token into the `GET` — don't write off IMDSv2-hardened targets as unexploitable until
  you've confirmed the SSRF primitive truly can't set a header/method.
- **User-data mining**: `GET /latest/user-data` often contains startup scripts with hardcoded
  creds, internal hostnames, or config — always pull it, not just the IAM credential block.
- **SSH public-key index brute**: `/latest/meta-data/public-keys/` — enumerate indices for
  exposed SSH keys.
- **Network/service discovery via metadata**: `/latest/meta-data/network/interfaces/macs/*/` leaks
  VPC/subnet/security-group IDs — useful for mapping what else lives on the same network before
  you pivot.

## 10. Reference

Source depth for anything not distilled above lives in cain-agent (Apache-2.0,
github.com/cdxiaodong/cain-agent) `skills/aws-{iam-privesc,lambda-privesc,lambda-persistence,
eks,ecs,s3,cognito,api-gateway,secrets,sns,sqs,metadata-ssrf,cloudformation,apprunner,fargate,
rds,waf,persistence}-attack.md` — fetch the specific file when you're deep in one service and
need more than this distillation. Back to `cloud.md` for the multi-cloud overview and the other
five providers.
