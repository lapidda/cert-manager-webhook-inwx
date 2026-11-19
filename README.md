# cert-manager-webhook-inwx

A [cert-manager](https://cert-manager.io) ACME **DNS-01 webhook solver for INWX**.
It lets cert-manager prove control of a domain hosted at INWX by creating the
`_acme-challenge` TXT record through the INWX DomRobot JSON-RPC API, which is
what you need for wildcard certificates such as `*.lab.p5y.de`.

- Solver name `inwx`, API group `acme.p5y.de`
- Built against cert-manager v1.21 / Kubernetes 1.36 libraries
- Image: `ghcr.io/lapidda/cert-manager-webhook-inwx`

## How it works

```
cert-manager controller
   │  POST ChallengePayload  (apis/acme.p5y.de/v1alpha1/inwx)
   ▼
kube-apiserver ── APIService v1alpha1.acme.p5y.de ──► Service inwx-webhook:443
                                                         │
                                                         ▼
                                              webhook pod (:8443, this repo)
                                               1. GET Secret inwx-credentials
                                               2. account.login (+ account.unlock)
                                               3. nameserver.info / createRecord / deleteRecord
                                               4. account.logout
                                                         │ HTTPS
                                                         ▼
                                                 api.domrobot.com
```

A cert-manager "webhook" solver is not an HTTP callback but a small
**aggregated API server**. cert-manager never calls the pod; it creates a
resource in the API group `acme.p5y.de`, and kube-apiserver proxies that to
the pod. The benefit is that authentication and authorization are plain
Kubernetes RBAC: only a subject allowed to `create` in `acme.p5y.de` can make
the webhook touch DNS, and that is bound to the cert-manager controller alone.

| File | Role |
|---|---|
| `main.go` | starts cert-manager's webhook server with our solver |
| `solver.go` | `Present` / `CleanUp`: config, Secret lookup, zone search, idempotency |
| `inwx/` | minimal INWX client (`client.go`), tolerant record id (`id.go`), TOTP (`totp.go`) |
| `internal/inwxtest/` | in-memory fake INWX API used by the tests |
| `deploy/` | kustomize manifests |
| `examples/` | ClusterIssuer and Secret templates |

## Design choices

**Why our own webhook.** cert-manager has no in-tree INWX solver. The
community webhook has been archived since 2022 and its fork fails in cleanup
with `record[0].id expected int, got string`, because INWX changed record ids
from JSON numbers to strings. The alternatives were delegating
`_acme-challenge` by CNAME to another DNS provider (a second provider and
account to operate) or certbot on the host (outside GitOps, and the
certificate would have to be copied into the cluster). A DNS-01 solver is
about 300 lines, so owning it is cheaper than carrying a dead dependency.

**Own INWX client instead of a library.** We need six API methods. A client
of ~200 lines has no transitive dependencies and lets us be lenient exactly
where the API has moved:

- *Record ids are opaque.* `inwx.ID` stores the raw JSON token (number or
  string) and sends the same token back to `nameserver.deleteRecord`. We never
  convert it, so a further type change cannot break us.
- *Only needed fields are decoded.* `ttl`, `prio`, `count` and friends are
  ignored, so their types do not matter either.
- *Record names are matched client-side.* The API docs do not say whether
  `nameserver.info` returns names relative or fully qualified; both forms are
  normalised before comparing.

**Zone lookup.** cert-manager passes a `ResolvedZone` from a public SOA
lookup. We try it first and, if INWX has no such zone (code 2303), walk up
from the challenge FQDN label by label. One `nameserver.info` call per
candidate both confirms the zone and returns its TXT records.

**Per-value create and delete.** A certificate for `lab.p5y.de` and
`*.lab.p5y.de` produces two challenges with the *same* record name and
different values. `Present` therefore treats "exists" as name **and** value,
and `CleanUp` deletes only the record with this challenge's value. Both are
idempotent: presenting twice creates one record; cleaning up a missing record
succeeds.

**Login per operation.** Each `Present`/`CleanUp` logs in, works and logs
out. That costs two extra round trips but removes all session state: nothing
to expire, refresh or share between goroutines. Operations are serialised by
a mutex, which is ample for a home lab and avoids two logins using the same
TOTP code within one 30-second window.

**No metrics endpoint.** The only HTTP surface is the authenticated API
server port. Health is visible through the probes, the APIService condition
`Available` and cert-manager's own challenge metrics, so there is no
ServiceMonitor.

## Security trade-offs

- **The cluster holds a credential that can edit DNS.** That is inherent to
  DNS-01. INWX has no per-record API tokens, so reduce the blast radius with
  a **separate INWX sub-account that only has the DNS role**, not your main
  login. With such a user a leak allows DNS changes in the account, but not
  domain transfers, contact changes or billing.
- **2FA.** If the API user has 2FA, the TOTP *shared secret* must be stored
  next to the password, which defeats the second factor for whoever can read
  the Secret. A DNS-only user without 2FA and with a long random password is
  the cleaner setup; keep 2FA on the main account.
- **Least privilege in the cluster.** The webhook's ServiceAccount may `get`
  exactly one Secret (`cert-manager/inwx-credentials`). It cannot list
  Secrets or read any other.
- **No endpoint in the config.** The solver config has `sandbox: true|false`
  but no URL field, so someone who can create an Issuer cannot redirect the
  login to a host of their choice.
- **Nothing sensitive is logged.** Errors never include request parameters;
  tests assert that the password and TOTP secret do not appear in errors.
- **Container hardening.** Static binary on distroless `nonroot`, read-only
  root filesystem, all capabilities dropped, seccomp `RuntimeDefault`,
  NetworkPolicies limiting egress to DNS, the Kubernetes API and public
  HTTPS.
- **Residual risks.** The INWX egress rule is "any public IP on 443" because
  NetworkPolicy cannot match host names. Anyone who can create Issuers in a
  namespace that contains a Secret readable by the webhook could use it;
  here only `cert-manager/inwx-credentials` is readable.

## Configuration

Solver block of an `Issuer` / `ClusterIssuer` (full example in
[`examples/clusterissuer.yaml`](examples/clusterissuer.yaml)):

```yaml
dns01:
  webhook:
    groupName: acme.p5y.de
    solverName: inwx
    config:
      ttl: 300                 # optional, default and minimum 300
      sandbox: false           # optional, true = INWX OTE (api.ote.domrobot.com)
      usernameSecretRef: { name: inwx-credentials, key: username }
      passwordSecretRef: { name: inwx-credentials, key: password }
      # totpSecretRef:   { name: inwx-credentials, key: totp-secret }  # only with 2FA
```

The Secret is read from the issuer's namespace; for a `ClusterIssuer` that is
cert-manager's cluster resource namespace (`cert-manager`). Template:
[`examples/secret.yaml`](examples/secret.yaml). If you rename the Secret,
change `resourceNames` in `deploy/rbac.yaml` too.

## Deploy

```bash
kubectl kustomize deploy          # render
kubectl apply -k deploy           # or reference deploy/ from Flux
```

`deploy/` assumes cert-manager runs in namespace `cert-manager` with a
controller ServiceAccount named `cert-manager`, the Kubernetes API at
`10.43.0.1:443` / `192.168.178.75:6443` (k3s on BigSRV) and CoreDNS labelled
`k8s-app=kube-dns`. Adjust `rbac.yaml` and `networkpolicy.yaml` elsewhere.

After rollout:

```bash
kubectl get apiservice v1alpha1.acme.p5y.de     # AVAILABLE must be True
kubectl -n cert-manager logs deploy/inwx-webhook
```

Always try a new issuer against Let's Encrypt **staging** first.

## Testing

**Unit tests** need nothing but Go. They run the real solver against an
in-memory fake INWX API (`internal/inwxtest`) and a fake Kubernetes client:

```bash
go test -race ./...
```

Covered: ids as numbers and as strings, relative and fully qualified record
names, several TXT values at one name, cleanup of a missing record, zone
walk-up, 2FA unlock (incl. RFC 6238 vectors), config errors, no credential
leaks in errors, sessions always logged out.

**Conformance suite.** cert-manager ships a DNS-01 conformance test
(`test/acme`) that drives a real solver and checks the records through DNS.
Run it against the INWX **OTE** sandbox, never the live account:

1. Register at <https://ote.inwx.de> and create a domain with a DNS zone there.
2. `cp testdata/inwx/secret.yaml.example testdata/inwx/secret.yaml` and put
   the OTE credentials in (the file is git-ignored).
3. Install envtest binaries (the suite starts a local kube-apiserver + etcd)
   and run, on Linux or macOS:

```bash
go run sigs.k8s.io/controller-runtime/tools/setup-envtest@latest use -p env   # prints KUBEBUILDER_ASSETS=...
export TEST_ZONE_NAME=your-ote-domain.com.
export TEST_DNS_SERVER=ns.ote.inwx.de:53    # OTE zones are not delegated publicly
go test -tags conformance -run TestConformance -v .
```

`TEST_DNS_SERVER` is the name server the suite queries to see the record;
check in the OTE web UI which name servers your test zone uses.

## Rotating credentials

1. In INWX, set a new password for the API user (or create a new sub-account
   with the DNS role).
2. Update the Secret `cert-manager/inwx-credentials` (in a GitOps repo: edit
   the sops-encrypted file and push).
3. Nothing to restart: the webhook reads the Secret on every challenge.
4. Verify with a throw-away `Certificate` against the staging issuer, then
   delete the old INWX user if you created a new one.

If the TOTP secret changes (2FA reset), update the `totp-secret` key the same
way.

## Releasing

Pushing a tag `vX.Y.Z` makes GitHub Actions run the tests, build the image
and push it to GHCR; the job summary shows the digest. Reference the image
as `ghcr.io/lapidda/cert-manager-webhook-inwx:vX.Y.Z@sha256:...` in
`deploy/deployment.yaml`: the tag is for humans, the digest is what the
kubelet pulls and cannot be moved.
