package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/cert-manager/cert-manager/pkg/acme/webhook/apis/acme/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/klog/v2"

	"github.com/lapidda/cert-manager-webhook-inwx/inwx"
)

const (
	solverName = "inwx"

	defaultTTL = 300 // also the minimum INWX accepts
	opTimeout  = 90 * time.Second
)

// secretRef points at one key of a Secret. The Secret is always read from
// the challenge's resource namespace: the Issuer's namespace, or for a
// ClusterIssuer cert-manager's "cluster resource namespace" (cert-manager).
type secretRef struct {
	Name string `json:"name"`
	Key  string `json:"key"`
}

// config is the `config:` block of the webhook solver in an (Cluster)Issuer.
// It deliberately has no endpoint field: whoever may create an Issuer must
// not be able to make the webhook send the credentials to a host they choose.
type config struct {
	TTL               int        `json:"ttl,omitempty"`
	Sandbox           bool       `json:"sandbox,omitempty"`
	UsernameSecretRef secretRef  `json:"usernameSecretRef"`
	PasswordSecretRef secretRef  `json:"passwordSecretRef"`
	TOTPSecretRef     *secretRef `json:"totpSecretRef,omitempty"`
}

func loadConfig(ch *v1alpha1.ChallengeRequest) (config, error) {
	cfg := config{TTL: defaultTTL}
	if ch.Config == nil {
		return cfg, errors.New("solver config is missing")
	}
	if err := json.Unmarshal(ch.Config.Raw, &cfg); err != nil {
		return cfg, fmt.Errorf("decode solver config: %w", err)
	}
	if cfg.TTL < defaultTTL {
		return cfg, fmt.Errorf("ttl must be at least %d", defaultTTL)
	}
	for field, ref := range map[string]secretRef{
		"usernameSecretRef": cfg.UsernameSecretRef,
		"passwordSecretRef": cfg.PasswordSecretRef,
	} {
		if ref.Name == "" || ref.Key == "" {
			return cfg, fmt.Errorf("%s needs both name and key", field)
		}
	}
	if r := cfg.TOTPSecretRef; r != nil && (r.Name == "" || r.Key == "") {
		return cfg, errors.New("totpSecretRef needs both name and key")
	}
	return cfg, nil
}

type solver struct {
	kube kubernetes.Interface

	// mu serialises operations. cert-manager presents the wildcard and the
	// apex challenge of one certificate concurrently; with 2FA both logins
	// would use the same TOTP code inside one 30 s window. One at a time is
	// plenty for a home lab and keeps the session handling trivial.
	mu sync.Mutex

	// Test seams. Zero values mean production behaviour.
	endpoint string           // overrides the INWX endpoint
	now      func() time.Time // clock for TOTP
}

func (s *solver) Name() string { return solverName }

func (s *solver) Initialize(kubeClientConfig *rest.Config, _ <-chan struct{}) error {
	cl, err := kubernetes.NewForConfig(kubeClientConfig)
	if err != nil {
		return fmt.Errorf("create kubernetes client: %w", err)
	}
	s.kube = cl
	return nil
}

// Present creates the TXT record for this challenge. cert-manager retries on
// error and may call it again after success, so it must be idempotent.
func (s *solver) Present(ch *v1alpha1.ChallengeRequest) error {
	return s.withSession(ch, func(ctx context.Context, c *inwx.Client, cfg config) error {
		zone, records, err := findZone(ctx, c, ch)
		if err != nil {
			return err
		}
		fqdn := canonical(ch.ResolvedFQDN, zone)
		for _, r := range records {
			// Several TXT values can live at this name (wildcard + apex share
			// _acme-challenge.<domain>), so "exists" means name AND value.
			if canonical(r.Name, zone) == fqdn && r.Content == ch.Key {
				klog.InfoS("TXT record already present", "fqdn", fqdn, "zone", zone, "id", r.ID.String())
				return nil
			}
		}
		id, err := c.CreateTXT(ctx, zone, relativeName(fqdn, zone), ch.Key, cfg.TTL)
		if inwx.IsExists(err) {
			klog.InfoS("TXT record already present", "fqdn", fqdn, "zone", zone)
			return nil
		}
		if err != nil {
			return err
		}
		klog.InfoS("created TXT record", "fqdn", fqdn, "zone", zone, "id", id.String())
		return nil
	})
}

// CleanUp deletes only the TXT record carrying this challenge's key. A record
// that is already gone is success, not an error.
func (s *solver) CleanUp(ch *v1alpha1.ChallengeRequest) error {
	return s.withSession(ch, func(ctx context.Context, c *inwx.Client, _ config) error {
		zone, records, err := findZone(ctx, c, ch)
		if err != nil {
			return err
		}
		fqdn := canonical(ch.ResolvedFQDN, zone)
		deleted := 0
		for _, r := range records {
			if canonical(r.Name, zone) != fqdn || r.Content != ch.Key {
				continue
			}
			if err := c.DeleteRecord(ctx, r.ID); err != nil && !inwx.IsNotFound(err) {
				return err
			}
			deleted++
			klog.InfoS("deleted TXT record", "fqdn", fqdn, "zone", zone, "id", r.ID.String())
		}
		if deleted == 0 {
			klog.InfoS("no TXT record to clean up", "fqdn", fqdn, "zone", zone)
		}
		return nil
	})
}

// withSession loads config and credentials, logs in, runs fn and logs out.
// One login per operation costs two extra round trips but means there is no
// session state to expire, refresh or leak between challenges.
func (s *solver) withSession(ch *v1alpha1.ChallengeRequest, fn func(context.Context, *inwx.Client, config) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), opTimeout)
	defer cancel()

	cfg, err := loadConfig(ch)
	if err != nil {
		return err
	}
	user, err := s.secretValue(ctx, ch.ResourceNamespace, cfg.UsernameSecretRef)
	if err != nil {
		return err
	}
	pass, err := s.secretValue(ctx, ch.ResourceNamespace, cfg.PasswordSecretRef)
	if err != nil {
		return err
	}
	var totp func() (string, error)
	if cfg.TOTPSecretRef != nil {
		shared, err := s.secretValue(ctx, ch.ResourceNamespace, *cfg.TOTPSecretRef)
		if err != nil {
			return err
		}
		now := s.now
		if now == nil {
			now = time.Now
		}
		totp = func() (string, error) { return inwx.TOTP(shared, now()) }
	}

	endpoint := inwx.LiveEndpoint
	if cfg.Sandbox {
		endpoint = inwx.OTEEndpoint
	}
	if s.endpoint != "" {
		endpoint = s.endpoint
	}

	c := inwx.New(endpoint)
	if err := c.Login(ctx, user, pass, totp); err != nil {
		return err
	}
	defer func() {
		// Own short context: log out even if the operation used up its time.
		lctx, lcancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer lcancel()
		if err := c.Logout(lctx); err != nil {
			klog.ErrorS(err, "INWX logout failed")
		}
	}()
	return fn(ctx, c, cfg)
}

// secretValue reads one key of a Secret. Error messages name the Secret and
// key but never contain the value.
func (s *solver) secretValue(ctx context.Context, namespace string, ref secretRef) (string, error) {
	if s.kube == nil {
		return "", errors.New("solver is not initialized")
	}
	sec, err := s.kube.CoreV1().Secrets(namespace).Get(ctx, ref.Name, metav1.GetOptions{})
	if err != nil {
		return "", fmt.Errorf("read secret %s/%s: %w", namespace, ref.Name, err)
	}
	v, ok := sec.Data[ref.Key]
	if !ok || len(v) == 0 {
		return "", fmt.Errorf("secret %s/%s has no key %q", namespace, ref.Name, ref.Key)
	}
	// A trailing newline from `echo` or an editor is the classic way to break a login.
	return strings.Trim(string(v), "\r\n"), nil
}

// findZone returns the INWX zone that holds the challenge name, plus that
// zone's TXT records (the same API call answers both questions).
//
// cert-manager's ResolvedZone comes from a public SOA lookup and is tried
// first. If INWX does not know it (e.g. split DNS, or a CNAME on the way),
// we walk up from the FQDN label by label.
func findZone(ctx context.Context, c *inwx.Client, ch *v1alpha1.ChallengeRequest) (string, []inwx.Record, error) {
	candidates := zoneCandidates(ch.ResolvedZone, ch.ResolvedFQDN)
	for _, zone := range candidates {
		records, err := c.TXTRecords(ctx, zone)
		if inwx.IsNotFound(err) {
			continue
		}
		if err != nil {
			return "", nil, err
		}
		return zone, records, nil
	}
	return "", nil, fmt.Errorf("no INWX zone found for %q (tried %s)", ch.ResolvedFQDN, strings.Join(candidates, ", "))
}

func zoneCandidates(resolvedZone, fqdn string) []string {
	var out []string
	seen := map[string]bool{}
	add := func(z string) {
		if z != "" && !seen[z] {
			seen[z] = true
			out = append(out, z)
		}
	}
	add(normalize(resolvedZone))
	labels := strings.Split(normalize(fqdn), ".")
	for i := 0; i+2 <= len(labels); i++ { // stop before the bare TLD
		add(strings.Join(labels[i:], "."))
	}
	return out
}

func normalize(name string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), "."))
}

// canonical turns a record name into a lower-case FQDN without trailing dot,
// whether the API reported it relative to the zone or fully qualified.
func canonical(name, zone string) string {
	n := normalize(name)
	switch {
	case n == "" || n == "@":
		return zone
	case n == zone || strings.HasSuffix(n, "."+zone):
		return n
	default:
		return n + "." + zone
	}
}

// relativeName is the inverse: the name relative to the zone, "" for the apex.
func relativeName(fqdn, zone string) string {
	if fqdn == zone {
		return ""
	}
	return strings.TrimSuffix(fqdn, "."+zone)
}
