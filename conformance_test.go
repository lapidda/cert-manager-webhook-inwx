//go:build conformance

package main

import (
	"os"
	"testing"

	acmetest "github.com/cert-manager/cert-manager/test/acme"
)

// TestConformance runs cert-manager's DNS-01 conformance suite against a real
// INWX environment (use the OTE sandbox). It is behind a build tag because it
// needs credentials, network access and envtest binaries; see the README.
//
//	TEST_ZONE_NAME=example.com. go test -tags conformance -run TestConformance .
func TestConformance(t *testing.T) {
	zone := os.Getenv("TEST_ZONE_NAME")
	if zone == "" {
		t.Skip("TEST_ZONE_NAME not set")
	}
	opts := []acmetest.Option{
		acmetest.SetResolvedZone(zone),
		acmetest.SetManifestPath("testdata/inwx"),
		// The suite's "basic" test presents ONE value; "extended" presents two
		// values at the same name, which is the wildcard + apex case.
		acmetest.SetStrict(true),
	}
	if ns := os.Getenv("TEST_DNS_SERVER"); ns != "" {
		// e.g. the OTE name server, since OTE zones are not delegated publicly.
		opts = append(opts, acmetest.SetDNSServer(ns), acmetest.SetUseAuthoritative(false))
	}
	fixture := acmetest.NewFixture(&solver{}, opts...)
	fixture.RunConformance(t)
}
