// Command webhook is a cert-manager ACME DNS-01 webhook solver for INWX.
//
// cert-manager does not talk to this process directly. The binary is a tiny
// Kubernetes *aggregated API server*: the APIService v1alpha1.<GROUP_NAME>
// tells kube-apiserver to proxy requests for that API group to us, and
// cert-manager "creates" a ChallengePayload resource there. cmd.RunWebhookServer
// provides all of that plumbing; we only supply the Solver.
package main

import (
	"os"

	"github.com/cert-manager/cert-manager/pkg/acme/webhook/cmd"
)

func main() {
	// The group name is the API group of the APIService and the `groupName`
	// in the issuer's webhook solver block. It must be a domain you own so
	// it cannot collide with another webhook in the cluster.
	groupName := os.Getenv("GROUP_NAME")
	if groupName == "" {
		panic("GROUP_NAME must be specified")
	}
	cmd.RunWebhookServer(groupName, &solver{})
}
