package input

import (
	"encoding/base64"
	"fmt"

	"github.com/openpaily/paily-fetch/node"

	"github.com/enfein/mieru/v3/pkg/appctl"
	pb "github.com/enfein/mieru/v3/pkg/appctl/appctlpb"
	"google.golang.org/protobuf/proto"
)

// parseMieru parses a mieru:// link containing a base64-encoded full ClientConfig protobuf.
// A single link may describe multiple profiles and servers; each server produces one ProxyNode.
func parseMieru(link string) ([]*node.ProxyNode, error) {
	config, err := appctl.URLToClientConfig(link)
	if err != nil {
		return nil, fmt.Errorf("mieru URLToClientConfig failed: %w", err)
	}
	return mieruConfigToNodes(config)
}

// parseMierus parses a mierus:// link (human-readable, single-server format).
func parseMierus(link string) ([]*node.ProxyNode, error) {
	profile, err := appctl.URLToClientProfile(link)
	if err != nil {
		return nil, fmt.Errorf("mierus URLToClientProfile failed: %w", err)
	}
	return mieruProfileToNodes(profile)
}

// mieruConfigToNodes converts a ClientConfig to ProxyNodes (one per profile+server combo).
func mieruConfigToNodes(config *pb.ClientConfig) ([]*node.ProxyNode, error) {
	var nodes []*node.ProxyNode
	for _, profile := range config.GetProfiles() {
		ns, _ := mieruProfileToNodes(profile)
		nodes = append(nodes, ns...)
	}
	return nodes, nil
}

// mieruProfileToNodes converts a ClientProfile to ProxyNodes (one per server).
func mieruProfileToNodes(profile *pb.ClientProfile) ([]*node.ProxyNode, error) {
	profileName := profile.GetProfileName()
	userName := profile.GetUser().GetName()
	password := profile.GetUser().GetPassword()

	var nodes []*node.ProxyNode
	for _, server := range profile.GetServers() {
		host := server.GetDomainName()
		if host == "" {
			host = server.GetIpAddress()
		}
		if host == "" {
			continue
		}

		bindings := server.GetPortBindings()
		if len(bindings) == 0 {
			continue
		}

		clash := map[string]any{
			"type":     "mieru",
			"name":     profileName,
			"server":   host,
			"username": userName,
			"password": password,
		}

		// Transport from first binding.
		clash["transport"] = bindings[0].GetProtocol().String()

		// Port or port-range from the first binding.
		b := bindings[0]
		if b.GetPortRange() != "" {
			clash["port-range"] = b.GetPortRange()
			clash["port"] = 0 // port is omitempty in MieruOption; 0 is a safe placeholder
		} else if p := b.GetPort(); p > 0 {
			clash["port"] = int(p)
		} else {
			continue // no usable port info
		}

		// Multiplexing
		if level := profile.GetMultiplexing().GetLevel(); level != pb.MultiplexingLevel_MULTIPLEXING_DEFAULT {
			clash["multiplexing"] = level.String()
		}

		// Handshake mode
		if mode := profile.GetHandshakeMode(); mode != pb.HandshakeMode_HANDSHAKE_DEFAULT {
		}

		// Traffic pattern (optional, marshal back to base64)
		if tp := profile.GetTrafficPattern(); tp != nil {
			if rawBytes, err := proto.Marshal(tp); err == nil {
				clash["traffic-pattern"] = base64.StdEncoding.EncodeToString(rawBytes)
			}
		}

		n, err := node.New(clash)
		if err != nil {
			continue
		}
		nodes = append(nodes, n)
	}
	return nodes, nil
}
