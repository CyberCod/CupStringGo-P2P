// -----------------BEGIN FILE-------------p2p_host.go
package main

import (
	"errors"
	"fmt"
	"log"

	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/multiformats/go-multiaddr"
)

func NewHost(config *Config) (host.Host, string, error) {
	// Define static relays (IPFS bootstrap nodes that support circuit relay)
	staticRelayAddrs := []string{
		"/dnsaddr/bootstrap.libp2p.io/p2p/QmNnooDu7bfjPFoTZYxMNLWUQJyrVwtbZg5gBMjTezGAJN",
		"/dnsaddr/bootstrap.libp2p.io/p2p/QmQCU2EcMqAqQPR2i9bChDtGNJchTbq5TbXJJ16u19uLTa",
		"/dnsaddr/bootstrap.libp2p.io/p2p/QmbLHAnMoJPWSCR5Zhtx6BHJX9KiKNN6tpvbUcqanj75Nb",
		"/dnsaddr/bootstrap.libp2p.io/p2p/QmcZf59bWwK5XFi76CZX8cbJ4BhTzzA3gU1ZjYZcYW3dwt",
		"/ip4/104.131.131.82/tcp/4001/p2p/QmaCpDMGvV2BGHeYERUEnRQAwe3N8SzbUtfsmvsqQLuvuJ",
	}

	var staticRelays []peer.AddrInfo
	for _, addrStr := range staticRelayAddrs {
		ma, err := multiaddr.NewMultiaddr(addrStr)
		if err != nil {
			log.Printf("Invalid relay multiaddr %s: %v", addrStr, err)
			continue
		}
		pi, err := peer.AddrInfoFromP2pAddr(ma)
		if err != nil {
			log.Printf("Invalid relay peer info from %s: %v", addrStr, err)
			continue
		}
		staticRelays = append(staticRelays, *pi)
	}

	if len(staticRelays) == 0 {
		return nil, "", errors.New("no valid static relays available")
	}

	h, err := libp2p.New(
		libp2p.ListenAddrStrings(fmt.Sprintf("/ip4/0.0.0.0/tcp/%d", config.LocalPort)),
		libp2p.EnableNATService(),
		libp2p.EnableRelay(),
		libp2p.EnableHolePunching(),
		libp2p.ForceReachabilityPublic(), // Assume we're publicly reachable via UPnP
		libp2p.EnableAutoRelayWithStaticRelays(staticRelays),
	)
	if err != nil {
		return nil, "", err
	}

	h.SetStreamHandler("/sync/1.0.0", func(s network.Stream) {
		TimestampLog(fmt.Sprintf("Incoming sync stream from %s", s.Conn().RemotePeer()))
		HandleSyncStream(s, config, true, h) // true for manager (sender)
	})

	addrs := h.Addrs()
	if len(addrs) == 0 {
		h.Close()
		return nil, "", errors.New("no listen addrs")
	}
	addr := fmt.Sprintf("/ip4/%s/tcp/%d/p2p/%s", config.ExternalIP, config.LocalPort, h.ID().String())
	TimestampLog(fmt.Sprintf("P2P host started: %s", addr))
	return h, addr, nil
}

// -----------------END OF FILE-------------p2p_host.go