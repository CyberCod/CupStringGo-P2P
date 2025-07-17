// -----------------BEGIN FILE-------------irc_discovery.go

package main

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"strings"
	"time"

	ircreader "github.com/ergochat/irc-go/ircreader"
	ircmsg "github.com/ergochat/irc-go/ircmsg"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/multiformats/go-multiaddr"
)

// StartBot launches the IRC bot: always connected for lurking, scans/challenges only when triggered by files.
func StartBot(loadedConfig *Config, myMultiAddressString string, p2pHost host.Host, triggerChan <-chan bool) {
	reconnectBackoff := time.Second
	var scanning bool

	for {
		rnd := make([]byte, 4)
		if _, err := rand.Read(rnd); err != nil {
			log.Printf("rand: %v", err)
			time.Sleep(reconnectBackoff)
			reconnectBackoff *= 2
			continue
		}
		nick := fmt.Sprintf("cs_%s_%s", loadedConfig.YourUsername, hex.EncodeToString(rnd))

		addr := fmt.Sprintf("%s:%d", loadedConfig.IRCServer, loadedConfig.IRCPort)
		var conn net.Conn
		var err error
		if loadedConfig.TLSEnabled {
			conn, err = tls.Dial("tcp", addr, &tls.Config{})
		} else {
			conn, err = net.Dial("tcp", addr)
		}
		if err != nil {
			log.Printf("dial: %v", err)
			time.Sleep(reconnectBackoff)
			reconnectBackoff *= 2
			if reconnectBackoff > 5*time.Minute {
				reconnectBackoff = 5 * time.Minute
			}
			continue
		}
		log.Printf("connected to IRC as %s", nick)

		fmt.Fprintf(conn, "NICK %s\r\nUSER %s 0 * :CupAndString Bot\r\nJOIN #%s\r\n",
			nick, nick, loadedConfig.ChannelName)
		reconnectBackoff = time.Second

		// Ticker for NAMES only when scanning triggered
		ticker := time.NewTicker(60 * time.Second)
		ticker.Stop() // Start stopped; enable on trigger

		// Trigger goroutine: Start/stop scanning based on channel
		go func() {
			for trigger := range triggerChan {
				if trigger && !scanning {
					scanning = true
					ticker.Reset(60 * time.Second)
					fmt.Fprintf(conn, "NAMES #%s\r\n", loadedConfig.ChannelName)
					TimestampLog("File queue non-empty; starting IRC scanning")
				} else if !trigger && scanning {
					scanning = false
					ticker.Stop()
					TimestampLog("File queue empty; stopping IRC scanning")
				}
			}
		}()

		pendingChallenges := make(map[string]struct{})
		blacklistedNicks := make(map[string]struct{})
		var warnedBusyChannel bool

		reader := ircreader.NewIRCReader(conn)
		for {
			line, err := reader.ReadLine()
			if err != nil {
				TimestampLog(fmt.Sprintf("read: %v", err))
				break
			}
			msg, err := ircmsg.ParseLine(string(line))
			if err != nil {
				TimestampLog(fmt.Sprintf("parse: %v", err))
				continue
			}

			if msg.Command == "PING" {
				fmt.Fprintf(conn, "PONG :%s\r\n", msg.Params[0])
				continue
			}

			if msg.Command == "353" && len(msg.Params) >= 4 && scanning {
				users := strings.Fields(strings.Join(msg.Params[3:], " "))
				for i := range users {
					if strings.HasPrefix(users[i], "@") || strings.HasPrefix(users[i], "+") {
						users[i] = users[i][1:]
					}
				}

				if len(users) > 5 && !warnedBusyChannel {
					TimestampLog("Channel busy (>5 users); consider unique channel name.")
					warnedBusyChannel = true
				}

				for _, userNick := range users {
					if userNick == nick || !strings.Contains(userNick, loadedConfig.RecipientUsername) {
						continue
					}
					if _, blacklisted := blacklistedNicks[userNick]; blacklisted {
						continue
					}
					if _, pending := pendingChallenges[userNick]; pending {
						continue
					}
					fmt.Fprintf(conn, "PRIVMSG %s :What are we talking about?\r\n", userNick)
					pendingChallenges[userNick] = struct{}{}
					go func(targetNick string) {
						time.Sleep(5 * time.Second)
						if _, stillPending := pendingChallenges[targetNick]; stillPending {
							delete(pendingChallenges, targetNick)
							blacklistedNicks[targetNick] = struct{}{}
							TimestampLog(fmt.Sprintf("Timeout for %s; blacklisted.", targetNick))
						}
					}(userNick)
				}
				continue
			}

			if msg.Command == "366" {
				continue
			}

			if msg.Command == "PRIVMSG" && len(msg.Params) == 2 {
				sender, text := msg.Nick(), msg.Params[1]

				if text == "What are we talking about?" && strings.Contains(sender, loadedConfig.RecipientUsername) {
					// Use the pairing secret from config instead of hardcoded "Practice"
					fmt.Fprintf(conn, "PRIVMSG %s :%s\r\n", sender, loadedConfig.PairingSecret)
					continue
				}

				// Check if the response matches our pairing secret
				if text == loadedConfig.PairingSecret {
					if _, wasPending := pendingChallenges[sender]; wasPending {
						delete(pendingChallenges, sender)
						msg := fmt.Sprintf("PEER_INFO:%s", myMultiAddressString)
						fmt.Fprintf(conn, "PRIVMSG %s :%s\r\n", sender, msg)
						TimestampLog(fmt.Sprintf("Sent PEER_INFO to %s", sender))
					}
					continue
				}

				if strings.HasPrefix(text, "PEER_INFO:") && strings.Contains(sender, loadedConfig.RecipientUsername) {
					peerAddr := strings.TrimPrefix(text, "PEER_INFO:")
					TimestampLog(fmt.Sprintf("Received peer addr from %s: %s", sender, peerAddr))

					ma, err := multiaddr.NewMultiaddr(peerAddr)
					if err != nil {
						TimestampLog(fmt.Sprintf("Bad multiaddr: %v", err))
						continue
					}
					p2pVal, err := ma.ValueForProtocol(multiaddr.P_P2P)
					if err != nil {
						TimestampLog(fmt.Sprintf("Bad p2p value: %v", err))
						continue
					}
					peerID, err := peer.Decode(p2pVal)
					if err != nil {
						TimestampLog(fmt.Sprintf("Bad peer ID: %v", err))
						continue
					}

					ctx := context.Background()
					if err := p2pHost.Connect(ctx, peer.AddrInfo{
						ID:    peerID,
						Addrs: []multiaddr.Multiaddr{ma},
					}); err != nil {
						TimestampLog(fmt.Sprintf("Connect failed: %v", err))
						continue
					}
					stream, err := p2pHost.NewStream(ctx, peerID, "/sync/1.0.0")
					if err != nil {
						TimestampLog(fmt.Sprintf("Stream failed: %v", err))
						continue
					}
					go HandleSyncStream(stream, loadedConfig, false, p2pHost) // false for responder (receiver)
				}
			}
		}

		ticker.Stop()
		conn.Close()
		TimestampLog("IRC disconnected; reconnecting...")
	}
}

// -----------------END OF FILE-------------irc_discovery.go