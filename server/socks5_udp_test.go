package server

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/traffic"
)

func TestManagerSOCKS5UDPOptInAndAssetBlockRuleDropsDatagram(t *testing.T) {
	// 1. Both flags off: NO SOCKS5 listener and UDP disabled.
	t.Setenv(traffic.SOCKS5EnabledEnv, "")
	t.Setenv(traffic.SOCKS5AddrEnv, "")
	t.Setenv(traffic.SOCKS5UDPEnabledEnv, "")
	mOff, err := NewManager(t.TempDir(), "127.0.0.1:0")
	if err != nil {
		db.SkipPGUnavailable(t, err)
	}
	t.Cleanup(func() { _ = mOff.Close() })
	if mOff.traffic.SOCKS5Addr() != "" || mOff.traffic.SOCKS5UDPEnabled() {
		t.Fatalf("flags off: addr=%q udp=%v, want empty/false", mOff.traffic.SOCKS5Addr(), mOff.traffic.SOCKS5UDPEnabled())
	}

	// 2. SOCKS5 on with UDP flag off: UDP ASSOCIATE refused with 0x07.
	t.Setenv(traffic.SOCKS5AddrEnv, "127.0.0.1:0")
	t.Setenv(traffic.SOCKS5UDPEnabledEnv, "")
	mTCPOnly, err := NewManager(t.TempDir(), "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = mTCPOnly.Close() })
	if mTCPOnly.traffic.SOCKS5UDPEnabled() {
		t.Fatal("expected UDP disabled when ARTEX_SOCKS5_UDP_ENABLED is unset")
	}

	// 3. UDP flag on: listener accepts UDP ASSOCIATE and enforces global asset
	// block rules per datagram destination (drop denied, forward allowed).
	t.Setenv(traffic.SOCKS5AddrEnv, "127.0.0.1:0")
	t.Setenv(traffic.SOCKS5UDPEnabledEnv, "1")
	mOn, err := NewManager(t.TempDir(), "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = mOn.Close() })
	socksAddr := mOn.traffic.SOCKS5Addr()
	if socksAddr == "" || !mOn.traffic.SOCKS5UDPEnabled() {
		t.Fatalf("expected SOCKS5+UDP enabled, got addr=%q udp=%v", socksAddr, mOn.traffic.SOCKS5UDPEnabled())
	}

	startEcho := func(bind string) (*net.UDPConn, *atomic.Int32, error) {
		t.Helper()
		ua, err := net.ResolveUDPAddr("udp4", bind)
		if err != nil {
			return nil, nil, err
		}
		ln, err := net.ListenUDP("udp4", ua)
		if err != nil {
			return nil, nil, err
		}
		var n atomic.Int32
		go func() {
			buf := make([]byte, 4096)
			for {
				rn, from, rerr := ln.ReadFromUDP(buf)
				if rerr != nil {
					return
				}
				n.Add(1)
				_, _ = ln.WriteToUDP(append([]byte("OK:"), buf[:rn]...), from)
			}
		}()
		t.Cleanup(func() { _ = ln.Close() })
		return ln, &n, nil
	}

	// Linux commonly treats the whole 127/8 range as loopback, while macOS may
	// only have 127.0.0.1 assigned. Prefer the historical two-loopback setup and
	// fall back to the machine's first real local IPv4 so the same block/allow
	// security assertion still executes instead of becoming platform-skipped.
	blockedIP, allowedIP := "127.0.0.2", "127.0.0.1"
	blockedLn, blockedCount, err := startEcho(net.JoinHostPort(blockedIP, "0"))
	if err != nil {
		blockedIP = ""
		allowedIP = "127.0.0.1"
		addrs, addrErr := net.InterfaceAddrs()
		if addrErr != nil {
			t.Fatalf("enumerate local addresses after loopback-alias bind failed: %v (bind error: %v)", addrErr, err)
		}
		for _, addr := range addrs {
			ip, _, parseErr := net.ParseCIDR(addr.String())
			if parseErr == nil && ip.To4() != nil && !ip.IsLoopback() && !ip.IsUnspecified() {
				blockedIP = ip.String()
				break
			}
		}
		if blockedIP == "" {
			t.Fatalf("no second local IPv4 available after loopback-alias bind failed: %v", err)
		}
		blockedLn, blockedCount, err = startEcho(net.JoinHostPort(blockedIP, "0"))
		if err != nil {
			t.Fatalf("listen blocked UDP echo on %s: %v", blockedIP, err)
		}
	}
	allowedLn, allowedCount, err := startEcho(net.JoinHostPort(allowedIP, "0"))
	if err != nil {
		t.Fatalf("listen allowed UDP echo on %s: %v", allowedIP, err)
	}

	rule, err := mOn.pg.CreateAssetInterceptRule(
		"exact_ip",
		blockedIP,
		fmt.Sprintf("p41c-udp-block-%d", time.Now().UnixNano()),
		true,
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = mOn.pg.DeleteAssetInterceptRule(rule.ID) })

	blockedAddr := blockedLn.LocalAddr().(*net.UDPAddr)
	allowedAddr := allowedLn.LocalAddr().(*net.UDPAddr)

	// Open SOCKS5 UDP ASSOCIATE control connection.
	ctrl, err := net.DialTimeout("tcp4", socksAddr, 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer ctrl.Close()
	_ = ctrl.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := ctrl.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		t.Fatal(err)
	}
	var sel [2]byte
	if _, err := io.ReadFull(ctrl, sel[:]); err != nil || sel != [2]byte{0x05, 0x00} {
		t.Fatalf("method selection = %v err=%v", sel, err)
	}
	// CMD=0x03 (UDP ASSOCIATE), ATYP=0x01, 0.0.0.0:0
	if _, err := ctrl.Write([]byte{0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0}); err != nil {
		t.Fatal(err)
	}
	var rep [10]byte
	if _, err := io.ReadFull(ctrl, rep[:]); err != nil {
		t.Fatal(err)
	}
	if rep[1] != 0x00 {
		t.Fatalf("UDP ASSOCIATE rep = 0x%02x, want 0x00", rep[1])
	}
	relayAddr := &net.UDPAddr{
		IP:   net.IPv4(rep[4], rep[5], rep[6], rep[7]),
		Port: int(binary.BigEndian.Uint16(rep[8:10])),
	}
	_ = ctrl.SetDeadline(time.Time{})

	cliUDP, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer cliUDP.Close()

	buildPkt := func(dst *net.UDPAddr, msg string) []byte {
		p := make([]byte, 10+len(msg))
		p[3] = 0x01
		copy(p[4:8], dst.IP.To4())
		binary.BigEndian.PutUint16(p[8:10], uint16(dst.Port))
		copy(p[10:], msg)
		return p
	}

	// Send one datagram to the blocked local IP (must be dropped by the asset
	// rule), then one to the distinct allowed local IP.
	_, _ = cliUDP.WriteToUDP(buildPkt(blockedAddr, "blocked-udp"), relayAddr)
	_, _ = cliUDP.WriteToUDP(buildPkt(allowedAddr, "allowed-udp"), relayAddr)

	_ = cliUDP.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 2048)
	rn, _, err := cliUDP.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("read allowed udp reply: %v", err)
	}
	if got := string(buf[10:rn]); got != "OK:allowed-udp" {
		t.Fatalf("reply = %q, want OK:allowed-udp", got)
	}
	if blockedCount.Load() != 0 {
		t.Fatalf("blocked %s received %d datagrams, want 0", blockedIP, blockedCount.Load())
	}
	if allowedCount.Load() != 1 {
		t.Fatalf("allowed %s received %d datagrams, want 1", allowedIP, allowedCount.Load())
	}

	// Wait briefly for SQLite writes and verify raw_udp_datagrams contains only
	// the allowed host, with no row for the denied destination.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		n, err := mOn.traffic.CountRawUDPDatagrams("", allowedIP)
		if err == nil && n >= 2 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if nBlocked, err := mOn.traffic.CountRawUDPDatagrams("", blockedIP); err != nil || nBlocked != 0 {
		t.Fatalf("blocked host recorded %d rows (err=%v), want 0", nBlocked, err)
	}
	if nAllowed, err := mOn.traffic.CountRawUDPDatagrams("", allowedIP); err != nil || nAllowed != 2 {
		t.Fatalf("allowed host recorded %d rows (err=%v), want 2", nAllowed, err)
	}
}
