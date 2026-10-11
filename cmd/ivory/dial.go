//go:build ivory

package main

import (
	"bufio"
	"context"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

const proxyHelp = "proxy for the TLS connections and the TSL and OCSP downloads: http://, socks5:// (local DNS) or socks5h:// (proxy's DNS), " +
	"as scheme://[user:pass@]host:port; \"env\" uses HTTPS_PROXY (else ALL_PROXY) and NO_PROXY, \"direct\" none"

const downloadProxyHelp = "proxy for the TSL and OCSP downloads: http://, socks5:// or socks5h://, " +
	"as scheme://[user:pass@]host:port; \"env\" uses HTTPS_PROXY (else ALL_PROXY) and NO_PROXY, \"direct\" none"

// dialer opens the TCP connections of client and probe, directly, through
// an HTTP proxy with CONNECT or through a SOCKS5 proxy (such as ssh -D).
// The proxy only relays bytes, so the handshake reaches the server
// unchanged.
type dialer struct {
	proxy   string // flag value: "env", "direct" or a URL
	timeout time.Duration
}

func (d *dialer) register(fs *flag.FlagSet) {
	fs.StringVar(&d.proxy, "proxy", "env", proxyHelp)
}

// registerDownloads registers -proxy for a command that only downloads
// through it (TSL, OCSP).
func (d *dialer) registerDownloads(fs *flag.FlagSet) {
	fs.StringVar(&d.proxy, "proxy", "env", downloadProxyHelp)
}

// proxyFor returns the proxy for addr, or nil for a direct connection.
func (d *dialer) proxyFor(addr string) (*url.URL, error) {
	switch d.proxy {
	case "direct", "":
		return nil, nil
	case "env":
		return envProxy(addr)
	}
	u, err := url.Parse(d.proxy)
	if err != nil {
		return nil, fmt.Errorf("-proxy: %v", err)
	}
	if !proxyScheme(u) {
		return nil, fmt.Errorf("-proxy %q: want http://, socks5:// or socks5h://host:port, env or direct", d.proxy)
	}
	return u, nil
}

// envProxy returns the proxy that the environment names for addr:
// HTTPS_PROXY (or https_proxy), else ALL_PROXY (or all_proxy, which curl
// reads and which often names an ssh -D proxy), unless NO_PROXY (or
// no_proxy) matches addr. Like net/http, it never proxies localhost and
// loopback addresses.
func envProxy(addr string) (*url.URL, error) {
	name, raw := firstEnv("HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy")
	if raw == "" {
		return nil, nil
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if ip := net.ParseIP(host); host == "localhost" || ip != nil && ip.IsLoopback() {
		return nil, nil
	}
	if _, np := firstEnv("NO_PROXY", "no_proxy"); noProxy(np, host, port) {
		return nil, nil
	}
	if !strings.Contains(raw, "://") {
		raw = "http://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil || !proxyScheme(u) {
		return nil, fmt.Errorf("%s: want http://, socks5:// or socks5h://host:port", name)
	}
	return u, nil
}

// firstEnv returns the first of the environment variables that is set.
func firstEnv(names ...string) (string, string) {
	for _, n := range names {
		if v := os.Getenv(n); v != "" {
			return n, v
		}
	}
	return "", ""
}

// noProxy reports whether the NO_PROXY list matches host and port. An
// entry is "*", an IP address, a CIDR prefix, or a domain name (with or
// without a leading "." or "*."), which matches the name and its
// subdomains; each may end in ":port".
func noProxy(list, host, port string) bool {
	ip := net.ParseIP(host)
	for _, e := range strings.FieldsFunc(strings.ToLower(list), func(r rune) bool { return r == ',' || r == ' ' }) {
		if e == "*" {
			return true
		}
		if h, p, err := net.SplitHostPort(e); err == nil {
			if p != port {
				continue
			}
			e = h
		}
		if _, n, err := net.ParseCIDR(e); err == nil {
			if ip != nil && n.Contains(ip) {
				return true
			}
			continue
		}
		if eip := net.ParseIP(strings.Trim(e, "[]")); eip != nil {
			if ip != nil && eip.Equal(ip) {
				return true
			}
			continue
		}
		e = strings.TrimPrefix(strings.TrimPrefix(e, "*"), ".")
		if e != "" && (host == e || strings.HasSuffix(host, "."+e)) {
			return true
		}
	}
	return false
}

// httpClient returns a client for the TSL and OCSP downloads that goes
// through the same proxy: an HTTP proxy as HTTP proxies are used (absolute
// URLs for http, CONNECT for https), a SOCKS5 proxy for every connection.
func (d *dialer) httpClient() *http.Client {
	t := http.DefaultTransport.(*http.Transport).Clone()
	t.Proxy = func(r *http.Request) (*url.URL, error) {
		port := r.URL.Port()
		if port == "" {
			port = map[string]string{"http": "80", "https": "443"}[r.URL.Scheme]
		}
		u, err := d.proxyFor(net.JoinHostPort(r.URL.Hostname(), port))
		if err != nil || u == nil || u.Scheme != "http" {
			return nil, err // SOCKS5: DialContext
		}
		return u, nil
	}
	direct := &net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second}
	t.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		if u, err := d.proxyFor(addr); err == nil && u != nil && u.Scheme != "http" {
			return d.dial(ctx, addr)
		}
		return direct.DialContext(ctx, network, addr)
	}
	return &http.Client{Transport: t}
}

func proxyScheme(u *url.URL) bool {
	return u.Host != "" && (u.Scheme == "http" || u.Scheme == "socks5" || u.Scheme == "socks5h")
}

// describe says how addr is reached, for reports.
func (d *dialer) describe(addr string) string {
	u, err := d.proxyFor(addr)
	if err != nil || u == nil {
		return ""
	}
	return u.Scheme + "://" + u.Host
}

func (d *dialer) dial(ctx context.Context, addr string) (net.Conn, error) {
	proxy, err := d.proxyFor(addr)
	if err != nil {
		return nil, err
	}
	nd := &net.Dialer{Timeout: d.timeout}
	if proxy == nil {
		return nd.DialContext(ctx, "tcp", addr)
	}
	proxyAddr := proxy.Host
	if proxy.Port() == "" {
		port := "80"
		if proxy.Scheme != "http" {
			port = "1080"
		}
		proxyAddr = net.JoinHostPort(proxy.Hostname(), port)
	}
	conn, err := nd.DialContext(ctx, "tcp", proxyAddr)
	if err != nil {
		return nil, fmt.Errorf("proxy %s: %w", proxyAddr, err)
	}
	if d.timeout > 0 {
		conn.SetDeadline(time.Now().Add(d.timeout))
	}
	var c net.Conn
	if proxy.Scheme == "http" {
		c, err = connect(conn, proxy, addr)
	} else {
		c, err = socks5(ctx, conn, proxy, addr)
	}
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("proxy %s: %w", proxyAddr, err)
	}
	conn.SetDeadline(time.Time{})
	return c, nil
}

// connect asks the proxy on conn for a tunnel to addr (RFC 9110,
// Section 9.3.6).
func connect(conn net.Conn, proxy *url.URL, addr string) (net.Conn, error) {
	req := "CONNECT " + addr + " HTTP/1.1\r\nHost: " + addr + "\r\n"
	if u := proxy.User; u != nil {
		pass, _ := u.Password()
		req += "Proxy-Authorization: Basic " + base64.StdEncoding.EncodeToString([]byte(u.Username()+":"+pass)) + "\r\n"
	}
	if _, err := conn.Write([]byte(req + "\r\n")); err != nil {
		return nil, err
	}
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
	if err != nil {
		return nil, err
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("CONNECT %s: %s", addr, resp.Status)
	}
	if br.Buffered() > 0 {
		// The server speaks after the client's first flight, so bytes
		// here mean a broken proxy.
		return nil, errors.New("proxy sent data before the tunnel was used")
	}
	return conn, nil
}

// socks5 asks the SOCKS5 proxy on conn to connect to addr (RFC 1928),
// with username and password (RFC 1929) if the proxy URL has them. For
// socks5 the name is resolved here, for socks5h by the proxy.
func socks5(ctx context.Context, conn net.Conn, proxy *url.URL, addr string) (net.Conn, error) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	port, err := net.LookupPort("tcp", portStr)
	if err != nil {
		return nil, err
	}
	methods := []byte{0x00}
	if proxy.User != nil {
		methods = []byte{0x02}
	}
	if _, err := conn.Write(append([]byte{5, byte(len(methods))}, methods...)); err != nil {
		return nil, err
	}
	var b [2]byte
	if _, err := io.ReadFull(conn, b[:]); err != nil {
		return nil, err
	}
	switch {
	case b[0] != 5:
		return nil, fmt.Errorf("not a SOCKS5 proxy (version %d)", b[0])
	case b[1] == 0x02 && proxy.User != nil:
		user := proxy.User.Username()
		pass, _ := proxy.User.Password()
		if len(user) > 255 || len(pass) > 255 {
			return nil, errors.New("SOCKS5 username or password too long")
		}
		req := append([]byte{1, byte(len(user))}, user...)
		req = append(append(req, byte(len(pass))), pass...)
		if _, err := conn.Write(req); err != nil {
			return nil, err
		}
		if _, err := io.ReadFull(conn, b[:]); err != nil {
			return nil, err
		}
		if b[1] != 0 {
			return nil, errors.New("SOCKS5 proxy refused the username and password")
		}
	case b[1] != 0x00:
		return nil, fmt.Errorf("SOCKS5 proxy accepts none of our authentication methods (it wants 0x%02x)", b[1])
	}

	req := []byte{5, 1, 0} // version, CONNECT, reserved
	ip := net.ParseIP(host)
	if ip == nil && proxy.Scheme == "socks5" {
		ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
		if err != nil {
			return nil, err
		}
		ip = net.IP(ips[0].Unmap().AsSlice())
	}
	switch {
	case ip == nil:
		if len(host) > 255 {
			return nil, errors.New("host name too long for SOCKS5")
		}
		req = append(append(req, 3, byte(len(host))), host...)
	case ip.To4() != nil:
		req = append(append(req, 1), ip.To4()...)
	default:
		req = append(append(req, 4), ip.To16()...)
	}
	req = append(req, byte(port>>8), byte(port))
	if _, err := conn.Write(req); err != nil {
		return nil, err
	}
	var h [4]byte
	if _, err := io.ReadFull(conn, h[:]); err != nil {
		return nil, err
	}
	if h[0] != 5 {
		return nil, fmt.Errorf("not a SOCKS5 reply (version %d)", h[0])
	}
	if h[1] != 0 {
		return nil, fmt.Errorf("SOCKS5 CONNECT %s: %s", addr, socksReply(h[1]))
	}
	// Skip the bound address.
	var n int
	switch h[3] {
	case 1:
		n = 4
	case 4:
		n = 16
	case 3:
		var l [1]byte
		if _, err := io.ReadFull(conn, l[:]); err != nil {
			return nil, err
		}
		n = int(l[0])
	default:
		return nil, fmt.Errorf("SOCKS5 reply with address type %d", h[3])
	}
	if _, err := io.ReadFull(conn, make([]byte, n+2)); err != nil {
		return nil, err
	}
	return conn, nil
}

func socksReply(code byte) string {
	msgs := []string{1: "general failure", 2: "not allowed by ruleset", 3: "network unreachable",
		4: "host unreachable", 5: "connection refused", 6: "TTL expired", 7: "command not supported",
		8: "address type not supported"}
	if int(code) < len(msgs) && msgs[code] != "" {
		return msgs[code]
	}
	return fmt.Sprintf("reply 0x%02x", code)
}
