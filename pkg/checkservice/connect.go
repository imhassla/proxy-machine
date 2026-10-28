package checkservice

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/url"
)

type bufferedConn struct {
	net.Conn
	reader *bufio.Reader
}

func (c *bufferedConn) Read(p []byte) (int, error) { return c.reader.Read(p) }

// connect uses identical strict CONNECT semantics for HTTPS requests and WSS,
// including TLS-to-proxy. The destination TLS handshake happens separately.
func (c *Client) connect(ctx context.Context, u *url.URL, target string) (net.Conn, error) {
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", u.Host)
	if err != nil {
		return nil, err
	}
	raw := conn
	closed := make(chan struct{})
	stop := context.AfterFunc(ctx, func() { _ = raw.Close(); close(closed) })
	defer func() {
		if !stop() {
			<-closed
		}
	}()
	fail := func(err error) (net.Conn, error) { _ = conn.Close(); return nil, err }
	if u.Scheme == "https" {
		tc := tls.Client(conn, &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: c.roots, ServerName: u.Hostname()})
		if err := tc.HandshakeContext(ctx); err != nil {
			return fail(err)
		}
		conn = tc
	}
	request := &http.Request{Method: "CONNECT", URL: &url.URL{Opaque: target}, Host: target, Header: make(http.Header)}
	if err := request.Write(conn); err != nil {
		return fail(err)
	}
	reader := bufio.NewReader(conn)
	var header bytes.Buffer
	for {
		// ReadSlice bounds an unterminated line to the reader's fixed buffer.
		line, err := reader.ReadSlice('\n')
		if err != nil {
			return fail(err)
		}
		if header.Len()+len(line) > 32<<10 {
			return fail(fmt.Errorf("proxy response headers too large"))
		}
		header.Write(line)
		if bytes.Equal(line, []byte("\r\n")) {
			break
		}
	}
	response, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(header.Bytes())), request)
	if err != nil {
		return fail(err)
	}
	if response.StatusCode != 200 {
		return fail(fmt.Errorf("proxy CONNECT status %d", response.StatusCode))
	}
	if err := ctx.Err(); err != nil {
		return fail(err)
	}
	return &bufferedConn{conn, reader}, nil
}
