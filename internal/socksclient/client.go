package socksclient

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/vponomarev/socks-proxy/internal/config"
)

const (
	version5       = 5
	methodNoAuth   = 0
	methodUserPass = 2
	methodRejected = 0xff
)

var dialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
	return (&net.Dialer{}).DialContext(ctx, network, address)
}

func Dial(ctx context.Context, upstream config.Upstream, host string, port uint16) (net.Conn, error) {
	if upstream.Address == "" {
		return nil, fmt.Errorf("SOCKS5 upstream address is empty")
	}
	dialCtx, cancel := context.WithTimeout(ctx, upstream.Timeout())
	defer cancel()
	conn, err := dialContext(dialCtx, "tcp", upstream.Address)
	if err != nil {
		return nil, fmt.Errorf("connect to SOCKS5 upstream %s: %w", upstream.Address, err)
	}
	ok := false
	defer func() {
		if !ok {
			conn.Close()
		}
	}()
	if deadline, hasDeadline := dialCtx.Deadline(); hasDeadline {
		if err := conn.SetDeadline(deadline); err != nil {
			return nil, err
		}
	}
	if err := negotiate(conn, upstream); err != nil {
		return nil, err
	}
	if err := connect(conn, host, port); err != nil {
		return nil, err
	}
	if err := conn.SetDeadline(time.Time{}); err != nil {
		return nil, err
	}
	ok = true
	return conn, nil
}

func negotiate(conn net.Conn, upstream config.Upstream) error {
	methods := []byte{methodNoAuth}
	if upstream.Username != "" || upstream.Password != "" {
		methods = append(methods, methodUserPass)
	}
	request := append([]byte{version5, byte(len(methods))}, methods...)
	if err := writeAll(conn, request); err != nil {
		return fmt.Errorf("write SOCKS5 greeting: %w", err)
	}
	response := make([]byte, 2)
	if _, err := io.ReadFull(conn, response); err != nil {
		return fmt.Errorf("read SOCKS5 greeting: %w", err)
	}
	if response[0] != version5 {
		return fmt.Errorf("unexpected SOCKS version %d", response[0])
	}
	switch response[1] {
	case methodNoAuth:
		return nil
	case methodUserPass:
		return authenticate(conn, upstream.Username, upstream.Password)
	case methodRejected:
		return fmt.Errorf("SOCKS5 upstream rejected all authentication methods")
	default:
		return fmt.Errorf("SOCKS5 upstream selected unsupported method %d", response[1])
	}
}

func authenticate(conn net.Conn, username, password string) error {
	if len(username) > 255 || len(password) > 255 {
		return fmt.Errorf("SOCKS5 username or password is too long")
	}
	request := []byte{1, byte(len(username))}
	request = append(request, username...)
	request = append(request, byte(len(password)))
	request = append(request, password...)
	if err := writeAll(conn, request); err != nil {
		return fmt.Errorf("write SOCKS5 authentication: %w", err)
	}
	response := make([]byte, 2)
	if _, err := io.ReadFull(conn, response); err != nil {
		return fmt.Errorf("read SOCKS5 authentication: %w", err)
	}
	if response[0] != 1 || response[1] != 0 {
		return fmt.Errorf("SOCKS5 username/password authentication failed")
	}
	return nil
}

func connect(conn net.Conn, host string, port uint16) error {
	request := []byte{version5, 1, 0}
	ip := net.ParseIP(host)
	switch {
	case ip != nil && ip.To4() != nil:
		request = append(request, 1)
		request = append(request, ip.To4()...)
	case ip != nil && ip.To16() != nil:
		request = append(request, 4)
		request = append(request, ip.To16()...)
	default:
		if len(host) == 0 || len(host) > 255 {
			return fmt.Errorf("invalid SOCKS5 target hostname length: %d", len(host))
		}
		request = append(request, 3, byte(len(host)))
		request = append(request, host...)
	}
	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, port)
	request = append(request, portBytes...)
	if err := writeAll(conn, request); err != nil {
		return fmt.Errorf("write SOCKS5 CONNECT: %w", err)
	}

	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		return fmt.Errorf("read SOCKS5 CONNECT: %w", err)
	}
	if header[0] != version5 {
		return fmt.Errorf("unexpected SOCKS version %d in CONNECT response", header[0])
	}
	if header[1] != 0 {
		return fmt.Errorf("SOCKS5 upstream CONNECT failed with reply %d", header[1])
	}
	if header[2] != 0 {
		return fmt.Errorf("invalid SOCKS5 reserved byte %d", header[2])
	}
	if err := discardAddress(conn, header[3]); err != nil {
		return fmt.Errorf("read SOCKS5 bound address: %w", err)
	}
	return nil
}

func discardAddress(conn net.Conn, atyp byte) error {
	var length int
	switch atyp {
	case 1:
		length = 4
	case 4:
		length = 16
	case 3:
		buf := make([]byte, 1)
		if _, err := io.ReadFull(conn, buf); err != nil {
			return err
		}
		length = int(buf[0])
	default:
		return fmt.Errorf("unsupported address type %d", atyp)
	}
	_, err := io.CopyN(io.Discard, conn, int64(length+2))
	return err
}

func writeAll(conn net.Conn, data []byte) error {
	for len(data) > 0 {
		n, err := conn.Write(data)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrUnexpectedEOF
		}
		data = data[n:]
	}
	return nil
}
