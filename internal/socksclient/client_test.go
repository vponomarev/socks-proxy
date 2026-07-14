package socksclient

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"

	"github.com/vponomarev/socks-proxy/internal/config"
)

func TestDialUsesDomainAddress(t *testing.T) {
	client, server := net.Pipe()
	done := make(chan error, 1)
	go func() {
		defer server.Close()
		greeting := make([]byte, 3)
		if _, err := io.ReadFull(server, greeting); err != nil {
			done <- err
			return
		}
		if _, err := server.Write([]byte{5, 0}); err != nil {
			done <- err
			return
		}
		header := make([]byte, 5)
		if _, err := io.ReadFull(server, header); err != nil {
			done <- err
			return
		}
		host := make([]byte, int(header[4]))
		if _, err := io.ReadFull(server, host); err != nil {
			done <- err
			return
		}
		port := make([]byte, 2)
		if _, err := io.ReadFull(server, port); err != nil {
			done <- err
			return
		}
		if string(host) != "example.com" || binary.BigEndian.Uint16(port) != 443 {
			done <- &unexpectedTarget{host: string(host), port: binary.BigEndian.Uint16(port)}
			return
		}
		if _, err := server.Write([]byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 80}); err != nil {
			done <- err
			return
		}
		one := make([]byte, 1)
		_, err := server.Read(one)
		if err == io.EOF {
			err = nil
		}
		done <- err
	}()

	originalDial := dialContext
	dialContext = func(context.Context, string, string) (net.Conn, error) { return client, nil }
	t.Cleanup(func() { dialContext = originalDial })

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	conn, err := Dial(ctx, config.Upstream{Address: "upstream:1080"}, "example.com", 443)
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestCheckCompletesSOCKSHandshakeWithoutConnect(t *testing.T) {
	client, server := net.Pipe()
	done := make(chan error, 1)
	go func() {
		defer server.Close()
		header := make([]byte, 2)
		if _, err := io.ReadFull(server, header); err != nil {
			done <- err
			return
		}
		methods := make([]byte, int(header[1]))
		if _, err := io.ReadFull(server, methods); err != nil {
			done <- err
			return
		}
		if _, err := server.Write([]byte{5, 0}); err != nil {
			done <- err
			return
		}
		one := make([]byte, 1)
		_, err := server.Read(one)
		if err == io.EOF {
			err = nil
		}
		done <- err
	}()

	originalDial := dialContext
	dialContext = func(context.Context, string, string) (net.Conn, error) { return client, nil }
	t.Cleanup(func() { dialContext = originalDial })

	if err := Check(context.Background(), config.Upstream{Address: "upstream:1080", ConnectTimeout: "1s"}); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

type unexpectedTarget struct {
	host string
	port uint16
}

func (e *unexpectedTarget) Error() string { return "unexpected SOCKS target " + e.host }
