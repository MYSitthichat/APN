package p2p

import (
	"context"
	"errors"
	"io"

	"github.com/hashicorp/yamux"
	"github.com/quic-go/quic-go"
)

var errDatagramsUnsupported = errors.New("datagrams unsupported on this transport")

// MuxSession abstracts a multiplexed bidirectional stream transport (QUIC or WebSocket+Yamux)
// plus optional RFC 9221 unreliable datagrams for WireGuard-grade L3 VPN packets.
type MuxSession interface {
	OpenStream(ctx context.Context) (io.ReadWriteCloser, error)
	AcceptStream(ctx context.Context) (io.ReadWriteCloser, error)
	SupportsDatagrams() bool
	SendDatagram(p []byte) error
	ReceiveDatagram(ctx context.Context) ([]byte, error)
	RemoteAddr() string
	TransportName() string
	Close() error
}

// ---- QUIC adapter ----

type quicSession struct {
	conn *quic.Conn
}

type quicStreamCloser struct {
	*quic.Stream
}

func (s quicStreamCloser) CloseWrite() error {
	return s.Stream.Close()
}

func (s quicStreamCloser) Close() error {
	s.Stream.CancelRead(0)
	return s.Stream.Close()
}

// WrapQUIC wraps a quic.Conn as a MuxSession.
func WrapQUIC(conn *quic.Conn) MuxSession {
	return &quicSession{conn: conn}
}

func (q *quicSession) OpenStream(ctx context.Context) (io.ReadWriteCloser, error) {
	st, err := q.conn.OpenStreamSync(ctx)
	if err != nil {
		return nil, err
	}
	return quicStreamCloser{st}, nil
}

func (q *quicSession) AcceptStream(ctx context.Context) (io.ReadWriteCloser, error) {
	st, err := q.conn.AcceptStream(ctx)
	if err != nil {
		return nil, err
	}
	return quicStreamCloser{st}, nil
}

func (q *quicSession) SupportsDatagrams() bool {
	return true
}

func (q *quicSession) SendDatagram(p []byte) error {
	return q.conn.SendDatagram(p)
}

func (q *quicSession) ReceiveDatagram(ctx context.Context) ([]byte, error) {
	return q.conn.ReceiveDatagram(ctx)
}

func (q *quicSession) RemoteAddr() string {
	return q.conn.RemoteAddr().String()
}

func (q *quicSession) TransportName() string {
	return "QUIC/UDP (TLS 1.3)"
}

func (q *quicSession) Close() error {
	return q.conn.CloseWithError(0, "closed")
}

// ---- Yamux (WebSocket) adapter ----

type yamuxSession struct {
	sess       *yamux.Session
	remoteAddr string
	transport  string
}

// WrapYamux wraps a yamux.Session as a MuxSession.
func WrapYamux(sess *yamux.Session, remoteAddr, transport string) MuxSession {
	if transport == "" {
		transport = "WSS/TCP (TLS 1.3)"
	}
	return &yamuxSession{
		sess:       sess,
		remoteAddr: remoteAddr,
		transport:  transport,
	}
}

func (y *yamuxSession) OpenStream(_ context.Context) (io.ReadWriteCloser, error) {
	return y.sess.OpenStream()
}

func (y *yamuxSession) AcceptStream(_ context.Context) (io.ReadWriteCloser, error) {
	return y.sess.AcceptStream()
}

func (y *yamuxSession) SupportsDatagrams() bool {
	return false
}

func (y *yamuxSession) SendDatagram(_ []byte) error {
	return errDatagramsUnsupported
}

func (y *yamuxSession) ReceiveDatagram(_ context.Context) ([]byte, error) {
	return nil, errDatagramsUnsupported
}

func (y *yamuxSession) RemoteAddr() string {
	return y.remoteAddr
}

func (y *yamuxSession) TransportName() string {
	return y.transport
}

func (y *yamuxSession) Close() error {
	return y.sess.Close()
}
