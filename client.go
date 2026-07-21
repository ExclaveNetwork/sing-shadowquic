package shadowquic

import (
	"context"
	"crypto/sha256"
	"io"
	"net"
	"runtime"
	"sync"
	"time"

	quic "github.com/metacubex/jls-quic-go"
	tls "github.com/metacubex/jls-tls"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	"github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/common/network"
)

type ClientOptions struct {
	Context           context.Context
	Dialer            network.Dialer
	ServerAddress     metadata.Socksaddr
	Username          string
	Password          string
	ServerName        string
	NextProtos        []string
	CongestionControl string
	UDPOverStream     bool
	ZeroRTTHandshake  bool
	SunnyQUIC         bool
}

type Client struct {
	ctx               context.Context
	dialer            network.Dialer
	serverAddr        metadata.Socksaddr
	tlsConfig         *tls.Config
	quicConfig        *quic.Config
	congestionControl string
	udpOverStream     bool
	zeroRTTHandshake  bool
	sunnyQUIC         bool
	sunnyQUICUsername string
	sunnyQUICPassword string

	connAccess sync.Mutex
	conn       *clientQUICConnection
	pending    *clientOffer
}

type ShadowQUICClientOptions struct {
	Context           context.Context
	Dialer            network.Dialer
	ServerAddress     metadata.Socksaddr
	TLSConfig         *tls.Config
	QUICConfig        *quic.Config
	CongestionControl string
	UDPOverStream     bool
	ZeroRTTHandshake  bool
}

type SunnyQUICClientOptions struct {
	Context           context.Context
	Dialer            network.Dialer
	ServerAddress     metadata.Socksaddr
	Username          string
	Password          string
	TLSConfig         *tls.Config
	QUICConfig        *quic.Config
	CongestionControl string
	UDPOverStream     bool
	ZeroRTTHandshake  bool
}

func NewClient(options ClientOptions) (*Client, error) {
	congestionControl := options.CongestionControl
	switch congestionControl {
	case "":
		congestionControl = "bbr"
	case "cubic", "new_reno", "bbr":
	default:
		return nil, exceptions.New("unknown congestion control algorithm: ", options.CongestionControl)
	}
	tlsConfig := &tls.Config{
		ServerName: options.ServerName,
		NextProtos: options.NextProtos,
	}
	if options.ZeroRTTHandshake {
		tlsConfig.ClientSessionCache = tls.NewLRUClientSessionCache(1)
	}
	if !options.SunnyQUIC {
		tlsConfig.JLSConfig = &tls.JLSConfig{
			Enable: true,
			User: tls.JLSUser{
				Username: options.Username,
				Password: options.Password,
			},
		}
	}
	quicConfig := &quic.Config{
		DisablePathMTUDiscovery: !(runtime.GOOS == "windows" || runtime.GOOS == "linux" || runtime.GOOS == "android" || runtime.GOOS == "darwin"),
		EnableDatagrams:         !options.UDPOverStream,
		MaxIncomingUniStreams:   1 << 60,
	}
	client := &Client{
		ctx:               options.Context,
		dialer:            options.Dialer,
		serverAddr:        options.ServerAddress,
		tlsConfig:         tlsConfig,
		quicConfig:        quicConfig,
		congestionControl: congestionControl,
		udpOverStream:     options.UDPOverStream,
		zeroRTTHandshake:  options.ZeroRTTHandshake,
	}
	if options.SunnyQUIC {
		client.sunnyQUIC = true
		client.sunnyQUICUsername = options.Username
		client.sunnyQUICPassword = options.Password
	}
	return client, nil
}

func NewShadowQUICClient(options ShadowQUICClientOptions) (*Client, error) {
	return &Client{
		ctx:               options.Context,
		dialer:            options.Dialer,
		serverAddr:        options.ServerAddress,
		tlsConfig:         options.TLSConfig,
		quicConfig:        options.QUICConfig,
		congestionControl: options.CongestionControl,
		udpOverStream:     options.UDPOverStream,
		zeroRTTHandshake:  options.ZeroRTTHandshake,
	}, nil
}

func NewSunnyQUICClient(options SunnyQUICClientOptions) (*Client, error) {
	return &Client{
		ctx:               options.Context,
		dialer:            options.Dialer,
		serverAddr:        options.ServerAddress,
		tlsConfig:         options.TLSConfig,
		quicConfig:        options.QUICConfig,
		congestionControl: options.CongestionControl,
		udpOverStream:     options.UDPOverStream,
		zeroRTTHandshake:  options.ZeroRTTHandshake,
		sunnyQUIC:         true,
		sunnyQUICUsername: options.Username,
		sunnyQUICPassword: options.Password,
	}, nil
}

func (c *Client) offer(ctx context.Context) (*clientQUICConnection, error) {
	c.connAccess.Lock()
	conn := c.conn
	if conn != nil && conn.active() {
		c.connAccess.Unlock()
		return conn, nil
	}
	pending := c.pending
	if pending != nil {
		c.connAccess.Unlock()
		select {
		case <-pending.done:
			return pending.conn, pending.err
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	offerCtx := c.ctx
	if offerCtx == nil {
		offerCtx = context.Background()
	}
	offerCtx, cancel := context.WithCancel(offerCtx)
	pending = &clientOffer{
		done:   make(chan struct{}),
		cancel: cancel,
	}
	c.pending = pending
	c.connAccess.Unlock()
	go c.completeOffer(pending, offerCtx)
	select {
	case <-pending.done:
		return pending.conn, pending.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (c *Client) completeOffer(pending *clientOffer, offerCtx context.Context) {
	conn, err := c.offerNew(offerCtx)
	pending.cancel()
	discardErr := err
	shouldDiscard := false
	c.connAccess.Lock()
	if pending.discarded {
		shouldDiscard = true
		if pending.cause != nil {
			discardErr = pending.cause
		}
		pending.err = discardErr
	} else {
		pending.conn = conn
		pending.err = err
		if err == nil {
			c.conn = conn
		}
	}
	if c.pending == pending {
		c.pending = nil
	}
	close(pending.done)
	c.connAccess.Unlock()
	if shouldDiscard && conn != nil {
		conn.close()
	}
}

func (c *Client) offerNew(ctx context.Context) (*clientQUICConnection, error) {
	udpConn, err := c.dialer.DialContext(c.ctx, "udp", c.serverAddr)
	if err != nil {
		return nil, err
	}
	var quicConn *quic.Conn
	if c.zeroRTTHandshake {
		quicConn, err = quic.Dial(ctx, bufio.NewUnbindPacketConn(udpConn), udpConn.RemoteAddr(), c.tlsConfig, c.quicConfig)
	} else {
		quicConn, err = quic.DialEarly(ctx, bufio.NewUnbindPacketConn(udpConn), udpConn.RemoteAddr(), c.tlsConfig, c.quicConfig)
	}
	if err != nil {
		udpConn.Close()
		return nil, err
	}
	setCongestion(c.ctx, quicConn, c.congestionControl)
	conn := &clientQUICConnection{
		quicConn:   quicConn,
		rawConn:    udpConn,
		connDone:   make(chan struct{}),
		sendIDs:    make(map[uint16]struct{}),
		receiveIDs: make(map[uint16]*controlMessage),
	}
	if c.sunnyQUIC {
		go func() {
			if hErr := c.sunnyQUICHandshake(c.ctx, quicConn); hErr != nil {
				conn.close()
			}
		}()
	}
	if c.udpOverStream {
		go conn.loopUniStreams(c.ctx)
	} else {
		go conn.loopDatagrams(c.ctx)
	}
	return conn, nil
}

func (c *Client) DialConn(ctx context.Context, destination metadata.Socksaddr) (net.Conn, error) {
	quicConn, err := c.offer(ctx)
	if err != nil {
		return nil, err
	}
	stream, err := quicConn.quicConn.OpenStreamSync(ctx)
	if err != nil {
		return nil, err
	}
	return &clientConn{
		Stream:      stream,
		parent:      quicConn,
		destination: destination,
	}, nil
}

func (c *Client) ListenPacket(ctx context.Context) (net.PacketConn, error) {
	quicConn, err := c.offer(ctx)
	if err != nil {
		return nil, err
	}
	control, err := quicConn.quicConn.OpenStreamSync(ctx)
	if err != nil {
		return nil, err
	}
	return newClientPacketConn(ctx, quicConn, control, c.udpOverStream), nil
}

func (c *Client) Close() error {
	c.connAccess.Lock()
	conn := c.conn
	c.conn = nil
	pending := c.pending
	if pending != nil {
		pending.discarded = true
	}
	c.connAccess.Unlock()
	if pending != nil {
		pending.cancel()
	}
	if conn != nil {
		conn.close()
	}
	return nil
}

type clientOffer struct {
	done      chan struct{}
	cancel    func()
	conn      *clientQUICConnection
	err       error
	discarded bool
	cause     error
}

type clientQUICConnection struct {
	quicConn  *quic.Conn
	rawConn   io.Closer
	closeOnce sync.Once
	connDone  chan struct{}

	access     sync.Mutex
	sendID     uint16
	sendIDs    map[uint16]struct{}
	receiveIDs map[uint16]*controlMessage
}

func (c *clientQUICConnection) active() bool {
	select {
	case <-c.quicConn.Context().Done():
		return false
	case <-c.connDone:
		return false
	default:
		return true
	}
}

func (c *clientQUICConnection) close() {
	c.closeOnce.Do(func() {
		close(c.connDone)
		c.quicConn.CloseWithError(0, "")
		c.rawConn.Close()
	})
}

type clientConn struct {
	*quic.Stream
	parent        *clientQUICConnection
	destination   metadata.Socksaddr
	headerWritten bool
}

var (
	_ net.Conn            = (*clientConn)(nil)
	_ network.EarlyWriter = (*clientConn)(nil)
)

func (c *clientConn) NeedHandshakeForWrite() bool {
	return !c.headerWritten
}

func (c *clientConn) Read(b []byte) (int, error) {
	n, err := c.Stream.Read(b)
	return n, wrapQUICError(err)
}

func (c *clientConn) Write(b []byte) (int, error) {
	if !c.headerWritten {
		request := buf.NewSize(1 + addressSerializer.AddrPortLen(c.destination) + len(b))
		common.Must(request.WriteByte(commandTCPConnect))
		common.Must(addressSerializer.WriteAddrPort(request, c.destination))
		common.Must1(request.Write(b))
		_, err := c.Stream.Write(request.Bytes())
		request.Release()
		if err != nil {
			return 0, wrapQUICError(err)
		}
		c.headerWritten = true
		return len(b), nil
	}
	n, err := c.Stream.Write(b)
	return n, wrapQUICError(err)
}

func (c *clientConn) Close() error {
	c.Stream.CancelRead(0)
	err := c.Stream.Close()
	c.Stream.SetWriteDeadline(time.Now())
	return err
}

func (c *clientConn) LocalAddr() net.Addr {
	return c.parent.quicConn.LocalAddr()
}

func (c *clientConn) RemoteAddr() net.Addr {
	return c.parent.quicConn.RemoteAddr()
}

func (c *Client) sunnyQUICHandshake(ctx context.Context, quicConn *quic.Conn) error {
	stream, err := quicConn.OpenStreamSync(ctx)
	if err != nil {

		return err
	}
	request := buf.NewSize(1 + 64)
	common.Must(request.WriteByte(commandSunnyQUICAuthentication))
	auth := sha256.Sum256([]byte(c.sunnyQUICUsername + ":" + c.sunnyQUICPassword))
	common.Must1(request.Write(auth[:]))
	common.Must(request.WriteZeroN(32))
	_, err = stream.Write(request.Bytes())
	request.Release()
	stream.Close()
	return err
}

func (c *Client) DialCustomCommandConn(ctx context.Context) (net.Conn, error) {
	conn, err := c.offer(ctx)
	if err != nil {
		return nil, err
	}
	stream, err := conn.quicConn.OpenStreamSync(ctx)
	if err != nil {
		return nil, err
	}
	clientConn := &clientConn{
		Stream: stream,
		parent: conn,
	}
	clientConn.headerWritten = true
	return clientConn, nil
}
