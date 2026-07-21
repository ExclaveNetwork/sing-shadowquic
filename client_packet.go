package shadowquic

import (
	"context"
	"encoding/binary"
	"net"

	quic "github.com/metacubex/jls-quic-go"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/metadata"
)

type packet struct {
	data    *buf.Buffer
	address metadata.Socksaddr
}

type controlMessage struct {
	ready   chan struct{}
	conn    *clientPacketConn
	address metadata.Socksaddr
}

func (c *clientQUICConnection) loopDatagrams(ctx context.Context) {
	for {
		datagram, err := c.quicConn.ReceiveDatagram(ctx)
		if err != nil {
			c.close()
			return
		}
		go c.handleDatagram(datagram)
	}
}

func (c *clientQUICConnection) loopUniStreams(ctx context.Context) {
	for {
		stream, err := c.quicConn.AcceptUniStream(ctx)
		if err != nil {
			c.close()
			return
		}
		go c.handleUniStream(stream)
	}
}

func (c *clientQUICConnection) handleUniStream(stream *quic.ReceiveStream) {
	defer stream.CancelRead(0)
	var id uint16
	err := binary.Read(stream, binary.BigEndian, &id)
	if err != nil {
		return
	}
	conn, address, err := c.waitReceiveID(id)
	if err != nil {
		return
	}
	for {
		var length uint16
		err := binary.Read(stream, binary.BigEndian, &length)
		if err != nil {
			return
		}
		data := buf.NewSize(int(length))
		if _, err = data.ReadFullFrom(stream, int(length)); err != nil {
			data.Release()
			return
		}
		select {
		case conn.inputPackets <- packet{
			data:    data,
			address: address,
		}:
		case <-conn.ctx.Done():
			data.Release()
			return
		case <-c.connDone:
			data.Release()
			return
		default:
			data.Release()
		}
	}
}

func (c *clientQUICConnection) handleDatagram(datagram []byte) {
	if len(datagram) < 2 {
		return
	}
	id := binary.BigEndian.Uint16(datagram[:2])
	conn, address, err := c.waitReceiveID(id)
	if err != nil {
		return
	}
	select {
	case conn.inputPackets <- packet{
		data:    buf.As(datagram[2:]),
		address: address,
	}:
	case <-conn.ctx.Done():
		return
	case <-c.connDone:
		return
	default:
	}
}

func (c *clientQUICConnection) waitReceiveID(id uint16) (*clientPacketConn, metadata.Socksaddr, error) {
	for {
		c.access.Lock()
		message, ok := c.receiveIDs[id]
		if ok && message.conn != nil {
			conn := message.conn
			address := message.address
			c.access.Unlock()
			return conn, address, nil
		}
		var ready chan struct{}
		if ok {
			ready = message.ready
		} else {
			ready = make(chan struct{})
			message = &controlMessage{ready: ready}
			c.receiveIDs[id] = message
		}
		c.access.Unlock()
		select {
		case <-ready:
		case <-c.connDone:
			return nil, metadata.Socksaddr{}, net.ErrClosed
		}
	}
}

func (c *clientQUICConnection) storeReceiveID(conn *clientPacketConn, id uint16, address metadata.Socksaddr) {
	c.access.Lock()
	message, ok := c.receiveIDs[id]
	if ok {
		ready := message.conn != nil
		message.conn = conn
		message.address = address
		if !ready {
			close(message.ready)
		}
	} else {
		message = &controlMessage{
			ready:   make(chan struct{}),
			conn:    conn,
			address: address,
		}
		c.receiveIDs[id] = message
		close(message.ready)
	}
	c.access.Unlock()
}

func (c *clientQUICConnection) allocateSendID() (uint16, error) {
	c.access.Lock()
	defer c.access.Unlock()
	start := c.sendID
	for {
		select {
		case <-c.connDone:
			return 0, net.ErrClosed
		default:
		}
		id := c.sendID
		c.sendID++
		if _, ok := c.sendIDs[id]; !ok {
			c.sendIDs[id] = struct{}{}
			return id, nil
		}
		if c.sendID == start {
			return 0, exceptions.New("too many udp contexts")
		}
	}
}

func (c *clientQUICConnection) removeSendIDs(ids []uint16) {
	c.access.Lock()
	for _, id := range ids {
		delete(c.sendIDs, id)
	}
	c.access.Unlock()
}

func (c *clientQUICConnection) removeReceiveIDs(ids []uint16) {
	c.access.Lock()
	for _, id := range ids {
		delete(c.receiveIDs, id)
	}
	c.access.Unlock()
}
