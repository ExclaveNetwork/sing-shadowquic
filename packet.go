package shadowquic

import (
	"context"
	"encoding/binary"
	"io"
	"maps"
	"net"
	"os"
	"slices"
	"sync"
	"time"

	quic "github.com/metacubex/jls-quic-go"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	"github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/pipe"
)

var (
	_ network.NetPacketConn = (*clientPacketConn)(nil)
	_ network.FrontHeadroom = (*clientPacketConn)(nil)
)

type clientPacketConn struct {
	ctx    context.Context
	cancel context.CancelFunc
	parent *clientQUICConnection

	udpOverStream   bool
	closeOnce       sync.Once
	readWaitOptions network.ReadWaitOptions
	readDeadline    pipe.Deadline
	writeDeadline   pipe.Deadline

	inputPackets chan packet

	controlAccess        sync.Mutex
	control              *quic.Stream
	controlHeaderWritten bool

	access       sync.Mutex
	sendIDs      map[metadata.Socksaddr]uint16
	sendIDSet    map[uint16]struct{}
	receiveIDSet map[uint16]struct{}
	sendStreams  map[metadata.Socksaddr]*quic.SendStream
}

func newClientPacketConn(ctx context.Context, parent *clientQUICConnection, control *quic.Stream, udpOverStream bool) network.NetPacketConn {
	ctx, cancel := context.WithCancel(ctx)
	c := &clientPacketConn{
		ctx:           ctx,
		cancel:        cancel,
		parent:        parent,
		udpOverStream: udpOverStream,
		readDeadline:  pipe.MakeDeadline(),
		writeDeadline: pipe.MakeDeadline(),
		inputPackets:  make(chan packet, 128),
		control:       control,
		sendIDs:       make(map[metadata.Socksaddr]uint16),
		sendIDSet:     make(map[uint16]struct{}),
		receiveIDSet:  make(map[uint16]struct{}),
	}
	if udpOverStream {
		c.sendStreams = make(map[metadata.Socksaddr]*quic.SendStream)
	}
	go c.loopReadControl()
	go func() {
		<-c.ctx.Done()
		c.Close()
	}()
	return c
}

func (c *clientPacketConn) loopReadControl() {
	for {
		addr, err := addressSerializer.ReadAddrPort(c.control)
		if err != nil {
			return
		}
		var id uint16
		err = binary.Read(c.control, binary.BigEndian, &id)
		if err != nil {
			return
		}
		c.access.Lock()
		c.receiveIDSet[id] = struct{}{}
		c.access.Unlock()
		c.parent.storeReceiveID(c, id, addr)
	}
}

func (c *clientPacketConn) writeControl(id uint16, destination metadata.Socksaddr) error {
	c.controlAccess.Lock()
	bufferSize := addressSerializer.AddrPortLen(destination) + 2
	if !c.controlHeaderWritten {
		bufferSize += 1 + addressSerializer.AddrPortLen(udpAssociateAddress)
	}
	request := buf.NewSize(bufferSize)
	if !c.controlHeaderWritten {
		if c.udpOverStream {
			common.Must(request.WriteByte(commandUDPAssociationOverStream))
		} else {
			common.Must(request.WriteByte(commandUDPAssociationOverDatagram))
		}
		common.Must(addressSerializer.WriteAddrPort(request, udpAssociateAddress))
	}
	common.Must(addressSerializer.WriteAddrPort(request, destination))
	common.Must(binary.Write(request, binary.BigEndian, id))
	_, err := c.control.Write(request.Bytes())
	request.Release()
	if err == nil {
		c.controlHeaderWritten = true
	}
	c.controlAccess.Unlock()
	return err
}

func (c *clientPacketConn) ReadPacket(buffer *buf.Buffer) (metadata.Socksaddr, error) {
	select {
	case packet := <-c.inputPackets:
		_, err := buffer.ReadOnceFrom(packet.data)
		packet.data.Release()
		if err != nil {
			return metadata.Socksaddr{}, err
		}
		return packet.address, nil
	case <-c.ctx.Done():
		return metadata.Socksaddr{}, io.ErrClosedPipe
	case <-c.readDeadline.Wait():
		return metadata.Socksaddr{}, os.ErrDeadlineExceeded
	}
}

func (c *clientPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	buffer := buf.With(p)
	destination, err := c.ReadPacket(buffer)
	if err != nil {
		return 0, nil, err
	}
	if destination.IsDomain() {
		return buffer.Len(), destination, nil
	} else {
		return buffer.Len(), destination.UDPAddr(), nil
	}
}

func (c *clientPacketConn) FrontHeadroom() int {
	if c.udpOverStream {
		return 2 + 2
	} else {
		return 2
	}
}

func (c *clientPacketConn) WritePacket(buffer *buf.Buffer, destination metadata.Socksaddr) error {
	defer buffer.Release()

	bufferLen := buffer.Len()
	if bufferLen > 0xffff {
		return &quic.DatagramTooLargeError{MaxDatagramPayloadSize: 0xffff}
	}

	select {
	case <-c.ctx.Done():
		return io.ErrClosedPipe
	case <-c.writeDeadline.Wait():
		return os.ErrDeadlineExceeded
	default:
	}

	c.access.Lock()
	id, ok := c.sendIDs[destination]
	if !ok {
		var err error
		id, err = c.parent.allocateSendID()
		if err != nil {
			c.access.Unlock()
			return err
		}
		c.sendIDs[destination] = id
		c.sendIDSet[id] = struct{}{}
		go func() {
			writeErr := c.writeControl(id, destination)
			if writeErr != nil {
				c.access.Lock()
				delete(c.sendIDs, destination)
				delete(c.sendIDSet, id)
				c.access.Unlock()
				c.parent.removeSendIDs([]uint16{id})
			}
		}()
	}
	c.access.Unlock()

	if c.udpOverStream {
		c.access.Lock()
		stream, ok := c.sendStreams[destination]
		c.access.Unlock()
		if ok {
			header := buf.With(buffer.ExtendHeader(2))
			common.Must(binary.Write(header, binary.BigEndian, uint16(bufferLen)))
		} else {
			var err error
			stream, err = c.parent.quicConn.OpenUniStreamSync(c.ctx)
			if err != nil {
				return err
			}
			header := buf.With(buffer.ExtendHeader(4))
			common.Must(binary.Write(header, binary.BigEndian, id))
			common.Must(binary.Write(header, binary.BigEndian, uint16(bufferLen)))
		}
		_, err := stream.Write(buffer.Bytes())
		if err == nil {
			c.access.Lock()
			c.sendStreams[destination] = stream
			c.access.Unlock()
		} else {
			stream.Close()
			c.access.Lock()
			delete(c.sendStreams, destination)
			c.access.Unlock()
		}
		return err
	} else {
		header := buf.With(buffer.ExtendHeader(2))
		common.Must(binary.Write(header, binary.BigEndian, id))
		return c.parent.quicConn.SendDatagram(buffer.Bytes())
	}
}

func (c *clientPacketConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	return bufio.WritePacketBuffer(c, buf.As(p), metadata.SocksaddrFromNet(addr))
}

func (c *clientPacketConn) Close() error {
	c.closeOnce.Do(func() {
		c.cancel()
		c.control.CancelRead(0)
		c.control.Close()
		c.control.SetWriteDeadline(time.Now())
		c.access.Lock()
		streams := c.sendStreams
		sendIDs := slices.Collect(maps.Keys(c.sendIDSet))
		receiveIDs := slices.Collect(maps.Keys(c.receiveIDSet))
		c.access.Unlock()
		for _, stream := range streams {
			stream.Close()
		}
		c.parent.removeSendIDs(sendIDs)
		c.parent.removeReceiveIDs(receiveIDs)
	})
	return nil
}

func (c *clientPacketConn) LocalAddr() net.Addr {
	return c.parent.quicConn.LocalAddr()
}

func (c *clientPacketConn) SetDeadline(t time.Time) error {
	c.readDeadline.Set(t)
	c.writeDeadline.Set(t)
	return nil
}

func (c *clientPacketConn) SetReadDeadline(t time.Time) error {
	c.readDeadline.Set(t)
	return nil
}

func (c *clientPacketConn) SetWriteDeadline(t time.Time) error {
	c.writeDeadline.Set(t)
	return nil
}
