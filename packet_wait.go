package shadowquic

import (
	"io"
	"os"

	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/common/network"
)

var (
	_ network.PacketReadWaiter = (*clientPacketConn)(nil)
)

func (c *clientPacketConn) InitializeReadWaiter(options network.ReadWaitOptions) (needCopy bool) {
	c.readWaitOptions = options
	return options.NeedHeadroom()
}

func (c *clientPacketConn) WaitReadPacket() (*buf.Buffer, metadata.Socksaddr, error) {
	select {
	case packet := <-c.inputPackets:
		if c.readWaitOptions.NeedHeadroom() {
			buffer := c.readWaitOptions.NewPacketBuffer()
			_, err := buffer.ReadOnceFrom(packet.data)
			packet.data.Release()
			if err != nil {
				buffer.Release()
				return buffer, packet.address, err
			}
			c.readWaitOptions.PostReturn(buffer)
			return buffer, packet.address, nil
		} else {
			return packet.data, packet.address, nil
		}
	case <-c.ctx.Done():
		return nil, metadata.Socksaddr{}, io.ErrClosedPipe
	case <-c.readDeadline.Wait():
		return nil, metadata.Socksaddr{}, os.ErrDeadlineExceeded
	}
}
