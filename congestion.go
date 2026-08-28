package shadowquic

import (
	congestion_meta1 "github.com/exclavenetwork/sing-shadowquic/internal/congestion_meta1"
	congestion_meta2 "github.com/exclavenetwork/sing-shadowquic/internal/congestion_meta2"
	quic "github.com/metacubex/jls-quic-go"
	"github.com/metacubex/jls-quic-go/congestion"
)

func setCongestion(connection *quic.Conn, congestionName string) {
	switch congestionName {
	case "cubic":
		connection.SetCongestionControl(
			congestion_meta1.NewCubicSender(
				congestion.ByteCount(connection.Config().InitialPacketSize),
				false,
			),
		)
	case "new_reno":
		connection.SetCongestionControl(
			congestion_meta1.NewCubicSender(
				congestion.ByteCount(connection.Config().InitialPacketSize),
				true,
			),
		)
	case "bbr":
		connection.SetCongestionControl(congestion_meta2.NewBbrSender(
			congestion.ByteCount(connection.Config().InitialPacketSize),
			congestion.ByteCount(congestion_meta2.InitialCongestionWindowPackets),
		))
	}
}
