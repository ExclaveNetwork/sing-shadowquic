package shadowquic

import (
	"context"
	"time"

	congestion_meta1 "github.com/exclavenetwork/sing-shadowquic/internal/congestion_meta1"
	congestion_meta2 "github.com/exclavenetwork/sing-shadowquic/internal/congestion_meta2"
	quic "github.com/metacubex/jls-quic-go"
	"github.com/metacubex/jls-quic-go/congestion"
	"github.com/sagernet/sing/common/ntp"
)

func setCongestion(ctx context.Context, connection *quic.Conn, congestionName string) {
	timeFunc := ntp.TimeFuncFromContext(ctx)
	if timeFunc == nil {
		timeFunc = time.Now
	}
	switch congestionName {
	case "cubic":
		connection.SetCongestionControl(
			congestion_meta1.NewCubicSender(
				congestion_meta1.DefaultClock{TimeFunc: timeFunc},
				congestion.ByteCount(connection.Config().InitialPacketSize),
				false,
			),
		)
	case "new_reno":
		connection.SetCongestionControl(
			congestion_meta1.NewCubicSender(
				congestion_meta1.DefaultClock{TimeFunc: timeFunc},
				congestion.ByteCount(connection.Config().InitialPacketSize),
				true,
			),
		)
	case "bbr":
		connection.SetCongestionControl(congestion_meta2.NewBbrSender(
			congestion_meta2.DefaultClock{TimeFunc: timeFunc},
			congestion.ByteCount(connection.Config().InitialPacketSize),
			congestion.ByteCount(congestion_meta1.InitialCongestionWindow),
		))
	}
}
