package shadowquic

import (
	"net/netip"

	"github.com/sagernet/sing/common/metadata"
)

const (
	commandTCPConnect                 byte = 0x01
	commandUDPAssociationOverDatagram byte = 0x03
	commandUDPAssociationOverStream   byte = 0x04
	commandSunnyQUICAuthentication    byte = 0x05
)

var addressSerializer = metadata.NewSerializer(
	metadata.AddressFamilyByte(0x01, metadata.AddressFamilyIPv4),
	metadata.AddressFamilyByte(0x03, metadata.AddressFamilyFqdn),
	metadata.AddressFamilyByte(0x04, metadata.AddressFamilyIPv6),
)

var (
	udpAssociateAddress = metadata.Socksaddr{Addr: netip.IPv4Unspecified(), Port: 0}
)
