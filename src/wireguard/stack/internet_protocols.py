from typing import Optional
from enum import IntEnum


# https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml#protocol-numbers-1
# yapf: disable
class InternetProtocol(IntEnum):
	IP_HOPOPT             = 0x00 # IPv6 Hop-by-Hop Option
	IP_ICMPV4             = 0x01 # Internet Control Message Protocol
	IP_IGMP               = 0x02 # Internet Group Management Protocol
	IP_GGP                = 0x03 # Gateway-to-Gateway Protocol
	IP_IPV4               = 0x04 # IPv4 encapsulation
	IP_ST                 = 0x05 # Stream
	IP_TCP                = 0x06 # Transmission Control Protocol
	IP_CBT                = 0x07 # Core-Based Trees
	IP_EGP                = 0x08 # Exterior Gateway Protocol
	IP_IGP                = 0x09 # Interior Gateway Protocol
	IP_BBN_RRC_MON        = 0x0A # BBN RCC Monitoring
	IP_NVP_II             = 0x0B # Network Voice Protocol
	IP_PUP                = 0x0C # Xerox PUP
	IP_ARGUS              = 0x0D # ARGUS
	IP_EMCON              = 0x0E # EMCON
	IP_XNET               = 0x0F # Cross Net Debugger
	IP_CHAOS              = 0x10 # Chaos
	IP_UDP                = 0x11 # User Datagram Protocol
	IP_MUX                = 0x12 # Multiplexing
	IP_DCN_MEAS           = 0x13 # DCN Measurement Subsystems
	IP_HMP                = 0x14 # Host Monitoring
	IP_PRM                = 0x15 # Packet Radio Measurement
	IP_XNS_IDP            = 0x16 # XEROX NS IDP
	IP_TRUNK_1            = 0x17 # Trunk-1
	IP_TRUNK_2            = 0x18 # Trunk-2
	IP_LEAF_1             = 0x19 # Leaf-1
	IP_LEAF_2             = 0x1A # Leaf-2
	IP_RDP                = 0x1B # Reliable Data Protocol
	IP_IRTP               = 0x1C # Internet Reliable Transaction
	IP_ISO_TP4            = 0x1D # ISO Transport Protocol Class 4
	IP_NETBLT             = 0x1E # Bulk Data Transfer Protocol
	IP_MFE_NSP            = 0x1F # MFE Network Services Protocol
	IP_MERIT_INP          = 0x20 # MERIT Internodal Protocol
	IP_DCCP               = 0x21 # Datagram Congestion Control Protocol
	IP_3PC                = 0x22 # Third Party Connect Protocol
	IP_IDPR               = 0x23 # Inter-Domain Policy Routing Protocol
	IP_XTP                = 0x24 # XTP
	IP_DDP                = 0x25 # Datagram Delivery Protocol
	IP_IDPR_CMTP          = 0x26 # IDPR Control Message Transport Proto
	IP_TPPP               = 0x27 # TP++ Transport Protocol
	IP_IL                 = 0x28 # IL Transport Protocol
	IP_IPV6               = 0x29 # IPv6 encapsulation
	IP_SDRP               = 0x2A # Source Demand Routing Protocol
	IP_IPV6_ROUTE         = 0x2B # Routing Header for IPv6
	IP_IPV6_FRAG          = 0x2C # Fragment Header for IPv6
	IP_IDRP               = 0x2D # Inter-Domain Routing Protocol
	IP_RSVP               = 0x2E # Reservation Protocol
	IP_GRE                = 0x2F # Generic Routing Encapsulation
	IP_DSR                = 0x30 # Dynamic Source Routing Protocol
	IP_BNA                = 0x31 # BNA
	IP_ESP                = 0x32 # Encap Security Payload
	IP_AH                 = 0x33 # Authentication Header
	IP_I_NLSP             = 0x34 # Integrated Net Layer Security  TUBA
	IP_SWIPE              = 0x35 # IP with Encryption (deprecated)
	IP_NARP               = 0x36 # NBMA Address Resolution Protocol
	IP_MIN_IPV4           = 0x37 # Minimal IPv4 Encapsulation
	IP_TLSP               = 0x38 # Transport Layer Security Protocol using Kryptonet key management
	IP_SKIP               = 0x39 # SKIP
	IP_ICMPV6             = 0x3A # ICMP for IPv6
	IP_IPV6_NO_NXT        = 0x3B # No Next Header for IPv6
	IP_IPV6_OPTIONS       = 0x3C # Destination Options for IPv6
	IP_ANY_HOST_INTERNAL  = 0x3D # Any host internal protocol
	IP_CFTP               = 0x3E # CFTP
	IP_ANY_LOCAL_NETWORK  = 0x3F # Any local network
	IP_SAT_EXPAK          = 0x40 # SATNET and Backroom EXPAK
	IP_KRYPTOLAN          = 0x41 # Kryptolan
	IP_RVD                = 0x42 # MIT Remote Virtual Disk Protocol
	IP_IPPC               = 0x43 # Internet Pluribus Packet Core
	IP_ANY_DISTRIBUTED_FS = 0x44 # Any distributed file system
	IP_SAT_MON            = 0x45 # SATNET Monitoring
	IP_VISA               = 0x46 # VISA Protocol
	IP_IPCV               = 0x47 # Internet Packet Core Utility
	IP_CPNX               = 0x48 # Computer Protocol Network Executive
	IP_CPHB               = 0x49 # Computer Protocol Heart Beat
	IP_WSN                = 0x4A # Wang Span Network
	IP_PVP                = 0x4B # Packet Video Protocol
	IP_BR_SAT_MON         = 0x4C # Backroom SATNET Monitoring
	IP_SUN_ND             = 0x4D # SUN ND PROTOCOL-Temporary
	IP_WB_MON             = 0x4E # WIDEBAND Monitoring
	IP_WB_EXPAK           = 0x4F # WIDEBAND EXPAK
	IP_ISO_IP             = 0x50 # ISO Internet Protocol
	IP_VMTP               = 0x51 # VMTP
	IP_SECURE_VMTP        = 0x52 # SECURE-VMTP
	IP_VINES              = 0x53 # VINES
	IP_IPTM               = 0x54 # Internet Protocol Traffic Manager
	IP_NSFNET_IGP         = 0x55 # NSFNET-IGP
	IP_DGP                = 0x56 # Dissimilar Gateway Protocol
	IP_TCF                = 0x57 # TCF
	IP_EIGRP              = 0x58 # EIGRP
	IP_OSPFIGP            = 0x59 # OSPFIGP
	IP_SPRITE_RPC         = 0x5A # Sprite RPC Protocol
	IP_LARP               = 0x5B # Locus Address Resolution Protocol
	IP_MTP                = 0x5C # Multicast Transport Protocol
	IP_AX_25              = 0x5D # AX.25 Frames
	IP_IPIP               = 0x5E # IP-within-IP Encapsulation Protocol
	IP_MICP               = 0x5F # Mobile Internetworking Control Pro. (deprecated)
	IP_SCC_SP             = 0x60 # Semaphore Communications Sec. Pro.
	IP_ETHERIP            = 0x61 # Ethernet-within-IP Encapsulation
	IP_ENCAP              = 0x62 # Encapsulation Header
	IP_ANY_PRIV_ENC       = 0x63 # Any private encryption scheme
	IP_GMTP               = 0x64 # GMTP
	IP_IFMP               = 0x65 # Ipsilon Flow Management Protocol
	IP_PNNI               = 0x66 # PNNI over IP
	IP_PIM                = 0x67 # Protocol Independent Multicast
	IP_ARIS               = 0x68 # ARIS
	IP_SCPS               = 0x69 # SCPS
	IP_QNX                = 0x6A # QNX
	IP_A_N                = 0x6B # Active Networks
	IP_IPCOMP             = 0x6C # IP Payload Compression Protocol
	IP_SNP                = 0x6D # Sitara Networks Protocol
	IP_COMPAQ_PEER        = 0x6E # Compaq Peer Protocol
	IP_IPX_IN_IP          = 0x6F # IPX in IP
	IP_VRRP               = 0x70 # Virtual Router Redundancy Protocol
	IP_PGM                = 0x71 # PGM Reliable Transport Protocol
	IP_ANY_0HOP           = 0x72 # Any 0-hop protocol
	IP_L2TP               = 0x73 # Layer Two Tunneling Protocol
	IP_DDX                = 0x74 # D-II Data Exchange (DDX)
	IP_IATP               = 0x75 # Interactive Agent Transfer Protocol
	IP_STP                = 0x76 # Schedule Transfer Protocol
	IP_SRP                = 0x77 # SpectraLink Radio Protocol
	IP_UTI                = 0x78 # UTI
	IP_SMP                = 0x79 # Simple Message Protocol
	IP_SM                 = 0x7A # Simple Multicast Protocol (deprecated)
	IP_PTP                = 0x7B # Performance Transparency Protocol
	IP_IS_IS_OVER_IPV4    = 0x7C # Intermediate System to Intermediate System over IPv4
	IP_FIRE               = 0x7D # Flexible Intra-AS Routing Environment
	IP_CRTP               = 0x7E # Combat Radio Transport Protocol
	IP_CRUDP              = 0x7F # Combat Radio User Datagram
	IP_SSCOPMCE           = 0x80 # Service-Specific Connection-Oriented Protocol in a Multilink and Connectionless Environment
	IP_IPLT               = 0x81
	IP_SPS                = 0x82 # Secure Packet Shield
	IP_PIPE               = 0x83 # Private IP Encapsulation within IP
	IP_SCTP               = 0x84 # Stream Control Transmission Protocol
	IP_FC                 = 0x85 # Fibre Channel
	IP_RSVP_E2E_IGNORE    = 0x86 # Reservation Protocol (RSVP) End-to-End Ignore
	IP_MOBILITY_HEADER    = 0x87 # Mobility Extension Header for IPv6
	IP_UDP_LITE           = 0x88 # Lightweight User Datagram Protocol
	IP_MPLS_IN_IP         = 0x89 # Multiprotocol Label Switching Encapsulated in IP
	IP_MANET              = 0x8A # MANET Protocols
	IP_HIP                = 0x8B # Host Identity Protocol
	IP_SHIM6              = 0x8C # Shim6 Protocol
	IP_WESP               = 0x8D # Wrapped Encapsulating Security Payload
	IP_ROHC               = 0x8E # Robust Header Compression
	IP_ETHERNET           = 0x8F # Ethernet
	IP_AGGFRAG            = 0x90 # AGGFRAG encapsulation payload for ESP
	IP_NSH                = 0x91 # Network Service Header
	IP_HOMA               = 0x92 # Homa
	IP_BIT_EMU            = 0x93 # Bit-stream Emulation
	# 0x94-0xFC Reserved
	# 0xFD, 0xFE Use for testing and experimentation
	# 0xFF Reserved
# yapf: enable


def internet_protocol_to_str(protocol: Optional[InternetProtocol | int]):
	if protocol is None:
		return "None"
	elif isinstance(protocol, InternetProtocol):
		return protocol.name

	# @note We don't use x in Enum because of back compatibility with python 3.10.x
	try:
		return InternetProtocol(protocol).name
	except ValueError:
		return "Unknown"
