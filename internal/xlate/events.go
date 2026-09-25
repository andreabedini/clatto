package xlate

import "net/netip"

// Kind classifies a packet event.
type Kind uint8

const (
	// KindDrop is a packet dropped silently.
	KindDrop Kind = iota
	// KindReject is a packet dropped with an ICMP error returned to the sender.
	KindReject
	// KindICMP is an ICMP message generated for another reason (time exceeded,
	// packet too big) or a fallback such as a synthesised source address.
	KindICMP
	// KindSelf is a packet addressed to the translator's own address.
	KindSelf
	// KindDynamic is a dynamic pool assignment event; Reason carries the detail.
	KindDynamic
	numKinds
)

var kindNames = [...]string{"drop", "reject", "icmp", "self", "dynamic"}

func (k Kind) String() string {
	if int(k) < len(kindNames) {
		return kindNames[k]
	}
	return "unknown"
}

// Reason identifies why an event was raised. The set is closed so that
// observers can pre-allocate counters per reason.
type Reason uint8

const (
	ReasonNone Reason = iota
	ReasonUnknownIPVersion
	ReasonIPHeaderLength
	ReasonIPHeaderInvalid
	ReasonICMPFragmented
	ReasonICMPHeaderLength
	ReasonIPv6OnlyProto
	ReasonIPv4OnlyProto
	ReasonFragmentMisaligned
	ReasonFragmentTooLong
	ReasonICMPChecksumInvalid
	ReasonSelfUnknownProto
	ReasonEchoRequest
	ReasonSelfUnknownICMPType
	ReasonTimeExceeded
	ReasonDestinationUnmappable
	ReasonSourceUnmappable
	ReasonPacketTooBig
	ReasonUDPHeaderLength
	ReasonUDPZeroChecksum
	ReasonTCPHeaderLength
	ReasonEmbeddedTooShort
	ReasonEmbeddedParseFailed
	ReasonICMPErrorOfICMPError
	ReasonEmbeddedUnmappable
	ReasonEmbeddedUntranslatable
	ReasonUnknownUnreachableCode
	ReasonParamProblemInvalidCode
	ReasonParamProblemInvalidPointer
	ReasonParamProblemUntranslatable
	ReasonUnknownICMPType
	ReasonSynthesisedSource
	ReasonExtHeaderLength
	ReasonFragHeaderLength
	ReasonRoutingHeaderSegmentsLeft
	ReasonNoMTUInPacketTooBig
	ReasonDynamicAssigned
	ReasonDynamicReactivated
	ReasonDynamicReassigned
	ReasonDynamicDormant
	ReasonDynamicReleased
	ReasonDynamicExhausted
	numReasons
)

var reasonNames = [...]string{
	"none",
	"unknown_ip_version",
	"ip_header_length",
	"ip_header_invalid",
	"icmp_fragmented",
	"icmp_header_length",
	"ipv6_only_protocol",
	"ipv4_only_protocol",
	"fragment_misaligned",
	"fragment_too_long",
	"icmp_checksum_invalid",
	"self_unknown_protocol",
	"echo_request",
	"self_unknown_icmp_type",
	"time_exceeded",
	"destination_unmappable",
	"source_unmappable",
	"packet_too_big",
	"udp_header_length",
	"udp_zero_checksum",
	"tcp_header_length",
	"embedded_too_short",
	"embedded_parse_failed",
	"icmp_error_of_icmp_error",
	"embedded_unmappable",
	"embedded_untranslatable",
	"unknown_unreachable_code",
	"param_problem_invalid_code",
	"param_problem_invalid_pointer",
	"param_problem_untranslatable",
	"unknown_icmp_type",
	"synthesised_source",
	"extension_header_length",
	"fragment_header_length",
	"routing_header_segments_left",
	"no_mtu_in_packet_too_big",
	"dynamic_assigned",
	"dynamic_reactivated",
	"dynamic_reassigned",
	"dynamic_dormant",
	"dynamic_released",
	"dynamic_exhausted",
}

func (r Reason) String() string {
	if int(r) < len(reasonNames) {
		return reasonNames[r]
	}
	return "unknown"
}

// NumKinds and NumReasons let observers size lookup tables.
const (
	NumKinds   = int(numKinds)
	NumReasons = int(numReasons)
)

// Event describes something that happened to a packet.
type Event struct {
	Kind   Kind
	Reason Reason
	// Family is the IP version of the packet the event refers to (4 or 6).
	Family uint8
	// Proto is the transport protocol of the packet, when parsed.
	Proto uint8
	// Length is the packet length in bytes, when parsed.
	Length int
	// Src and Dst are the packet addresses, when parsed. For dynamic events
	// they are the IPv4 and IPv6 side of the mapping.
	Src, Dst netip.Addr
}

// Observer receives translation statistics and packet events. Methods are
// called from the packet path and must be cheap and safe for concurrent use.
type Observer interface {
	// Translated is called once for every packet successfully translated.
	// family is the IP version of the input packet and n its length.
	Translated(family uint8, n int)
	// Event is called for every drop, reject, generated ICMP or self-addressed
	// packet.
	Event(e Event)
}

// NopObserver ignores everything.
type NopObserver struct{}

func (NopObserver) Translated(uint8, int) {}
func (NopObserver) Event(Event)           {}

// MultiObserver fans out to several observers.
type MultiObserver []Observer

func (m MultiObserver) Translated(f uint8, n int) {
	for _, o := range m {
		o.Translated(f, n)
	}
}

func (m MultiObserver) Event(e Event) {
	for _, o := range m {
		o.Event(e)
	}
}
