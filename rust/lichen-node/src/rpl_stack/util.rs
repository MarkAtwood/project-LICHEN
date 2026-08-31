// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: The contributors to the LICHEN project

//! IPv6 and L2 address utility functions.

use std::vec;
use std::vec::Vec;

use lichen_core::announce::Announce;
use lichen_core::constants::RPL_ICMPV6_TYPE;
use lichen_core::icmpv6::hdr_field;
use lichen_core::ipv6::{field, next_header, IPV6_HEADER_LEN};
use lichen_core::l2_payload::{
    body as l2_payload_body, classify as classify_l2_payload, L2PayloadKind,
    L2_ROUTING_TYPE_ANNOUNCE,
};
use lichen_ipv6::{icmpv6_checksum, Addr, Ipv6Header};
use lichen_link::frame::{AddrMode, LichenFrame};
use lichen_link::identity::PeerIdentity;
use lichen_link::link_layer::LinkRxError;
use lichen_link::schnorr;
use lichen_rpl::routing::MAX_ROUTE_HOPS;
use lichen_schc::codec;

use crate::announce::AnnounceRejectReason;
use crate::node::{claims_rpl_ipv6, rpl_code};
use crate::stack::RxError;

pub(crate) const RPL_ALL_NODES: [u8; 16] =
    [0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x1a];

pub(crate) fn ipv6_eui64(address: [u8; 16]) -> [u8; 8] {
    let mut eui64: [u8; 8] = address[8..].try_into().unwrap();
    eui64[0] ^= 0x02;
    eui64
}

pub(crate) fn ipv6_l2_destination(address: [u8; 16]) -> Option<[u8; 8]> {
    (address[0] != 0xff).then(|| ipv6_eui64(address))
}

pub(crate) fn link_local_from_iid(iid: [u8; 8]) -> [u8; 16] {
    let mut address = [0u8; 16];
    address[0] = 0xfe;
    address[1] = 0x80;
    address[8..].copy_from_slice(&iid);
    address
}

pub(crate) fn eui64_link_local(mut eui64: [u8; 8]) -> [u8; 16] {
    eui64[0] ^= 0x02;
    link_local_from_iid(eui64)
}

pub(crate) fn rpl_ipv6_packet(
    source: [u8; 16],
    destination: [u8; 16],
    code: u8,
    body: &[u8],
) -> Option<Vec<u8>> {
    let payload_len = hdr_field::BODY_OFFSET.checked_add(body.len())?;
    let payload_len = u16::try_from(payload_len).ok()?;
    let mut packet = vec![0u8; IPV6_HEADER_LEN + usize::from(payload_len)];
    let src = Addr(source);
    let dst = Addr(destination);
    Ipv6Header::new(next_header::ICMPV6, src, dst)
        .write_to(payload_len, &mut packet[..IPV6_HEADER_LEN])
        .ok()?;
    packet[IPV6_HEADER_LEN] = RPL_ICMPV6_TYPE;
    packet[IPV6_HEADER_LEN + 1] = code;
    packet[IPV6_HEADER_LEN + hdr_field::BODY_OFFSET..].copy_from_slice(body);
    let checksum = icmpv6_checksum(&src, &dst, &packet[IPV6_HEADER_LEN..]).ok()?;
    packet[IPV6_HEADER_LEN + 2..IPV6_HEADER_LEN + 4].copy_from_slice(&checksum.to_be_bytes());
    Some(packet)
}

pub(crate) fn dao_ipv6_packet(
    source: [u8; 16],
    destination: [u8; 16],
    dao: &[u8],
) -> Option<Vec<u8>> {
    rpl_ipv6_packet(source, destination, rpl_code::DAO, dao)
}

pub(crate) fn dao_parts(ipv6: &[u8]) -> Option<([u8; 16], &[u8])> {
    use crate::node::valid_rpl_ipv6;

    if !valid_rpl_ipv6(ipv6) || ipv6[IPV6_HEADER_LEN + 1] != rpl_code::DAO {
        return None;
    }
    let source = ipv6[field::SRC_OFFSET..field::DST_OFFSET].try_into().ok()?;
    Some((source, &ipv6[IPV6_HEADER_LEN + hdr_field::BODY_OFFSET..]))
}

pub(crate) fn multicast_dis_jitter(local_eui64: [u8; 8], source: [u8; 16], now_ms: u64) -> u32 {
    let mut hash = 0x811c_9dc5u32;
    for byte in local_eui64
        .into_iter()
        .chain(source)
        .chain(now_ms.to_be_bytes())
    {
        hash = (hash ^ u32::from(byte)).wrapping_mul(0x0100_0193);
    }
    hash
}

pub(crate) fn bootstrap_announce_peer(wire: &[u8]) -> Option<PeerIdentity> {
    let frame = LichenFrame::from_bytes(wire).ok()?;
    if !frame.signature.is_present() {
        return None;
    }
    let inner = frame.payload;
    let announce = Announce::from_bytes(routing_announce(inner).ok()?).ok()?;
    let peer = PeerIdentity::from_pubkey(lichen_link::keys::PublicKey::new(*announce.pubkey));
    let mut expected_signer_eui64 = peer.iid;
    expected_signer_eui64[0] ^= 0x02;
    if peer.iid != *announce.originator_iid
        || frame.signer_eui64 != expected_signer_eui64
        || !schnorr::verify_frame(
            wire[0],
            wire[1],
            frame.epoch,
            frame.seqnum,
            frame.dst_addr,
            frame.signer_eui64,
            frame.payload,
            frame.mic,
            &peer.pubkey,
        )
    {
        return None;
    }
    Some(peer)
}

pub(crate) fn routing_announce(payload: &[u8]) -> Result<&[u8], AnnounceRejectReason> {
    if classify_l2_payload(payload) != L2PayloadKind::Routing {
        return Err(AnnounceRejectReason::Malformed);
    }
    let body = l2_payload_body(payload);
    match body.first() {
        Some(&L2_ROUTING_TYPE_ANNOUNCE) => Ok(body),
        Some(_) | None => Err(AnnounceRejectReason::Malformed),
    }
}

pub(crate) fn wire_is_for_local(wire: &[u8], local_eui64: [u8; 8]) -> Result<bool, LinkRxError> {
    let frame = LichenFrame::from_bytes(wire)?;
    Ok(match frame.addr_mode {
        AddrMode::None => inspect_schc_ipv6(&frame)
            .is_none_or(|ipv6| !claims_rpl_ipv6(&ipv6) || rpl_ipv6_multicast_is_allowed(&ipv6)),
        AddrMode::Short => false,
        AddrMode::Extended => frame.dst_addr == local_eui64,
        AddrMode::Elided => inspect_schc_ipv6(&frame).is_some_and(|ipv6| {
            if claims_rpl_ipv6(&ipv6) {
                return rpl_ipv6_multicast_is_allowed(&ipv6)
                    && ipv6_destination(&ipv6).is_some_and(|destination| {
                        destination[0] == 0xff || ipv6_eui64(destination) == local_eui64
                    });
            }
            let destination: [u8; 16] =
                ipv6[field::DST_OFFSET..IPV6_HEADER_LEN].try_into().unwrap();
            destination[0] == 0xff || ipv6_eui64(destination) == local_eui64
        }),
    })
}

fn inspect_schc_ipv6(frame: &LichenFrame<'_>) -> Option<Vec<u8>> {
    if !frame.signature.is_present() {
        return None;
    }
    let inner = frame.payload;
    if classify_l2_payload(inner) != L2PayloadKind::Schc {
        return None;
    }
    let mut ipv6 = vec![0u8; 256];
    let len = codec::decompress(l2_payload_body(inner), &mut ipv6).ok()?;
    if len < IPV6_HEADER_LEN || ipv6[0] >> 4 != 6 {
        return None;
    }
    ipv6.truncate(len);
    Some(ipv6)
}

pub(crate) fn ipv6_destination(ipv6: &[u8]) -> Option<[u8; 16]> {
    ipv6.get(field::DST_OFFSET..IPV6_HEADER_LEN)
        .and_then(|bytes| <[u8; 16]>::try_from(bytes).ok())
}

pub(crate) fn rpl_ipv6_multicast_is_allowed(ipv6: &[u8]) -> bool {
    ipv6_destination(ipv6)
        .is_some_and(|destination| destination[0] != 0xff || destination == RPL_ALL_NODES)
}

pub(crate) fn dio_dis_destination_is_allowed(ipv6: &[u8], local_rpl_addr: [u8; 16]) -> bool {
    let Some(code) = ipv6.get(IPV6_HEADER_LEN + hdr_field::CODE_OFFSET) else {
        return false;
    };
    if !matches!(*code, rpl_code::DIO | rpl_code::DIS) {
        return true;
    }
    let canonical_source = ipv6
        .get(field::SRC_OFFSET..field::DST_OFFSET)
        .is_some_and(|source| source[..8] == [0xfe, 0x80, 0, 0, 0, 0, 0, 0]);
    canonical_source
        && ipv6_destination(ipv6).is_some_and(|destination| {
            destination == RPL_ALL_NODES
                || (destination[..8] == [0xfe, 0x80, 0, 0, 0, 0, 0, 0]
                    && destination[8..] == local_rpl_addr[8..])
        })
}

/// A located, policy-valid RPL source-routing header within a packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SourceRouteView {
    /// Offset of the Routing header within the packet.
    pub offset: usize,
    /// Total Routing header length in bytes (`(hdr_ext_len + 1) * 8`).
    pub routing_len: usize,
    /// Byte position of the next-header field that points at this header
    /// (6 for the IPv6 header, or the previous extension header's position).
    pub previous_next_header_position: usize,
    /// Number of 16-byte grid addresses.
    pub address_count: usize,
    /// Segments still to be visited.
    pub segments_left: u8,
}

impl SourceRouteView {
    /// True when the header still has segments to visit: RFC 6554 forwarding
    /// precedence applies and the datagram must never be delivered locally.
    pub(crate) fn in_transit(&self) -> bool {
        self.segments_left != 0
    }
}

/// Outcome of surveying a packet's extension chain for RPL source routing
/// (mirrors the C router's `parse_ipv6_dispatch` policy in
/// `lichen/subsys/lichen/routing/router.c`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RoutingHeaderSurvey {
    /// No Routing header in the chain.
    Absent,
    /// Exactly one policy-valid RH3 present (segments consumed or not).
    SourceRouted(SourceRouteView),
}

/// Validate the extension chain and locate any RPL source-routing header.
///
/// Fails closed on: inconsistent payload length, an exhausted Hop Limit, an
/// unspecified or multicast source, unsupported or malformed extensions, a
/// misplaced or repeated Hop-by-Hop header, more than one Routing header, a
/// non-RH3 routing type, misaligned or compression/pad-violating RH3s, more
/// than [`MAX_ROUTE_HOPS`] grid addresses, and grid addresses that are
/// unspecified, multicast, duplicated, equal to the outer destination, or
/// equal to the packet source. An in-transit RH3 (`segments_left != 0`)
/// additionally requires `segments_left < hop_limit` (spec 05-routing 8.4 /
/// RFC 6554).
pub(crate) fn survey_routing_headers(ipv6: &[u8]) -> Result<RoutingHeaderSurvey, RxError> {
    if ipv6.len() < IPV6_HEADER_LEN || ipv6[0] >> 4 != 6 {
        return Err(RxError::InvalidSourceRoute);
    }
    let payload_len = usize::from(u16::from_be_bytes([ipv6[4], ipv6[5]]));
    if IPV6_HEADER_LEN + payload_len != ipv6.len() {
        return Err(RxError::InvalidSourceRoute);
    }
    let source: [u8; 16] = ipv6[8..24].try_into().expect("checked header length");
    let destination: [u8; 16] = ipv6[24..40].try_into().expect("checked header length");
    let hop_limit = ipv6[7];
    if hop_limit == 0 {
        return Err(RxError::InvalidSourceRoute);
    }
    if source == [0; 16] || source[0] == 0xff {
        return Err(RxError::InvalidSourceRoute);
    }

    let mut next_header = ipv6[6];
    let mut offset = IPV6_HEADER_LEN;
    let mut previous_next_header_position = 6usize;
    let mut saw_hop_by_hop = false;
    let mut terminal = false;
    let mut routing: Option<SourceRouteView> = None;
    for _extension_count in 0..4 {
        match next_header {
            next_header::UDP => {
                if ipv6.len() - offset < 8 {
                    return Err(RxError::InvalidSourceRoute);
                }
                terminal = true;
                break;
            }
            next_header::ICMPV6 => {
                if ipv6.len() - offset < 4 {
                    return Err(RxError::InvalidSourceRoute);
                }
                terminal = true;
                break;
            }
            next_header::IPV6_IN_IPV6 => {
                if ipv6.len() - offset < IPV6_HEADER_LEN {
                    return Err(RxError::InvalidSourceRoute);
                }
                terminal = true;
                break;
            }
            next_header::NO_NEXT => {
                if offset != ipv6.len() {
                    return Err(RxError::InvalidSourceRoute);
                }
                terminal = true;
                break;
            }
            next_header::FRAGMENT => return Err(RxError::InvalidSourceRoute),
            next_header::HOP_BY_HOP | next_header::ROUTING | next_header::DEST_OPTIONS => {
                if offset + 2 > ipv6.len() {
                    return Err(RxError::InvalidSourceRoute);
                }
                let routing_len = (usize::from(ipv6[offset + 1]) + 1) * 8;
                let extension_end = offset + routing_len;
                if extension_end > ipv6.len() {
                    return Err(RxError::InvalidSourceRoute);
                }
                // RFC 8200: Hop-by-Hop Options is unique and must immediately
                // follow the IPv6 header.
                if next_header == next_header::HOP_BY_HOP
                    && (saw_hop_by_hop || offset != IPV6_HEADER_LEN)
                {
                    return Err(RxError::InvalidSourceRoute);
                }
                saw_hop_by_hop |= next_header == next_header::HOP_BY_HOP;
                if next_header == next_header::ROUTING {
                    if routing.is_some() || ipv6[offset + 2] != 3 {
                        return Err(RxError::InvalidSourceRoute);
                    }
                    // RFC 6554 4.2: the CmprI/CmprE octet must be zero for
                    // LICHEN's uncompressed profile and the Pad bits must be
                    // zero whenever compression is absent; the remaining
                    // reserved bits are ignored, matching the C router.
                    if (routing_len - 8) % 16 != 0
                        || ipv6[offset + 4] != 0
                        || (ipv6[offset + 5] & 0xf0) != 0
                    {
                        return Err(RxError::InvalidSourceRoute);
                    }
                    let address_count = (routing_len - 8) / 16;
                    if address_count > MAX_ROUTE_HOPS {
                        return Err(RxError::InvalidSourceRoute);
                    }
                    let segments_left = ipv6[offset + 3];
                    if usize::from(segments_left) > address_count {
                        return Err(RxError::InvalidSourceRoute);
                    }
                    for index in 0..address_count {
                        let start = offset + 8 + index * 16;
                        let address: [u8; 16] =
                            ipv6[start..start + 16].try_into().expect("aligned grid");
                        if address == [0; 16]
                            || address[0] == 0xff
                            || address == destination
                            || address == source
                        {
                            return Err(RxError::InvalidSourceRoute);
                        }
                        for prior in 0..index {
                            let prior_start = offset + 8 + prior * 16;
                            if ipv6[prior_start..prior_start + 16] == address {
                                return Err(RxError::InvalidSourceRoute);
                            }
                        }
                    }
                    if segments_left != 0 && usize::from(segments_left) >= usize::from(hop_limit) {
                        return Err(RxError::InvalidSourceRoute);
                    }
                    routing = Some(SourceRouteView {
                        offset,
                        routing_len,
                        previous_next_header_position,
                        address_count,
                        segments_left,
                    });
                }
                previous_next_header_position = offset;
                next_header = ipv6[offset];
                offset = extension_end;
            }
            _ => return Err(RxError::InvalidSourceRoute),
        }
    }
    // Bounded embedded profile: the chain must terminate in an upper protocol
    // within four hops; anything longer is rejected (C router -E2BIG). Without
    // this an unsurveyed fifth header could smuggle an in-transit RH3 past
    // forwarding precedence.
    if !terminal {
        return Err(RxError::InvalidSourceRoute);
    }

    Ok(match routing {
        None => RoutingHeaderSurvey::Absent,
        Some(view) => RoutingHeaderSurvey::SourceRouted(view),
    })
}

/// Consume one RFC 6554 source-route segment in place.
///
/// `current_destination` is the packet's outer destination (the caller's local
/// address); `sender_iid` is the authenticated link-layer sender, whose
/// link-local address must never appear as the next hop (forwarding loop).
///
/// Returns the next destination to relay to, or `None` when `segments_left`
/// was already zero: the header is consumed, stripped, and the packet is
/// addressed to this node for local delivery.
pub(crate) fn advance_rpl_source_route(
    ipv6: &mut Vec<u8>,
    current_destination: [u8; 16],
    sender_iid: [u8; 8],
) -> Result<Option<[u8; 16]>, RxError> {
    let view = match survey_routing_headers(ipv6)? {
        RoutingHeaderSurvey::SourceRouted(view) => view,
        RoutingHeaderSurvey::Absent => return Err(RxError::InvalidSourceRoute),
    };
    if ipv6[24..40] != current_destination {
        return Err(RxError::InvalidSourceRoute);
    }

    if view.segments_left == 0 {
        let plain_payload_len =
            usize::from(u16::from_be_bytes([ipv6[4], ipv6[5]])) - view.routing_len;
        let mut plain = Vec::with_capacity(ipv6.len() - view.routing_len);
        plain.extend_from_slice(&ipv6[..view.offset]);
        plain[view.previous_next_header_position] = ipv6[view.offset];
        plain.extend_from_slice(&ipv6[view.offset + view.routing_len..]);
        plain[4..6].copy_from_slice(&(plain_payload_len as u16).to_be_bytes());
        *ipv6 = plain;
        return Ok(None);
    }

    let next_index = view.address_count - usize::from(view.segments_left);
    let next_start = view.offset + 8 + next_index * 16;
    let next_destination: [u8; 16] = ipv6[next_start..next_start + 16]
        .try_into()
        .expect("surveyed grid address");
    if ipv6_eui64(next_destination) == ipv6_eui64(link_local_from_iid(sender_iid)) {
        return Err(RxError::InvalidSourceRoute);
    }
    ipv6[next_start..next_start + 16].copy_from_slice(&current_destination);
    ipv6[24..40].copy_from_slice(&next_destination);
    ipv6[view.offset + 3] -= 1;
    Ok(Some(next_destination))
}

/// Strip an IPv6-in-IPv6 outer header (spec 05-routing 8.9 R-05-063).
///
/// `expected_dst` is this node's authorized primary 02xx address: the
/// inner destination MUST match it (the E check) or the packet is rejected.
/// Fails closed on any malformed outer or inner header.
pub(crate) fn decapsulate_ipv6(outer: &[u8], expected_dst: [u8; 16]) -> Result<Vec<u8>, RxError> {
    let consistent_payload_len = |packet: &[u8]| {
        packet.len() >= IPV6_HEADER_LEN
            && packet[0] >> 4 == 6
            && IPV6_HEADER_LEN + usize::from(u16::from_be_bytes([packet[4], packet[5]]))
                == packet.len()
    };
    if !consistent_payload_len(outer) || outer[6] != next_header::IPV6_IN_IPV6 {
        return Err(RxError::InvalidSourceRoute);
    }
    let inner = &outer[IPV6_HEADER_LEN..];
    if !consistent_payload_len(inner) {
        return Err(RxError::InvalidSourceRoute);
    }
    if inner[24..40] != expected_dst {
        return Err(RxError::InvalidSourceRoute);
    }
    Ok(inner.to_vec())
}
