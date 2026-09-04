// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: The contributors to the LICHEN project

//! Packet transmission methods.

use std::vec::Vec;

use lichen_core::announce::Announce;
use lichen_core::ipv6::{next_header, IPV6_HEADER_LEN};
use lichen_hal::{NonVolatile, Radio, RadioConfig};
use lichen_ipv6::Ipv6Header;
use lichen_link::identity::iid_from_pubkey;
use lichen_link::schnorr;
use lichen_rpl::routing::DaoTxError;

use crate::node::{rpl_code, valid_ipv6_envelope};
use crate::stack::{Priority, TxError};

use super::error::{DaoSendError, RplControlError};
use super::util::{
    dao_ipv6_packet, ipv6_eui64, ipv6_l2_destination, link_local_from_iid, rpl_ipv6_packet,
    RPL_ALL_NODES,
};
use super::{RplRole, RplStack};

/// Root DIO signature validity window (spec 06 8.10.1: expiry is an
/// absolute Unix timestamp; 5 minutes bounds the replay-useful window
/// while tolerating clock skew).
#[cfg(feature = "root-sig")]
pub(crate) const ROOT_SIG_TTL_SECONDS: u64 = 300;

impl<R: Radio, S: NonVolatile> RplStack<R, S> {
    pub fn configure_radio(&mut self, config: &RadioConfig) {
        self.stack.radio().configure(config);
    }

    pub async fn send_announce(
        &mut self,
        announce_wire: &[u8],
        _now_ms: u32,
    ) -> Result<(), RplControlError> {
        let announce =
            Announce::from_bytes(announce_wire).map_err(|_| RplControlError::MalformedAnnounce)?;
        let local_key = self.stack.local_public_key();
        let mut signed = [0u8; 256];
        let signed_len = announce
            .write_signed_data(&mut signed)
            .map_err(|_| RplControlError::MalformedAnnounce)?;
        if *announce.originator_iid != iid_from_pubkey(&local_key)
            || *announce.pubkey != *local_key.as_bytes()
            || !schnorr::verify(&local_key, &signed[..signed_len], announce.signature)
        {
            return Err(RplControlError::MalformedAnnounce);
        }
        let mut payload = Vec::with_capacity(announce_wire.len() + 1);
        payload.push(lichen_core::constants::L2_DISPATCH_ROUTING);
        payload.extend_from_slice(announce_wire);
        self.stack
            .send_l2_payload_to(&payload, &[])
            .await
            .map_err(RplControlError::Transmit)
    }

    pub async fn send_dio(&mut self, _destination: [u8; 16]) -> Result<(), TxError> {
        let mut body = [0u8; 512];
        // Root-signature producer (spec 06 8.10.1, bead b7z9.88.2): when
        // this stack is the DODAG root with a valid wall clock, sign the
        // DIO (expiry = now + ROOT_SIG_TTL_SECONDS) and append the 0x17
        // option. Receivers without a pin or with an unassessable clock
        // degrade to link-layer baseline (R-06-307).
        #[cfg(feature = "root-sig")]
        let len = if self.rpl.router.dodag.is_root() {
            match self.wall_clock_unix {
                Some(clock) => self
                    .rpl
                    .router
                    .build_authenticated_dio_with_root_sig(
                        &mut body,
                        self.stack.link_ref(),
                        clock() + ROOT_SIG_TTL_SECONDS,
                    ),
                None => self
                    .rpl
                    .router
                    .build_authenticated_dio(&mut body, self.stack.link_ref()),
            }
        } else {
            self.rpl
                .router
                .build_authenticated_dio(&mut body, self.stack.link_ref())
        };
        #[cfg(not(feature = "root-sig"))]
        let len = self
            .rpl
            .router
            .build_authenticated_dio(&mut body, self.stack.link_ref());
        if len == 0 {
            return Err(TxError::BufferTooSmall);
        }
        // Canonical multicast DIO delivery (spec 09 13.3 R-09-005): every
        // DIO — solicited or trickle — targets ff02::1a with broadcast L2.
        // Unicast-dst DIOs are inadmissible at wire_is_for_local (the
        // profile's admission contract, Python authenticated_dio.py parity),
        // so callers naming a neighbor are re-targeted to the all-RPL-nodes
        // multicast group. RFC 6550 8.3's unicast-response SHOULD is
        // superseded by this profile contract.
        let control_destination = RPL_ALL_NODES;
        let packet = rpl_ipv6_packet(
            self.local_control_addr,
            control_destination,
            rpl_code::DIO,
            &body[..len],
        )
        .ok_or(TxError::BufferTooSmall)?;
        let l2_destination = ipv6_l2_destination(control_destination);
        // RPL DIO is control traffic (P1) and is carried uncompressed
        // (Rule 255): the authenticated-DIO admission gate accepts only
        // Rule 255 frames (spec 09 13.3 R-09-005).
        self.stack
            .send_ipv6_uncompressed_to(
                &packet,
                l2_destination.as_ref().map_or(&[], <[u8; 8]>::as_slice),
            )
            .await
    }

    pub async fn send_dis(&mut self, destination: [u8; 16]) -> Result<(), TxError> {
        let control_destination = if destination[0] == 0xff {
            destination
        } else {
            link_local_from_iid(destination[8..].try_into().expect("complete IPv6 IID"))
        };
        let packet = rpl_ipv6_packet(
            self.local_control_addr,
            control_destination,
            rpl_code::DIS,
            &[0, 0],
        )
        .ok_or(TxError::BufferTooSmall)?;
        let l2_destination = ipv6_l2_destination(control_destination);
        // RPL DIS is control traffic (P1)
        self.stack
            .send_ipv6_to(
                &packet,
                l2_destination.as_ref().map_or(&[], <[u8; 8]>::as_slice),
                Priority::Routing,
            )
            .await
    }

    pub async fn send_dao(&mut self) -> Result<(), DaoSendError<S::Error>> {
        let RplRole::Leaf(tx) = &mut self.role else {
            return Err(DaoSendError::NotLeaf);
        };
        let dao = if let Some(dao) = tx.last_signed_dao() {
            dao.to_vec()
        } else {
            self.rpl
                .build_signed_dao(
                    self.local_rpl_addr,
                    tx,
                    &mut self.storage,
                    self.stack.link(),
                )
                .map_err(DaoSendError::Dao)?
        };
        self.transmit_dao(&dao).await?;
        let RplRole::Leaf(tx) = &mut self.role else {
            unreachable!("DAO sender role changed during transmission")
        };
        tx.clear_transmitted(&mut self.storage)
            .map_err(DaoSendError::Dao)
    }

    async fn transmit_dao(&mut self, dao: &[u8]) -> Result<(), DaoSendError<S::Error>> {
        let dodag_id = self.rpl.router.dodag_id();
        let next_hop = self
            .rpl
            .preferred_parent()
            .ok_or(DaoSendError::Dao(DaoTxError::NotJoined))?;
        let packet = dao_ipv6_packet(self.local_rpl_addr, dodag_id, dao)
            .ok_or(DaoSendError::PacketTooLarge)?;
        // RPL DAO is control traffic (P1)
        self.stack
            .send_ipv6_to(&packet, &ipv6_eui64(next_hop), Priority::Routing)
            .await
            .map_err(DaoSendError::Transmit)
    }

    /// Send a non-CoAP IPv6 diagnostic through the selected RPL/gradient next hop.
    pub async fn send_ipv6(&mut self, ipv6: &[u8], now_ms: u64) -> Result<(), TxError> {
        let header = Ipv6Header::from_bytes(ipv6).map_err(|_| TxError::BufferTooSmall)?;
        if !valid_ipv6_envelope(ipv6) {
            return Err(TxError::BufferTooSmall);
        }
        if header.next_header == next_header::UDP {
            let udp = lichen_ipv6::UdpHeader::from_bytes(&ipv6[IPV6_HEADER_LEN..])
                .map_err(|_| TxError::BufferTooSmall)?;
            if udp.src_port == lichen_core::constants::PORT_COAP
                || udp.dst_port == lichen_core::constants::PORT_COAP
            {
                return Err(TxError::PlaintextCoap);
            }
        } else if matches!(header.next_header, 0 | 43 | 44 | 50 | 51 | 60) {
            return Err(TxError::UnsupportedIpv6Extension);
        }
        let route = self
            .route_for(header.dst.0, now_ms, false)
            .ok_or(TxError::NoRoute)?;
        // Non-CoAP IPv6 diagnostic uses Normal priority (P3)
        self.stack
            .send_ipv6_to_route(ipv6, &route.next_hop, &route.source_route, Priority::Normal)
            .await
    }

    /// Border-router egress for an already routed IPv6 packet.
    ///
    /// This still uses the owned stack's durable link tuple allocation,
    /// SCHC compressor, signer, CCA, and radio path. `destination` is the
    /// immediate link EUI-64; `None` emits a signed broadcast.
    pub async fn send_border_ipv6(
        &mut self,
        ipv6: &[u8],
        destination: Option<[u8; 8]>,
    ) -> Result<(), TxError> {
        if !valid_ipv6_envelope(ipv6) {
            return Err(TxError::BufferTooSmall);
        }
        self.stack
            .send_ipv6_to(
                ipv6,
                destination.as_ref().map_or(&[], <[u8; 8]>::as_slice),
                Priority::Normal,
            )
            .await
    }

    pub fn last_signed_dao(&self) -> Option<&[u8]> {
        match &self.role {
            RplRole::Leaf(state) => state.last_signed_dao(),
            RplRole::Root(_) => None,
        }
    }
}
