//! Gateway state and packet forwarding.

use lichen_core::addr::NodeId;
use lichen_node::Node;
use lichen_schc::codec::{compress, decompress, SchcError};
use tracing::{info, warn};

/// Top-level border router state.
pub struct Gateway {
    pub node: Node,
    /// Routes installed in the kernel routing table.
    /// Key: mesh IPv6 address (16 bytes, network order); Value: nexthop EUI-64.
    routes: std::collections::HashMap<[u8; 16], NodeId>,
}

impl Gateway {
    pub fn new(node_id: NodeId) -> Self {
        info!(?node_id, "gateway initialising");
        Self {
            node: Node::new(node_id),
            routes: std::collections::HashMap::new(),
        }
    }

    /// SCHC-decompress a frame received from the mesh via SLIP.
    ///
    /// Returns the raw IPv6 packet to inject into the upstream TUN device, or
    /// `None` if decompression fails or the result is not a valid IPv6 packet.
    pub fn mesh_to_upstream(&mut self, schc_frame: &[u8]) -> Option<Vec<u8>> {
        let mut out = vec![0u8; 1500];
        match decompress(schc_frame, &mut out) {
            Ok(n) => {
                out.truncate(n);
                if out.len() < 40 || out[0] >> 4 != 6 {
                    warn!(len = out.len(), "decompressed frame is not IPv6");
                    return None;
                }
                let payload_len = u16::from_be_bytes([out[4], out[5]]);
                info!(payload_len, "mesh → upstream");
                Some(out)
            }
            Err(SchcError::UnknownRuleId(id)) => {
                warn!(rule_id = id, "SCHC: unknown rule — dropping");
                None
            }
            Err(e) => {
                warn!("SCHC decompress: {e:?}");
                None
            }
        }
    }

    /// SCHC-compress an IPv6 packet from the upstream TUN device for the mesh.
    ///
    /// Returns the compressed frame to send via SLIP, or `None` on error.
    pub fn upstream_to_mesh(&mut self, ipv6_packet: &[u8]) -> Option<Vec<u8>> {
        if ipv6_packet.len() < 40 || ipv6_packet[0] >> 4 != 6 {
            warn!(
                len = ipv6_packet.len(),
                "upstream packet is not IPv6 — dropping"
            );
            return None;
        }
        let dst: [u8; 16] = ipv6_packet[24..40].try_into().unwrap();
        if let Some(nexthop) = self.routes.get(&dst) {
            info!(?nexthop, "routing to mesh node");
        }
        let mut out = vec![0u8; ipv6_packet.len() + 2];
        match compress(ipv6_packet, &mut out) {
            Ok(n) => {
                out.truncate(n);
                info!(compressed_len = n, "upstream → mesh");
                Some(out)
            }
            Err(e) => {
                warn!("SCHC compress: {e:?}");
                None
            }
        }
    }

    /// Record that `node_id` is reachable via `addr`.
    pub fn add_route(&mut self, addr: [u8; 16], node_id: NodeId) {
        self.routes.insert(addr, node_id);
    }
}
