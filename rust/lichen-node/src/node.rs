//! Node state and receive-path dispatch.

use lichen_core::{addr::Ipv6Addr, addr::NodeId, icmpv6};
use lichen_schc::codec;

/// Top-level node state.
pub struct Node {
    pub node_id: NodeId,
}

impl Node {
    pub fn new(node_id: NodeId) -> Self {
        Self { node_id }
    }

    /// Process a received SCHC frame.
    ///
    /// Decompresses the frame and dispatches on protocol:
    /// - ICMPv6 Echo Request addressed to this node → builds a SCHC-compressed
    ///   Echo Reply into `reply` and returns the byte count.
    ///
    /// Returns 0 when no reply should be sent.
    ///
    /// `reply` must be at least 258 bytes (2-byte rule header + max ICMPv6 echo).
    pub fn handle_frame(&self, schc_frame: &[u8], reply: &mut [u8]) -> usize {
        let mut ipv6 = [0u8; 256];
        let n = match codec::decompress(schc_frame, &mut ipv6) {
            Ok(n) => n,
            Err(_) => return 0,
        };
        if n < 40 || ipv6[0] >> 4 != 6 {
            return 0;
        }
        let pkt = &ipv6[..n];

        let nh = pkt[6];
        if nh == 58 && n >= 48 && pkt[40] == icmpv6::ECHO_REQUEST {
            let mut dst_bytes = [0u8; 16];
            dst_bytes.copy_from_slice(&pkt[24..40]);
            if dst_bytes == self.node_id.link_local_addr().0 {
                return self.reply_echo(pkt, reply);
            }
        }
        0
    }

    fn reply_echo(&self, ipv6: &[u8], out: &mut [u8]) -> usize {
        let mut reply_src = [0u8; 16];
        let mut reply_dst = [0u8; 16];
        reply_src.copy_from_slice(&ipv6[24..40]); // original dst = our address
        reply_dst.copy_from_slice(&ipv6[8..24]); // original src = requester

        let id = u16::from_be_bytes([ipv6[44], ipv6[45]]);
        let seq = u16::from_be_bytes([ipv6[46], ipv6[47]]);
        let data = &ipv6[48..];

        let mut reply_pkt = [0u8; 256];
        let n = icmpv6::echo_reply(
            &Ipv6Addr(reply_src),
            &Ipv6Addr(reply_dst),
            id,
            seq,
            data,
            &mut reply_pkt,
        );

        codec::compress(&reply_pkt[..n], out).unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node(iid: u8) -> Node {
        Node::new(NodeId([0x02, 0, 0, 0, 0, 0, 0, iid]))
    }

    /// Build a SCHC-compressed ICMPv6 Echo Request from src_iid to dst_iid.
    fn schc_echo_request(src_iid: u8, dst_iid: u8) -> ([u8; 64], usize) {
        let src = NodeId([0x02, 0, 0, 0, 0, 0, 0, src_iid]).link_local_addr();
        let dst = NodeId([0x02, 0, 0, 0, 0, 0, 0, dst_iid]).link_local_addr();
        let mut pkt = [0u8; 52];
        let n = icmpv6::echo_request(&src, &dst, 42, 7, b"ping", &mut pkt);
        let mut out = [0u8; 64];
        let clen = codec::compress(&pkt[..n], &mut out).unwrap();
        (out, clen)
    }

    #[test]
    fn echo_request_to_self_yields_reply() {
        let n = node(1);
        let (req, rlen) = schc_echo_request(2, 1); // from node 2 to node 1
        let mut reply = [0u8; 258];
        let len = n.handle_frame(&req[..rlen], &mut reply);
        assert_ne!(len, 0, "expected a reply");
        // Verify reply decompresses to a valid Echo Reply
        let mut ipv6 = [0u8; 256];
        let rn = codec::decompress(&reply[..len], &mut ipv6).unwrap();
        assert_eq!(ipv6[40], icmpv6::ECHO_REPLY, "type should be Echo Reply");
        assert_eq!(&ipv6[48..rn], b"ping", "payload should be echoed");
    }

    #[test]
    fn echo_request_to_other_node_yields_no_reply() {
        let n = node(1);
        let (req, rlen) = schc_echo_request(1, 2); // for node 2, not node 1
        let mut reply = [0u8; 258];
        assert_eq!(n.handle_frame(&req[..rlen], &mut reply), 0);
    }

    #[test]
    fn non_icmpv6_frame_yields_no_reply() {
        let n = node(1);
        let mut reply = [0u8; 258];
        // Rule 255 header + garbage: decompressor will return a short packet
        let frame = [0xffu8, 0x00];
        assert_eq!(n.handle_frame(&frame, &mut reply), 0);
    }
}
