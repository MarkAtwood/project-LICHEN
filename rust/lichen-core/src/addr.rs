//! Address types: IPv6Addr and NodeId (EUI-64).

/// A 128-bit IPv6 address, stored in network (big-endian) byte order.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct Ipv6Addr(pub [u8; 16]);

impl Ipv6Addr {
    pub const UNSPECIFIED: Self = Self([0u8; 16]);

    /// True if this is a link-local address (fe80::/10).
    pub fn is_link_local(&self) -> bool {
        self.0[0] == 0xfe && (self.0[1] & 0xc0) == 0x80
    }
}

/// A 64-bit node identifier (EUI-64 derived from the radio hardware address).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct NodeId(pub [u8; 8]);

impl NodeId {
    /// Derive the link-local IPv6 address from this EUI-64 (spec §6.2).
    ///
    /// Flips the U/L bit (bit 6 of octet 0) and prefixes with `fe80::/64`.
    /// NodeId is already EUI-64 — no `ff:fe` insertion (that is the separate
    /// MAC-48 → EUI-64 step, not needed here).
    pub fn link_local_addr(&self) -> Ipv6Addr {
        self.addr_with_prefix([0xfe, 0x80, 0, 0, 0, 0, 0, 0])
    }

    /// Derive a ULA or GUA address from this EUI-64 and a `/64` prefix.
    ///
    /// `prefix` is the high 8 bytes of the target address; the low 8 bytes
    /// are the EUI-64 interface identifier (U/L bit flipped per RFC 4291).
    /// Equivalent to `link_local_addr` but with a caller-supplied prefix.
    pub fn ula_addr(&self, prefix: [u8; 8]) -> Ipv6Addr {
        self.addr_with_prefix(prefix)
    }

    fn addr_with_prefix(&self, prefix: [u8; 8]) -> Ipv6Addr {
        let e = self.0;
        Ipv6Addr([
            prefix[0],
            prefix[1],
            prefix[2],
            prefix[3],
            prefix[4],
            prefix[5],
            prefix[6],
            prefix[7],
            e[0] ^ 0x02,
            e[1],
            e[2],
            e[3],
            e[4],
            e[5],
            e[6],
            e[7],
        ])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn link_local_flips_ul_bit() {
        let node = NodeId([0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01]);
        let ll = node.link_local_addr();
        assert_eq!(ll.0[0], 0xfe);
        assert_eq!(ll.0[1], 0x80);
        assert_eq!(ll.0[8], 0x00); // 0x02 ^ 0x02 = 0x00
    }

    #[test]
    fn ula_addr_uses_supplied_prefix() {
        let node = NodeId([0x02, 0xAB, 0xCD, 0xEF, 0x00, 0x00, 0x00, 0x01]);
        let prefix = [0xfd, 0x00, 0x11, 0x22, 0x33, 0x44, 0x00, 0x00];
        let ula = node.ula_addr(prefix);
        assert_eq!(&ula.0[..8], &prefix);
        assert_eq!(ula.0[8], 0x00); // 0x02 ^ 0x02
        assert_eq!(&ula.0[9..], &[0xAB, 0xCD, 0xEF, 0x00, 0x00, 0x00, 0x01]);
    }

    #[test]
    fn is_link_local() {
        let node = NodeId([0x02, 0, 0, 0, 0, 0, 0, 1]);
        assert!(node.link_local_addr().is_link_local());
    }

    #[test]
    fn ula_addr_is_not_link_local() {
        let node = NodeId([0x02, 0, 0, 0, 0, 0, 0, 1]);
        let prefix = [0xfd, 0x00, 0, 0, 0, 0, 0, 0];
        assert!(!node.ula_addr(prefix).is_link_local());
    }
}
