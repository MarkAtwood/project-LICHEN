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

    /// True if this is a Unique Local Address (fc00::/7, typically fd00::/8).
    ///
    /// Per RFC 4193, ULAs have the prefix fc00::/7. In practice, the L bit
    /// (bit 8) is set to 1 for locally-assigned addresses, giving fd00::/8.
    pub fn is_ula(&self) -> bool {
        // fc00::/7 means first byte has top 7 bits = 1111110x (0xfc or 0xfd)
        (self.0[0] & 0xfe) == 0xfc
    }

    /// True if this is a Global Unicast Address (2000::/3).
    ///
    /// Per RFC 4291, GUAs have the prefix 2000::/3, meaning the first 3 bits
    /// are 001 (addresses 2000:: through 3fff::).
    pub fn is_gua(&self) -> bool {
        // 2000::/3 means first byte has top 3 bits = 001 (0x20..0x3f)
        (self.0[0] & 0xe0) == 0x20
    }

    /// True if this is a multicast address (ff00::/8).
    pub fn is_multicast(&self) -> bool {
        self.0[0] == 0xff
    }

    /// True if this is the loopback address (::1).
    pub fn is_loopback(&self) -> bool {
        self.0 == [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]
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

    #[test]
    fn is_ula_fd00() {
        // fd00::/8 is a common ULA prefix
        let addr = Ipv6Addr([0xfd, 0x00, 0x12, 0x34, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        assert!(addr.is_ula());
        assert!(!addr.is_link_local());
        assert!(!addr.is_gua());
    }

    #[test]
    fn is_ula_fc00() {
        // fc00::/8 is also technically ULA (but L=0, rarely used)
        let addr = Ipv6Addr([0xfc, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        assert!(addr.is_ula());
    }

    #[test]
    fn is_gua() {
        // 2001:db8::/32 is documentation prefix (a GUA)
        let addr = Ipv6Addr([0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        assert!(addr.is_gua());
        assert!(!addr.is_ula());
        assert!(!addr.is_link_local());
    }

    #[test]
    fn is_gua_range() {
        // 2000::/3 means 2000:: through 3fff::
        let addr_2000 = Ipv6Addr([0x20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        let addr_3fff = Ipv6Addr([0x3f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0, 0, 0, 0, 0, 0, 0, 1]);
        assert!(addr_2000.is_gua());
        assert!(addr_3fff.is_gua());

        // 4000:: is NOT a GUA
        let addr_4000 = Ipv6Addr([0x40, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        assert!(!addr_4000.is_gua());
    }

    #[test]
    fn is_multicast() {
        let addr = Ipv6Addr([0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        assert!(addr.is_multicast());
        assert!(!addr.is_ula());
        assert!(!addr.is_gua());
    }

    #[test]
    fn is_loopback() {
        let addr = Ipv6Addr([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        assert!(addr.is_loopback());
        assert!(!addr.is_ula());
        assert!(!addr.is_gua());
        assert!(!addr.is_multicast());
    }
}
