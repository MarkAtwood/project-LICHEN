//! Authenticated L2 inner-payload dispatch helpers.

use crate::constants::{L2_DISPATCH_ROUTING, L2_DISPATCH_SCHC, L2_DISPATCH_SOS};
use crate::error::BufferTooSmall;

/// Routing/control message type for LICHEN announce.
pub const L2_ROUTING_TYPE_ANNOUNCE: u8 = 0x01;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum L2PayloadKind {
    Schc,
    Routing,
    /// SOS emergency alert (dispatch 0x16, spec 02-physical-link.md §4.1).
    Sos,
    Unknown,
}

pub fn classify(payload: &[u8]) -> L2PayloadKind {
    if payload.len() < 2 {
        return L2PayloadKind::Unknown;
    }
    match payload.first().copied() {
        Some(L2_DISPATCH_SCHC) => L2PayloadKind::Schc,
        Some(L2_DISPATCH_ROUTING) => L2PayloadKind::Routing,
        Some(L2_DISPATCH_SOS) => L2PayloadKind::Sos,
        _ => L2PayloadKind::Unknown,
    }
}

/// Unknown L2 dispatch byte (or empty payload).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnknownDispatch;

/// Classify and reject unknown dispatch bytes.
pub fn classify_known(payload: &[u8]) -> Result<L2PayloadKind, UnknownDispatch> {
    match classify(payload) {
        L2PayloadKind::Unknown => Err(UnknownDispatch),
        kind => Ok(kind),
    }
}

pub fn body(payload: &[u8]) -> &[u8] {
    payload.get(1..).unwrap_or(&[])
}

/// Prefix a compressed SCHC packet with the L2 SCHC dispatch byte.
pub fn wrap_schc_payload<'a>(schc: &[u8], out: &'a mut [u8]) -> Result<&'a [u8], BufferTooSmall> {
    let needed = schc
        .len()
        .checked_add(1)
        .ok_or(BufferTooSmall::new(usize::MAX, out.len()))?;
    if out.len() < needed {
        return Err(BufferTooSmall::new(needed, out.len()));
    }
    out[0] = L2_DISPATCH_SCHC;
    out[1..needed].copy_from_slice(schc);
    Ok(&out[..needed])
}

/// Prefix a §18.4.2 CBOR SOS alert map with the L2 SOS dispatch byte (0x16).
/// The body is NOT SCHC-compressed (SOS is small and latency-critical,
/// spec 02-physical-link.md §4.1).
pub fn wrap_sos_payload<'a>(sos_cbor: &[u8], out: &'a mut [u8]) -> Result<&'a [u8], BufferTooSmall> {
    let needed = sos_cbor
        .len()
        .checked_add(1)
        .ok_or(BufferTooSmall::new(usize::MAX, out.len()))?;
    if out.len() < needed {
        return Err(BufferTooSmall::new(needed, out.len()));
    }
    out[0] = L2_DISPATCH_SOS;
    out[1..needed].copy_from_slice(sos_cbor);
    Ok(&out[..needed])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::RULE_GLOBAL_COAP;

    #[test]
    fn dispatch_distinguishes_global_coap_rule_from_announce() {
        let schc = [L2_DISPATCH_SCHC, RULE_GLOBAL_COAP, 0x40];
        let announce = [L2_DISPATCH_ROUTING, L2_ROUTING_TYPE_ANNOUNCE, 0x00];

        assert_eq!(classify(&schc), L2PayloadKind::Schc);
        assert_eq!(body(&schc), &[RULE_GLOBAL_COAP, 0x40]);
        assert_eq!(classify(&announce), L2PayloadKind::Routing);
        assert_eq!(body(&announce), &[L2_ROUTING_TYPE_ANNOUNCE, 0x00]);
        assert_eq!(schc[1], announce[1]);
    }

    #[test]
    fn unwrapped_first_byte_is_unknown() {
        assert_eq!(classify(&[RULE_GLOBAL_COAP, 0x00]), L2PayloadKind::Unknown);
        assert_eq!(classify(&[]), L2PayloadKind::Unknown);
        assert_eq!(
            classify_known(&[RULE_GLOBAL_COAP, 0x00]),
            Err(UnknownDispatch)
        );
        assert_eq!(classify_known(&[]), Err(UnknownDispatch));
        // 0x16 is the SOS dispatch (spec 02-physical-link.md §4.1), NOT unknown.
        assert_eq!(classify_known(&[0x16, 0xa0]), Ok(L2PayloadKind::Sos));
        assert_eq!(
            classify_known(&[L2_DISPATCH_SCHC, RULE_GLOBAL_COAP]),
            Ok(L2PayloadKind::Schc)
        );
        assert_eq!(
            classify_known(&[L2_DISPATCH_ROUTING, L2_ROUTING_TYPE_ANNOUNCE]),
            Ok(L2PayloadKind::Routing)
        );
    }

    #[test]
    fn sos_dispatch_classifies_and_wraps() {
        // spec 12-apps.md §18.4.3: SOS is emitted with dispatch 0x16 carrying
        // the §18.4.2 CBOR alert map, NOT SCHC-compressed.
        let sos_cbor = [0xa2, 0x62, 0x74, 0x73, 0x1a]; // fragment of a CBOR map
        let mut out = [0u8; 16];
        let wrapped = wrap_sos_payload(&sos_cbor, &mut out).unwrap();
        assert_eq!(wrapped[0], L2_DISPATCH_SOS);
        assert_eq!(&wrapped[1..], &sos_cbor);
        assert_eq!(classify(wrapped), L2PayloadKind::Sos);
        assert_eq!(body(wrapped), &sos_cbor);
        // Buffer too small -> BufferTooSmall, no partial write past len.
        let mut tiny = [0u8; 2];
        assert!(wrap_sos_payload(&sos_cbor, &mut tiny).is_err());
    }

    #[test]
    fn dispatch_namespace_is_exhaustive_and_single_octet_is_malformed() {
        for dispatch in u8::MIN..=u8::MAX {
            let expected = match dispatch {
                L2_DISPATCH_SCHC => L2PayloadKind::Schc,
                L2_DISPATCH_ROUTING => L2PayloadKind::Routing,
                L2_DISPATCH_SOS => L2PayloadKind::Sos,
                _ => L2PayloadKind::Unknown,
            };

            assert_eq!(classify(&[dispatch, 0]), expected);
            assert_eq!(classify(&[dispatch]), L2PayloadKind::Unknown);
        }
    }

    #[test]
    fn wrap_schc_payload_roundtrips_dispatch_and_body() {
        let schc = [RULE_GLOBAL_COAP, 0x40];
        let mut out = [0u8; 4];
        let wrapped = wrap_schc_payload(&schc, &mut out).unwrap();
        assert_eq!(wrapped, &[L2_DISPATCH_SCHC, RULE_GLOBAL_COAP, 0x40]);
        assert_eq!(classify(wrapped), L2PayloadKind::Schc);
        assert_eq!(body(wrapped), &schc);
        assert_eq!(
            wrap_schc_payload(&schc, &mut [0u8; 2]),
            Err(BufferTooSmall::new(3, 2))
        );
    }
}
