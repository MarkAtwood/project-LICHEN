<!-- SPDX-License-Identifier: CC-BY-4.0 -->
<!-- SPDX-FileCopyrightText: The contributors to the LICHEN project -->

# Primary RF Authority Rule Matrix (US, 902-928 MHz)

**Status:** Dated primary-source record. Read-only research; confers no
permission to contact an authority, file documents, or transmit. Bead
`project-LICHEN-worker6-x7hh.2.2.1` (hpc8-deep leaf `authority.02`).

**Source policy:** The conference decision `project-LICHEN-worker6-b79z`
selected Part 15 ISM as the operating basis family. This matrix records rule
branches; it does not select any deployment's regulatory classification and
does not reopen that decision. Amateur (Part 97) operation is a separate
basis, out of scope here except where rule text cross-references it.

**Retrieval date:** 2026-09-09, all eCFR links below. eCFR content current as
of 2026-09-04 (Title 47 last amended 2026-09-03). eCFR is authoritative but
unofficial; the published CFR is annual. Equations rendered as images in the
source are cited by pinpoint reference, not reproduced.

**Classes:** `rule` = CFR rule text; `rule (project)` = LICHEN spec or
conformance requirement, not authority text; `guidance` = FCC/OET published
guidance (non-binding per its own terms); `device` = device/grant-specific
condition; `unresolved` = interpretation question reserved for human
adjudication.

## 1. Ordinary FHSS (frequency-hopping spread spectrum)

| Branch | Requirement | Citation | Class |
|--------|-------------|----------|-------|
| Carrier separation | Hopping carriers separated by min 25 kHz or the 20 dB bandwidth of the hopping channel, whichever is greater | [47 CFR 15.247(a)(1)](https://www.ecfr.gov/current/title-47/part-15/section-15.247) | rule |
| Pseudorandom use | Hop to frequencies selected from a pseudo-randomly ordered list; each frequency used equally on average by each transmitter; receiver input bandwidths match hopping channel bandwidths and shift in synchronization | 15.247(a)(1) | rule |
| 20 dB BW < 250 kHz | At least 50 hopping frequencies; average occupancy per frequency ≤ 0.4 s within any 20 s period | 15.247(a)(1)(i) | rule |
| 20 dB BW ≥ 250 kHz | At least 25 hopping frequencies; average occupancy per frequency ≤ 0.4 s within any 10 s period | 15.247(a)(1)(i) | rule |
| Max bandwidth | Maximum allowed 20 dB bandwidth of the hopping channel: 500 kHz | 15.247(a)(1)(i) | rule |
| Power, ≥50 channels | Max peak conducted output power 1 W | 15.247(b)(2) | rule |
| Power, 25-49 channels | Max peak conducted output power 0.25 W | 15.247(b)(2) | rule |
| Channel use | System need not use all channels each transmission, but must comply if presented a continuous data stream; short-burst systems must still distribute transmissions over the minimum hopping-channel count | 15.247(g) | rule |
| Adaptive hopsets | Intelligence recognizing other users and independently adapting hopsets is permitted; coordination between hopping systems to avoid simultaneous occupancy of individual frequencies is **not** permitted | 15.247(h) | rule |
| Fixed-channel scheduling | Whether a fixed receiver-home/CH0 schedule within an otherwise FHSS design satisfies "system shall hop" and (g)'s continuous-stream test is an interpretation question for the grantee/TCB; not resolved by rule text alone | 15.247(a)(1), (g) | unresolved |

## 2. DTS (digitally modulated systems)

| Branch | Requirement | Citation | Class |
|--------|-------------|----------|-------|
| Bandwidth | Minimum 6 dB bandwidth ≥ 500 kHz (902-928, 2400-2483.5, 5725-5850 MHz). 125 kHz LoRa CSS does not qualify by itself | [15.247(a)(2)](https://www.ecfr.gov/current/title-47/part-15/section-15.247) | rule |
| Power | 1 W max conducted; compliance may be based on maximum conducted output power (averaged per (b)(3) definition) | 15.247(b)(3) | rule |
| Spectral density | ≤ 8 dBm in any 3 kHz band during any continuous transmission interval | 15.247(e) | rule |

## 3. Hybrid systems (FHSS + digital modulation)

| Branch | Requirement | Citation | Class |
|--------|-------------|----------|-------|
| FHSS leg | With digital modulation off, average occupancy ≤ 0.4 s within (number of hopping frequencies × 0.4 s) | [15.247(f)](https://www.ecfr.gov/current/title-47/part-15/section-15.247) | rule |
| DTS leg | With hopping off, PSD ≤ 8 dBm in any 3 kHz | 15.247(f) | rule |
| Transition | § 15.37(h) transition provisions apply to hybrids beginning 2015-06-02 (Note to (f)) | 15.247(f) note | rule |
| Test conditions | Hybrid test configuration selection (which leg off, dwell accounting) is test-procedure guidance, not rule text | 15.247(f); KDB guidance channel (§9) | unresolved |

## 4. Out-of-band and unwanted emissions

| Branch | Requirement | Citation | Class |
|--------|-------------|----------|-------|
| Out-of-band | In any 100 kHz outside the operating band, RF power ≥ 20 dB below the in-band 100 kHz maximum (30 dB if conducted-power compliance used RMS averaging per (b)(3)); restricted-band emissions must additionally meet § 15.209(a) per § 15.205(c) | [15.247(d)](https://www.ecfr.gov/current/title-47/part-15/section-15.247) | rule |
| Restricted bands | Only spurious emissions permitted in the § 15.205(a) band table; field strength within them ≤ § 15.209 limits; ≤1000 MHz measured CISPR quasi-peak, >1000 MHz average | [15.205(a)-(c)](https://www.ecfr.gov/current/title-47/part-15/section-15.205) (last amended 2026-01-26, 91 FR 3069) | rule |
| General limits | Radiated limits by frequency: 0.009-0.490 MHz 2400/F(kHz) µV/m @ 300 m; 0.490-1.705 MHz 24000/F(kHz) @ 30 m; 1.705-30 MHz 30 µV/m @ 30 m; 30-88 MHz 100 µV/m @ 3 m; 88-216 MHz 150 @ 3 m; 216-960 MHz 200 @ 3 m; above 960 MHz 500 @ 3 m; tighter limit applies at band edges | [15.209(a)-(b)](https://www.ecfr.gov/current/title-47/part-15/section-15.209) | rule |

## 5. Antennas

| Branch | Requirement | Citation | Class |
|--------|-------------|----------|-------|
| Approved antenna only | Intentional radiator designed so no antenna other than the responsible party's is used; permanently attached antenna or unique coupling satisfies this; a standard antenna jack or connector is prohibited (user replacement of a broken antenna allowed only with non-standard coupling) | [15.203](https://www.ecfr.gov/current/title-47/part-15/section-15.203) (last amended 2017-09-01, 82 FR 41559) | rule |
| Gain > 6 dBi | Conducted power reduced below the (b) limits by the dB amount the directional gain exceeds 6 dBi | [15.247(b)(4)](https://www.ecfr.gov/current/title-47/part-15/section-15.247) | rule |
| Fixed point-to-point exception | >6 dBi antennas without full reduction exist only for 2400-2483.5 MHz (1 dB per 3 dB) and 5725-5850 MHz (no reduction); **no fixed PtP exception is enumerated for 902-928 MHz** — the (b)(4) reduction applies | 15.247(c)(1)(i)-(iii) | rule |
| Multi-beam | Sequential/simultaneous directional-beam provisions apply to 2400-2483.5 MHz only | 15.247(c)(2) | rule |

## 6. Equipment changes (post-grant)

| Branch | Requirement | Citation | Class |
|--------|-------------|----------|-------|
| Basic changes | Changes to frequency-determining/stabilizing circuitry (incl. clock/data rates), frequency multiplication stages, basic modulator circuit, or max power/field-strength ratings require a new grant; software changes that do not affect RF emissions need no filing and may be made by non-grantees | [47 CFR 2.1043(a)](https://www.ecfr.gov/current/title-47/part-2/section-2.1043) | rule |
| Class I permissive | Modifications not degrading accepted characteristics; no filing; grantee-only (except as specified) | 2.1043(b)(1), (b)(4) | rule |
| Class II permissive | Modifications degrading reported performance but still meeting minimums; grantee files information/tests; equipment must not be marketed before acknowledgement; filing must include Covered-List statement and US agent-for-service-of-process details | 2.1043(b)(2) (as amended 2023-02-06, 88 FR 7625; 2025-11-25, 90 FR 53237) | rule |
| Class III permissive | SDR software changes altering frequency range, modulation type, or max output power outside approved parameters, or changing operating circumstances; grantee-only, and only when no Class II changes from the originally approved device; software must not be loaded/marketed before acknowledgement | 2.1043(b)(3) | rule |
| Other changes | Any change outside permissive classes, or one changing the FCC ID, requires a new application and grant before marketing | 2.1043(c)-(d) | rule |
| Amateur exception | Part 97-certificated equipment may be modified notwithstanding (b) under licensed-amateur conditions | 2.1043(e) | rule |
| Firmware/scheduling changes | Whether a CCP scheduling-profile change on an already-certified module is a (b)(1), (b)(2), (b)(3), or new-grant event depends on the module's grant and SDR status; device-specific, not derivable from rule text | 2.1043(a)-(c) | unresolved |

## 7. Module integration

| Branch | Requirement | Citation | Class |
|--------|-------------|----------|-------|
| Single module | Shielded radio elements; buffered modulation/data inputs; own power-supply regulation; antenna per § 15.203 (permanent or unique coupler; professional-installation provision inapplicable); tested stand-alone; FCC ID labeling/e-label incl. host exterior "Contains FCC ID" label; RF exposure compliance in final configuration | [47 CFR 15.212(a)(1)](https://www.ecfr.gov/current/title-47/part-15/section-15.212) (last amended 2020-04-01, 85 FR 18149) | rule |
| Split module | Front-end shielding, ≥150 mV p-p digital interface, tested in representative host(s), authorized-pair enforcement | 15.212(a)(2) | rule |
| Limited modular approval | Available where not all (a) conditions met; applicant must state how end-product compliance control is maintained | 15.212(b) | rule |
| Host integration beyond grant | Integrating a certified module into a host outside the grant's conditions (antenna, separation distance, co-location) is a device-specific grant-condition question; grant exhibits control | grant-specific (see § 9) | device |

## 8. RF exposure

| Branch | Requirement | Citation | Class |
|--------|-------------|----------|-------|
| Applicability | Part 15 devices subject to §§ 1.1307(b), 1.1310, 2.1091, 2.1093; equipment-authorization applications must contain a compliance statement; technical basis submitted on request | [15.247(i)](https://www.ecfr.gov/current/title-47/part-15/section-15.247); [15.212(a)(1)(viii)](https://www.ecfr.gov/current/title-47/part-15/section-15.212) | rule |
| Evaluation gate | Single RF source exempt from routine evaluation if ≤ 1 mW available max time-averaged power, or ≤ P_th formula (0.3-6 GHz, 0.5-40 cm, equation in source), or ≤ Table 1 ERP threshold at separation R ≥ λ/2π (300-1500 MHz: 0.0128·R²·f W; arithmetic illustration, not a measurement: f=915 MHz, R=0.2 m → ≈0.47 W) | [1.1307(b)(1)-(3)](https://www.ecfr.gov/current/title-47/part-1/section-1.1307) | rule |
| SAR limits | Occupational: 0.4 W/kg whole body, 8 W/kg peak 1 g (20 W/kg extremities 10 g), ≤6 min averaging. General population: 0.08 W/kg, 1.6 W/kg 1 g (4 W/kg extremities 10 g), ≤30 min averaging. SAR applies 100 kHz-6 GHz | [1.1310(a)-(c)](https://www.ecfr.gov/current/title-47/part-1/section-1.1310) (source 85 FR 18145, 2020-04-01) | rule |
| MPE alternative | 300 kHz-6 GHz may use Table 1 MPE (at 902-928 MHz: occupational f/300 ≈ 3 mW/cm², general population f/1500 ≈ 0.6 mW/cm²); >6 GHz must use MPE; portable devices always SAR per 2.1093 | 1.1310(d)-(e) | rule |
| Mobile (≥20 cm) | Evaluation required above the § 1.1307(b)(3)(i) exemptions and the ERP_20cm formula in 2.1091(c)(1) (equation in source); compliance statement in application; consumer devices use general-population limits; time averaging based on maximum duty factor is not usable for consumer general-population exposure, while source-based time averaging on an inherent property of the RF source is allowed over ≤ 30 min (2.1091(d)(2)(ii)) | [2.1091(b)-(d)](https://www.ecfr.gov/current/title-47/part-2/section-2.1091) | rule |
| Portable (<20 cm) | SAR evaluation (lab measurement or validated computation) above exemptions/P_th formula (0.5-20 cm, equation in source); consumer portables always general-population; visual advisories cannot convert consumer use to occupational | [2.1093(b)-(d)](https://www.ecfr.gov/current/title-47/part-2/section-2.1093) | rule |
| Mitigation (fixed) | Category One (compliant) requires no mitigation, optional INFORMATION sign only; signage and positive-access-control duties for fixed sources attach at Categories Two through Four where limits are exceeded | 1.1307(b)(4) | rule |
| Exposure evaluation methods | OET Bulletin 65 and supplements; OET Lab Division KDB for SAR measurement/computation procedures — staff guidance, expressly non-binding | 1.1310(d)(4); [2.1093(d)(2)](https://www.ecfr.gov/current/title-47/part-2/section-2.1093) | guidance |

## 9. Device-specific conditions and guidance not attached here

| Item | Status | Class |
|------|--------|-------|
| Per-FCC-ID grant conditions (grants, exhibits, TCB correspondence) | Collected under roll-up `x7hh.2.1`; each module's grant controls over this generic matrix | device |
| KDB publication numbers for FHSS/hybrid measurement and module integration | KDB index named by 1.1310(d)(4) and 2.1093(d)(2) as the guidance channel; specific publications not retrieved or attached in this leaf | guidance |
| LICHEN deployment-profile duties | `spec/02b-ccp-receiver-aware.md` CCP2-022 requires each deployment profile to document its operating authority and measured-bandwidth/occupancy/power conditions; `docs/ccp-conformance.md` CCP2-022/CCP2-026 rows map evidence classes | rule (project) |
| Regulatory classification of any LICHEN deployment (FHSS vs DTS vs hybrid, permissive-change class, exposure category) | Reserved for grantee/TCB determination and human adjudication (`x7hh.2.3` roll-up); nothing here selects a classification | unresolved |

## 10. Downstream use

- `authority.01` and later qualification leaves derive authorization tuples
  from the device inventory and this matrix together; a matrix row plus a
  device grant, not a matrix row alone, establishes an applicable condition.
- Any wire, PHY, or scheduling change touching CCP2-022 evidence must
  re-check § 6 (permissive-change class) and § 1-3 (operating-basis branch)
  before claiming continued authorization coverage.
- Retrieval dates are part of every citation; re-verify eCFR currency before
  relying on this matrix after 2026-09-09.
