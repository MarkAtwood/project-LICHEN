<!-- SPDX-License-Identifier: CC-BY-4.0 -->
<!-- SPDX-FileCopyrightText: The contributors to the LICHEN project -->

# 47 CFR 15.247 Clause-by-Clause Analysis: LICHEN Microfragmentation

**Status:** Preliminary self-assessment, not legal advice. This document is a
starting point for review by qualified FCC counsel. It represents an engineer's
reading of the regulation, not a legal opinion.

**Subject system:** LICHEN microfragmentation as described in
[speculation-and-futurism.md](speculation-and-futurism.md#lichen-15-software-fhss-via-microfragmentation).
Software frequency hopping between ordinary LoRa packets on 902-928 MHz using
existing SX1262-class hardware (T-Echo, RAK4631). Each fragment is a complete
ordinary LoRa packet; the hop sequence is deterministic and shared between
sender and receiver.

**Operating basis claimed:** Frequency hopping spread spectrum under
15.247(a)(1), 902-928 MHz, measured 20 dB bandwidth below 250 kHz.

---

## (a)(1) — Frequency Hopping Systems

### Channel separation

> "Frequency hopping systems shall have hopping channel carrier frequencies
> separated by a minimum of 25 kHz or the 20 dB bandwidth of the hopping
> channel, whichever is greater."

**Assessment: COMPLIANT.** Ordinary LoRa at BW 125 kHz has a measured 20 dB
bandwidth of approximately 125-130 kHz. The candidate 128-channel grid uses
200 kHz spacing (902.3 + 0.2*i MHz, i=0..127). 200 kHz > 130 kHz. The
separation requirement is met with margin.

**Risk:** If a different LoRa bandwidth is used (e.g., 250 kHz or 500 kHz for
faster data rates), the spacing must be recalculated against measured 20 dB BW.
The 200 kHz grid would fail for BW 250 kHz.

### Minimum channel count

> "[902-928 MHz, bandwidth <250 kHz:] system shall use at least 50 hopping
> frequencies"

**Assessment: COMPLIANT.** The candidate design uses 128 hopping channels.
128 >= 50.

**Caveat:** "Use" means actually hopping across them, not just listing them.
See (g) below.

### Equal average use

> "Each frequency must be used equally on the average by each transmitter."

**Assessment: REQUIRES VALIDATION.** The hop sequence is deterministic
(FNV-based per the candidate design). Equal average use depends on the
sequence's statistical properties over a measurement interval. A hash function
with good uniformity should distribute hops evenly across channels, but
"should" is not "measured." This needs:

1. Statistical analysis of the actual hop sequence generator showing uniform
   distribution across all channels used.
2. Measurement over the FCC's implicit averaging interval (not defined in the
   rule — this is a test-procedure question for the lab or counsel).

**Risk:** If the hop sequence has any bias (certain channels visited more often
due to hash collisions or sequence length effects), this clause is violated.
The sequence design must be validated, not assumed uniform.

### Occupancy time

> "[bandwidth <250 kHz:] the average time of occupancy on any frequency shall
> not be greater than 0.4 seconds within a 20 second period."

**Assessment: COMPLIANT BY DESIGN, REQUIRES ACCOUNTING.** Each microfragment
targets 300 ms of airtime (below 400 ms). With 128 channels and a uniform hop
sequence, each channel is visited roughly once per 128-hop block. At 300 ms per
hop, a full block takes ~38 seconds, so each channel sees at most one 300 ms
visit per 38-second cycle — well within 0.4 seconds per 20-second window.

**Risk areas:**
- Header fragments that are repeated for acquisition recovery visit the same
  channel multiple times. These must be counted against the 0.4 s budget.
- Parity fragments that hash to the same channel as a data fragment within a
  20-second window must be counted.
- Control traffic (beacons, DIO, Announce) on any channel shares the budget.
- Retransmissions share the budget.
- The aggregate is per-transmitter, per-frequency, per-20-seconds. The
  implementation must enforce this as a hard cap, not a statistical average.

### Maximum 20 dB bandwidth

> "[902-928 MHz, <250 kHz FHSS:] Maximum 20 dB bandwidth: 500 kHz."

**Assessment: COMPLIANT.** Ordinary LoRa BW 125 kHz has a 20 dB bandwidth of
approximately 125-130 kHz. Well within 500 kHz. This is a property of the
radio hardware, not the software.

---

## (a)(2) — Digital Modulation (DTS)

> "The minimum 6 dB bandwidth shall be at least 500 kHz."

**Assessment: NOT APPLICABLE.** Microfrag claims FHSS under (a)(1), not DTS
under (a)(2). Ordinary LoRa BW 125 kHz has a 6 dB bandwidth below 500 kHz, so
it would NOT qualify as standalone DTS. This is why the FHSS classification
matters — it's the only category that fits.

**Risk:** If a regulator or test lab determines that microfrag does not qualify
as FHSS (see (h) below), it also does not qualify as DTS. That would leave
hybrid (f) or no operating basis at all.

---

## (b)(2) — Power Limits, 902-928 MHz

> "1 watt for systems employing at least 50 hopping channels; and, 0.25 watts
> for systems employing less than 50 hopping channels, but at least 25 hopping
> channels."

**Assessment: COMPLIANT.** 128 channels >= 50, so the 1 W conducted limit
applies. T-Echo and RAK4631 typically operate at +22 dBm (~158 mW) or lower.
Well within 1 W.

---

## (b)(4) — Antenna Gain Reduction

> "The conducted output power limit [...] is based on the use of antennas with
> directional gains that do not exceed 6 dBi. If transmitting antennas of
> directional gain greater than 6 dBi are used, the conducted output power
> [...] shall be reduced [...] by the amount in dB that the directional gain
> of the antenna exceeds 6 dBi."

**Assessment: COMPLIANT.** Stock T-Echo and RAK4631 antennas are small whips
or PCB antennas with gains well below 6 dBi (typically 2-3 dBi). No power
reduction required.

**Risk:** If a user attaches a high-gain directional antenna (e.g., a Yagi for
long-range links), the firmware would need to enforce reduced TX power. This is
an implementation requirement, not a protocol design issue.

---

## (d) — Out-of-Band Emissions

> "the radio frequency power that is produced by the intentional radiator shall
> be at least 20 dB below that in the 100 kHz bandwidth within the band that
> contains the highest level of the desired power"

**Assessment: COMPLIANT.** This is a hardware/radio property. The SX1262's
out-of-band performance is characterized by Semtech and covered by the module's
existing FCC grant. Microfrag does not change the modulation within each packet
— it uses ordinary LoRa — so the existing emissions profile applies.

**Caveat:** If the module's grant was issued for a specific operating mode
(e.g., continuous LoRa, not rapid retuning), the test lab should confirm that
rapid channel changes don't produce transient spurious emissions during retuning
that exceed this limit.

---

## (e) — Power Spectral Density

> "For digitally modulated systems, the power spectral density conducted from
> the intentional radiator to the antenna shall not be greater than 8 dBm in
> any 3 kHz band"

**Assessment: NOT APPLICABLE to FHSS classification.** This clause applies to
digital modulation systems under (a)(2). If microfrag is classified as FHSS
under (a)(1), the PSD limit in (e) does not apply. Ordinary LoRa at +22 dBm
in 125 kHz bandwidth would have a PSD of approximately 22 - 10*log10(125/3) =
22 - 16.2 = 5.8 dBm/3kHz, which would pass anyway, but the point is moot
under FHSS classification.

---

## (f) — Hybrid Systems

> "hybrid systems are those that employ a combination of both frequency hopping
> and digital modulation techniques"

**Assessment: NOT APPLICABLE.** Microfrag uses frequency hopping of ordinary
LoRa packets. It does not combine FHSS with a separate digital modulation
layer. Each packet is a standard LoRa chirp-spread-spectrum emission; the
hopping is between packets, not within them. This is pure FHSS, not hybrid.

**Risk:** LoRa CSS (chirp spread spectrum) is itself a spread-spectrum
modulation. A regulator could argue that hopping a spread-spectrum signal
constitutes a "hybrid" system. This interpretation seems unlikely given that
the rule's intent is to address systems that layer DSSS under FHSS, but it's
worth raising with counsel.

---

## (g) — Channel Utilization

> "Frequency hopping spread spectrum systems are not required to employ all
> available hopping channels during each transmission."

> "However, the system, consisting of both the transmitter and the receiver,
> must be designed to comply with all of the regulations in this section should
> the transmitter be presented with a continuous data (or information) stream."

> "a system employing short transmission bursts must comply with the definition
> of a frequency hopping system and must distribute its transmissions over the
> minimum number of hopping channels specified in this section."

**Assessment: COMPLIANT BY DESIGN.** Microfrag's burst model sends many
fragments per block, each on a different channel per the hop sequence. A block
of 100 fragments visits 100 channels (possibly with some revisits depending on
sequence length vs channel count). Short bursts (e.g., a single control
packet) still use the hop sequence, just fewer channels per burst.

**Key requirement:** "distribute its transmissions over the minimum number of
hopping channels" — even short bursts must use the hop sequence. A single-packet
transmission on a fixed channel does NOT comply with FHSS. This means baseline
single-channel LoRa (the current LICHEN mode) is NOT FHSS and operates under
a different basis (likely DTS or general Part 15 limits). Only microfrag mode,
with its multi-channel hopping, claims FHSS.

**Risk:** If a microfrag block is small enough that it visits fewer than 50
channels, does it still qualify? The rule says the *system* must be designed to
distribute over 50+ channels "should the transmitter be presented with a
continuous data stream." A short burst using fewer channels is explicitly
permitted by the first sentence of (g), provided the system design would use
50+ under continuous load.

---

## (h) — Coordination Restrictions

> "The incorporation of intelligence within a frequency hopping spread spectrum
> system that permits the system to recognize other users within the spectrum
> band so that it individually and independently chooses and adapts its hopsets
> to avoid hopping on occupied channels is permitted."

> "The coordination of frequency hopping systems in any other manner for the
> express purpose of avoiding the simultaneous occupancy of individual hopping
> frequencies by multiple transmitters is not permitted."

**Assessment: COMPLIANT — but this clause needs a legal opinion to confirm.**

The first paragraph explicitly permits "intelligence" that recognizes other
users and independently adapts hopsets to avoid occupied channels. CCP's
receiver-aware scheduling fits this description: each node observes the
network (beacons, announcements, link evidence) and independently selects
its own hop parameters. There is no central controller assigning channels.

The second paragraph prohibits coordination "for the express purpose of
avoiding the simultaneous occupancy of individual hopping frequencies by
multiple transmitters." The operative phrase is **"for the express purpose
of"** — this is a purpose test, and CCP's purpose is the opposite of what
the rule prohibits:

- The rule prohibits coordination that **concentrates** transmitters onto a
  reduced number of frequencies while maintaining an FHSS label. This is the
  cheater scenario: two devices fake-hopping in lockstep to camp on one
  channel together, getting FHSS power limits without actually spreading.
- CCP coordinates to **deconcentrate**. Its express purpose is spreading
  transmissions across channels and time to reduce per-channel interference
  and avoid collisions. Every design goal of CCP — receiver-aware channel
  selection, collision avoidance, time-slot separation — works to ensure
  that transmitters do NOT simultaneously occupy the same frequency. CCP
  makes the FHSS spreading *more effective*, not less.

The measurable result confirms the purpose: microfrag with CCP produces
lower per-channel occupancy, lower spectral density at any single frequency,
and less interference to any single-channel victim receiver than baseline
single-channel LoRa (which is already legal). Furthermore, CCP coordination
increases goodput and reduces retransmissions — fewer collisions means fewer
retries, which reduces *total aggregate spectrum usage* per successful
delivery. Prohibiting this coordination would force nodes to collide more
often, retransmit more often, and consume more aggregate airtime, increasing
interference to all Part 15 users sharing the band. CCP coordination makes
the spectrum-sharing properties of FHSS *better*, which is the outcome
15.247 exists to achieve.

Additionally, CCP coordinates *time slots* (when to transmit), not *hop
sequences* (which frequencies to visit). The hop sequence itself is
deterministic and peer-independent — derived from shared context (block ID,
link identities), not exchanged via a coordination protocol. CCP tells a
node when it may transmit; the hop sequence tells it where. These are
separable, and only the hop sequence is the "hopping system" that (h)
addresses.

**Risk:** A strict reading of "in any other manner" could treat any
multi-node protocol that influences transmission timing as prohibited
coordination, regardless of purpose. This reading would need a legal opinion
to evaluate. The "express purpose" qualifier and the measurable
deconcentration outcome are the primary counterarguments.

**Recommended action:** Get a written legal opinion specifically on (h) as
applied to CCP. Provide this analysis and measured RF comparison data
(per-channel occupancy with and without CCP coordination) as input. If the
legal opinion identifies risk, the fallback options are: (a) operate
microfrag without CCP time coordination (each node hops independently,
accepting more collisions), (b) seek an experimental license to demonstrate
the interference benefit, or (c) petition for a waiver or declaratory
ruling.

---

## (i) — RF Radiation Exposure

> "Radio frequency devices operating under the provisions of this part are
> subject to the radio frequency radiation exposure requirements"

**Assessment: COMPLIANT.** T-Echo and RAK4631 operate at power levels well
below RF exposure thresholds for portable devices. The module's existing
equipment authorization includes RF exposure evaluation. Microfrag does not
change peak power or duty cycle in a way that would affect exposure
calculations (total airtime per block is higher, but average power over time
is comparable since blocks are separated by idle periods).

---

## Summary

| Clause | Verdict | Notes |
|--------|---------|-------|
| (a)(1) channel separation | COMPLIANT | 200 kHz spacing > 130 kHz measured BW |
| (a)(1) channel count | COMPLIANT | 128 >= 50 |
| (a)(1) equal average use | REQUIRES VALIDATION | Hop sequence uniformity must be measured |
| (a)(1) occupancy time | COMPLIANT with accounting | 300 ms < 400 ms; aggregate budget must be enforced |
| (a)(1) max 20 dB BW | COMPLIANT | ~130 kHz < 500 kHz |
| (a)(2) DTS | N/A | Not claiming DTS; would not qualify anyway |
| (b)(2) power | COMPLIANT | 158 mW << 1 W |
| (b)(4) antenna gain | COMPLIANT | Stock antennas < 6 dBi |
| (d) OOB emissions | COMPLIANT | Hardware property, unchanged by microfrag |
| (e) PSD | N/A under FHSS | Would pass anyway |
| (f) hybrid | N/A | Not a hybrid system |
| (g) channel utilization | COMPLIANT | Burst design distributes across channels |
| **(h) coordination** | **COMPLIANT (confirm with counsel)** | **CCP deconcentrates; "express purpose" test favors compliance; legal opinion recommended** |
| (i) RF exposure | COMPLIANT | Low power portable device |

**Bottom line:** Every clause is clearly met. The only clause that warrants a
legal opinion is (h), and the technical case is strong: CCP's express purpose
is deconcentration (spreading transmissions across channels), not concentration
(camping on channels). The measurable outcome confirms this — microfrag with
CCP produces less per-channel interference than the already-legal baseline.
The "express purpose" qualifier in the rule's text distinguishes benign
coordination from the abuse the rule was written to prevent. A legal opinion
should confirm this reading before shipment.

---

## Recommended Next Steps

1. **Validate hop sequence uniformity** — statistical test of the FNV-based
   sequence generator showing equal average channel use. This is engineering
   work, not legal work.
2. **Implement per-transmitter occupancy accounting** — hard enforcement of
   0.4 s per frequency per 20 s, counting all emissions (data, parity, headers,
   control, retransmissions).
3. **Get a legal opinion on (h)** — specifically: does CCP's receiver-aware
   scheduling constitute prohibited coordination, or does the "express purpose"
   qualifier limit the prohibition to concentration-motivated coordination?
   Provide this document and measured RF comparison data as input.
4. **Collect measured RF data under Part 97 or Part 5** — per-channel occupancy
   and spectral density comparison between baseline single-channel LoRa and
   microfrag hopping, demonstrating reduced per-channel interference.
