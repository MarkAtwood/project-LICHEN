/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file schc.c
 * @brief SCHC compress/decompress (RFC 8724) - rules 0-4 + uncompressed fallback
 *
 * Ported from rust/lichen-schc/src/codec.rs.
 * Bit order: MSB-first (network bit order). The residue is zero-padded to
 * a byte boundary.
 */

#include <lichen/schc.h>
#include <string.h>
#include <stdbool.h>

/* ─── bit-packing ─────────────────────────────────────────────────────────── */

struct bit_writer {
	uint8_t *buf;
	size_t buf_len;
	size_t nbits;
};

static void bit_writer_init(struct bit_writer *w, uint8_t *buf, size_t len)
{
	memset(buf, 0, len);
	w->buf = buf;
	w->buf_len = len;
	w->nbits = 0;
}

/**
 * Write the low @p nbits of @p value, MSB first.
 * Returns 0 on success, -1 if buffer too small.
 */
static int bit_writer_write(struct bit_writer *w, uint64_t value, int nbits)
{
	for (int i = nbits - 1; i >= 0; i--) {
		uint8_t bit = (value >> i) & 1;
		size_t byte_pos = w->nbits / 8;
		int bit_pos = 7 - (w->nbits % 8);

		if (byte_pos >= w->buf_len) {
			return -1;
		}
		w->buf[byte_pos] |= bit << bit_pos;
		w->nbits++;
	}
	return 0;
}

/**
 * Write 128 bits (for full IPv6 addresses).
 */
static int bit_writer_write128(struct bit_writer *w,
			       const uint8_t value[16], int nbits)
{
	for (int i = 0; i < nbits; i++) {
		int byte_idx = i / 8;
		int bit_idx = 7 - (i % 8);
		uint8_t bit = (value[byte_idx] >> bit_idx) & 1;

		size_t byte_pos = w->nbits / 8;
		int bit_pos = 7 - (w->nbits % 8);

		if (byte_pos >= w->buf_len) {
			return -1;
		}
		w->buf[byte_pos] |= bit << bit_pos;
		w->nbits++;
	}
	return 0;
}

static size_t bit_writer_byte_len(const struct bit_writer *w)
{
	return (w->nbits + 7) / 8;
}

struct bit_reader {
	const uint8_t *buf;
	size_t buf_len;
	size_t pos;
};

static void bit_reader_init(struct bit_reader *r, const uint8_t *buf, size_t len)
{
	r->buf = buf;
	r->buf_len = len;
	r->pos = 0;
}

/**
 * Read @p nbits from the bit stream (max 64 bits).
 * Returns 0 on success, -1 if not enough data.
 */
static int bit_reader_read(struct bit_reader *r, int nbits, uint64_t *out)
{
	if (r->pos + nbits > r->buf_len * 8) {
		return -1;
	}
	uint64_t value = 0;
	for (int i = 0; i < nbits; i++) {
		uint8_t byte = r->buf[r->pos / 8];
		uint8_t bit = (byte >> (7 - (r->pos % 8))) & 1;
		value = (value << 1) | bit;
		r->pos++;
	}
	*out = value;
	return 0;
}

/**
 * Read up to 128 bits into a byte array.
 * @p out_size specifies the size of the output buffer (must be >= nbits/8).
 */
static int bit_reader_read_bytes(struct bit_reader *r, int nbits,
				 uint8_t *out, size_t out_size)
{
	size_t bytes_needed = (nbits + 7) / 8;
	if (bytes_needed > out_size || r->pos + nbits > r->buf_len * 8) {
		return -1;
	}
	memset(out, 0, bytes_needed);
	for (int i = 0; i < nbits; i++) {
		uint8_t byte = r->buf[r->pos / 8];
		uint8_t bit = (byte >> (7 - (r->pos % 8))) & 1;
		int byte_idx = i / 8;
		int bit_idx = 7 - (i % 8);
		out[byte_idx] |= bit << bit_idx;
		r->pos++;
	}
	return 0;
}

static size_t bit_reader_residue_byte_end(const struct bit_reader *r)
{
	return (r->pos + 7) / 8;
}

/* ─── address helpers ─────────────────────────────────────────────────────── */

static bool is_link_local(const uint8_t addr[16])
{
	return addr[0] == 0xFE && (addr[1] & 0xC0) == 0x80;
}

static bool is_global(const uint8_t addr[16])
{
	return (addr[0] >> 5) == 0x01; /* 001x xxxx = 2000::/3 */
}

/* ─── checksum helpers ────────────────────────────────────────────────────── */

static uint32_t oc_add(uint32_t a, uint32_t b)
{
	uint32_t s = a + b;
	if (s >> 16) {
		s = (s & 0xFFFF) + (s >> 16);
	}
	return s;
}

static uint32_t checksum_bytes(const uint8_t *data, size_t len)
{
	uint32_t sum = 0;
	size_t i;

	for (i = 0; i + 1 < len; i += 2) {
		sum = oc_add(sum, ((uint16_t)data[i] << 8) | data[i + 1]);
	}
	if (i < len) {
		sum = oc_add(sum, (uint32_t)data[i] << 8);
	}
	return sum;
}

static uint32_t pseudo_sum(const uint8_t src[16], const uint8_t dst[16],
			   uint8_t next_header, uint16_t length)
{
	uint32_t sum = 0;

	for (int i = 0; i < 16; i += 2) {
		sum = oc_add(sum, ((uint16_t)src[i] << 8) | src[i + 1]);
	}
	for (int i = 0; i < 16; i += 2) {
		sum = oc_add(sum, ((uint16_t)dst[i] << 8) | dst[i + 1]);
	}
	sum = oc_add(sum, length);
	sum = oc_add(sum, next_header);
	return sum;
}

static uint16_t finalize_checksum(uint32_t sum)
{
	while (sum >> 16) {
		sum = (sum & 0xFFFF) + (sum >> 16);
	}
	return ~((uint16_t)sum);
}

static uint16_t udp_checksum(const uint8_t src[16], const uint8_t dst[16],
			     uint16_t src_port, uint16_t dst_port,
			     const uint8_t *payload, size_t payload_len)
{
	/* UDP length field is 16 bits; header is 8 bytes, max payload is 65527 */
	if (payload_len > UINT16_MAX - 8) {
		return 0;
	}
	uint16_t udp_len = (uint16_t)(8 + payload_len);
	uint32_t sum = pseudo_sum(src, dst, 17, udp_len);

	sum = oc_add(sum, src_port);
	sum = oc_add(sum, dst_port);
	sum = oc_add(sum, udp_len);
	/* checksum field (0 during computation) */
	sum = oc_add(sum, checksum_bytes(payload, payload_len));
	return finalize_checksum(sum);
}

static uint16_t icmpv6_checksum(const uint8_t src[16], const uint8_t dst[16],
				const uint8_t *icmpv6_payload, size_t len)
{
	uint32_t sum = pseudo_sum(src, dst, 58, len);

	sum = oc_add(sum, checksum_bytes(icmpv6_payload, len));
	return finalize_checksum(sum);
}

/* ─── per-rule compress ───────────────────────────────────────────────────── */

/**
 * Common epilogue for compress_* functions: compute output size, bounds-check,
 * copy the uncompressed tail, and return the total compressed length.
 *
 * @param w         Pointer to bit_writer (already populated with residue)
 * @param out       Output buffer (rule ID already at out[0])
 * @param out_len   Size of output buffer
 * @param tail      Pointer to uncompressed tail data
 * @param tail_len  Length of tail data
 * @return          Total compressed length on success, SCHC_ERR_BUFFER_TOO_SMALL on failure
 */
static int compress_finish(const struct bit_writer *w, uint8_t *out,
			   size_t out_len, const uint8_t *tail, size_t tail_len)
{
	size_t residue_len = bit_writer_byte_len(w);
	size_t tail_start = 1 + residue_len;
	size_t needed = tail_start + tail_len;

	if (needed > out_len) {
		return SCHC_ERR_BUFFER_TOO_SMALL;
	}
	memcpy(&out[tail_start], tail, tail_len);
	return (int)needed;
}

/**
 * Common prologue for link-local compress_* functions: write hop_limit and
 * src/dst IIDs (64 bits each).
 *
 * @param w          Pointer to initialized bit_writer
 * @param hop_limit  IPv6 hop limit
 * @param src        Source IPv6 address (16 bytes)
 * @param dst        Destination IPv6 address (16 bytes)
 * @return           0 on success, -1 on buffer overflow
 */
static int compress_link_local_header(struct bit_writer *w, uint8_t hop_limit,
				      const uint8_t *src, const uint8_t *dst)
{
	if (bit_writer_write(w, hop_limit, 8) < 0 ||
	    bit_writer_write128(w, &src[8], 64) < 0 ||
	    bit_writer_write128(w, &dst[8], 64) < 0) {
		return -1;
	}
	return 0;
}

/**
 * Rule 0 (link-local) and Rule 1 (global): IPv6 + UDP + CoAP.
 */
static int compress_coap(const uint8_t *packet, size_t pkt_len,
			 uint8_t *out, size_t out_len, uint8_t rule_id)
{
	if (pkt_len < 40 + 8 + 4) {
		return SCHC_ERR_NO_MATCHING_RULE;
	}

	uint8_t hop_limit = packet[7];
	const uint8_t *src = &packet[8];
	const uint8_t *dst = &packet[24];
	const uint8_t *udp = &packet[40];
	uint16_t src_port = ((uint16_t)udp[0] << 8) | udp[1];
	uint16_t dst_port = ((uint16_t)udp[2] << 8) | udp[3];
	const uint8_t *coap = &udp[8];
	uint8_t coap_type = (coap[0] >> 4) & 0x3;
	uint8_t coap_tkl = coap[0] & 0x0F;
	uint8_t coap_code = coap[1];
	uint16_t coap_mid = ((uint16_t)coap[2] << 8) | coap[3];
	const uint8_t *tail = &coap[4];
	size_t tail_len = pkt_len - 40 - 8 - 4;

	if (out_len == 0) {
		return SCHC_ERR_BUFFER_TOO_SMALL;
	}
	out[0] = rule_id;

	struct bit_writer w;
	bit_writer_init(&w, &out[1], out_len - 1);

	if (bit_writer_write(&w, hop_limit, 8) < 0) {
		return SCHC_ERR_BUFFER_TOO_SMALL;
	}

	if (rule_id == SCHC_RULE_LINK_LOCAL_COAP) {
		/* Send only IID (64 bits) */
		if (bit_writer_write128(&w, &src[8], 64) < 0 ||
		    bit_writer_write128(&w, &dst[8], 64) < 0) {
			return SCHC_ERR_BUFFER_TOO_SMALL;
		}
	} else {
		/* Send full 128-bit addresses */
		if (bit_writer_write128(&w, src, 128) < 0 ||
		    bit_writer_write128(&w, dst, 128) < 0) {
			return SCHC_ERR_BUFFER_TOO_SMALL;
		}
	}

	if (bit_writer_write(&w, src_port, 16) < 0 ||
	    bit_writer_write(&w, dst_port, 16) < 0 ||
	    bit_writer_write(&w, coap_type, 2) < 0 ||
	    bit_writer_write(&w, coap_tkl, 4) < 0 ||
	    bit_writer_write(&w, coap_code, 8) < 0 ||
	    bit_writer_write(&w, coap_mid, 16) < 0) {
		return SCHC_ERR_BUFFER_TOO_SMALL;
	}

	return compress_finish(&w, out, out_len, tail, tail_len);
}

/**
 * Rule 2: link-local IPv6 + ICMPv6 Echo.
 */
static int compress_icmpv6_echo(const uint8_t *packet, size_t pkt_len,
				uint8_t *out, size_t out_len)
{
	if (pkt_len < 40 + 8) {
		return SCHC_ERR_NO_MATCHING_RULE;
	}

	uint8_t hop_limit = packet[7];
	const uint8_t *src = &packet[8];
	const uint8_t *dst = &packet[24];
	const uint8_t *icmp = &packet[40];
	uint8_t icmp_type = icmp[0];
	uint16_t icmp_id = ((uint16_t)icmp[4] << 8) | icmp[5];
	uint16_t icmp_seq = ((uint16_t)icmp[6] << 8) | icmp[7];
	const uint8_t *tail = &icmp[8];
	size_t tail_len = pkt_len - 40 - 8;

	out[0] = SCHC_RULE_ICMPV6_ECHO;

	struct bit_writer w;
	bit_writer_init(&w, &out[1], out_len - 1);

	if (compress_link_local_header(&w, hop_limit, src, dst) < 0 ||
	    bit_writer_write(&w, icmp_type, 8) < 0 ||
	    bit_writer_write(&w, icmp_id, 16) < 0 ||
	    bit_writer_write(&w, icmp_seq, 16) < 0) {
		return SCHC_ERR_BUFFER_TOO_SMALL;
	}

	return compress_finish(&w, out, out_len, tail, tail_len);
}

/**
 * Rule 3: link-local IPv6 + ICMPv6 RPL DIO.
 */
static int compress_rpl_dio(const uint8_t *packet, size_t pkt_len,
			    uint8_t *out, size_t out_len)
{
	if (pkt_len < 40 + 4 + 24) {
		return SCHC_ERR_NO_MATCHING_RULE;
	}

	uint8_t hop_limit = packet[7];
	const uint8_t *src = &packet[8];
	const uint8_t *dst = &packet[24];
	const uint8_t *rpl = &packet[44]; /* skip ICMPv6 type/code/checksum (4B) */
	uint8_t instance = rpl[0];
	uint8_t version = rpl[1];
	uint16_t rank = ((uint16_t)rpl[2] << 8) | rpl[3];
	uint8_t gmop = rpl[4];
	uint8_t dtsn = rpl[5];
	/* flags (rpl[6]) and reserved (rpl[7]) are NOT_SENT */
	const uint8_t *dodagid = &rpl[8];
	const uint8_t *tail = &rpl[24];
	size_t tail_len = pkt_len - 40 - 4 - 24;

	out[0] = SCHC_RULE_RPL_DIO;

	struct bit_writer w;
	bit_writer_init(&w, &out[1], out_len - 1);

	if (compress_link_local_header(&w, hop_limit, src, dst) < 0 ||
	    bit_writer_write(&w, instance, 8) < 0 ||
	    bit_writer_write(&w, version, 8) < 0 ||
	    bit_writer_write(&w, rank, 16) < 0 ||
	    bit_writer_write(&w, gmop, 8) < 0 ||
	    bit_writer_write(&w, dtsn, 8) < 0 ||
	    bit_writer_write128(&w, dodagid, 128) < 0) {
		return SCHC_ERR_BUFFER_TOO_SMALL;
	}

	return compress_finish(&w, out, out_len, tail, tail_len);
}

/**
 * Rule 4: link-local IPv6 + ICMPv6 RPL DAO with DODAGID.
 */
static int compress_rpl_dao(const uint8_t *packet, size_t pkt_len,
			    uint8_t *out, size_t out_len)
{
	if (pkt_len < 40 + 4 + 20) {
		return SCHC_ERR_NO_MATCHING_RULE;
	}

	uint8_t hop_limit = packet[7];
	const uint8_t *src = &packet[8];
	const uint8_t *dst = &packet[24];
	const uint8_t *rpl = &packet[44];
	uint8_t instance = rpl[0];
	uint8_t kd_flags = rpl[1];
	/* reserved (rpl[2]) is NOT_SENT */
	uint8_t seq = rpl[3];
	const uint8_t *dodagid = &rpl[4];
	const uint8_t *tail = &rpl[20];
	size_t tail_len = pkt_len - 40 - 4 - 20;

	out[0] = SCHC_RULE_RPL_DAO;

	struct bit_writer w;
	bit_writer_init(&w, &out[1], out_len - 1);

	if (compress_link_local_header(&w, hop_limit, src, dst) < 0 ||
	    bit_writer_write(&w, instance, 8) < 0 ||
	    bit_writer_write(&w, kd_flags, 8) < 0 ||
	    bit_writer_write(&w, seq, 8) < 0 ||
	    bit_writer_write128(&w, dodagid, 128) < 0) {
		return SCHC_ERR_BUFFER_TOO_SMALL;
	}

	return compress_finish(&w, out, out_len, tail, tail_len);
}

/* ─── per-rule decompress ─────────────────────────────────────────────────── */

static int decompress_coap(const uint8_t *data, size_t data_len,
			   uint8_t *out, size_t out_len, uint8_t rule_id)
{
	/*
	 * Minimum residue size (excluding rule ID byte):
	 * - Rule 0 (link-local): 8 + 64 + 64 + 16 + 16 + 2 + 4 + 8 + 16 = 198 bits = 25 bytes
	 * - Rule 1 (global):     8 + 128 + 128 + 16 + 16 + 2 + 4 + 8 + 16 = 326 bits = 41 bytes
	 */
	size_t min_residue = (rule_id == SCHC_RULE_LINK_LOCAL_COAP) ? 25 : 41;
	if (data_len < 1 + min_residue) {
		return SCHC_ERR_TOO_SHORT;
	}

	struct bit_reader r;
	bit_reader_init(&r, &data[1], data_len - 1);

	uint64_t hop_limit;
	if (bit_reader_read(&r, 8, &hop_limit) < 0) {
		return SCHC_ERR_TOO_SHORT;
	}

	uint8_t src[16], dst[16];

	if (rule_id == SCHC_RULE_LINK_LOCAL_COAP) {
		/* Reconstruct link-local prefix + IID */
		memset(src, 0, 16);
		memset(dst, 0, 16);
		src[0] = 0xFE;
		src[1] = 0x80;
		dst[0] = 0xFE;
		dst[1] = 0x80;
		if (bit_reader_read_bytes(&r, 64, &src[8], 8) < 0 ||
		    bit_reader_read_bytes(&r, 64, &dst[8], 8) < 0) {
			return SCHC_ERR_TOO_SHORT;
		}
	} else {
		if (bit_reader_read_bytes(&r, 128, src, 16) < 0 ||
		    bit_reader_read_bytes(&r, 128, dst, 16) < 0) {
			return SCHC_ERR_TOO_SHORT;
		}
	}

	uint64_t src_port, dst_port, coap_type, coap_tkl, coap_code, coap_mid;
	if (bit_reader_read(&r, 16, &src_port) < 0 ||
	    bit_reader_read(&r, 16, &dst_port) < 0 ||
	    bit_reader_read(&r, 2, &coap_type) < 0 ||
	    bit_reader_read(&r, 4, &coap_tkl) < 0 ||
	    bit_reader_read(&r, 8, &coap_code) < 0 ||
	    bit_reader_read(&r, 16, &coap_mid) < 0) {
		return SCHC_ERR_TOO_SHORT;
	}

	size_t residue_end = bit_reader_residue_byte_end(&r);
	const uint8_t *tail = &data[1 + residue_end];
	size_t tail_len = data_len - 1 - residue_end;

	/* Build CoAP header: ver(2)=1 | type(2) | tkl(4), code, mid[2] */
	uint8_t coap_b0 = (1 << 6) | ((coap_type & 0x3) << 4) | (coap_tkl & 0x0F);
	size_t coap_len = 4 + tail_len;
	uint16_t udp_len = 8 + coap_len;

	/* Build CoAP for checksum computation */
	uint8_t coap_buf[512];

	/* Ensure tail fits in working buffer */
	if (tail_len > sizeof(coap_buf) - 4) {
		return SCHC_ERR_BUFFER_TOO_SMALL;
	}

	coap_buf[0] = coap_b0;
	coap_buf[1] = (uint8_t)coap_code;
	coap_buf[2] = (uint8_t)(coap_mid >> 8);
	coap_buf[3] = (uint8_t)coap_mid;
	if (tail_len > 0) {
		memcpy(&coap_buf[4], tail, tail_len);
	}

	uint16_t udp_cksum = udp_checksum(src, dst, (uint16_t)src_port,
					  (uint16_t)dst_port, coap_buf, coap_len);

	uint16_t ipv6_payload_len = udp_len;
	size_t total = 40 + 8 + coap_len;

	if (total > out_len) {
		return SCHC_ERR_BUFFER_TOO_SMALL;
	}

	/* IPv6 header */
	out[0] = 0x60;
	out[1] = 0;
	out[2] = 0;
	out[3] = 0;
	out[4] = (uint8_t)(ipv6_payload_len >> 8);
	out[5] = (uint8_t)ipv6_payload_len;
	out[6] = 17; /* UDP */
	out[7] = (uint8_t)hop_limit;
	memcpy(&out[8], src, 16);
	memcpy(&out[24], dst, 16);

	/* UDP header */
	out[40] = (uint8_t)(src_port >> 8);
	out[41] = (uint8_t)src_port;
	out[42] = (uint8_t)(dst_port >> 8);
	out[43] = (uint8_t)dst_port;
	out[44] = (uint8_t)(udp_len >> 8);
	out[45] = (uint8_t)udp_len;
	out[46] = (uint8_t)(udp_cksum >> 8);
	out[47] = (uint8_t)udp_cksum;

	/* CoAP */
	memcpy(&out[48], coap_buf, coap_len);

	return (int)total;
}

static int decompress_icmpv6_echo(const uint8_t *data, size_t data_len,
				  uint8_t *out, size_t out_len)
{
	/*
	 * Minimum residue size (excluding rule ID byte):
	 * 8 + 64 + 64 + 8 + 16 + 16 = 176 bits = 22 bytes
	 */
	if (data_len < 1 + 22) {
		return SCHC_ERR_TOO_SHORT;
	}

	struct bit_reader r;
	bit_reader_init(&r, &data[1], data_len - 1);

	uint64_t hop_limit;
	uint8_t src[16], dst[16];

	if (bit_reader_read(&r, 8, &hop_limit) < 0) {
		return SCHC_ERR_TOO_SHORT;
	}

	memset(src, 0, 16);
	memset(dst, 0, 16);
	src[0] = 0xFE;
	src[1] = 0x80;
	dst[0] = 0xFE;
	dst[1] = 0x80;

	if (bit_reader_read_bytes(&r, 64, &src[8], 8) < 0 ||
	    bit_reader_read_bytes(&r, 64, &dst[8], 8) < 0) {
		return SCHC_ERR_TOO_SHORT;
	}

	uint64_t icmp_type, icmp_id, icmp_seq;
	if (bit_reader_read(&r, 8, &icmp_type) < 0 ||
	    bit_reader_read(&r, 16, &icmp_id) < 0 ||
	    bit_reader_read(&r, 16, &icmp_seq) < 0) {
		return SCHC_ERR_TOO_SHORT;
	}

	size_t residue_end = bit_reader_residue_byte_end(&r);
	const uint8_t *tail = &data[1 + residue_end];
	size_t tail_len = data_len - 1 - residue_end;

	size_t icmp_len = 8 + tail_len;
	size_t total = 40 + icmp_len;

	if (total > out_len) {
		return SCHC_ERR_BUFFER_TOO_SMALL;
	}

	/* Build ICMPv6 with zero checksum for computation */
	uint8_t icmp_buf[512];

	/* Ensure tail fits in working buffer */
	if (tail_len > sizeof(icmp_buf) - 8) {
		return SCHC_ERR_BUFFER_TOO_SMALL;
	}

	icmp_buf[0] = (uint8_t)icmp_type;
	icmp_buf[1] = 0; /* code NOT_SENT = 0 */
	icmp_buf[2] = 0; /* checksum placeholder */
	icmp_buf[3] = 0;
	icmp_buf[4] = (uint8_t)(icmp_id >> 8);
	icmp_buf[5] = (uint8_t)icmp_id;
	icmp_buf[6] = (uint8_t)(icmp_seq >> 8);
	icmp_buf[7] = (uint8_t)icmp_seq;
	if (tail_len > 0) {
		memcpy(&icmp_buf[8], tail, tail_len);
	}

	uint16_t cksum = icmpv6_checksum(src, dst, icmp_buf, icmp_len);

	/* IPv6 header */
	out[0] = 0x60;
	out[1] = 0;
	out[2] = 0;
	out[3] = 0;
	out[4] = (uint8_t)(icmp_len >> 8);
	out[5] = (uint8_t)icmp_len;
	out[6] = 58; /* ICMPv6 */
	out[7] = (uint8_t)hop_limit;
	memcpy(&out[8], src, 16);
	memcpy(&out[24], dst, 16);

	/* ICMPv6 */
	out[40] = (uint8_t)icmp_type;
	out[41] = 0;
	out[42] = (uint8_t)(cksum >> 8);
	out[43] = (uint8_t)cksum;
	out[44] = (uint8_t)(icmp_id >> 8);
	out[45] = (uint8_t)icmp_id;
	out[46] = (uint8_t)(icmp_seq >> 8);
	out[47] = (uint8_t)icmp_seq;
	if (tail_len > 0) {
		memcpy(&out[48], tail, tail_len);
	}

	return (int)total;
}

static int decompress_rpl_dio(const uint8_t *data, size_t data_len,
			      uint8_t *out, size_t out_len)
{
	struct bit_reader r;
	bit_reader_init(&r, &data[1], data_len - 1);

	uint64_t hop_limit;
	uint8_t src[16], dst[16];

	if (bit_reader_read(&r, 8, &hop_limit) < 0) {
		return SCHC_ERR_TOO_SHORT;
	}

	memset(src, 0, 16);
	memset(dst, 0, 16);
	src[0] = 0xFE;
	src[1] = 0x80;
	dst[0] = 0xFE;
	dst[1] = 0x80;

	if (bit_reader_read_bytes(&r, 64, &src[8], 8) < 0 ||
	    bit_reader_read_bytes(&r, 64, &dst[8], 8) < 0) {
		return SCHC_ERR_TOO_SHORT;
	}

	uint64_t instance, version, rank, gmop, dtsn;
	uint8_t dodagid[16];

	if (bit_reader_read(&r, 8, &instance) < 0 ||
	    bit_reader_read(&r, 8, &version) < 0 ||
	    bit_reader_read(&r, 16, &rank) < 0 ||
	    bit_reader_read(&r, 8, &gmop) < 0 ||
	    bit_reader_read(&r, 8, &dtsn) < 0 ||
	    bit_reader_read_bytes(&r, 128, dodagid, 16) < 0) {
		return SCHC_ERR_TOO_SHORT;
	}

	size_t residue_end = bit_reader_residue_byte_end(&r);
	const uint8_t *tail = &data[1 + residue_end];
	size_t tail_len = data_len - 1 - residue_end;

	/* RPL DIO base (24 bytes) + tail */
	size_t rpl_body_len = 24 + tail_len;
	size_t icmp_len = 4 + rpl_body_len; /* type+code+cksum + body */
	size_t total = 40 + icmp_len;

	if (total > out_len) {
		return SCHC_ERR_BUFFER_TOO_SMALL;
	}

	uint8_t icmp_buf[512];

	/* Ensure tail fits in working buffer (28 = DIO header) */
	if (tail_len > sizeof(icmp_buf) - 28) {
		return SCHC_ERR_BUFFER_TOO_SMALL;
	}

	icmp_buf[0] = 155; /* RPL */
	icmp_buf[1] = 1;   /* DIO code */
	icmp_buf[2] = 0;   /* checksum placeholder */
	icmp_buf[3] = 0;
	icmp_buf[4] = (uint8_t)instance;
	icmp_buf[5] = (uint8_t)version;
	icmp_buf[6] = (uint8_t)(rank >> 8);
	icmp_buf[7] = (uint8_t)rank;
	icmp_buf[8] = (uint8_t)gmop;
	icmp_buf[9] = (uint8_t)dtsn;
	icmp_buf[10] = 0; /* flags (NOT_SENT = 0) */
	icmp_buf[11] = 0; /* reserved (NOT_SENT = 0) */
	memcpy(&icmp_buf[12], dodagid, 16);
	if (tail_len > 0) {
		memcpy(&icmp_buf[28], tail, tail_len);
	}

	uint16_t cksum = icmpv6_checksum(src, dst, icmp_buf, icmp_len);

	/* IPv6 header */
	out[0] = 0x60;
	out[1] = 0;
	out[2] = 0;
	out[3] = 0;
	out[4] = (uint8_t)(icmp_len >> 8);
	out[5] = (uint8_t)icmp_len;
	out[6] = 58; /* ICMPv6 */
	out[7] = (uint8_t)hop_limit;
	memcpy(&out[8], src, 16);
	memcpy(&out[24], dst, 16);

	/* ICMPv6 / RPL DIO */
	memcpy(&out[40], icmp_buf, icmp_len);
	out[42] = (uint8_t)(cksum >> 8);
	out[43] = (uint8_t)cksum;

	return (int)total;
}

static int decompress_rpl_dao(const uint8_t *data, size_t data_len,
			      uint8_t *out, size_t out_len)
{
	struct bit_reader r;
	bit_reader_init(&r, &data[1], data_len - 1);

	uint64_t hop_limit;
	uint8_t src[16], dst[16];

	if (bit_reader_read(&r, 8, &hop_limit) < 0) {
		return SCHC_ERR_TOO_SHORT;
	}

	memset(src, 0, 16);
	memset(dst, 0, 16);
	src[0] = 0xFE;
	src[1] = 0x80;
	dst[0] = 0xFE;
	dst[1] = 0x80;

	if (bit_reader_read_bytes(&r, 64, &src[8], 8) < 0 ||
	    bit_reader_read_bytes(&r, 64, &dst[8], 8) < 0) {
		return SCHC_ERR_TOO_SHORT;
	}

	uint64_t instance, kd_flags, seq;
	uint8_t dodagid[16];

	if (bit_reader_read(&r, 8, &instance) < 0 ||
	    bit_reader_read(&r, 8, &kd_flags) < 0 ||
	    bit_reader_read(&r, 8, &seq) < 0 ||
	    bit_reader_read_bytes(&r, 128, dodagid, 16) < 0) {
		return SCHC_ERR_TOO_SHORT;
	}

	size_t residue_end = bit_reader_residue_byte_end(&r);
	const uint8_t *tail = &data[1 + residue_end];
	size_t tail_len = data_len - 1 - residue_end;

	size_t rpl_body_len = 20 + tail_len;
	size_t icmp_len = 4 + rpl_body_len;
	size_t total = 40 + icmp_len;

	if (total > out_len) {
		return SCHC_ERR_BUFFER_TOO_SMALL;
	}

	uint8_t icmp_buf[512];

	/* Ensure tail fits in working buffer (24 = DAO header) */
	if (tail_len > sizeof(icmp_buf) - 24) {
		return SCHC_ERR_BUFFER_TOO_SMALL;
	}

	icmp_buf[0] = 155; /* RPL */
	icmp_buf[1] = 2;   /* DAO code */
	icmp_buf[2] = 0;   /* checksum placeholder */
	icmp_buf[3] = 0;
	icmp_buf[4] = (uint8_t)instance;
	icmp_buf[5] = (uint8_t)kd_flags;
	icmp_buf[6] = 0; /* reserved (NOT_SENT = 0) */
	icmp_buf[7] = (uint8_t)seq;
	memcpy(&icmp_buf[8], dodagid, 16);
	if (tail_len > 0) {
		memcpy(&icmp_buf[24], tail, tail_len);
	}

	uint16_t cksum = icmpv6_checksum(src, dst, icmp_buf, icmp_len);

	/* IPv6 header */
	out[0] = 0x60;
	out[1] = 0;
	out[2] = 0;
	out[3] = 0;
	out[4] = (uint8_t)(icmp_len >> 8);
	out[5] = (uint8_t)icmp_len;
	out[6] = 58;
	out[7] = (uint8_t)hop_limit;
	memcpy(&out[8], src, 16);
	memcpy(&out[24], dst, 16);

	/* ICMPv6 / RPL DAO */
	memcpy(&out[40], icmp_buf, icmp_len);
	out[42] = (uint8_t)(cksum >> 8);
	out[43] = (uint8_t)cksum;

	return (int)total;
}

/* ─── public API ──────────────────────────────────────────────────────────── */

int lichen_schc_compress(const uint8_t *packet, size_t pkt_len,
			 uint8_t *out, size_t out_len)
{
	int ret;

	if (pkt_len < 40 || (packet[0] >> 4) != 6) {
		/* Not IPv6 - uncompressed fallback */
		size_t needed = 1 + pkt_len;
		if (out_len < needed) {
			return SCHC_ERR_BUFFER_TOO_SMALL;
		}
		out[0] = SCHC_RULE_UNCOMPRESSED;
		memcpy(&out[1], packet, pkt_len);
		return (int)needed;
	}

	uint8_t nh = packet[6];
	const uint8_t *src = &packet[8];
	const uint8_t *dst = &packet[24];

	if (nh == 17) {
		/* UDP - rules 0 or 1 */
		if (is_link_local(src) && is_link_local(dst)) {
			ret = compress_coap(packet, pkt_len, out, out_len,
					    SCHC_RULE_LINK_LOCAL_COAP);
			if (ret > 0) {
				return ret;
			}
		} else if (is_global(src) && is_global(dst)) {
			ret = compress_coap(packet, pkt_len, out, out_len,
					    SCHC_RULE_GLOBAL_COAP);
			if (ret > 0) {
				return ret;
			}
		}
	} else if (nh == 58 && pkt_len >= 40 + 4) {
		/* ICMPv6 */
		uint8_t icmp_type = packet[40];
		uint8_t icmp_code = packet[41];

		if ((icmp_type == 128 || icmp_type == 129) &&
		    icmp_code == 0 &&
		    is_link_local(src) && is_link_local(dst) &&
		    pkt_len >= 40 + 8) {
			ret = compress_icmpv6_echo(packet, pkt_len, out, out_len);
			if (ret > 0) {
				return ret;
			}
		} else if (icmp_type == 155 &&
			   is_link_local(src) && is_link_local(dst)) {
			if (icmp_code == 1 && pkt_len >= 40 + 4 + 24) {
				/* DIO */
				ret = compress_rpl_dio(packet, pkt_len, out, out_len);
				if (ret > 0) {
					return ret;
				}
			} else if (icmp_code == 2 && pkt_len >= 40 + 4 + 20) {
				/* DAO - only rule 4 if D flag set */
				uint8_t kd_flags = packet[45];
				if (kd_flags & 0x40) {
					ret = compress_rpl_dao(packet, pkt_len,
							       out, out_len);
					if (ret > 0) {
						return ret;
					}
				}
			}
		}
	}

	/* Uncompressed fallback */
	size_t needed = 1 + pkt_len;
	if (out_len < needed) {
		return SCHC_ERR_BUFFER_TOO_SMALL;
	}
	out[0] = SCHC_RULE_UNCOMPRESSED;
	memcpy(&out[1], packet, pkt_len);
	return (int)needed;
}

int lichen_schc_decompress(const uint8_t *data, size_t data_len,
			   uint8_t *out, size_t out_len)
{
	if (data_len == 0) {
		return SCHC_ERR_TOO_SHORT;
	}

	switch (data[0]) {
	case SCHC_RULE_LINK_LOCAL_COAP:
		return decompress_coap(data, data_len, out, out_len,
				       SCHC_RULE_LINK_LOCAL_COAP);
	case SCHC_RULE_GLOBAL_COAP:
		return decompress_coap(data, data_len, out, out_len,
				       SCHC_RULE_GLOBAL_COAP);
	case SCHC_RULE_ICMPV6_ECHO:
		return decompress_icmpv6_echo(data, data_len, out, out_len);
	case SCHC_RULE_RPL_DIO:
		return decompress_rpl_dio(data, data_len, out, out_len);
	case SCHC_RULE_RPL_DAO:
		return decompress_rpl_dao(data, data_len, out, out_len);
	case SCHC_RULE_UNCOMPRESSED: {
		const uint8_t *payload = &data[1];
		size_t payload_len = data_len - 1;
		if (out_len < payload_len) {
			return SCHC_ERR_BUFFER_TOO_SMALL;
		}
		memcpy(out, payload, payload_len);
		return (int)payload_len;
	}
	default:
		return SCHC_ERR_UNKNOWN_RULE_ID;
	}
}
