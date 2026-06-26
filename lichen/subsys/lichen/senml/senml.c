/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file senml.c
 * @brief SenML CBOR encoder
 *
 * Encodes sensor data as SenML (RFC 8428) in CBOR format.
 * Uses minimal hand-rolled CBOR encoding to avoid dependencies.
 */

#include <string.h>
#include <math.h>
#include <lichen/senml.h>

/* CBOR SenML label indices (RFC 8428 Section 6) */
enum senml_label {
	SENML_LABEL_BS = -6,  /* Base Sum */
	SENML_LABEL_BV = -5,  /* Base Value */
	SENML_LABEL_BU = -4,  /* Base Unit */
	SENML_LABEL_BT = -3,  /* Base Time */
	SENML_LABEL_BN = -2,  /* Base Name */
	SENML_LABEL_N  =  0,  /* Name */
	SENML_LABEL_U  =  1,  /* Unit */
	SENML_LABEL_V  =  2,  /* Value */
	SENML_LABEL_VS =  3,  /* String Value */
	SENML_LABEL_VB =  4,  /* Boolean Value */
	SENML_LABEL_S  =  5,  /* Sum */
	SENML_LABEL_T  =  6,  /* Time */
	SENML_LABEL_UT =  7,  /* Update Time */
	SENML_LABEL_VD =  8,  /* Data Value */
};

/*
 * Minimal CBOR encoding helpers.
 * Returns bytes written, or -1 on overflow.
 */

static int cbor_encode_uint(uint8_t *buf, size_t buflen, uint8_t major, uint64_t val)
{
	if (val <= 23) {
		if (buflen < 1) return -1;
		buf[0] = (major << 5) | (uint8_t)val;
		return 1;
	} else if (val <= 0xFF) {
		if (buflen < 2) return -1;
		buf[0] = (major << 5) | 24;
		buf[1] = (uint8_t)val;
		return 2;
	} else if (val <= 0xFFFF) {
		if (buflen < 3) return -1;
		buf[0] = (major << 5) | 25;
		buf[1] = (uint8_t)(val >> 8);
		buf[2] = (uint8_t)val;
		return 3;
	} else if (val <= 0xFFFFFFFF) {
		if (buflen < 5) return -1;
		buf[0] = (major << 5) | 26;
		buf[1] = (uint8_t)(val >> 24);
		buf[2] = (uint8_t)(val >> 16);
		buf[3] = (uint8_t)(val >> 8);
		buf[4] = (uint8_t)val;
		return 5;
	} else {
		if (buflen < 9) return -1;
		buf[0] = (major << 5) | 27;
		buf[1] = (uint8_t)(val >> 56);
		buf[2] = (uint8_t)(val >> 48);
		buf[3] = (uint8_t)(val >> 40);
		buf[4] = (uint8_t)(val >> 32);
		buf[5] = (uint8_t)(val >> 24);
		buf[6] = (uint8_t)(val >> 16);
		buf[7] = (uint8_t)(val >> 8);
		buf[8] = (uint8_t)val;
		return 9;
	}
}

static int cbor_encode_int(uint8_t *buf, size_t buflen, int64_t val)
{
	if (val >= 0) {
		return cbor_encode_uint(buf, buflen, 0, (uint64_t)val);
	} else {
		return cbor_encode_uint(buf, buflen, 1, (uint64_t)(-1 - val));
	}
}

static int cbor_encode_tstr(uint8_t *buf, size_t buflen, const char *str)
{
	size_t len = strlen(str);
	/* Guard against strings too long to express in a signed int return */
	if (len > (size_t)INT_MAX - 9) {
		return -1;
	}
	int hdr = cbor_encode_uint(buf, buflen, 3, len);
	if (hdr < 0) return -1;
	if ((size_t)hdr + len > buflen) return -1;
	memcpy(buf + hdr, str, len);
	return hdr + (int)len;
}

static int cbor_encode_float(uint8_t *buf, size_t buflen, float val)
{
	/* IEEE 754 single-precision float (CBOR major 7, additional 26) */
	if (buflen < 5) return -1;

	uint32_t bits;
	memcpy(&bits, &val, sizeof(bits));

	buf[0] = 0xFA; /* float32 */
	buf[1] = (uint8_t)(bits >> 24);
	buf[2] = (uint8_t)(bits >> 16);
	buf[3] = (uint8_t)(bits >> 8);
	buf[4] = (uint8_t)bits;
	return 5;
}

static int cbor_encode_bool(uint8_t *buf, size_t buflen, bool val)
{
	if (buflen < 1) return -1;
	buf[0] = val ? 0xF5 : 0xF4; /* true : false */
	return 1;
}

void senml_pack_init(struct senml_pack *pack,
		     const char *base_name,
		     uint64_t base_time)
{
	memset(pack, 0, sizeof(*pack));
	pack->base_name = base_name;
	if (base_time > 0) {
		pack->base_time = base_time;
		pack->has_base_time = true;
	}
}

int senml_add_float(struct senml_pack *pack,
		    const char *name,
		    const char *unit,
		    float value)
{
	if (pack->record_count >= SENML_MAX_RECORDS) {
		return -1;
	}

	struct senml_record *rec = &pack->records[pack->record_count++];
	rec->name = name;
	rec->unit = unit;
	rec->type = SENML_VALUE_FLOAT;
	rec->value.f = value;
	rec->has_time = false;

	return 0;
}

int senml_add_float_t(struct senml_pack *pack,
		      const char *name,
		      const char *unit,
		      float value,
		      int32_t time_offset)
{
	if (pack->record_count >= SENML_MAX_RECORDS) {
		return -1;
	}

	struct senml_record *rec = &pack->records[pack->record_count++];
	rec->name = name;
	rec->unit = unit;
	rec->type = SENML_VALUE_FLOAT;
	rec->value.f = value;
	rec->time_offset = time_offset;
	rec->has_time = true;

	return 0;
}

int senml_add_bool(struct senml_pack *pack,
		   const char *name,
		   bool value)
{
	if (pack->record_count >= SENML_MAX_RECORDS) {
		return -1;
	}

	struct senml_record *rec = &pack->records[pack->record_count++];
	rec->name = name;
	rec->unit = NULL;
	rec->type = SENML_VALUE_BOOL;
	rec->value.b = value;
	rec->has_time = false;

	return 0;
}

/*
 * Encode a single SenML record as a CBOR map.
 */
static int encode_record(const struct senml_record *rec,
			 const struct senml_pack *pack,
			 bool is_first,
			 uint8_t *buf, size_t buflen)
{
	size_t off = 0;
	int r;

	/* Count map entries */
	int entries = 0;
	if (is_first && pack->base_name != NULL) entries++;
	if (is_first && pack->has_base_time) entries++;
	if (rec->name != NULL) entries++;
	if (rec->unit != NULL) entries++;
	entries++; /* value always present */
	if (rec->has_time) entries++;

	/* Map header */
	r = cbor_encode_uint(buf + off, buflen - off, 5, (uint64_t)entries);
	if (r < 0) return -1;
	off += (size_t)r;

	/* Base name (first record only) */
	if (is_first && pack->base_name != NULL) {
		r = cbor_encode_int(buf + off, buflen - off, SENML_LABEL_BN);
		if (r < 0) return -1;
		off += (size_t)r;

		r = cbor_encode_tstr(buf + off, buflen - off, pack->base_name);
		if (r < 0) return -1;
		off += (size_t)r;
	}

	/* Base time (first record only) */
	if (is_first && pack->has_base_time) {
		r = cbor_encode_int(buf + off, buflen - off, SENML_LABEL_BT);
		if (r < 0) return -1;
		off += (size_t)r;

		r = cbor_encode_uint(buf + off, buflen - off, 0, pack->base_time);
		if (r < 0) return -1;
		off += (size_t)r;
	}

	/* Name */
	if (rec->name != NULL) {
		r = cbor_encode_int(buf + off, buflen - off, SENML_LABEL_N);
		if (r < 0) return -1;
		off += (size_t)r;

		r = cbor_encode_tstr(buf + off, buflen - off, rec->name);
		if (r < 0) return -1;
		off += (size_t)r;
	}

	/* Unit */
	if (rec->unit != NULL) {
		r = cbor_encode_int(buf + off, buflen - off, SENML_LABEL_U);
		if (r < 0) return -1;
		off += (size_t)r;

		r = cbor_encode_tstr(buf + off, buflen - off, rec->unit);
		if (r < 0) return -1;
		off += (size_t)r;
	}

	/* Value */
	switch (rec->type) {
	case SENML_VALUE_FLOAT:
		r = cbor_encode_int(buf + off, buflen - off, SENML_LABEL_V);
		if (r < 0) return -1;
		off += (size_t)r;

		r = cbor_encode_float(buf + off, buflen - off, rec->value.f);
		if (r < 0) return -1;
		off += (size_t)r;
		break;

	case SENML_VALUE_BOOL:
		r = cbor_encode_int(buf + off, buflen - off, SENML_LABEL_VB);
		if (r < 0) return -1;
		off += (size_t)r;

		r = cbor_encode_bool(buf + off, buflen - off, rec->value.b);
		if (r < 0) return -1;
		off += (size_t)r;
		break;

	default:
		return -1;
	}

	/* Time offset */
	if (rec->has_time) {
		r = cbor_encode_int(buf + off, buflen - off, SENML_LABEL_T);
		if (r < 0) return -1;
		off += (size_t)r;

		r = cbor_encode_int(buf + off, buflen - off, rec->time_offset);
		if (r < 0) return -1;
		off += (size_t)r;
	}

	return (int)off;
}

int senml_encode_cbor(const struct senml_pack *pack,
		      uint8_t *buf, size_t buflen)
{
	size_t off = 0;
	int r;

	if (pack->record_count == 0) {
		return -1;
	}

	/* SenML is an array of records */
	r = cbor_encode_uint(buf, buflen, 4, pack->record_count);
	if (r < 0) return -1;
	off += (size_t)r;

	/* Encode each record */
	for (size_t i = 0; i < pack->record_count; i++) {
		r = encode_record(&pack->records[i], pack, (i == 0), buf + off, buflen - off);
		if (r < 0) return -1;
		off += (size_t)r;
	}

	return (int)off;
}

int senml_encode_location(const char *base_name, uint64_t base_time,
			  float lat, float lon, float alt,
			  uint8_t *buf, size_t buflen)
{
	struct senml_pack pack;

	senml_pack_init(&pack, base_name, base_time);
	senml_add_float(&pack, "lat", "lat", lat);
	senml_add_float(&pack, "lon", "lon", lon);

	if (!isnan(alt)) {
		senml_add_float(&pack, "alt", "m", alt);
	}

	return senml_encode_cbor(&pack, buf, buflen);
}

int senml_encode_battery(const char *base_name, uint64_t base_time,
			 uint8_t percent, uint16_t mv, bool charging,
			 uint8_t *buf, size_t buflen)
{
	struct senml_pack pack;

	senml_pack_init(&pack, base_name, base_time);
	senml_add_float(&pack, "pct", "%RH", (float)percent);
	senml_add_float(&pack, "mv", "mV", (float)mv);
	senml_add_bool(&pack, "charging", charging);

	return senml_encode_cbor(&pack, buf, buflen);
}

int senml_encode_temperature(const char *base_name, uint64_t base_time,
			     float temp_c,
			     uint8_t *buf, size_t buflen)
{
	struct senml_pack pack;

	senml_pack_init(&pack, base_name, base_time);
	senml_add_float(&pack, "temp", "Cel", temp_c);

	return senml_encode_cbor(&pack, buf, buflen);
}
