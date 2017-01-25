#ifndef MESON_COMMON_H
#define MESON_COMMON_H

#include <stdint.h>

#include "fip.h"

#define ROUND_UP(x, a) (((x) + ((a) - 1)) & ~((a) - 1))

#define AMLOGIC_SIGNATURE "@AML"

struct __attribute((__packed__)) AmlogicHeader {
	char sig[4];
	uint32_t size;
	uint16_t header_size;
	uint16_t header_version;
	uint32_t id;
	uint32_t encrypted;
	uint32_t digest_offset;
	uint32_t digest_size;
	uint32_t data_offset;
	uint32_t data_size;
	uint32_t bl2_offset;
	uint32_t bl2_size;
	uint32_t _offset2;
	uint32_t pad2;
	uint32_t _size2;
	uint32_t fip_offset;
	uint32_t unknown;
};

#endif
