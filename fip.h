#ifndef MESON_FIP_H
#define MESON_FIP_H

#include <stdint.h>

#define FIP_SIGNATURE 0xaa640001

struct __attribute((__packed__)) FipEntry {
	uint64_t uuid[2];
	uint64_t offset_address;
	uint64_t size;
	uint64_t flags;
};

struct __attribute((__packed__)) FipHeader {
	uint64_t sig;
	uint64_t res;
	struct FipEntry entries[0];
};

#endif
