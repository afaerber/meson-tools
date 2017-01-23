#include <assert.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/sha.h>

#define AMLOGIC_SIGNATURE "@AML"

struct __attribute((__packed__)) AmlogicHeader {
	char sig[4];
	uint32_t size;
	uint16_t header_size;
	char x4;
	char pad1;
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

#define ROUND_UP(x, a) (((x) + ((a) - 1)) & ~((a) - 1))

static int do_fip(FILE *fout, FILE *fin)
{
	uint8_t *toc_buf, *buf;
	struct FipHeader *ptoc;
	int i, n;
	long toc_pos;

	assert(sizeof(struct FipEntry) == 40);

	toc_buf = malloc(0x4000);
	if (toc_buf == NULL)
		return 1;

	ptoc = (struct FipHeader *)toc_buf;
	toc_pos = ftell(fout);
	//printf("toc_pos = %lx\n", toc_pos);
	fread(toc_buf, 1, 0x4000, fin);
	n = 0;
	while (ptoc->entries[n].size != 0) {
		n++;
	}
	fwrite(toc_buf, 1, 0x4000, fout);

	buf = malloc(0x10000);
	if (buf == NULL)
		return 1;

	for (i = 0; i < n; i++) {
		struct AmlogicHeader fip_hdr = {
			.sig = AMLOGIC_SIGNATURE,
			.size = 64,
			.header_size = sizeof(struct AmlogicHeader),
			.x4 = 1,
			.digest_size = SHA256_DIGEST_LENGTH,
		};
		SHA256_CTX sha256_ctx;
		uint8_t sha256_digest[SHA256_DIGEST_LENGTH];
		size_t len;
		long pos;
		long remaining;
		int padlen;

		pos = ftell(fout);

		printf("FIP TOC entry offset_address: %" PRIx64 "\n", ptoc->entries[i].offset_address);
		printf("FIP TOC entry size: %" PRIx64 "\n", ptoc->entries[i].size);

		fseek(fin, toc_pos + ptoc->entries[i].offset_address, SEEK_SET);
		printf("Input at %lx\n", ftell(fin));

		len = ptoc->entries[i].size & (16 - 1);
		padlen = (len != 0) ? (16 - len) : 0;

		memset(buf, 0, 0x10000);
		fip_hdr.size += fip_hdr.digest_size + ptoc->entries[i].size + padlen;
		//fip_hdr.id = 0x4ee06c7b;
		fip_hdr.id = 0x42424200 + i;
		fip_hdr.digest_offset = fip_hdr.header_size;
		fip_hdr.data_offset = fip_hdr.digest_offset + fip_hdr.digest_size;
		fip_hdr.bl2_offset = fip_hdr.data_offset;
		fip_hdr._offset2 = fip_hdr.size - 0x60;
		fip_hdr.fip_offset = fip_hdr.size - 0x60;
		fip_hdr._size2 = fip_hdr.header_size + SHA256_DIGEST_LENGTH;
		memcpy(buf, &fip_hdr, sizeof(fip_hdr));

		fwrite(buf, 1, fip_hdr.header_size + fip_hdr.digest_size, fout);

		SHA256_Init(&sha256_ctx);
		SHA256_Update(&sha256_ctx, buf, fip_hdr.header_size);
		SHA256_Update(&sha256_ctx, buf + fip_hdr.data_offset, 0);
		remaining = ptoc->entries[i].size;
		len = fread(buf, 1, fip_hdr.header_size + fip_hdr.digest_size, fin);
		if (strncmp(buf + 16, "@AML", 4) == 0) {
			fprintf(stderr, "@AML discovered in input FIP section %i!\n", i);
			return 1;
		}
		SHA256_Update(&sha256_ctx, buf, len);
		remaining -= len;
		while (remaining > 0) {
			len = fread(buf, 1, (remaining > 0x4000) ? 0x4000 : remaining, fin);
			//printf("Read %lx\n", len);
			remaining -= len;
			memset(buf + len, 0, len & 0xf);
			SHA256_Update(&sha256_ctx, buf, ROUND_UP(len, 16));
			fwrite(buf, 1, ROUND_UP(len, 16), fout);
		}
		SHA256_Final(sha256_digest, &sha256_ctx);
		fseek(fout, pos + fip_hdr.digest_offset, SEEK_SET);
		fwrite(sha256_digest, 1, sizeof(sha256_digest), fout);
		fseek(fout, 0, SEEK_END);

		fseek(fin, toc_pos + ptoc->entries[i].offset_address, SEEK_SET);
		len = fread(buf, 1, fip_hdr.header_size + fip_hdr.digest_size, fin);
		fwrite(buf, 1, len, fout);

		ptoc->entries[i].size += fip_hdr.header_size + fip_hdr.digest_size + padlen;
		//ptoc->entries[i].offset_address += padlen;
		//printf("FIP TOC entry offset_address: %" PRIx64 "\n", ptoc->entries[i].offset_address);
		printf("FIP TOC entry size: %" PRIx64 "\n", ptoc->entries[i].size);
		len = ptoc->entries[i].size & (0x4000 - 1);
		if (len != 0) {
			len = 0x4000 - len;
			memset(buf, 0, len);
			fwrite(buf, 1, len, fout);
		}
	}
	free(buf);
	//ptoc->entries[i].offset_address = ROUND_UP(ptoc->entries[i].offset_address, 16);
	fseek(fout, toc_pos, SEEK_SET);
	fwrite(toc_buf, 1, 0x4000, fout);
	fseek(fout, 0, SEEK_END);
	free(toc_buf);
}

static int test(void)
{
	FILE *fin, *fout;
	uint8_t random[16];
	uint8_t *src_buf, *buf, *fip_buf;
	struct AmlogicHeader hdr = {
		.sig = AMLOGIC_SIGNATURE,
		.size = 64,
		.header_size = 64,
		.x4 = 1,
		.encrypted = 0,
		.digest_offset = 64,
		.digest_size = 512,
	};
	SHA256_CTX sha256_ctx;
	uint8_t sha256_digest[SHA256_DIGEST_LENGTH];
	int i;

	assert(sizeof(struct AmlogicHeader) == 64);

	src_buf = malloc(0xb000);
	if (src_buf == NULL)
		return 1;

	fin = fopen("../boot_new.bin", "rb");
	if (fin == NULL)
		return 1;

	fout = fopen("test.out", "wb");
	if (fout == NULL)
		return 1;

	for (i = 0; i < 16; i++)
	//	random[i] = rand();
		random[i] = 0x42;
	//memcpy(random, (uint8_t[]){ 0xde, 0x49, 0x4c, 0x47, 0xe1, 0xd4, 0x86, 0xca,  0xb7, 0x4f, 0x10, 0xa4, 0x29, 0x3f, 0x28, 0x00 }, 16);

	fwrite(random, 1, 16, fout);

	fread(src_buf, 1, 0xb000, fin);

	if (strncmp(src_buf + 16, "@AML", 4) == 0) {
		fprintf(stderr, "@AML discovered in input!\n");
		return 1;
	}

	fseek(fin, 0xc000, SEEK_SET);

	hdr.size += hdr.digest_size;
	hdr.size += 0xdb0;
	hdr.size += 0xb000;
	hdr.digest_offset = hdr.header_size;
	hdr.data_offset = hdr.header_size + SHA256_DIGEST_LENGTH;
	hdr.bl2_offset = hdr.digest_offset + 512;
	hdr.bl2_size = 3504;
	hdr._offset2 = hdr.size - hdr.data_offset;
	hdr._size2 = hdr.bl2_offset + hdr.bl2_size;
	hdr.fip_offset = 0xb000;

	buf = malloc(hdr.size);
	if (buf == NULL)
		return 1;

	memset(buf, 0, hdr.size);
	memcpy(buf, &hdr, sizeof(struct AmlogicHeader));
	memcpy(buf + hdr.bl2_offset + hdr.bl2_size, src_buf, 0xb000);

	SHA256_Init(&sha256_ctx);
	SHA256_Update(&sha256_ctx, buf, hdr.header_size);
	SHA256_Update(&sha256_ctx, buf + hdr.data_offset, hdr._offset2);
	memset(sha256_digest, 0, sizeof(sha256_digest));
	SHA256_Final(sha256_digest, &sha256_ctx);
	memcpy(buf + hdr.digest_offset, sha256_digest, sizeof(sha256_digest));

	fwrite(buf, 1, hdr.size, fout);

	if (do_fip(fout, fin) != 0)
		return 1;

	fclose(fout);
	fclose(fin);

	free(src_buf);

	return 0;
}

int main(void)
{
	return test();
}
