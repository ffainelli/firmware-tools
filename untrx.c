/*
 * untrx v0.1
 * 
 * Copyright (C) 2011, Florian Fainelli <florian@openwrt.org>
 *
 * Deconstruct a file with a TRX header. Definitions
 * borrowed from OpenWrt's tools/firmware-utils/src/trx.c.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE. 
 * 
 */

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <endian.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <limits.h>
#include <libgen.h>
#include <getopt.h>
#include <arpa/inet.h>

#define trx_printf(...)				\
	do {						\
		if (verbose)				\
			printf(__VA_ARGS__);	\
	} while (0);

#if __BYTE_ORDER == __BIG_ENDIAN
#define STORE32_LE(X)           bswap_32(X)
#define LOAD32_LE(X)            bswap_32(X)
#elif __BYTE_ORDER == __LITTLE_ENDIAN
#define STORE32_LE(X)           (X)
#define LOAD32_LE(X)            (X)
#else
#error unkown endianness!
#endif

#define TRX_MAGIC	0x30524448      /* "HDR0" */
#define TRX_MAX_LEN	0x720000
#define TRX_ROUND	0x1000
#define TRX_FSMARK	0x00088b1f	/* FIXME: not sure what it is about */

#define ARRAY_SIZE(x)	(sizeof(x) / sizeof(x[0]))

struct trx_header {
	uint32_t magic;		/* "HDR0" */
	uint32_t len;		/* Length of file including header */
	uint32_t crc32;		/* 32-bit CRC from flag_version to end of file */
	uint32_t flag_version;	/* 0:15 flags, 16:31 version */
	uint32_t offsets[4];	/* Offsets of partitions from start of header */
};

#define BPB 		8 /* bits/byte */

static uint32_t crc32[1 << BPB];

static unsigned int verbose;

static uint32_t parts[4];

/*
 * Initialize the crc32 array
 */
static void init_crc32()
{
	const uint32_t poly = ntohl(0x2083b8ed);
	int n;

	for (n = 0; n < 1<<BPB; n++) {
		uint32_t crc = n;
		int bit;

		for (bit = 0; bit < BPB; bit++)
			crc = (crc & 1) ? (poly ^ (crc >> 1)) : (crc >> 1);
		crc32[n] = crc;
	}
}

/*
 * Return the CRC32 of a given buffer
 */
static uint32_t crc32buf(unsigned char *buf, size_t len)
{
	uint32_t crc = ~0;

	for (; len; len--, buf++)
		crc = crc32[(uint8_t)crc ^ *buf] ^ (crc >> BPB);

	return crc;
}

/*
 * Compare two uint32_t values
 */
static int cmp_uint32t(const void *a, const void *b)
{
	return (*(const uint32_t *)a - *(const uint32_t *)b);
}

/*
 * Determine if the given TRX header is valid (using version and crc32)
 */
static bool untrx_header_is_valid(struct trx_header *hdr,
				void *buf, size_t len,
				off_t hdr_offset)
{
	unsigned int version;
	unsigned int i;
	unsigned int num_parts = 0;
	uint32_t crc;
	size_t crc_len;

	init_crc32();

	if (htole32(hdr->magic) != TRX_MAGIC) {
		fprintf(stderr, "invalid magic: 0x%08x (expected: %08x)\n",
				hdr->magic, TRX_MAGIC);
		return false;
	}

	version = (htole32(hdr->flag_version) >> 16);
	if (version > 2) {
		fprintf(stderr, "unknown TRX version: %d\n", version);
		return false;
	}

	trx_printf("TRX header version: %d\n", version);

	crc_len = hdr->len - offsetof(struct trx_header, flag_version);

	crc = crc32buf((unsigned char *)&hdr->flag_version, crc_len);
	if (htole32(hdr->crc32) != crc) {
		fprintf(stderr, "crc32 mismatch: 0x%08x (expected: 0x%08x)\n",
							crc, hdr->crc32);
		return false;
	}

	for (i = 0; i < ARRAY_SIZE(hdr->offsets); i++) {
		trx_printf("TRX part: %d, offset: 0x%08x\n",
						i, htole32(hdr->offsets[i]));

		if (htole32(hdr->offsets[i]))
			num_parts++;
	}

	trx_printf("TRX with %d parts\n", num_parts);

	/* Copy then sort the array of partitions */
	for (i = 0; i < num_parts; i++) {
		if (htole32(hdr->offsets[i]) == TRX_FSMARK)
			continue;
		parts[i] = htole32(hdr->offsets[i]);
	}

	qsort(&parts[0], ARRAY_SIZE(parts), sizeof(parts[0]), cmp_uint32t);

	return true;
}

/*
 * Extract a partition from the given buffer
 */
static int untrx_extract_part(void *buf, size_t size,
			unsigned int offset, const char *out,
			unsigned int number)
{
	FILE *fp;
	size_t cnt;

	trx_printf("Extracting part %d (offset: 0x%08x, size: %zd)\n",
						number, offset, size);

	fp = fopen(out, "wb+");
	if (!fp) {
		perror("fopen");
		return -1;
	}

	cnt = fwrite(buf + offset, 1, size, fp);
	if (cnt < size) {
		fprintf(stderr, "short write: %zd\n", cnt);
		goto err;
	}

	fclose(fp);
	return 0;

err:
	if (fp)
		fclose(fp);
	unlink(out);

	return -1;
}

/*
 * Find a TRX header using the magic in a buffer
 */
static int untrx_find_header(void *buf, size_t len, off_t *offset)
{
	uint32_t *signature;
	unsigned int i;

	*offset = 0;

	/* Walk the buffer by jumps of 4 bytes */
	for (i = 0; i < len; i += 4) {
		signature = htole32(buf + i);
		if (*signature == TRX_MAGIC) {
			*offset = i;
			break;
		}
	}

	if (i == len) {
		fprintf(stderr, "could not find signature!\n");
		return -1;
	}

	trx_printf("Found magic at offset: 0x%08lx\n", *offset);

	return 0;
}

static void usage(void)
{
	fprintf(stderr, "untrx [options] [file]\n"
			"-b:     basename (used to create <basename>.part<N> files, default: file)\n"
			"-v:     be verbose (default: no)\n"
			"-h:     this help\n");
	exit(1);
}

int main(int argc, char **argv)
{
	int ret = 0;
	int fd = -1;
	int opt;
	const char *filename = NULL;
	char *bname = NULL;
	void *buf;
	off_t size;
	off_t header_offset;
	struct trx_header *hdr;
	unsigned int i;
	char partname[PATH_MAX];
	size_t partsize;

	while ((opt = getopt(argc, argv, "vb:h")) > 0) {
		switch (opt) {
		case 'b':
			bname = optarg;
			break;
		case 'v':
			verbose = 1;
			break;
		case 'h':
		default:
			usage();
			break;
		}
	}

	argc -= optind;
	argv += optind;

	filename = argv[0];

	if (!filename)
		usage();

	fd = open(filename, O_RDONLY);
	if (fd < 0) {
		perror("open");
		return fd;
	}

	/* Get file size */
	size = lseek(fd, 0, SEEK_END);
	if (size < 0) {
		fprintf(stderr, "invalid file length: %zd\n", size);
		ret = -1;
		goto out;
	}

	lseek(fd, 0, SEEK_SET);

	buf = mmap(NULL, size, PROT_READ, MAP_PRIVATE, fd, 0);
	if (buf == MAP_FAILED) {
		perror("mmap");
		ret = -1;
		goto out;
	}

	/* Find header */
	ret = untrx_find_header(buf, size, &header_offset);
	if (ret) {
		fprintf(stderr, "invalid file\n");
		goto out;
	}

	/* Verify the header is valid */
	hdr = buf + header_offset;
	if (!untrx_header_is_valid(hdr, buf, size, header_offset)) {
		fprintf(stderr, "invalid TRX header, aborting\n");
		ret = -1;
		goto out;
	}

	/* Get the basename of the file and use it for writing parts */
	if (!bname)
		bname = basename((char *)filename);

	trx_printf("Using %s as basename\n", bname);

	for (i = 0; i < ARRAY_SIZE(parts); i++) {
		snprintf(partname, sizeof(partname), "%s.part%d",
						bname, i);

		if (i == (ARRAY_SIZE(parts) - 1))
			partsize = size - parts[i];
		else
			partsize = parts[i + 1] - parts[i];

		ret = untrx_extract_part(buf + header_offset,
						partsize,
						parts[i],
						partname, i);
		if (ret) {
			fprintf(stderr, "failed to extract part: %d\n", i);
			goto out;
		}
	}

	trx_printf("Done\n");

out:
	if (buf)
		munmap(buf, size);

	if (fd)
		close(fd);

	return ret;
}
