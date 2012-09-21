/*
 * Deconstruct an image created by the utility lapbind
 *
 * Copyright (C) 2012, Florian Fainelli <florian@openwrt.org>
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
 */

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/mman.h>
#include <errno.h>
#include <string.h>

#include <openssl/md5.h>

/* Upgrade type is a bitmask, you can combine several upgrades */
#define UPGRADE_TYPE_AUTO	0x00
#define UPGRADE_TYPE_KERNEL	0x01
#define UPGRADE_TYPE_ROOTFS	0x02
#define UPGRADE_TYPE_BOOTROM	0x10
#define UPGRADE_TYPE_BOARD_DATA	0x20

#define PID_SIZE		112	/* bytes */

/*
 * File layout is the following:
 * - PID			112 bytes
 * - Main lap header		5 bytes
 * - bootloader descriptor	7 bytes
 * - bootloader			<described in header>
 * - kernel descriptor		7 bytes
 * - kernel			<described in header>
 * - rootfs descriptor		7 bytes
 * - rootfs			<described in header>
 * - board data descriptor	7 bytes
 * - board data			<described in header>
 * - Final MD5			16 bytes
 */

/* Main header */
struct lap_hdr {
	uint32_t	length;
	uint8_t		upgrade_type;
} __attribute__ ((__packed__));

/* File descriptors headers */
struct lap_desc_hdr {
	uint8_t upgrade_type;
	uint16_t version;
	uint32_t length;
} __attribute__ ((__packed__));

static const char *filenames[] = {
	"u-boot.bin",
	"vmlinux.gz.uImage",
	"rootfs.sqsh",
	"board.radio",
	NULL
};

static const char *upgrade_type_to_str(uint8_t type)
{
	switch (type) {
	case UPGRADE_TYPE_AUTO:
		return "auto";
	case UPGRADE_TYPE_KERNEL:
		return "kernel";
	case UPGRADE_TYPE_ROOTFS:
		return "rootfs";
	case UPGRADE_TYPE_BOOTROM:
		return "bootrom";
	case UPGRADE_TYPE_BOARD_DATA:
		return "board data";
	default:
		return "unknown";
	}
}

static void print_lap_desc_hdr(struct lap_desc_hdr *hdr)
{
	fprintf(stdout, "Upgrade type: %02x (%s)\n",
		hdr->upgrade_type,
		upgrade_type_to_str(hdr->upgrade_type));
	fprintf(stdout, "Version: %04x\n", be16toh(hdr->version));
	fprintf(stdout, "Length: %d\n", be32toh(hdr->length));
}

static void print_md5digest(unsigned char *digest)
{
	unsigned int i;

	for (i = 0; i < MD5_DIGEST_LENGTH; i++)
		fprintf(stdout, "%02x", digest[i]);
}

int main(int argc, char **argv)
{
	int ret = -1;
	const char *firmware = argv[1];
	void *buf;
	FILE *fp;
	int fd;
	off_t filesize;
	struct lap_hdr *hdr;
	struct lap_desc_hdr *desc_hdr;
	unsigned int index = 0;
	unsigned int offset = 0;
	MD5_CTX md5_ctx;
	unsigned char digest[MD5_DIGEST_LENGTH];

	memset(&md5_ctx, 0, sizeof(md5_ctx));

	MD5_Init(&md5_ctx);

	fd = open(firmware, O_RDONLY);
	if (fd < 0) {
		fprintf(stderr, "failed to open %s\n", argv[1]);
		return fd;
	}

	filesize = lseek(fd, 0, SEEK_END);
	lseek(fd, 0, SEEK_SET);

	if (!filesize) {
		fprintf(stderr, "empty file size: %zu\n", filesize);
		goto out;
	}

	buf = mmap(NULL, filesize, PROT_READ, MAP_PRIVATE, fd, 0);
	if (buf == MAP_FAILED) {
		fprintf(stderr, "failed to create mmap\n");
		goto out;
	}

	MD5_Update(&md5_ctx, buf, filesize - MD5_DIGEST_LENGTH);
	MD5_Final(digest, &md5_ctx);

	fp = fopen("pid.txt", "wb+");
	if (!fp) {
		fprintf(stderr, "failed to create pid.bin\n");
		goto out_unmap;
	}

	fwrite(buf, PID_SIZE, 1, fp);
	fclose(fp);

	offset = PID_SIZE;
	hdr = (struct lap_hdr *)(buf + offset);
	fprintf(stdout, "File length: %u\n", be32toh(hdr->length));
	fprintf(stdout, "Upgrade type: %d (%s)\n",
		hdr->upgrade_type, upgrade_type_to_str(hdr->upgrade_type));
	offset += sizeof(struct lap_hdr);

	while (offset != be32toh(hdr->length)) {
		desc_hdr = (struct lap_desc_hdr *)(buf + offset);
		print_lap_desc_hdr(desc_hdr);

		fp = fopen(filenames[index], "wb+");
		if (!fp) {
			perror("fopen");
			goto out_unmap;
		}

		fwrite(buf + offset + sizeof(*desc_hdr), be32toh(desc_hdr->length), 1, fp);
		fclose(fp);

		offset += be32toh(desc_hdr->length) + sizeof(*desc_hdr);
		index++;
	}

	/* Now check MD5 against the one present */
	ret = memcmp(buf + filesize - MD5_DIGEST_LENGTH, digest, MD5_DIGEST_LENGTH);
	fprintf(stdout, "MD5sum: %smatch, got: ", ret != 0 ? "mis" : "");
	print_md5digest(buf + filesize - MD5_DIGEST_LENGTH);
	fprintf(stdout, " expected: ");
	print_md5digest(digest);
	fprintf(stdout, "\n");

out_unmap:
	munmap(buf, filesize);
out:
	close(fd);
	return ret;
}
