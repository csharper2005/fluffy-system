// SPDX-License-Identifier: GPL-2.0-only
/*
 * TP-Link v3 image generation tool (for TP-Link EC330-G5u v1)
 * Copyright (C) 2023 Mikhail Zhilkin <csharper2005@gmail.com>
 *
 * The main idea was suggested by:
 *   Alexey Bartenev <41exey@proton.me>
 *
 * This tool was based on:
 *   TP-Link v2 image generation tool
 *   Copyright (C) 2009 Gabor Juhos <juhosg@openwrt.org>
 */

#define BUF_SIZE		0x100000
#define	CLOUD_ID_BYTE_LEN	0x10
#define	HDR_OS0_LEN		0x500
#define	HDR_PART_LEN		0xb00
#define	MAGIC_NUM_LEN		0x14
#define	MD5_DIGEST_LENGTH	0x10
#define	OS0_SIG_LEN		0x28
#define	PART_LABEL_LEN		0x20
#define	SIG_LEN			0x80
#define	TOKEN_LEN		0x14

#define ERR(fmt, ...) do { \
	fflush(0); \
	fprintf(stderr, "[%s] *** error: " fmt "\n", \
		this_fname, ## __VA_ARGS__ ); \
} while (0)

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <libgen.h>
#include <unistd.h>
#include <openssl/evp.h>

typedef struct _hdr
{
	uint32_t	tag_version;			/* 0x00:  tag version number */
	uint8_t		hw_id[CLOUD_ID_BYTE_LEN];	/* 0x04:  hwid for cloud */
	uint8_t		fw_id[CLOUD_ID_BYTE_LEN];	/* 0x14:  fwid for cloud */
	uint8_t		oem_id[CLOUD_ID_BYTE_LEN];	/* 0x24:  oemid for cloud */
	uint32_t	product_id;			/* 0x34:  product id */
	uint32_t	product_ver;			/* 0x38:  product version */
	uint32_t	add_hw_ver;			/* 0x3c:  addtional hardware version */
	uint8_t		file_md5[TOKEN_LEN];		/* 0x40:  image validation token (md5 */
							/*        chksum) */
	uint8_t		magic_num[MAGIC_NUM_LEN];	/* 0x54:  magic number */
	uint32_t	kernel_text_addr;		/* 0x68:  kernel text section address */
	uint32_t	kernel_entry_point; 		/* 0x6c:  kernel entry point address */
	uint32_t	total_image_len;		/* 0x70:  kernel+rootfs+tag length */
	uint32_t	kernel_address;			/* 0x74:  kernel image offset (from */
							/*        beginning of FILE_TAG) */
	uint32_t	kernel_len;			/* 0x78:  length of kernel image */
	uint32_t	rootfs_address;			/* 0x7c:  filesystem image offset*/
	uint32_t	rootfs_len;			/* 0x80:  length of filesystem image */
	uint32_t	boot_address;			/* 0x84:  bootloader image offset */
	uint32_t	boot_len;			/* 0x88:  length of bootloader image */
	uint32_t	sw_revision;			/* 0x8c:  software revision */
	uint32_t	platform_ver;			/* 0x90:  platform version */
	uint32_t	special_ver;			/* 0x94:  special version */
	uint32_t	bin_crc32;			/* 0x98:  crc32 kernel+rootfs */
	uint32_t	file_size;			/* 0x9c:  file size */
	uint32_t	up_ptn_entry_num;		/* 0xa0:  up_ptn_entry_num */
	uint32_t	flash_ptn_entry_num;		/* 0xa4:  flash_ptn_entry_num */
	uint32_t	reserved1[0xa];			/* 0xa8:  reserved for future */
	uint8_t		sig[SIG_LEN];			/* 0xd0:  signature for update */
	uint8_t		res_sig[SIG_LEN];		/* 0x150: reserved for signature */
	uint32_t	reserved2[0xc];			/* 0x1d0: reserved for future */
	uint8_t		os0_sig[HDR_OS0_LEN];		/* 0x200: os0 signature */
	uint8_t		layout_info[HDR_PART_LEN];	/* 0x700: flash layout info */
} __attribute__ ((packed)) _hdr;

typedef struct _part
{
	char		label[PART_LABEL_LEN];
	uint32_t	size;
	uint32_t	offset;
} _part;

/* TP-Link EC330-g5u partitions */
const _part ec330_parts[0x6] = {
	{ "uboot",	0x400000,	0x0 },
	{ "os0",	0x3000000,	0x400000 },
	{ "os1",	0x3000000,	0x3400000 },
	{ "userfs",	0x1000000,	0x6400000 },
	{ "ubootenv",	0x400000,	0x7400000 },
	{ "factory",	0x400000,	0x7800000 }
};

uint8_t md5_salt[TOKEN_LEN] = {
	0x8c, 0xef, 0x33, 0x5f, 0xd5, 0xc5, 0xce, 0xfa,
	0xac, 0x9c, 0x28, 0xda, 0xb2, 0xe9, 0x0f, 0x42,
};

char *this_fname, *in_fname, *out_fname;

void append_file(FILE *file, FILE *add)
{
	uint8_t buf[BUF_SIZE];
	ssize_t bytes;

	fseek(add, 0L, SEEK_SET);
	while ( 1 ) {
		bytes = fread(buf, 1, BUF_SIZE, add);
		if (bytes > 0)
			fwrite(&buf, bytes, 1, file);
		else
			break;
	}
}

static int check_options(void)
{
	if (in_fname == NULL) {
		ERR("No input file specified");
		return -1;
	}

	if (out_fname == NULL) {
		ERR("No output file specified");
		return -1;
	}

	return 0;
}

int get_file_size(FILE *file)
{
	int f_size;

	fseek(file, 0L, SEEK_END);
	f_size = ftell(file);

	return f_size;
}

void get_md5_hash(const void *data, size_t count,
		  FILE *file, uint8_t *md5)
{
	ssize_t bytes;
	uint32_t md5_len;
	uint8_t buf[BUF_SIZE];
	EVP_MD_CTX* md5_cntxt;

	md5_cntxt = EVP_MD_CTX_new();
	EVP_DigestInit_ex(md5_cntxt, EVP_md5(), NULL);
	EVP_DigestUpdate(md5_cntxt, data, count);
	fseek(file, 0L, SEEK_SET);
	while ( 1 ) {
		bytes = fread(buf, 1, BUF_SIZE, file);
		if (bytes > 0)
			EVP_DigestUpdate(md5_cntxt, buf, bytes);
		else
			break;
	}
	EVP_DigestFinal_ex(md5_cntxt, md5, &md5_len);
	EVP_MD_CTX_free(md5_cntxt);
}

void print_md5(const uint8_t *md5, uint8_t size)
{
	printf("md5 hash: ");
	for(uint8_t n = 0; n < size; n++)
		printf("%02x", md5[n]);
	printf("\n");
}

void set_main_hdr(struct _hdr *hdr)
{
	memset(hdr, 0xff, sizeof(*hdr));
	hdr->tag_version = 0x3000003;
	uint8_t hw_id[CLOUD_ID_BYTE_LEN] = {
		0x4c, 0x0b, 0xd0, 0xd6, 0xa6, 0x61, 0xff, 0x19,
		0x39, 0x04, 0xe1, 0x81, 0x51, 0x3b, 0x2f, 0xd0,
	};
	memcpy(hdr->hw_id, hw_id, sizeof(hw_id));

	uint8_t fw_id[CLOUD_ID_BYTE_LEN] = {
		0xd0, 0x49, 0xa3, 0xb7, 0xd1, 0x9d, 0x5b, 0x58,
		0x0c, 0x53, 0x10, 0x86, 0xae, 0x1e, 0xa4, 0xf3,
	};
	memcpy(hdr->fw_id, fw_id, sizeof(fw_id));

	hdr->product_id  = 0x5c5cbb01;
	hdr->product_ver = 0x60037;
	hdr->add_hw_ver  = 0x1;
	memcpy(hdr->file_md5, md5_salt, sizeof(md5_salt));
	uint8_t magic_num[MAGIC_NUM_LEN] = {
		0x55, 0xaa, 0x55, 0xaa, 0xf1, 0xe2, 0xd3, 0xc4,
		0xe5, 0xa6, 0x6a, 0x5e, 0x4c, 0x3d, 0x2e, 0x1f,
		0xaa, 0x55, 0xaa, 0x55,
	};
	memcpy(hdr->magic_num, magic_num, sizeof(magic_num));

	hdr->kernel_address	= 0x200;
	hdr->kernel_len		= 0x0;
	hdr->boot_address	= 0x0;
	hdr->boot_len		= 0x0;
	hdr->sw_revision	= 0x55aa0310;
	hdr->platform_ver	= 0xa5000901;
	hdr->special_ver	= 0x0;
	hdr->up_ptn_entry_num	= 0x1;
	hdr->flash_ptn_entry_num = 0x6;
	uint8_t sig[SIG_LEN] = {
		0xb3, 0x35, 0x5d, 0x47, 0xc7, 0x4d, 0x2d, 0xd4,
		0x9e, 0xc8, 0xe5, 0xe6, 0x82, 0xb2, 0x70, 0xae,
		0xc1, 0x97, 0xb3, 0xbf, 0xee, 0xd6, 0xdd, 0x05,
		0xe0, 0x4e, 0xe3, 0x39, 0xb8, 0xb9, 0xc3, 0xac,
		0x17, 0xe4, 0x6e, 0x3f, 0x43, 0xe6, 0x11, 0x3c,
		0x16, 0x0a, 0xb5, 0x9c, 0x84, 0x04, 0xce, 0x7a,
		0x4f, 0x3d, 0xdd, 0x90, 0x15, 0x0b, 0x09, 0x44,
		0x83, 0xfc, 0x51, 0xf5, 0x26, 0x7f, 0x5d, 0x23,
		0xb2, 0x1d, 0xc5, 0x00, 0x71, 0x94, 0xcb, 0xf6,
		0x8c, 0x12, 0xb5, 0xb8, 0xff, 0x23, 0xb2, 0xee,
		0xcc, 0x7a, 0x90, 0xa5, 0x26, 0x18, 0x42, 0x3b,
		0x44, 0x72, 0x4d, 0x0a, 0x1b, 0x21, 0xa6, 0xfe,
		0x6d, 0x8f, 0xbd, 0xf8, 0x25, 0x81, 0xeb, 0x6b,
		0xbe, 0xde, 0xc4, 0x8e, 0x45, 0xdc, 0x2f, 0x5f,
		0x50, 0xbc, 0x2e, 0x47, 0xca, 0xbe, 0x51, 0x1b,
		0xb5, 0xe2, 0x23, 0xa9, 0x62, 0xea, 0x51, 0x72,
	};
	memcpy(hdr->sig, sig, sizeof(sig));
	memset(hdr->res_sig, 0x0, SIG_LEN * sizeof(uint8_t));

	return;
}

void set_os0_sig(struct _hdr *hdr)
{
	memset(hdr->os0_sig, 0x0, OS0_SIG_LEN * sizeof(uint8_t));
	hdr->os0_sig[0x0]  = 'o';
	hdr->os0_sig[0x1]  = 's';
	hdr->os0_sig[0x2]  = '0';
	hdr->os0_sig[0x22] = 0x16;
	hdr->os0_sig[0x23] = 0x1;
	hdr->os0_sig[0x25] = 0x10;

	return;
}

void set_part_info(struct _hdr *hdr)
{
	memcpy(hdr->layout_info, &ec330_parts, sizeof(ec330_parts));

	return;
}

void create_fw_hdr(struct _hdr *hdr)
{
	set_main_hdr(hdr);
	set_os0_sig(hdr);
	set_part_info(hdr);

	return;
}

void usage(int status)
{
	FILE *stream = (status != EXIT_SUCCESS) ? stderr : stdout;

	fprintf(stream, "TP-Link v3 image generation tool "
			"(for TP-Link EC330-G5u v1)\n");
	fprintf(stream, "Copyright (C) 2023 Mikhail Zhilkin\n");
	fprintf(stream, "Usage: %s [OPTIONS...]\n", this_fname);
	fprintf(stream,
		"\n"
		"Options:\n"
		"  -h              show this screen\n"
		"  -i <file>       input file <file>\n"
		"  -o <file>       output file <file>\n"
	);

	exit(status);
}

int main(int argc, char *argv[])
{
	_hdr fw_hdr;
	FILE *ifile, *ofile;
	int ret = EXIT_FAILURE, size;
	uint8_t md5_hash[MD5_DIGEST_LENGTH];

	this_fname = basename(argv[0]);
	while ( 1 ) {
		int c;

		c = getopt(argc, argv, "i:o:");
		if (c == -1)
			break;

		switch (c) {
		case 'i':
			in_fname = optarg;
			break;
		case 'o':
			out_fname = optarg;
			break;
		case 'h':
			usage(EXIT_SUCCESS);
			break;
		default:
			usage(EXIT_FAILURE);
			break;
		}
	}

	ret = check_options();
	if (ret) {
		usage(ret);
	}

	create_fw_hdr(&fw_hdr);
	size = sizeof(fw_hdr);
	printf("HDR size: %d (0x%08x) bytes\n", size, size);

	ifile = fopen(in_fname, "r");
	if (ifile == NULL) {
		ERR("Error opening input file %s", in_fname);
		return EXIT_FAILURE;
	}
	size = get_file_size(ifile);
	printf("Input file size: %d (0x%08x) bytes\n", size, size);

	fw_hdr.file_size = size + sizeof(fw_hdr);
	get_md5_hash(&fw_hdr, sizeof(fw_hdr), ifile, (uint8_t *)&md5_hash);
	print_md5(md5_hash, MD5_DIGEST_LENGTH);
	memcpy(&fw_hdr.file_md5, &md5_hash, sizeof(md5_hash));

	ofile = fopen(out_fname, "wb");
	if (ofile == NULL) {
		ERR("Error opening output file %s", out_fname);
		return EXIT_FAILURE;
	}

	fwrite(&fw_hdr, sizeof(fw_hdr), 1, ofile);
	append_file(ofile, ifile);

	fclose(ifile);
	size = get_file_size(ofile);
	fclose(ofile);
	printf("Output file size: %d (0x%08x) bytes\n", size, size);

	return 0;
}
