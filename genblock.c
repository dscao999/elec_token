#include <stdio.h>
#include <stdlib.h>
#include "tok_block.h"

#define K32B	(32*1024)

static char blkbuf[K32B];

int main(int argc, char *argv[])
{
	int blklen, zbits;
	struct bl_header *hdr;
	struct sha256 sha;
	FILE *fh;

	if (argc > 1)
		zbits = atoi(argv[1]);
	else
		zbits = 24;
	tok_block_init(zbits);
	blklen = gensis_block(blkbuf, K32B);
	printf("Gensis block mined, length: %d\n", blklen);
	hdr = (struct bl_header *)blkbuf;
	sha256_reset(&sha);
	sha256(&sha, (const unsigned char *)hdr, sizeof(struct bl_header));
	printf("Fist Integer: %08X %08X\n", sha.H[0], sha.H[1]);

	fh = fopen("/tmp/gensis.dat", "wb");
	fwrite(blkbuf, 1, sizeof(struct bl_header), fh);
	fclose(fh);
	return 0;
}
