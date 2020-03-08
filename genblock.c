#include <stdio.h>
#include "tok_block.h"

#define K32B	(32*1024)

static char blkbuf[K32B];

int main(int argc, char *argv[])
{
	int zbits;
	struct bl_header *hdr;
	struct sha256 sha;

	zbits = gensis_block(blkbuf, K32B);
	printf("Gensis block mined: %d\n", zbits);
	hdr = (struct bl_header *)blkbuf;
	sha256_reset(&sha);
	sha256(&sha, (const unsigned char *)hdr, sizeof(struct bl_header));
	printf("Fist Integer: %08X\n", sha.H[0]);
	return 0;
}
