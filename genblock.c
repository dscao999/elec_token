#include <stdio.h>
#include <stdlib.h>
#include "tok_block.h"
#include "global_param.h"

#define K32B	(32*1024)

static char blkbuf[K32B];

int main(int argc, char *argv[])
{
	int blklen, i;
	struct bl_header *hdr;
	unsigned char sha_dgst[SHA_DGST_LEN];
	FILE *fh;

	global_param_init(NULL, 1, 0);
	blklen = gensis_block(blkbuf, K32B);
	printf("Gensis block mined, length: %d\n", blklen);
	hdr = (struct bl_header *)blkbuf;
	sha256_dgst_2str(sha_dgst, (const unsigned char *)hdr,
			sizeof(struct bl_header));
	printf("Block Header Digest: ");
	for (i = 0; i < SHA_DGST_LEN; i++)
		printf(" %02X", sha_dgst[i]);
	printf(".\nNumber of leading bits: %d\n", zbits_blkhdr(hdr, NULL));

	fh = fopen("/tmp/gensis.dat", "wb");
	fwrite(blkbuf, 1, sizeof(struct bl_header), fh);
	fclose(fh);
	return 0;
}
