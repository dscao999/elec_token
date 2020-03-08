#include <stdio.h>
#include <string.h>
#include "loglog.h"
#include "base64.h"
#include "virtmach.h"

int main(int argc, char *argv[])
{
	char *pkhash, *special;
	FILE *pkf;
	unsigned char ripemd[21], dup[2], checksig[2];
	int numb;

	if (argc > 1)
		pkhash = argv[1];
	else
		return 0;

	numb = str2bin_b64(ripemd+1, 20, pkhash);
	if (numb + 1 != 20) {
		logmsg(LOG_ERR, "not a ripemd160 hash!\n");
		return 1;
	}

	dup[0] = OP_DUP;
	dup[1] = OP_RIPEMD160;
	checksig[0] = OP_EQUALVERIFY;
	checksig[1] = OP_CHECKSIG;
	special = pkhash + strlen(pkhash) - 1;
	if (*special == '=')
		*special = 0;
	special = pkhash;
	while (special) {
		special = strchr(special, '/');
		if (special) {
			*special = '_';
			special++;
		}
	}
	ripemd[0] = 20;
	pkf = fopen(pkhash, "wb");
	fwrite(dup, 1, 2, pkf);
	fwrite(ripemd, 1, 21, pkf);
	fwrite(checksig, 1, 2, pkf);
	fclose(pkf);

	return 0;
}
