#include <stdio.h>
#include <assert.h>
#include "toktx.h"

int main(int argc, char *argv[])
{
	int retv = 0, suc;
	const char *fname;
	FILE *fin;
	unsigned long fsize;
	char *buf;
	struct txrec *tx;

	if (argc > 1)
		fname = argv[1];
	else
		fname = "/tmp/txrec-ser.dat";
	fin = fopen(fname, "rb");
	retv = fseek(fin, 0, SEEK_END);
	fsize = ftell(fin);
	rewind(fin);
	buf = malloc(fsize);
	retv = fread(buf, 1, fsize, fin);
	assert(retv == fsize);
	fclose(fin);
	ecc_init();

	tx = tx_deserialize(buf, fsize);
	printf("TX vins: %d, vouts: %d\n", tx->vin_num, tx->vout_num);
	suc = tx_verify(tx);
	if (suc == 0)
		printf("Invalid Transaction.\n");
	else
		printf("Transaction verified.\n");
	tx_destroy(tx);

	return retv;
}
