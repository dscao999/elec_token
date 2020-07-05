#include <stdio.h>
#include <assert.h>
#include "toktx_svr.h"
#include "global_param.h"

int main(int argc, char *argv[])
{
	int retv = 0, suc;
	const char *fname;
	FILE *fin;
	ulong64 fsize;
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
	buf = malloc(2048);
	retv = fread(buf, 1, fsize, fin);
	assert(retv == fsize);
	fclose(fin);
	global_param_init(NULL);

	tx = tx_deserialize(buf, fsize);
	if (!tx) {
		printf("Cannot deserialize\n");
		goto exit_10;
	}
	printf("TX vins: %d, vouts: %d\n", tx->vin_num, tx->vout_num);
	suc = tx_verify((unsigned char *)buf, fsize);
	if (suc == 0)
		printf("Invalid Transaction.\n");
	else
		printf("Transaction verified.\n");
	retv = tx_serialize(buf, 2048, tx, 1);
	tx_destroy(tx);

exit_10:
	global_param_exit();
	return retv;
}
