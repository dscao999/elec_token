#include <stdio.h>
#include <assert.h>
#include <my_global.h>
#include <mysql.h>
#include "toktx.h"
#include "txcheck.h"
#include "global_param.h"

int main(int argc, char *argv[])
{
	int retv = 0, suc;
	const char *fname, *cnfname;
	FILE *fin;
	ulong64 fsize;
	char *buf;
	struct txrec *tx;
	struct txpack_op *op;
	MYSQL *mcon;

	if (argc > 1)
		fname = argv[1];
	else
		fname = "/tmp/txrec-ser.dat";
	if (argc > 2)
		cnfname = argv[2];
	else
		cnfname = "./etoken.ini";
	fin = fopen(fname, "rb");
	retv = fseek(fin, 0, SEEK_END);
	fsize = ftell(fin);
	rewind(fin);
	buf = malloc(2048);
	retv = fread(buf, 1, fsize, fin);
	assert(retv == fsize);
	fclose(fin);
	global_param_init(cnfname);

	op = malloc(sizeof(struct txpack_op));
	mcon = mysql_init(NULL);
	if (mysql_real_connect(mcon, g_param->db.host, g_param->db.user,
				g_param->db.passwd, g_param->db.dbname, 0,
				NULL, 0) == NULL) {
		retv = mysql_errno(mcon);
		goto exit_20;
	}
	if (txpack_op_init(op, mcon))
		goto exit_20;
	tx = tx_deserialize(buf, fsize);
	if (!tx) {
		printf("Cannot deserialize\n");
		goto exit_30;
	}
	printf("TX vins: %d, vouts: %d\n", tx->vin_num, tx->vout_num);
	suc = tx_verify((unsigned char *)buf, fsize, op);
	if (suc == 0)
		printf("Invalid Transaction.\n");
	else
		printf("Transaction verified.\n");
	retv = tx_serialize(buf, 2048, tx, 1);
	tx_destroy(tx);

exit_30:
	txpack_op_release(op);
exit_20:
	mysql_close(mcon);
	free(op);
	global_param_exit();
	free(buf);
	return retv;
}
