#include "global_param.h"
#include "ecc_secp256k1.h"
#include "alsarec.h"

#define MAX_TXSIZE	2048
#define MAX_BLKSIZE	(128*1024)

static struct global_param all_param = {
	.db = {
		.host = "localhost",
		.dbname = "electoken",
		.user = "dscao",
		.passwd = ""
	},
	.netp = {
		.port = 6001
	},
	.thp = {
		.numths = 2
	},
	.tx = {
		.max_txsize = MAX_TXSIZE
	},
	.mine = {
		.zbits = 25,
		.max_blksize = MAX_BLKSIZE
	}
};

const struct global_param *g_param;

void global_param_init(const char *cnf)
{
	g_param = &all_param;
	ecc_init();
}

void global_param_exit(void)
{
	ecc_exit();
}
