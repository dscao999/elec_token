#include "global_param.h"
#include "ecc_secp256k1.h"
#include "alsarec.h"
#include "tok_block.h"

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

void global_param_init(const char *cnf, int ecc, int alsa)
{
	g_param = &all_param;
	if (ecc)
		ecc_init();
	if (alsa)
		alsa_init(NULL);
	all_param.ecc = ecc;
	all_param.alsa = alsa;
	if (tok_block_init() != 0) {
		logmsg(LOG_ERR, "tok_block_init failed!\n");
		exit(10);
	}
}

void global_param_exit(void)
{
	tok_block_exit();
	if (g_param->ecc)
		ecc_exit();
	if (g_param->alsa)
		alsa_exit();
}
