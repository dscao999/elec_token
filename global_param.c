#include "global_param.h"
#include "ecc_secp256k1.h"
#include "alsarec.h"

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
	.mine = {
		.zbits = 25
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
}
