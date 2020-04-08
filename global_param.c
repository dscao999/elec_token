#include "global_param.h"

static struct global_param all_param = {
	.db = {
		.host = "localhost",
		.dbname = "electoken",
		.user = "dscao",
		.passwd = ""
	},
	.netp = {
		.port = 6001
	}
};

const struct global_param *g_param;

void global_param_init(const char *cnf)
{
	g_param = &all_param;
}
