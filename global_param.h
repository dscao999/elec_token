#ifndef GLOBAL_PARAM_DSCAO__
#define GLOBAL_PARAM_DSCAO__
struct db_param {
	char host[64];
	char passwd[32];
	char user[16];
	char dbname[16];
};

struct net_param {
	int port;
};

struct global_param {
	struct db_param db;
	struct net_param netp;
};

extern const struct global_param *g_param;

void global_param_init(const char *cnf);
#endif /* GLOBAL_PARAM_DSCAO__ */
