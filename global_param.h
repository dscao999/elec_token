#ifndef GLOBAL_PARAM_DSCAO__
#define GLOBAL_PARAM_DSCAO__
struct db_param {
	char host[64];
	char passwd[32];
	char user[16];
	char dbname[16];
	int probe;
};

struct net_param {
	int port;
};

struct thread_param {
	int numths;
};

struct blk_mining {
	int zbits;
	int max_blksize;
};

struct txrec_param {
	int max_txsize;
};

struct node_info {
	int nodeid;
};

struct global_param {
	struct db_param db;
	struct net_param netp;
	struct thread_param thp;
	struct txrec_param tx;
	struct blk_mining mine;
	struct node_info node;
};

extern const struct global_param *g_param;

void global_param_init(const char *cnf);
void global_param_exit(void);
#endif /* GLOBAL_PARAM_DSCAO__ */
