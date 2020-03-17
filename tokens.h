#ifndef TOKENS_DSCAO__
#define TOKENS_DSCAO__
#include <stdlib.h>
#include "loglog.h"

#define BYTE unsigned char
#define HALFW unsigned short
#define WORD unsigned int
#define LONGW unsigned long

enum OPTION {
	TKSER = 0x01, ENDUSER = 0x10, ENDOPT = 0xff
};

struct etk_option {
	struct etk_option *next;
	BYTE id;
	BYTE len;
	BYTE desc[0];
};

struct etoken {
	LONGW value;
	LONGW expire;
	LONGW token_id;
	struct etk_option *options;
};

int etoken_length(const struct etoken *et);
int etoken_serialize(char *buf, int len, const struct etoken *cet);
int etoken_deserialize(const unsigned char *buf, int len, struct etoken *cet);
int etoken_expired(const struct etoken *et);

void etoken_init(struct etoken *et, int token, unsigned long value, int days);
struct etoken *etoken_clone(const struct etoken *et, unsigned long value);

struct etoken *etoken_new(int token, unsigned long value, int days);

static inline void etoken_del(struct etoken *et)
{
	struct etk_option *opt, *del;

	opt = et->options;
	while (opt) {
		del = opt;
		opt = opt->next;
		free(del);
	}
	free(et);
}

#endif  /* TOKENS_DSCAO__ */
