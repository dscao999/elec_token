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

int etoken_option_length(const struct etoken *et);
int etoken_option_serialize(char *buf, int buflen, const struct etoken *cet);
int etoken_option_deserialize(const char *buf, int buflen,
		struct etoken *cet);
int etoken_expired(const struct etoken *et);

void etoken_init(struct etoken *et, int token, unsigned long value, int days);
struct etoken *etoken_clone(const struct etoken *et, unsigned long value);

struct etoken *etoken_new(int token, unsigned long value, int days);

static inline int etoken_equiv(const struct etoken *l, const struct etoken *r)
{
	int equ = 0;
	equ = (l->token_id == r->token_id) &&
		(l->expire == r->expire);
	return equ;
}

static inline void etoken_option_del(const struct etoken *et)
{
	struct etk_option *opt, *del;

	opt = et->options;
	while (opt) {
		del = opt;
		opt = opt->next;
		free(del);
	}
}

#endif  /* TOKENS_DSCAO__ */
