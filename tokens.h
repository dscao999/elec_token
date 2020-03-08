#ifndef TOKENS_DSCAO__
#define TOKENS_DSCAO__
#include <stdlib.h>

#define BYTE unsigned char
#define HALFW unsigned short
#define WORD unsigned int
#define LONGW unsigned long

enum OPTION {
	TKSER = 0x01, ENDUSER = 0x10
};
struct etk_option {
	BYTE id;
	BYTE len;
	BYTE desc[0];
};

struct etoken {
	LONGW value;
	LONGW expire;
	WORD token;
	WORD numopts;
	struct etk_option options[0];
};

int etoken_optlen(const struct etk_option *copts, int numopts);

static inline int etoken_length(const struct etoken *et) {
	return sizeof(struct etoken) + etoken_optlen(et->options, et->numopts);
}

int etoken_expired(const struct etoken *et);

void etoken_init(struct etoken *et, WORD token, LONGW value, int days,
		int numopts, const struct etk_option *opts);
struct etoken *etoken_clone(const struct etoken *et, LONGW value);

struct etoken *etoken_new(WORD token, LONGW value, int days, int numopts,
		const struct etk_option *opts);

#endif  /* TOKENS_DSCAO__ */
