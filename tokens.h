#ifndef TOKENS_DSCAO__
#define TOKENS_DSCAO__
#include <stdlib.h>

#define BYTE unsigned char
#define HALFW unsigned short
#define WORD unsigned int
#define LONGW unsigned long

#define ETK_VERSION 1
#define ETK_SUB_VERSION 0

enum OPTION {
	PAYTO = 0xf0, ENDUSER = 0x10, TKSER = 0xe0, ENDOPT = 0xff
};
struct etk_option {
	BYTE id;
	BYTE len;
	BYTE desc[0];
};

struct etoken {
	HALFW vendor;
	HALFW type;
	HALFW subtype;
	HALFW hlen;

	LONGW value;
	LONGW tm;
	LONGW expire;

	HALFW lockoff;
	HALFW locklen;

	BYTE ver;
	BYTE subver;
	HALFW optlen;
	struct etk_option options[0];
};

static inline int etoken_length(const struct etoken *et)
{
	return et->hlen + et->optlen;
}
static inline int etoken_sum_len(const struct etoken *et, int num)
{
	const struct etoken *etn = et;;
	int sumlen = 0, i, len;

	for (i = 0; i < num; i++) {
		len = etoken_length(et);
		sumlen += len;
		etn = ((const void *)etn) + len;
	}
	return sumlen;
}

static inline void etoken_set_type(struct etoken *et, int vendor, int type,
		int subtype)
{
	et->vendor = vendor;
	et->type = type;
	et->subtype = subtype;
}

static inline void etoken_set_value(struct etoken *et, unsigned long value)
{
	et->value = value;
}

int etoken_option_insert(struct etoken **pet, const struct etk_option *copt);

static inline void etoken_set_expire(struct etoken *et, int days)
{
	et->expire = et->tm + days*24*3600;
}

int etoken_expired(const struct etoken *et);

int etoken_equiv_type(const struct etoken *etl, const struct etoken *etr);

struct etoken *etoken_new(int vendor, int type, int subtype, unsigned long v);
struct etoken *etoken_clone(const struct etoken *et, unsigned long value);

void etoken_destroy(struct etoken *et)
{
	if (et)
		free(et);
}

int etoken_lock(struct etoken **pet, int locklen, const BYTE *lockscript);

#endif  /* TOKENS_DSCAO__ */
