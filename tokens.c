#include <stdio.h>
#include <string.h>
#include <time.h>
#include "tokens.h"
#include "loglog.h"

static const int LENOVO = 168;
static const int PCWANT = 168;

void etoken_set_subtype(struct etoken *et, int sub, const char *desc)
{
	et->subtype = sub;
	memset(et->desc, 0, 12);
	strncpy((char *)et->desc, desc, 12);

}

void etoken_set_options(struct etoken *et,
		int numopt, const struct etk_option *opts)
{
	int i;
	struct etk_option *opt;

	et->numopt = numopt;
	for (opt = et->options, i = 0; i < numopt; i++, opt++, opts++)
		*opt = *opts;
}

int etoken_equiv(const struct etoken *etl, const struct etoken *etr)
{
	if (etl->vendor != etr->vendor)
		return 0;
	if (etl->type != etr->type)
		return 0;
	if (etl->hlen != etr->hlen)
		return 0;
	if (etl->subtype != etr->subtype)
		return 0;
	if (memcmp(etl->desc, etr->desc, 12) != 0)
		return 0;
	if (etl->ver != etr->ver)
		return 0;
	if (etl->numopt != etr->numopt)
		return 0;
	if (memcmp(etl->options, etr->options,
				sizeof(struct etk_option)*etl->numopt) != 0)
		return 0;

	return 1;
}

struct etoken *etoken_new(unsigned long value, int subtype, const char *desc,
		int numopt, const struct etk_option *opts)
{
	struct etoken *et;
	int tlen;
	struct timespec tm;

	tlen = sizeof(struct etoken) + numopt * sizeof(struct etk_option);
	et = malloc(tlen);
	if (!et) {
		logmsg(LOG_CRIT, "Out of Memory!\n");
		exit(100);
	}
	etoken_set_vendor(et, LENOVO, PCWANT);
	et->hlen = sizeof(struct etoken);
	et->value = value;
	etoken_set_subtype(et, subtype, desc);
	etoken_set_options(et, numopt, opts);
	et->locklen = 0;
	et->lockscript = NULL;
	clock_gettime(CLOCK_REALTIME, &tm);
	et->tm = tm.tv_sec;
	memset(et->id, 0, 20);

	return et;
}

struct etoken *etoken_clone(const struct etoken *et, unsigned long value)
{
	struct etoken *etn;
	int len;
	struct timespec tm;

	len = sizeof(struct etoken) + et->numopt * sizeof(struct etk_option);
	etn = malloc(len);
	if (etn) {
		logmsg(LOG_CRIT, "Out of Memory!\n");
		exit(100);
	}
	memcpy(etn, et, len);
	etn->locklen = 0;
	etn->lockscript = NULL;
	etn->value = value;
	clock_gettime(CLOCK_REALTIME, &tm);
	etn->tm = tm.tv_sec;
	memset(etn->id, 0, 20);
	return etn;
}

void etoken_lock(struct etoken *et, int locklen, const BYTE *lockscript)
{
	et->locklen = locklen;
	et->lockscript = malloc(locklen);
	if (!et->lockscript) {
		logmsg(LOG_CRIT, "Out of Memory!\n");
		exit(100);
	}
	memcpy(et->lockscript, lockscript, locklen);
}
