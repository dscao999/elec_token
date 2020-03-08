#include <stdio.h>
#include <string.h>
#include <time.h>
#include <assert.h>
#include "tokens.h"
#include "loglog.h"

static inline struct etk_option *next_option(struct etk_option *opt)
{
	struct etk_option *nx_opt;
	
	nx_opt = ((void *)(opt + 1)) + opt->len;
	assert(nx_opt->id > opt->id);
	return nx_opt;
}

static inline const struct etk_option *cnext_option(const struct etk_option *opt)
{
	const struct etk_option *nx_opt;

	nx_opt = ((const void *)(opt + 1)) + opt->len;
	assert(nx_opt->id > opt->id);
	return nx_opt;
}

int etoken_optlen(const struct etk_option *opts, int numopts)
{
	const struct etk_option *copt = opts;
	int len = 0;

	while (numopts--) {
		len += sizeof(struct etk_option) + copt->len;
		copt = cnext_option(copt);
	}
	return len;
}

int etoken_expired(const struct etoken *et)
{
	struct timespec tm;

	clock_gettime(CLOCK_REALTIME, &tm);
	if (et->expire < tm.tv_sec)
		return 1;
	return 0;
}

struct etoken *etoken_new(WORD token, LONGW value, int days, int numopts,
		const struct etk_option *opts)
{
	struct etoken *et;

	et = malloc(sizeof(struct etoken) + etoken_optlen(opts, numopts));
	if (!et)
		return et;
	etoken_init(et, token, value, days, numopts, opts);
	return et;
}

void etoken_init(struct etoken *et, WORD token, LONGW value, int days,
		int numopts, const struct etk_option *opts)
{
	struct timespec tm;
	int optlen;

	et->token = token;
	et->value = et->value;
	et->numopts = numopts;
	optlen = etoken_optlen(opts, numopts);
	memcpy(et->options, opts, optlen);

	clock_gettime(CLOCK_REALTIME, &tm);
	if (days == 0)
		et->expire = tm.tv_sec + 3650*24*3600;
	else
		et->expire = tm.tv_sec + days*24*3600;
}

struct etoken *etoken_clone(const struct etoken *cet, LONGW value)
{
	struct etoken *et;

	et = malloc(sizeof(struct etoken) +
			etoken_optlen(cet->options, cet->numopts));
	if (!et)
		return et;

	*et = *cet;
	et->value = value;
	return et;
}
