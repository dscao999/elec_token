#include <stdio.h>
#include <string.h>
#include <time.h>
#include <assert.h>
#include "tokens.h"
#include "loglog.h"

int etoken_option_length(const struct etoken *cet)
{
	int len;
	struct etk_option *opt;

	len = 0;
	opt = cet->options;
	while (opt) {
		len += opt->len + 2;
		opt = opt->next;
	}
	len += 2;
	return align8(len);
}

int etoken_expired(const struct etoken *et)
{
	struct timespec tm;

	clock_gettime(CLOCK_REALTIME, &tm);
	if (et->expire < tm.tv_sec)
		return 1;
	return 0;
}

struct etoken *etoken_new(int token, unsigned long value, int days)
{
	struct etoken *et;

	et = malloc(sizeof(struct etoken));
	if (!check_pointer(et))
		return et;
	etoken_init(et, token, value, days);
	return et;
}

void etoken_init(struct etoken *et, int token, unsigned long value, int days)
{
	struct timespec tm;

	et->token_id = token;
	et->value = et->value;
	et->options = NULL;
	clock_gettime(CLOCK_REALTIME, &tm);
	if (days == 0)
		et->expire = tm.tv_sec + 3650*24*3600;
	else
		et->expire = tm.tv_sec + days*24*3600;
}

struct etoken *etoken_clone(const struct etoken *cet, unsigned long value)
{
	struct etoken *et;
	const struct etk_option *etkopt;
	struct etk_option *prev, *nopt;

	et = malloc(sizeof(struct etoken));
	if (!check_pointer(et))
		return et;

	*et = *cet;
	et->value = value;
	et->options = NULL;

	prev = NULL;
	etkopt = cet->options;
	while (etkopt) {
		nopt = malloc(sizeof(struct etk_option) + etkopt->len);
		if (!check_pointer(nopt)) {
			etoken_option_del(et);
			return NULL;
		}
		nopt->next = NULL;
		if (prev == NULL)
			et->options = nopt;
		else
			prev->next = nopt;
		nopt->id = etkopt->id;
		nopt->len = etkopt->len;
		memcpy(nopt->desc, etkopt->desc, nopt->len);
		prev = nopt;
		etkopt = etkopt->next;
	}
	
	return et;
}

int etoken_option_serialize(char *buf, int buflen, const struct etoken *cet)
{
	int len;
	const struct etk_option *opt;
	char *nxt;

	len = etoken_option_length(cet);
	if (buflen < len)
		return -1;
	opt = cet->options;
	nxt = buf;
	while (opt) {
		memcpy(nxt, &opt->id, opt->len + 2);
		opt = opt->next;
		nxt += opt->len + 2;
	}
	*nxt = ENDOPT;
	*(nxt+1) = 0;
	return len;
}

int etoken_option_deserialize(const char *buf, int buflen,
		struct etoken *et)
{
	struct etk_option *opt, *prev;
	unsigned char mop, optlen;
	const unsigned char *cc;
	int len;

	if (buflen < 2) {
		logmsg(LOG_ERR, "Illformed etoken, not enough length\n");
		return -1;
	}
	et->options = NULL;
	cc = buf;
	mop = *cc;
	optlen = *(cc+1);
	prev = NULL;
	len = 0;
	while (mop != ENDOPT) {
		opt = malloc(sizeof(struct etk_option) + optlen);
		if (!check_pointer(opt)) {
			etoken_option_del(et);
			return -ENOMEM;
		}
		opt->next = NULL;
		opt->id = mop;
		opt->len = optlen;
		if ((len - (buf - cc)) < opt->len + 2) {
			logmsg(LOG_ERR, "Ill-formed etoken, premature end.\n");
			len = -2;
			break;
		}
		memcpy(opt->desc, cc+2, opt->len);
		if (prev == NULL)
			et->options = opt;
		else
			prev->next = opt;

		prev = opt;
		cc += optlen + 2;
		if ((len - (cc - buf)) <  2) {
			logmsg(LOG_ERR, "Illformed token, no ENDOPT\n");
			len = -3;
			break;
		}
		mop = *cc;
		optlen = *(cc+1);
		len += opt->len + 2;
	}
	len += 2;
	return len;
}
