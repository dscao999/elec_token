#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include "global_param.h"
#include "loglog.h"
#include "ecc_secp256k1.h"
#include "toktx.h"
#include "alsarec.h"

void save_tx(const char *fname, const struct txrec *tx);
struct txrec *tx_read(const char *fname);

int main(int argc, char *argv[])
{
	const char *payto, *prkey, *fname, *ofname;
	struct txrec *tx;
	int verify = 0;
	int mark, fin, value, token, import = 0;
	extern char *optarg;
	extern int opterr, optopt;

	opterr = 0;
	payto = NULL;
	prkey = NULL;
	fname = NULL;
	ofname = NULL;
	value = 0;
	token = 0;
	fin = 0;
	do {
		mark = getopt(argc, argv, ":f:k:h:v:n:mro:");
		switch(mark) {
		case 'o':
			ofname = optarg;
			break;
		case -1:
			fin = 1;
			break;
		case 'r':
			verify = 1;
			import = 1;
			break;
		case 'n':
			token = atoi(optarg);
			break;
		case 'k':
			prkey = optarg;
			break;
		case 'h':
			payto = optarg;
			break;
		case 'f':
			fname = optarg;
			break;
		case 'v':
			value = atoi(optarg);
			break;
		case 'm':
			import = 1;
			break;
		case '?':
			logmsg(LOG_ERR, "Unknown option: %c\n", optopt);
			break;
		case ':':
			logmsg(LOG_ERR, "Missing arguments for %c\n", optopt);
			break;
		default:
			assert(0);
		}
	} while (fin == 0);
	global_param_init(NULL);
	if ((!payto || !prkey) && import == 0) {
		logmsg(LOG_ERR, "no key, or no receipient!\n");
		return 1;
	}
	if (value == 0)
		value = 1010;
	if (token == 0)
		token = 40033;

	alsa_init(NULL);
	ecc_init();

	if (import == 0) {
		tx = tx_create(token, value, 0, payto, prkey);
		if (tx == NULL) {
			logmsg(LOG_ERR, "Token Creation failed.\n");
			return 2;
		}

		save_tx(fname, tx);
	} else {
		tx = tx_read(fname);
		if (verify) {
			if (!tx_verify(tx))
				logmsg(LOG_ERR, "Invalid transaction.\n");
			else
				logmsg(LOG_INFO, "Valid transaction.\n");
		}
		if (ofname != NULL)
			save_tx(ofname, tx);
	}

	tx_destroy(tx);
	return 0;
}

void save_tx(const char *fname, const struct txrec *tx)
{
	FILE *fh;
	char *buf;
	int len;

	if (!fname)
		return;

	fh = fopen(fname, "wb");
	if (!fh) {
		logmsg(LOG_ERR, "Cannot open file %s for write: %s\n", fname,
				strerror(errno));
		return;
	}
	buf = malloc(1024);
	if (!check_pointer(buf))
		goto exit_10;

	len = tx_serialize(buf, 1024, tx, 1);
	if (len <= 1024)
		fwrite(buf, 1, len, fh);

	free(buf);
exit_10:
	fclose(fh);
}

struct txrec *tx_read(const char *fname)
{
	struct txrec *tx = NULL;
	FILE *fin;
	int len, numb;
	char *buf;

	fin = fopen(fname, "rb");
	if (!fin)
		return NULL;
	fseek(fin, 0, SEEK_END);
	len = ftell(fin);
	buf = malloc(len);
	if (!check_pointer(buf))
		goto exit_10;
	fseek(fin, 0, SEEK_SET);
	numb = fread(buf, 1, len, fin);
	if (unlikely(numb != len))
		goto exit_20;
	tx = tx_deserialize(buf, len);
	if (unlikely(tx == NULL))
		logmsg(LOG_ERR, "Cannot construct a TXREC.\n");

exit_20:
	free(buf);
exit_10:
	fclose(fin);
	return tx;
}
