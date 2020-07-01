#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include "global_param.h"
#include "ecc_secp256k1.h"
#include "loglog.h"
#include "ezini.h"

#define MAX_TXSIZE	2048
#define MAX_BLKSIZE	(128*1024)

static struct global_param all_param = {
	.db = {
		.host = "localhost",
		.dbname = "electoken",
		.user = "dscao",
		.passwd = ""
	},
	.netp = {
		.port = 6001
	},
	.thp = {
		.numths = 2
	},
	.tx = {
		.max_txsize = MAX_TXSIZE
	},
	.mine = {
		.zbits = 25,
		.max_blksize = MAX_BLKSIZE
	}
};

void set_blockchain(const ini_entry_t *pent)
{
	if (strcmp(pent->key, "zero_bits") == 0)
		all_param.mine.zbits = atoi(pent->value);
	else if (strcmp(pent->key, "max_size") == 0)
		all_param.mine.max_blksize = atoi(pent->value);
	else
		logmsg(LOG_WARNING, "Unknown key: %s in Section blockchain\n",
				pent->key);
}

void set_tx_param(const ini_entry_t *pent)
{
	if (strcmp(pent->key, "max_size") == 0)
		all_param.tx.max_txsize = atoi(pent->value);
	else
		logmsg(LOG_WARNING, "Unkown key: %s in Section tx_param\n",
				pent->key);
}

void set_db(const ini_entry_t *pent)
{
	if (strcmp(pent->key, "host") == 0)
		strcpy(all_param.db.host, pent->value);
	else if (strcmp(pent->key, "user") == 0)
		strcpy(all_param.db.user, pent->value);
	else if (strcmp(pent->key, "dbname") == 0)
		strcpy(all_param.db.dbname, pent->value);
	else if (strcmp(pent->key, "passwd") == 0)
		strcpy(all_param.db.passwd, pent->value);
	else
		logmsg(LOG_WARNING, "Unknown Key: %s in Section db\n",
				pent->key);
}

void set_server(const ini_entry_t *pent)
{
	if (strcmp(pent->key, "host") == 0)
		;
	else if (strcmp(pent->key, "port") == 0)
		all_param.netp.port = atoi(pent->value);
	else
		logmsg(LOG_WARNING, "Unknown Key: %s in Section server\n",
				pent->key);

}

void set_param(const ini_entry_t *pent)
{
	if (strcmp(pent->section, "db") == 0)
		set_db(pent);
	else if (strcmp(pent->section, "server") == 0)
		set_server(pent);
	else if (strcmp(pent->section, "tx_param") == 0)
		set_tx_param(pent);
	else if (strcmp(pent->section, "blockchain") == 0)
		set_blockchain(pent);
	else if (strcmp(pent->section, "global") == 0)
		;
	else
		logmsg(LOG_WARNING, "Unknown Section: %s\n", pent->section);
}

const struct global_param *g_param;

void global_param_init(const char *cnf)
{
	FILE *inif;
	int retcode;
	ini_entry_t ment;

	g_param = &all_param;
	ecc_init();

	if (!cnf)
		return;
	inif = fopen(cnf, "rb");
	if (!inif) {
		logmsg(LOG_WARNING, "Cannot open configuration: %s\n",
				strerror(errno));
		return;
	}
	memset(&ment, 0, sizeof(ment));
	retcode = GetEntryFromFile(inif, &ment);
	while (retcode != 0) {
		if (retcode == -1)
			logmsg(LOG_WARNING, "Invalid ini item.\n");
		else
			set_param(&ment);
		retcode = GetEntryFromFile(inif, &ment);
	}
	fclose(inif);
}

void global_param_exit(void)
{
	ecc_exit();
}
