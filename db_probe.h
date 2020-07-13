#ifndef DB_PROBE__DSCAO
#define DB_PROBE__DSCAO
#include <time.h>
#include <my_global.h>
#include <mysql.h>

int check_db_probe(MYSQL *mcon, struct timespec *tm0);

#endif  /* DB_PROBE__DSCAO */
