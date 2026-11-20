#ifndef DATABASE_H
#define DATABASE_H

#include "cweb.h"
#include "server.h"

int db_init(const char* conninfo, int per_core_conns);
int db_free(int conns_per_core);

PGconn* acquire_db_conn(void);
ConnContext* release_db_conn(PGconn* conn);

#endif
