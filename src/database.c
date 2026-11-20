#include "../include/database.h"

static PGconn** db_list = NULL;
static int db_list_top = -1;
static int db_pool_capacity = 0;

static ConnContext* db_queue[DB_QUEUE_SIZE];
static int db_queue_head = 0;
static int db_queue_tail = 0;

static void sanitize_db_conn(PGconn* conn) {
    if (!conn || PQstatus(conn) != CONNECTION_OK) return;

    // Drain any remaining results or active pipeline state on the existing socket
    if (PQisBusy(conn) || PQpipelineStatus(conn) != PQ_PIPELINE_OFF) {
        PQflush(conn);
        for (;;) {
            PGresult *res = PQgetResult(conn);
            if (!res) {
                if (PQpipelineStatus(conn) == PQ_PIPELINE_OFF) break;
                if (PQconsumeInput(conn) == 0) break;
                if (PQexitPipelineMode(conn) == 1) break;
                continue;
            }
            ExecStatusType st = PQresultStatus(res);
            PQclear(res);
            if (st == PGRES_PIPELINE_SYNC) {
                PQexitPipelineMode(conn);
            }
        }
    }

    // Roll back any uncommitted or aborted transaction block
    PGTransactionStatusType tx = PQtransactionStatus(conn);
    if (tx == PQTRANS_INTRANS || tx == PQTRANS_INERROR) {
        PGresult *rb = PQexec(conn, "ROLLBACK");
        if (rb) PQclear(rb);
    }
}

int db_free(int conns_per_core) {
    (void)conns_per_core;
    if (!db_list) return 0;

    for (int i = 0; i < db_pool_capacity; i++) {
        if (db_list[i]) {
            PQfinish(db_list[i]);
            db_list[i] = NULL;
        }
    }
    free(db_list);
    db_list = NULL;
    db_list_top = -1;
    db_pool_capacity = 0;
    db_queue_head = 0;
    db_queue_tail = 0;
    return 0;
}

int db_init(const char* conninfo, int conns_per_core) {
    if (!conninfo || strcmp(conninfo, "") == 0 || conns_per_core <= 0) return 0;
    if (db_list) return -1; // Guard against double initialization

    db_list_top = -1;
    db_pool_capacity = conns_per_core;
    db_queue_head = 0;
    db_queue_tail = 0;

    db_list = calloc((size_t)conns_per_core, sizeof(PGconn*));
    if (!db_list) {
        fprintf(stderr, "Database connection list failed to initialize\n");
        db_pool_capacity = 0;
        return -1;
    }

    for (int i = 0; i < conns_per_core; i++) {
        PGconn *conn = PQconnectdb(conninfo);
        if (!conn || PQstatus(conn) != CONNECTION_OK) {
            fprintf(stderr, "Connection to database failed: %s\n", conn ? PQerrorMessage(conn) : "OOM");
            if (conn) PQfinish(conn);
            db_free(conns_per_core);
            return -1;
        }
        db_list[++db_list_top] = conn;
    }
    return 0;
}

PGconn* acquire_db_conn(void) {
    if (db_list && db_list_top >= 0) {
        return db_list[db_list_top--];
    }
    return NULL;
}

ConnContext* release_db_conn(PGconn* conn) {
    if (!conn) return NULL;

    // If connection is broken, still busy, in pipeline mode, or inside an open/aborted transaction,
    // dont reset just flush. Reset blocked by the seccomp sandbox
    sanitize_db_conn(conn);

    // Pop from wait queue, skipping any contexts that closed/timed out while queued
    while (db_queue_head != db_queue_tail) {
        ConnContext* waiting_ctx = db_queue[db_queue_head];
        db_queue[db_queue_head] = NULL;
        db_queue_head = (db_queue_head + 1) % DB_QUEUE_SIZE;

        if (waiting_ctx && waiting_ctx->in_use && waiting_ctx->state == QUEUED) {
            waiting_ctx->db_conn = conn;
            return waiting_ctx;
        }
    }

    if (db_list && db_list_top < db_pool_capacity - 1) {
        db_list[++db_list_top] = conn;
    }
    else {
        PQfinish(conn); // Defensive fallback if pool is somehow full
    }
    return NULL;
}

// The Framework API wrapper
int db_query(CwebContext* pub_ctx, const char *query, int nParams, const char *const *paramValues) {
    if (!pub_ctx || !query || nParams < 0 || (nParams > 0 && !paramValues)) return -1;

    ConnContext* ctx = (ConnContext *)pub_ctx;
    if (!ctx->db_conn) ctx->db_conn = acquire_db_conn();
    if (!ctx->db_conn) return -1;

    int res = PQsendQueryParams(ctx->db_conn, query, nParams, NULL, paramValues, NULL, NULL, 0);
    if (res != 1) {
        return -1;
    }
    return 0;
}

int db_query_rls(CwebContext* pub_ctx, const char *role, RlsVariable *vars, int num_vars, const char *query, int nParams, const char *const *paramValues) {
    if (!pub_ctx || !query || num_vars < 0 || (num_vars > 0 && !vars) || nParams < 0 || (nParams > 0 && !paramValues)) {
        return -1;
    }

    ConnContext* ctx = (ConnContext *)pub_ctx;
    if (!ctx->db_conn) ctx->db_conn = acquire_db_conn();
    if (!ctx->db_conn) return -1;

    if (PQenterPipelineMode(ctx->db_conn) != 1) goto fail;
    if (PQsendQueryParams(ctx->db_conn, "BEGIN", 0, NULL, NULL, NULL, NULL, 0) != 1) goto fail;

    if (role) {
        const char *role_param[1] = { role };
        if (PQsendQueryParams(ctx->db_conn, "SELECT set_config('role', $1, true)", 1, NULL, role_param, NULL, NULL, 0) != 1) goto fail;
    }

    for (int i = 0; i < num_vars; i++) {
        if (!vars[i].key || !vars[i].value) goto fail;
        const char *conf_params[2] = { vars[i].key, vars[i].value };
        if (PQsendQueryParams(ctx->db_conn, "SELECT set_config($1, $2, true)", 2, NULL, conf_params, NULL, NULL, 0) != 1) goto fail;
    }

    if (PQsendQueryParams(ctx->db_conn, query, nParams, NULL, paramValues, NULL, NULL, 0) != 1) goto fail;
    if (PQsendQueryParams(ctx->db_conn, "COMMIT", 0, NULL, NULL, NULL, NULL, 0) != 1) goto fail;
    if (PQpipelineSync(ctx->db_conn) != 1) goto fail;

    return 0;

    fail:
    sanitize_db_conn(ctx->db_conn);
    return -1;
}

int queue_db_request(CwebContext* pub_ctx) {
    if (!pub_ctx) return -1;
    ConnContext* ctx = (ConnContext *)pub_ctx;
    if ((db_queue_tail + 1) % DB_QUEUE_SIZE == db_queue_head) {
        return -1; // Queue is completely full!
    }
    db_queue[db_queue_tail] = ctx;
    db_queue_tail = (db_queue_tail + 1) % DB_QUEUE_SIZE;
    return 0;
}
