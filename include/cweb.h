/*
 * Copyright (c) 2026 Saad Al Abeed
 * Email: saadalabeed1737@gmail.com
 * Studying Bsc in CSE in Islamic University of Technology, Gazipur, Bangladesh
 */

#ifndef CWEB_H
#define CWEB_H

#include <stddef.h>
#include <stdbool.h>
#include <sys/types.h>
#include <libpq-fe.h> // For PGresult

// ==========================================
// TYPES & ENUMS
// ==========================================
#define QUEUE_DEPTH 8192 // must be power of 2
#define MAX_CLIENTS 4096
#define BATCH_SIZE 512
#define MAX_BUFFER_SIZE 16384 // 16 KB
#define MAX_PIPES 2048
#define MAX_PIPELINES 16
#define MAX_HEADERS_COUNT 64
#define MAX_RES_HEADERS_COUNT 16
#define MAX_PATH_PARAMS 16
#define DB_QUEUE_SIZE 4096
#define MAX_RADIX_NODES 2048
#define MAX_PATH_SEGMENT_LEN 128
#define MAX_MIDDLEWARES 8

typedef enum {
    GET, POST, PUT, PATCH, DELETE, HEAD, OPTIONS, TRACE, CONNECT, UNKNOWN
} Method;

typedef enum {
    DB_DONE, DB_WAIT, DB_QUEUED, MW_NEXT, MW_ABORT, UPLOAD_START
} HandlerState;

typedef struct {
    char* name;
    char* value;
} Header;

typedef struct {
    char* str;
    int len;
} StringView;

typedef struct {
    Method method;
    char* path;
    char* query_string;
    char* version;
    StringView path_params[MAX_PATH_PARAMS];
    int num_params;
    Header headers[MAX_HEADERS_COUNT];
    int num_headers;
    size_t content_len;
    char* body;
    bool keep_alive;
} HttpRequest;

// ==========================================
// THE PUBLIC CONTEXT (No internal fields)
// ==========================================
typedef struct {
    HttpRequest request;
    PGresult* db_result;
    int handler_step;

    // File Upload Data
    int file_fd;
    off_t file_offset;
    size_t upload_remaining;
    size_t upload_chunk_len;
    char* upload_ptr;

    // WebSocket Data
    bool is_websocket;
    char *ws_payload;
    size_t ws_payload_len; // required for boundary frames and bounds tracking
    int ws_opcode;
} CwebContext;

// ==========================================
// HANDLERS & ROUTING API
// ==========================================
typedef HandlerState (*RouteHandler)(CwebContext* ctx);
typedef HandlerState (*MiddlewareHandler)(CwebContext* ctx);

int insert_route(Method method, char* path, RouteHandler handler);
int insert_middleware(Method method, char* path, MiddlewareHandler handler);

// ==========================================
// RESPONSE API
// ==========================================
int add_header(CwebContext *ctx, const char *key, const char *value);
char* get_header(CwebContext* ctx, const char* key);
int get_query_param(CwebContext *ctx, const char *key, char *out_buffer, size_t out_size);
void send_text(CwebContext *ctx, int status_code, const char *text);
void send_json(CwebContext *ctx, int status_code, const char *json_body);
void send_error(CwebContext *ctx, int status_code, const char *message);
void send_file(CwebContext *pub_ctx, int status_code, const char *file_path, const char *content_type);
void send_bytes(CwebContext *pub_ctx, int status_code, const char *content_type, const void *data, size_t len);

// ==========================================
// WEBSOCKET API
// ==========================================
void upgrade_to_websocket(CwebContext* ctx);
void send_ws_text(CwebContext *ctx, const char *text);

// ==========================================
// DATABASE API
// ==========================================
typedef struct {
    const char *key;
    const char *value;
} RlsVariable;

int db_query(CwebContext *ctx, const char *query, int nParams, const char *const *paramValues);
int db_query_rls(CwebContext *ctx, const char *role, RlsVariable *vars, int num_vars, const char *query, int nParams, const char *const *paramValues);
int queue_db_request(CwebContext* ctx);

// ==========================================
// JSON API
// ==========================================
typedef struct {
    char *buffer;
    size_t remaining;
    bool is_first;
} JsonBuilder;

int json_begin(JsonBuilder *jb, char *buffer, size_t size);
int json_add_str(JsonBuilder *jb, const char *key, const char *value);
int json_add_int(JsonBuilder *jb, const char *key, int value);
int json_add_bool(JsonBuilder *jb, const char *key, bool value);
int json_end(JsonBuilder *jb);

int json_extract_str(const char *json, const char *key, char *out_buffer, size_t out_size);
int json_extract_int(const char *json, const char *key, long long *out_val);
int json_extract_bool(const char *json, const char *key, bool *out_val);

void json_escape_string(const char* src, char* dest, size_t max_len);
void json_unescape_string(char* str);

// ==========================================
// SERVER LIFECYCLE
// ==========================================
int cweb_run_server(int port, const char* db_url, int db_conns_per_cpu_core);

#endif // CWEB_H
