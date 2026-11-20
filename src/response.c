#include "../include/response.h"

static const char* status_reasons[600] = {
    // 1xx: Informational
    [100] = "Continue",
    [101] = "Switching Protocols",
    [102] = "Processing",                  // RFC 2518 (WebDAV)
    [103] = "Early Hints",                 // RFC 8297

    // 2xx: Success
    [200] = "OK",
    [201] = "Created",
    [202] = "Accepted",
    [203] = "Non-Authoritative Information",
    [204] = "No Content",
    [205] = "Reset Content",
    [206] = "Partial Content",
    [207] = "Multi-Status",                // RFC 4918 (WebDAV)
    [208] = "Already Reported",            // RFC 5842 (WebDAV)
    [226] = "IM Used",                     // RFC 3229

    // 3xx: Redirection
    [300] = "Multiple Choices",
    [301] = "Moved Permanently",
    [302] = "Found",                       // Previously "Moved Temporarily"
    [303] = "See Other",
    [304] = "Not Modified",
    [305] = "Use Proxy",
    [307] = "Temporary Redirect",
    [308] = "Permanent Redirect",          // RFC 7538

    // 4xx: Client Error
    [400] = "Bad Request",
    [401] = "Unauthorized",                // Actually means "Unauthenticated"
    [402] = "Payment Required",            // Reserved for future use, but occasionally used
    [403] = "Forbidden",
    [404] = "Not Found",
    [405] = "Method Not Allowed",
    [406] = "Not Acceptable",
    [407] = "Proxy Authentication Required",
    [408] = "Request Timeout",
    [409] = "Conflict",
    [410] = "Gone",
    [411] = "Length Required",
    [412] = "Precondition Failed",
    [413] = "Payload Too Large",           // Previously "Request Entity Too Large"
    [414] = "URI Too Long",
    [415] = "Unsupported Media Type",
    [416] = "Range Not Satisfiable",
    [417] = "Expectation Failed",
    [418] = "I'm a teapot",                // RFC 2324 (Standardized Easter egg)
    [421] = "Misdirected Request",         // RFC 7540 (HTTP/2)
    [422] = "Unprocessable Entity",        // RFC 4918 (WebDAV - standard for validation errors)
    [423] = "Locked",                      // RFC 4918 (WebDAV)
    [424] = "Failed Dependency",           // RFC 4918 (WebDAV)
    [425] = "Too Early",                   // RFC 8470
    [426] = "Upgrade Required",
    [428] = "Precondition Required",       // RFC 6585
    [429] = "Too Many Requests",           // RFC 6585 (Standard for rate limiting)
    [431] = "Request Header Fields Too Large", // RFC 6585
    [451] = "Unavailable For Legal Reasons",   // RFC 7725

    // 5xx: Server Error
    [500] = "Internal Server Error",
    [501] = "Not Implemented",
    [502] = "Bad Gateway",
    [503] = "Service Unavailable",
    [504] = "Gateway Timeout",
    [505] = "HTTP Version Not Supported",
    [506] = "Variant Also Negotiates",     // RFC 2295
    [507] = "Insufficient Storage",        // RFC 4918 (WebDAV)
    [508] = "Loop Detected",               // RFC 5842 (WebDAV)
    [510] = "Not Extended",                // RFC 2774
    [511] = "Network Authentication Required" // RFC 6585
};

const char* get_status_reason(int code) {
    if (code < 100 || code >= 600 || !status_reasons[code]) {
        return "Unknown";
    }
    return status_reasons[code];
}

int add_header(CwebContext *pub_ctx, const char *key, const char *value) {
    if (!pub_ctx || !key || !value) {
        return -1;
    }

    // key validation
    if (strchr(key, '\r') || strchr(key, '\n')) return -1;

    size_t key_len = strlen(key);
    size_t value_len = strlen(value);

    if (key_len >= 64 || value_len >= 192) return -1;

    for (size_t i = 0; i < key_len; i++) {
        if (key[i] < 0x21 || key[i] >= 0x7F || key[i] == ':') return -1;
    }

    // value validation
    if (strchr(value, '\r') || strchr(value, '\n')) return -1;

    ConnContext* ctx = (ConnContext *)pub_ctx;

    if (ctx->res_header_count >= MAX_RES_HEADERS_COUNT) {
        fprintf(stderr, "Headers limit exceeded\n");
        return -1;
    }

    strncpy(ctx->response_headers[ctx->res_header_count].key, key, key_len);
    strncpy(ctx->response_headers[ctx->res_header_count].value, value, value_len);
    ctx->res_header_count++;
    return 0;
}

char* get_header(CwebContext *pub_ctx, const char* key) {
    if (!pub_ctx || !key) return NULL;

    ConnContext* ctx = (ConnContext *)pub_ctx;

    for (int i = 0; i < ctx->pub.request.num_headers; i++) {
        if (strcasecmp(ctx->pub.request.headers[i].name, key) == 0) {
            return ctx->pub.request.headers[i].value;
        }
    }

    return NULL;
}

int get_query_param(CwebContext *ctx, const char *key, char *out_buffer, size_t out_size) {
    if (!ctx || !key || !out_buffer || out_size == 0) return -1;

    if (key[0] == '\0') return -1;

    if (!ctx->request.query_string) {
        fprintf(stderr, "Query string not found in this request\n");
        return -1;
    }
    if (strlen(key) > 128) {
        fprintf(stderr, "Key can't be more than 128 chars long\n");
        return -1; // Key can't be more than 127 bytes long
    }

    // Construct the search key (e.g., "limit=")
    char search_key[130];
    snprintf(search_key, sizeof(search_key), "%s=", key);

    // Find it in the query string
    char *start = strstr(ctx->request.query_string, search_key);

    while (start) {
        if (start == ctx->request.query_string || *(start - 1) == '&') {
            break; // We found the exact key!
        }
        // False positive, keep searching from the next character
        start = strstr(start + 1, search_key);
    }

    if (!start) {
        // fprintf(stderr, "Key %s not found\n", key);
        return -1;
    }

    start += strlen(search_key); // Move to the value

    // Copy the value out until we hit '&' or the end of the string
    size_t i = 0;
    while (start[i] != '\0' && start[i] != '&' && i < out_size - 1) {
        out_buffer[i] = start[i];
        i++;
    }
    out_buffer[i] = '\0'; // Null-terminate the copy

    return 0; // Success
}

static inline void init_http_response_buf(ConnContext *ctx, char **ptr_out, size_t *avail_out) {
    // If pipelined HTTP requests are waiting in ctx->buffer after current_req_len,
    // place the outgoing response after ctx->bytes_read + 1 so we never clobber them!
    size_t offset = (ctx->current_req_len > 0 && ctx->bytes_read > ctx->current_req_len) ? (ctx->bytes_read + 1) : 0;
    if (offset + 128 >= MAX_BUFFER_SIZE) { // assuming at least 128 bytes space free for response generation
        offset = 0; // Fallback: too full to pipeline, keep_alive will be disabled
        ctx->pub.request.keep_alive = false;
    }
    ctx->response_ptr = ctx->buffer + offset;
    *ptr_out = ctx->response_ptr;
    *avail_out = MAX_BUFFER_SIZE - offset;
}

void send_text(CwebContext *pub_ctx, int status_code, const char *text) {
    if (!pub_ctx) return;
    if (!text) text = "";
    ConnContext* ctx = (ConnContext *)pub_ctx;

    // take snapshot of text if it points in the buffer via VLA
    size_t tlen = strnlen(text, MAX_BUFFER_SIZE - 1);
    char stack_copy[tlen + 1];
    if (text >= ctx->buffer && text < ctx->buffer + MAX_BUFFER_SIZE) {
        memcpy(stack_copy, text, tlen);
        stack_copy[tlen] = '\0';
        text = stack_copy;
    }

    char *ptr;
    size_t available;
    init_http_response_buf(ctx, &ptr, &available);
    int written;

    // Write the Status Line
    written = snprintf(ptr, available, "HTTP/1.1 %d %s\r\n", status_code, get_status_reason(status_code));
    if (written < 0 || (size_t)written >= available) goto overflow; // Safely abort
    ptr += written; available -= written;

    // Write the standard Headers
    written = snprintf(ptr, available, "Content-Type: text/plain\r\nContent-Length: %zu\r\n", strlen(text));
    if (written < 0 || (size_t)written >= available) goto overflow; // Safely abort
    ptr += written; available -= written;

    // Write the Custom Headers (from ctx->response_headers)
    for (int i = 0; i < ctx->res_header_count; i++) {
        written = snprintf(ptr, available, "%s: %s\r\n", ctx->response_headers[i].key, ctx->response_headers[i].value);
        if (written < 0 || (size_t)written >= available) goto overflow; // Safely abort
        ptr += written; available -= written;
    }

    // Write the final blank line and Body
    written = snprintf(ptr, available, "\r\n%s", text);
    if (written < 0 || (size_t)written >= available) goto overflow; // Safely abort
    ptr += written; available -= written;

    // Success! Tell io_uring how much to send
    ctx->response_len = (ptr - ctx->response_ptr);
    return;

    overflow:
    fprintf(stderr, "CRITICAL: Response buffer overflow prevented on fd %d\n", ctx->fd);

    const char *err_msg = "HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\n\r\n";

    ctx->response_ptr = ctx->buffer; // Reset pointer to index 0
    written = snprintf(ctx->response_ptr, MAX_BUFFER_SIZE, "%s", err_msg);

    // Now it is safe to assign the length
    ctx->response_len = written;
    ctx->pub.request.keep_alive = false;
}

void send_json(CwebContext *pub_ctx, int status_code, const char *json_body) {
    if (!pub_ctx) return;
    if (!json_body) json_body = "{}";
    ConnContext* ctx = (ConnContext *)pub_ctx;

    // take snapshot of json if it points in the buffer via VLA
    size_t tlen = strnlen(json_body, MAX_BUFFER_SIZE - 1);
    char stack_copy[tlen + 1];
    if (json_body >= ctx->buffer && json_body < ctx->buffer + MAX_BUFFER_SIZE) {
        memcpy(stack_copy, json_body, tlen);
        stack_copy[tlen] = '\0';
        json_body = stack_copy;
    }

    char *ptr;
    size_t available;
    init_http_response_buf(ctx, &ptr, &available);
    int written;

    // Write the Status Line
    written = snprintf(ptr, available, "HTTP/1.1 %d %s\r\n", status_code, get_status_reason(status_code));
    if (written < 0 || (size_t)written >= available) goto overflow; // Safely abort // Safely abort!
    ptr += written; available -= written;

    // Write the standard Headers
    written = snprintf(ptr, available, "Content-Type: application/json\r\nContent-Length: %zu\r\n", strlen(json_body));
    if (written < 0 || (size_t)written >= available) goto overflow; // Safely abort
    ptr += written; available -= written;

    // Write the Custom Headers (from ctx->response_headers)
    for (int i = 0; i < ctx->res_header_count; i++) {
        written = snprintf(ptr, available, "%s: %s\r\n", ctx->response_headers[i].key, ctx->response_headers[i].value);
        if (written < 0 || (size_t)written >= available) goto overflow; // Safely abort
        ptr += written; available -= written;
    }

    // Write the final blank line and Body
    written = snprintf(ptr, available, "\r\n%s", json_body);
    if (written < 0 || (size_t)written >= available) goto overflow; // Safely abort
    ptr += written; available -= written;

    // Success! Tell io_uring how much to send
    ctx->response_len = (ptr - ctx->response_ptr);
    return;

    overflow:
    fprintf(stderr, "CRITICAL: Response buffer overflow prevented on fd %d\n", ctx->fd);

    const char *err_msg = "HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\n\r\n";

    ctx->response_ptr = ctx->buffer; // Reset pointer to index 0
    written = snprintf(ctx->response_ptr, MAX_BUFFER_SIZE, "%s", err_msg);

    // Now it is safe to assign the length
    ctx->response_len = written;
    ctx->pub.request.keep_alive = false;
}

void send_error(CwebContext *pub_ctx, int status_code, const char *message) {
    if (!pub_ctx) return;
    if (!message) message = "";
    ConnContext* ctx = (ConnContext *)pub_ctx;

    // take snapshot of message if it points in the buffer via VLA
    size_t tlen = strnlen(message, MAX_BUFFER_SIZE - 1);
    char stack_copy[tlen + 1];
    if (message >= ctx->buffer && message < ctx->buffer + MAX_BUFFER_SIZE) {
        memcpy(stack_copy, message, tlen);
        stack_copy[tlen] = '\0';
        message = stack_copy;
    }

    char *ptr;
    size_t available;
    init_http_response_buf(ctx, &ptr, &available);
    int written;

    // Write the Status Line
    written = snprintf(ptr, available, "HTTP/1.1 %d %s\r\n", status_code, get_status_reason(status_code));
    if (written < 0 || (size_t)written >= available) goto overflow; // Safely abort // Safely abort!
    ptr += written; available -= written;

    // Write the standard Headers
    written = snprintf(ptr, available, "Content-Type: text/plain; charset=utf-8\r\nContent-Length: %zu\r\n", strlen(message));
    if (written < 0 || (size_t)written >= available) goto overflow; // Safely abort
    ptr += written; available -= written;

    // Write the Custom Headers (from ctx->response_headers)
    for (int i = 0; i < ctx->res_header_count; i++) {
        written = snprintf(ptr, available, "%s: %s\r\n", ctx->response_headers[i].key, ctx->response_headers[i].value);
        if (written < 0 || (size_t)written >= available) goto overflow; // Safely abort
        ptr += written; available -= written;
    }

    // Write the final blank line and Body
    written = snprintf(ptr, available, "\r\n%s", message);
    if (written < 0 || (size_t)written >= available) goto overflow; // Safely abort
    ptr += written; available -= written;

    // Success! Tell io_uring how much to send
    ctx->response_len = (ptr - ctx->response_ptr);
    return;

    overflow:
    fprintf(stderr, "CRITICAL: Response buffer overflow prevented on fd %d\n", ctx->fd);

    const char *err_msg = "HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\n\r\n";

    ctx->response_ptr = ctx->buffer; // Reset pointer to index 0
    written = snprintf(ctx->response_ptr, MAX_BUFFER_SIZE, "%s", err_msg);

    // Now it is safe to assign the length
    ctx->response_len = written;
    ctx->pub.request.keep_alive = false;
}

static bool has_path_traversal(const char *path) {
    if (!path || path[0] == '\0') return true; // reject empty or null paths

    const char* temp = path;
    while (temp) {
        const char* match = strstr(temp, "..");
        if (!match) return false; // no directory traversal

        if ((match == path || *(match - 1) == '/') && (match[2] == '/' || match[2] == '\0')) return true;

        temp = match + 2;
    }
    return false;
}

void send_file(CwebContext *pub_ctx, int status_code, const char *file_path, const char *content_type) {
    if (!pub_ctx) return;
    ConnContext* ctx = (ConnContext *)pub_ctx;

    if (!file_path || !content_type) {
        send_error(pub_ctx, 400, "Bad Request");
        return;
    }

    if (has_path_traversal(file_path)) {
        send_error(pub_ctx, 403, "Forbidden");
        return;
    }

    if (strchr(content_type, '\r') || strchr(content_type, '\n')) {
        send_error(pub_ctx, 500, "Internal server error");
        return;
    }

    // strip leading slash (additional safety because the worker is in a filesystem jail)
    while (*file_path == '/') file_path++;
    if (*file_path == '\0') { send_error(pub_ctx, 404, "File Not Found"); return; }

    // Open the file
    int fd = openat(AT_FDCWD, file_path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) {
        send_error(pub_ctx, 404, "File Not Found");
        return;
    }

    // Get the exact file size via fstat
    struct stat st;
    if (fstat(fd, &st) < 0) {
        close(fd);
        send_error(pub_ctx, 500, "Internal Server Error");
        return;
    }

    // verify regular file (no symlinks or named pipes)
    if (!S_ISREG(st.st_mode)) {
        close(fd);
        send_error(pub_ctx, 403, "Forbidden");
        return;
    }

    // Set the variables for the io_uring SPLICE states!
    ctx->pub.file_offset = 0;
    ctx->file_size = (size_t)st.st_size; // We can access private fields here!

    // handle 0 byte file serving
    if (ctx->file_size == 0) {
        close(fd);
        ctx->pub.file_fd = -1;
    }
    else ctx->pub.file_fd = fd;

    // Formulate the HTTP Headers in RAM
    char *ptr;
    size_t available;
    init_http_response_buf(ctx, &ptr, &available);
    int written;

    written = snprintf(ptr, available, "HTTP/1.1 %d %s\r\n", status_code, get_status_reason(status_code));
    if (written < 0 || (size_t)written >= available) goto overflow;
    ptr += written; available -= written;

    written = snprintf(ptr, available, "Content-Type: %s\r\nContent-Length: %zu\r\n", content_type, ctx->file_size);
    if (written < 0 || (size_t)written >= available) goto overflow;
    ptr += written; available -= written;

    for (int i = 0; i < ctx->res_header_count; i++) {
        written = snprintf(ptr, available, "%s: %s\r\n", ctx->response_headers[i].key, ctx->response_headers[i].value);
        if (written < 0 || (size_t)written >= available) goto overflow;
        ptr += written; available -= written;
    }

    written = snprintf(ptr, available, "\r\n");
    if (written < 0 || (size_t)written >= available) goto overflow;
    ptr += written; available -= written;

    ctx->response_len = (size_t)(ptr - ctx->response_ptr);
    return;

    // The framework will now naturally send these headers, then splice the file!
    overflow:
    fprintf(stderr, "CRITICAL: Response buffer overflow prevented in send_file on fd %d\n", ctx->fd);
    if (ctx->pub.file_fd >= 0) {
        close(ctx->pub.file_fd);
        ctx->pub.file_fd = -1;
    }
    ctx->file_size = 0;
    const char *err_msg = "HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\n\r\n";
    ctx->response_ptr = ctx->buffer;
    written = snprintf(ctx->response_ptr, MAX_BUFFER_SIZE, "%s", err_msg);
    ctx->response_len = (written > 0) ? (size_t)written : 0;
    ctx->pub.request.keep_alive = false;
}

void send_bytes(CwebContext *pub_ctx, int status_code, const char *content_type, const void *data, size_t len) {
    if (!pub_ctx) return;
    if (!content_type) content_type = "application/octet-stream";
    ConnContext* ctx = (ConnContext *)pub_ctx;

    char *ptr;
    size_t available;
    init_http_response_buf(ctx, &ptr, &available);
    int written;

    written = snprintf(ptr, available, "HTTP/1.1 %d %s\r\n", status_code, get_status_reason(status_code));
    if (written < 0 || (size_t)written >= available) goto overflow;
    ptr += written; available -= written;

    written = snprintf(ptr, available, "Content-Type: %s\r\nContent-Length: %zu\r\n", content_type, len);
    if (written < 0 || (size_t)written >= available) goto overflow;
    ptr += written; available -= written;

    for (int i = 0; i < ctx->res_header_count; i++) {
        written = snprintf(ptr, available, "%s: %s\r\n", ctx->response_headers[i].key, ctx->response_headers[i].value);
        if (written < 0 || (size_t)written >= available) goto overflow;
        ptr += written; available -= written;
    }

    written = snprintf(ptr, available, "\r\n");
    if (written < 0 || (size_t)written >= available) goto overflow;
    ptr += written; available -= written;

    if (len > available) goto overflow;
    if (len > 0 && data) {
        memmove(ptr, data, len);
        ptr += len;
    }

    ctx->response_len = (size_t)(ptr - ctx->response_ptr);
    return;

    overflow:
    fprintf(stderr, "CRITICAL: Response buffer overflow prevented in send_bytes on fd %d\n", ctx->fd);
    const char *err_msg = "HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\n\r\n";
    ctx->response_ptr = ctx->buffer;
    written = snprintf(ctx->response_ptr, MAX_BUFFER_SIZE, "%s", err_msg);
    ctx->response_len = (written > 0) ? (size_t)written : 0;
    ctx->pub.request.keep_alive = false;
}

void upgrade_to_websocket(CwebContext *pub_ctx) {
    if (!pub_ctx) return;
    ConnContext* ctx = (ConnContext*)pub_ctx;
    if (pub_ctx->request.method != GET) {
        send_error(pub_ctx, 405, "Method Not Allowed");
        return;
    }

    const char *upgrade = get_header(pub_ctx, "Upgrade");
    const char *conn_hdr = get_header(pub_ctx, "Connection");
    if (!upgrade || strcasecmp(upgrade, "websocket") != 0 ||
        !conn_hdr || !strcasestr(conn_hdr, "Upgrade")) {
        send_error(pub_ctx, 400, "Bad Request");
        return;
    }

    const char *version = get_header(pub_ctx, "Sec-WebSocket-Version");
    if (!version || strcmp(version, "13") != 0) {
        send_error(pub_ctx, 400, "Bad Request");
        return;
    }

    char *client_key = get_header(pub_ctx, "Sec-WebSocket-Key");
    if (!client_key || strlen(client_key) != 24) {
        send_error(pub_ctx, 400, "Bad Request");
        return;
    }

    char accept_key[32];
    generate_ws_accept_key(client_key, accept_key);

    ctx->response_ptr = ctx->buffer;
    int written = snprintf(ctx->response_ptr, MAX_BUFFER_SIZE,
                            "HTTP/1.1 101 Switching Protocols\r\n"
                            "Upgrade: websocket\r\n"
                            "Connection: Upgrade\r\n"
                            "Sec-WebSocket-Accept: %s\r\n\r\n", accept_key);
    if (written < 0 || (size_t)written >= MAX_BUFFER_SIZE) {
        send_error(pub_ctx, 500, "Internal Server Error");
        return;
    }
    ctx->response_len = (size_t)written;
    ctx->ws_frame_len = 0; // Signals initial handshake to WRITE state
    ctx->pub.is_websocket = true;
}

void send_ws_text(CwebContext *pub_ctx, const char *text) {
    if (!pub_ctx) return;
    ConnContext* ctx = (ConnContext *)pub_ctx;

    // If coalesced frames exist after the current frame, write outgoing frame after bytes_read + 1
    size_t out_offset = (ctx->bytes_read > ctx->ws_frame_len) ? (ctx->bytes_read + 1) : 0;
    if (out_offset + 4 >= MAX_BUFFER_SIZE) {
        out_offset = 0;
    }
    size_t capacity = MAX_BUFFER_SIZE - out_offset;

    ctx->response_ptr = ctx->buffer + out_offset;
    uint8_t *ptr = (uint8_t*)ctx->response_ptr;

    if (!text) {
        fprintf(stderr, "WS payload not provided\n");
        goto overflow;
    }

    size_t len = (text == ctx->pub.ws_payload) ? ctx->pub.ws_payload_len : strnlen(text, capacity);
    if (len + 4 >= capacity) {
        fprintf(stderr, "WS payload too large for RAM buffer\n");
        goto overflow;
    }

    size_t hdr_len = (len <= 125) ? 2 : 4;
    memmove(ptr + hdr_len, text, len); // Move payload first in case text aliases ctx->buffer

    uint8_t op = (ctx->pub.ws_opcode == 2 || ctx->pub.ws_opcode == 10) ? (uint8_t)ctx->pub.ws_opcode : 1;
    ptr[0] = (uint8_t)(0x80 | op); // FIN + Opcode (1=Text, 2=Binary, 10=Pong)
    if (len <= 125) {
        ptr[1] = (uint8_t)len;
    }
    else {
        ptr[1] = 126;
        ptr[2] = (uint8_t)((len >> 8) & 0xFF);
        ptr[3] = (uint8_t)(len & 0xFF);
    }
    ctx->response_len = hdr_len + len;
    return;

    overflow:
    ptr[0] = 0x88;
    ptr[1] = 0x02;
    ptr[2] = 0x03;
    ptr[3] = 0xF3;
    ctx->response_len = 4;
}
