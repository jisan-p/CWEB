#ifndef CRYPTO_H
#define CRYPTO_H

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

void sha1(const uint8_t *data, size_t length, uint8_t out_hash[20]);
void base64_encode(const uint8_t *data, size_t input_length, char *out_str);
void generate_ws_accept_key(const char *client_key, char *out_key);

#endif
