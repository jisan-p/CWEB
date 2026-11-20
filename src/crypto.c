#include "../include/crypto.h"

static inline uint32_t sha1_rol32(uint32_t val, int bits) {
    return (val << bits) | (val >> (32 - bits));
}

static void sha1_transform(uint32_t state[5], const uint8_t block[64]) {
    uint32_t w[80];
    for (int i = 0; i < 16; i++) {
        w[i] = ((uint32_t)block[i * 4 + 0] << 24) |
        ((uint32_t)block[i * 4 + 1] << 16) |
        ((uint32_t)block[i * 4 + 2] << 8)  |
        ((uint32_t)block[i * 4 + 3]);
    }
    for (int i = 16; i < 80; i++) {
        w[i] = sha1_rol32(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
    }

    uint32_t a = state[0], b = state[1], c = state[2], d = state[3], e = state[4];

    for (int i = 0; i < 80; i++) {
        uint32_t f, k;
        if (i < 20) {
            f = (b & c) | ((~b) & d);
            k = 0x5A827999;
        } else if (i < 40) {
            f = b ^ c ^ d;
            k = 0x6ED9EBA1;
        } else if (i < 60) {
            f = (b & c) | (b & d) | (c & d);
            k = 0x8F1BBCDC;
        } else {
            f = b ^ c ^ d;
            k = 0xCA62C1D6;
        }
        uint32_t temp = sha1_rol32(a, 5) + f + e + k + w[i];
        e = d;
        d = c;
        c = sha1_rol32(b, 30);
        b = a;
        a = temp;
    }

    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
    state[4] += e;
}

void generate_ws_accept_key(const char *client_key, char *out_accept) {
    // 24-byte client_key + 36-byte magic GUID = 60 bytes (requires two 64-byte SHA-1 blocks!)
    uint8_t blocks[128];
    memset(blocks, 0, sizeof(blocks));

    memcpy(blocks, client_key, 24);
    memcpy(blocks + 24, "258EAFA5-E914-47DA-95CA-C5AB0DC85B11", 36);
    blocks[60] = 0x80; // SHA-1 1-bit padding right after byte 59

    // 60 bytes = 480 bits (0x01E0) stored in big-endian at the end of block 2 (bytes 120..127)
    blocks[126] = 0x01;
    blocks[127] = 0xE0;

    uint32_t state[5] = {
        0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0
    };
    sha1_transform(state, blocks);      // First 64-byte block
    sha1_transform(state, blocks + 64); // Second 64-byte block

    uint8_t hash[20];
    for (int i = 0; i < 5; i++) {
        hash[i * 4 + 0] = (uint8_t)((state[i] >> 24) & 0xFF);
        hash[i * 4 + 1] = (uint8_t)((state[i] >> 16) & 0xFF);
        hash[i * 4 + 2] = (uint8_t)((state[i] >> 8)  & 0xFF);
        hash[i * 4 + 3] = (uint8_t)(state[i] & 0xFF);
    }

    static const char b64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    int j = 0;
    for (int i = 0; i < 18; i += 3) {
        uint32_t v = ((uint32_t)hash[i] << 16) | ((uint32_t)hash[i + 1] << 8) | hash[i + 2];
        out_accept[j++] = b64[(v >> 18) & 0x3F];
        out_accept[j++] = b64[(v >> 12) & 0x3F];
        out_accept[j++] = b64[(v >> 6)  & 0x3F];
        out_accept[j++] = b64[v & 0x3F];
    }
    // Final 2 bytes (hash[18], hash[19]) -> 3 base64 chars + '='
    uint32_t v = ((uint32_t)hash[18] << 16) | ((uint32_t)hash[19] << 8);
    out_accept[j++] = b64[(v >> 18) & 0x3F];
    out_accept[j++] = b64[(v >> 12) & 0x3F];
    out_accept[j++] = b64[(v >> 6)  & 0x3F];
    out_accept[j++] = '=';
    out_accept[j]   = '\0';
}
