#ifndef CRYPTO_H
#define CRYPTO_H

#include "echostream.h"

// Function declarations
char* encode_base64(const unsigned char* data, size_t len);
int decode_base64(const char* input, unsigned char* output);
size_t decode_base64_len(const char* input, unsigned char* output);
unsigned char* encrypt_data(const unsigned char* data, size_t data_len, const unsigned char* key, size_t* out_len);
unsigned char* decrypt_data(const unsigned char* data, size_t data_len, const unsigned char* key, size_t* out_len);

#endif // CRYPTO_H
