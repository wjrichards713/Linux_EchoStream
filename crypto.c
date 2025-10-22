#include "crypto.h"

char* encode_base64(const unsigned char* data, size_t len) {
    static const char table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    static const int padding[] = {0, 2, 1};
    
    size_t output_len = 4 * ((len + 2) / 3);
    char* encoded = malloc(output_len + 1);
    if (!encoded) return NULL;
    
    for (size_t i = 0, j = 0; i < len;) {
        uint32_t a = i < len ? data[i++] : 0;
        uint32_t b = i < len ? data[i++] : 0;
        uint32_t c = i < len ? data[i++] : 0;
        uint32_t triple = (a << 0x10) + (b << 0x08) + c;
        
        encoded[j++] = table[(triple >> 3 * 6) & 0x3F];
        encoded[j++] = table[(triple >> 2 * 6) & 0x3F];
        encoded[j++] = table[(triple >> 1 * 6) & 0x3F];
        encoded[j++] = table[(triple >> 0 * 6) & 0x3F];
    }
    
    for (int i = 0; i < padding[len % 3]; i++)
        encoded[output_len - 1 - i] = '=';
    
    encoded[output_len] = '\0';
    return encoded;
}

int decode_base64(const char* input, unsigned char* output) {
    static const int table[] = {
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 62, -1, -1, -1, 63,
        52, 53, 54, 55, 56, 57, 58, 59, 60, 61, -1, -1, -1, -1, -1, -1,
        -1,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14,
        15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, -1, -1, -1, -1, -1,
        -1, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
        41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, -1, -1, -1, -1, -1
    };
    
    size_t input_len = strlen(input);
    if (input_len % 4 != 0) return 0;
    
    size_t output_len = input_len / 4 * 3;
    if (input[input_len - 1] == '=') output_len--;
    if (input[input_len - 2] == '=') output_len--;
    
    for (size_t i = 0, j = 0; i < input_len;) {
        uint32_t a = (input[i] == '=') ? (i++, 0u) : (uint32_t)table[(size_t)input[i++]];
        uint32_t b = (input[i] == '=') ? (i++, 0u) : (uint32_t)table[(size_t)input[i++]];
        uint32_t c = (input[i] == '=') ? (i++, 0u) : (uint32_t)table[(size_t)input[i++]];
        uint32_t d = (input[i] == '=') ? (i++, 0u) : (uint32_t)table[(size_t)input[i++]];
        
        uint32_t triple = (a << 3 * 6) + (b << 2 * 6) + (c << 1 * 6) + (d << 0 * 6);
        
        if (j < output_len) output[j++] = (triple >> 2 * 8) & 0xFF;
        if (j < output_len) output[j++] = (triple >> 1 * 8) & 0xFF;
        if (j < output_len) output[j++] = (triple >> 0 * 8) & 0xFF;
    }
    
    return 1;
}

size_t decode_base64_len(const char* input, unsigned char* output) {
    static const int table[] = {
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 62, -1, -1, -1, 63,
        52, 53, 54, 55, 56, 57, 58, 59, 60, 61, -1, -1, -1, -1, -1, -1,
        -1,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14,
        15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, -1, -1, -1, -1, -1,
        -1, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
        41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, -1, -1, -1, -1, -1
    };
    
    size_t input_len = strlen(input);
    if (input_len % 4 != 0) return 0;
    
    size_t output_len = input_len / 4 * 3;
    if (input_len > 0 && input[input_len - 1] == '=') output_len--;
    if (input_len > 1 && input[input_len - 2] == '=') output_len--;
    
    for (size_t i = 0, j = 0; i < input_len;) {
        uint32_t a = (input[i] == '=') ? (i++, 0u) : (uint32_t)table[(size_t)input[i++]];
        uint32_t b = (input[i] == '=') ? (i++, 0u) : (uint32_t)table[(size_t)input[i++]];
        uint32_t c = (input[i] == '=') ? (i++, 0u) : (uint32_t)table[(size_t)input[i++]];
        uint32_t d = (input[i] == '=') ? (i++, 0u) : (uint32_t)table[(size_t)input[i++]];
        
        uint32_t triple = (a << 3 * 6) + (b << 2 * 6) + (c << 1 * 6) + (d << 0 * 6);
        
        if (j < output_len) output[j++] = (triple >> 2 * 8) & 0xFF;
        if (j < output_len) output[j++] = (triple >> 1 * 8) & 0xFF;
        if (j < output_len) output[j++] = (triple >> 0 * 8) & 0xFF;
    }
    
    return output_len;
}

unsigned char* encrypt_data(const unsigned char* data, size_t data_len, const unsigned char* key, size_t* out_len) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return NULL;
    
    unsigned char iv[12];
    if (RAND_bytes(iv, 12) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return NULL;
    }
    
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return NULL;
    }
    
    unsigned char* encrypted = malloc(data_len + 12 + 16);
    if (!encrypted) {
        EVP_CIPHER_CTX_free(ctx);
        return NULL;
    }
    
    memcpy(encrypted, iv, 12);
    
    int len;
    if (EVP_EncryptUpdate(ctx, encrypted + 12, &len, data, data_len) != 1) {
        free(encrypted);
        EVP_CIPHER_CTX_free(ctx);
        return NULL;
    }
    
    int ciphertext_len = len;
    if (EVP_EncryptFinal_ex(ctx, encrypted + 12 + len, &len) != 1) {
        free(encrypted);
        EVP_CIPHER_CTX_free(ctx);
        return NULL;
    }
    ciphertext_len += len;
    
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, encrypted + 12 + ciphertext_len) != 1) {
        free(encrypted);
        EVP_CIPHER_CTX_free(ctx);
        return NULL;
    }
    
    *out_len = 12 + ciphertext_len + 16;
    EVP_CIPHER_CTX_free(ctx);
    return encrypted;
}

unsigned char* decrypt_data(const unsigned char* data, size_t data_len, const unsigned char* key, size_t* out_len) {
    if (data_len < 28) return NULL; // IV(12) + TAG(16) minimum
    
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return NULL;
    
    const unsigned char* iv = data;
    const unsigned char* ciphertext = data + 12;
    const unsigned char* tag = data + data_len - 16;
    size_t ciphertext_len = data_len - 28;
    
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return NULL;
    }
    
    unsigned char* decrypted = malloc(ciphertext_len);
    if (!decrypted) {
        EVP_CIPHER_CTX_free(ctx);
        return NULL;
    }
    
    int len;
    if (EVP_DecryptUpdate(ctx, decrypted, &len, ciphertext, ciphertext_len) != 1) {
        free(decrypted);
        EVP_CIPHER_CTX_free(ctx);
        return NULL;
    }
    
    int plaintext_len = len;
    
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, (void*)tag) != 1) {
        free(decrypted);
        EVP_CIPHER_CTX_free(ctx);
        return NULL;
    }
    
    if (EVP_DecryptFinal_ex(ctx, decrypted + len, &len) != 1) {
        free(decrypted);
        EVP_CIPHER_CTX_free(ctx);
        return NULL;
    }
    
    plaintext_len += len;
    *out_len = plaintext_len;
    
    EVP_CIPHER_CTX_free(ctx);
    return decrypted;
}
