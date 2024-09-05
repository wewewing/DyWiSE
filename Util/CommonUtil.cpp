#include "CommonUtil.h"
#include <cstring>
#include <string>
#include <iostream>
extern "C"
{
#include <sys/socket.h>
}

void recv_data(int sock, unsigned char *buf, int length)
{
    int recv_len = 0;
    while (recv_len < length)
    {
        recv_len += recv(sock, buf + recv_len, length - recv_len, 0);
    }
}

void recv_bytes(int sock, std::string &str_out)
{
    int buf_len;
    unsigned char buf[512];

    recv_data(sock, (unsigned char*)&buf_len, sizeof(int));
    recv_data(sock, buf, buf_len);
    str_out.assign((const char*)buf, buf_len);
}

void send_bytes(int sock, const std::string &str_in)
{
    int len;

    len = str_in.size();
    send(sock, &len, sizeof(int), 0);
    send(sock, str_in.c_str(), len, 0);
}

int aes_encrypt(unsigned char *plaintext, int plaintext_len,
                unsigned char *key, unsigned char *iv,
                unsigned char *ciphertext)
{
    EVP_CIPHER_CTX *ctx;

    int len = 0;

    int ciphertext_len;

    /* Create and initialise the context */
    ctx = EVP_CIPHER_CTX_new();

    /* Initialise the encryption operation. */
    EVP_EncryptInit_ex(ctx, EVP_aes_128_ctr(), NULL, key, iv);

    /* Encrypt the message */
    EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len);
    ciphertext_len = len;

    /* Finalise the encryption */
    EVP_EncryptFinal_ex(ctx, ciphertext + len, &len);
    ciphertext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}

int aes_decrypt(unsigned char *ciphertext, int ciphertext_len,
                unsigned char *key, unsigned char *iv,
                unsigned char *plaintext)
{
    EVP_CIPHER_CTX *ctx;

    int len = 0;

    int plaintext_len;

    /* Create and initialise the context */
    ctx = EVP_CIPHER_CTX_new();

    /* Initialise the decryption operation. */
    EVP_DecryptInit_ex(ctx, EVP_aes_128_ctr(), NULL, key, iv);

    /* decrypt the message */
    EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len);
    plaintext_len = len;

    /* Finalise the encryption */
    EVP_DecryptFinal_ex(ctx, plaintext + len, &len);
    plaintext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return plaintext_len;
}

void sha256_digest(unsigned char *plaintext, int plaintext_len,
                   unsigned char *digest)
{
    /* Create and initialise the context */
    SHA256_CTX ctx;
    SHA256_Init(&ctx);

    /* compute the digest */
    SHA256_Update(&ctx, plaintext, plaintext_len);

    /* Finalise the digest */
    SHA256_Final(digest, &ctx);
}

unsigned int hmac_digest(unsigned char *digest, const unsigned char *plaintext, int plaintext_len,
                         const unsigned char *key, int key_len)
{
    HMAC_CTX *ctx;

    unsigned int len;

    /* Create and initialise the context */
    ctx = HMAC_CTX_new();

    /* Initialise the decryption operation. */
    HMAC_Init_ex(ctx, key, key_len, EVP_sha256(), NULL);

    /* compute the digest */
    HMAC_Update(ctx, plaintext, plaintext_len);

    /* Finalise the digest */
    HMAC_Final(ctx, digest, &len);

    /* Clean up */
    HMAC_CTX_free(ctx);

    return len;
}

unsigned int key_derivation(unsigned char *plaintext, int plaintext_len,
                            unsigned char *key, int key_len,
                            unsigned char *digest)
{
    HMAC_CTX *ctx;

    unsigned int len;
    unsigned char buf[32];

    /* Create and initialise the context */
    ctx = HMAC_CTX_new();

    /* Initialise the decryption operation. */
    HMAC_Init_ex(ctx, key, key_len, EVP_sha3_256(), NULL);

    /* compute the digest */
    HMAC_Update(ctx, plaintext, plaintext_len);

    /* Finalise the digest */
    HMAC_Final(ctx, buf, &len);

    /* Clean up */
    HMAC_CTX_free(ctx);

    memcpy(digest, buf, 16);

    return len;
}

void encrypt_id(std::string &cip_out, const std::string &ind, const unsigned char *key)
{
    unsigned char IV[16], buf[128], plain[32];
    AES_KEY aes_key;

    memset(plain, 0, 32);
    memset(buf, 0, 128);

    AES_set_encrypt_key(key, 128, &aes_key);
    RAND_bytes(IV, 16);
    memcpy(buf, IV, 16);

    memcpy(plain, ind.c_str(), ind.size() > 12 ? 12 : ind.size());
    plain[12] = 'c';
    plain[13] = '#';
    plain[14] = '*';
    plain[15] = '$';

    AES_cbc_encrypt(plain, buf + 16, 16, &aes_key, IV, AES_ENCRYPT);

    cip_out.assign((const char *) buf, 32);
}

bool decrypt_id(std::string &ind_out, const std::string &cip, const unsigned char *key)
{
    unsigned char IV[16], plain[32];
    AES_KEY aes_key;

    memset(plain, 0, 32);

    AES_set_decrypt_key(key, 128, &aes_key);
    memcpy(IV, cip.c_str(), 16);

    AES_cbc_encrypt((const unsigned char *) cip.c_str() + 16, plain, 16, &aes_key, IV, AES_DECRYPT);

    if (!((plain[12] == 'c') && (plain[13] == '#') && (plain[14] == '*') && (plain[15] == '$')))
        return false;

    plain[12] = 0;

    ind_out = (char *) plain;

    return true;
}

void print_hex(const void *data, int len)
{
    const uint8_t *data_ = (const uint8_t *) data;
    for (int i = 0; i < len; i++)
        printf("%02X ", data_[i]);
    std::cout << std::endl;
}