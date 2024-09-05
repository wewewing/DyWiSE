#ifndef AURA_COMMONUTIL_H
#define AURA_COMMONUTIL_H

#include <string>

extern "C"
{
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
};

#define AES_BLOCK_SIZE 16
#define DIGEST_SIZE 32
#define GGM_SIZE 958505
//#define GGM_SIZE 191701
#define HASH_SIZE 3

enum NetworkOp
{
    OP_SETUP,
    OP_SAVE_CIPHER,
    OP_SRCH_QRY,
    OP_KEY_UPDT_GET_CIPHER,
    OP_KEY_UPDT_RETURN_CIPHER,
    OP_BACKUP_EDB,
    OP_LOAD_EDB
};

void recv_data(int sock, unsigned char *buf, int length);
void recv_bytes(int sock, std::string &str_out);
void send_bytes(int sock, const std::string &str_in);

int aes_encrypt(unsigned char *plaintext, int plaintext_len,
                unsigned char *key, unsigned char *iv,
                unsigned char *ciphertext);

int aes_decrypt(unsigned char *ciphertext, int ciphertext_len,
                unsigned char *key, unsigned char *iv,
                unsigned char *plaintext);

void sha256_digest(unsigned char *plaintext, int plaintext_len,
                unsigned char *digest);

unsigned int hmac_digest(unsigned char *digest, const unsigned char *plaintext, int plaintext_len,
                 const unsigned char *key, int key_len);

unsigned int key_derivation(unsigned char *plaintext, int plaintext_len,
                            unsigned char *key, int key_len,
                            unsigned char *digest);

void encrypt_id(std::string &cip_out, const std::string &ind, const unsigned char *key);

bool decrypt_id(std::string &ind_out, const std::string &cip, const unsigned char *key);

void print_hex(const void *data, int len);

#endif //AURA_COMMONUTIL_H
