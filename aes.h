
#ifndef AES
#define AES

#include<stdint.h>

#define BLOCK_SIZE_BYTE	16
#define KEY_SIZE_BYTE	16 // 24, 32
#define ROUNDS		10 // 12, 14

//typedef	uint8_t	  = uint8_t
//typedef uint16_t  = uint16_t
//typedef uint32_t  = u32
//typedef uint64_t  = uint64_t

/*
 * Key schedule
 * key: master keys
 * roundkeys: round keys
 */
void key_expansion(const uint8_t *key, uint8_t *roundkeys);

/*
 * Encryption: Only one block is encrypted. After encryption, cipher text will override plain text.
 * plain: plain text
 * roundkeys: round keys
 */
void encrypt(uint8_t *plain, const uint8_t *roundkeys);

/*
 * Decryption: Only one block is decrypted. After decrypiton, plain text will override cipher text
 * cipher: cipher text
 * roundkeys: round keys
 */
void decrypt(uint8_t *cipher, const uint8_t *roundkeys);

#endif
