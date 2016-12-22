### AES-128

[![Build Status](https://travis-ci.org/openluopworld/aes_128?branch=master)](https://travis-ci.org/openluopworld/aes_128)

C implementation of AES-128.<br><br>

```C
/**
 * @purpose:			Key schedule for AES-128
 * @par[in]key:			16 bytes of master keys
 * @par[out]roundkeys:	176 bytes of round keys
 */
void aes_key_schedule_128(const uint8_t *key, uint8_t *roundkeys);

/**
 * @purpose:			Encryption. The length of plain and cipher should be one block (16 bytes).
 *						The plaintext and ciphertext may point to the same memory
 * @par[in]roundkeys:	round keys
 * @par[in]plaintext:	plain text
 * @par[out]ciphertext:	cipher text
 */
void aes_encrypt_128(const uint8_t *roundkeys, const uint8_t *plaintext, uint8_t *ciphertext);

/**
 * @purpose:			Decryption. The length of plain and cipher should be one block (16 bytes).
 *						The ciphertext and plaintext may point to the same memory
 * @par[in]roundkeys:	round keys
 * @par[in]ciphertext:	cipher text
 * @par[out]plaintext:	plain text
 */
void aes_decrypt_128(const uint8_t *roundkeys, const uint8_t *ciphertext, uint8_t *plaintext);
```