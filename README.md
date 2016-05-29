### AES-128

C implementation of AES-128.<br><br>

```C
/**
 * Key schedule for AES-128
 */
void aes_key_schedule_128(const uint8_t *key, uint8_t *roundkeys);
/**
 * Encryption. The length of plain and cipher should be one block (16 bytes)
 */
void aes_encrypt_128(const uint8_t *roundkeys, const uint8_t *plain, uint8_t *cipher);
/**
 * Decryption. The length of plain and cipher should be one block (16 bytes)
 */
void aes_decrypt_128(const uint8_t *roundkeys, const uint8_t *cipher, uint8_t *plain);
```
