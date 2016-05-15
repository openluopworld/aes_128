### AES-128

C implementation of AES-128.<br><br>

```C
/**
 * Key schedule for AES-128
 */
void key_schedule(const uint8_t *key, uint8_t *roundkeys);
/**
 * Encryption. Only one block is encrypted. After encryption, cipher text will override plain text.
 */
void encrypt(uint8_t *plain, const uint8_t *roundkeys);
/**
 * Decryption. Only one block is decrypted. After decrypiton, plain text will override cipher text.
 */
void decrypt(uint8_t *cipher, const uint8_t *roundkeys);
```
