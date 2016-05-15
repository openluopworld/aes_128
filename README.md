### AES-128

C implementation of AES-128.<br><br>

<font color="blue">void</font> key_schedule(const uint8_t *key, uint8_t *roundkeys);<br>
void encrypt(uint8_t *plain, const uint8_t *roundkeys);<br>
void decrypt(uint8_t *cipher, const uint8_t *roundkeys);<br>
