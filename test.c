#include <stdio.h>

#include "aes.h"

int main(int argc, char *argv[]) {

	uint8_t i;

	/* 128 bit key */
	uint8_t key[] = {
		0x00, 0x01, 0x02, 0x03, 
		0x04, 0x05, 0x06, 0x07, 
		0x08, 0x09, 0x0a, 0x0b, 
		0x0c, 0x0d, 0x0e, 0x0f};

	uint8_t plain[] = {
		0x00, 0x11, 0x22, 0x33,
		0x44, 0x55, 0x66, 0x77,
		0x88, 0x99, 0xaa, 0xbb,
		0xcc, 0xdd, 0xee, 0xff};
	
	uint8_t roundkeys[KEY_SIZE_BYTE*(ROUNDS+1)];

	// key schedule
	key_expansion(key, roundkeys);

	// encryption
	encrypt(plain, roundkeys);

	printf("Cipher text:\n");
	for (i = 0; i < 4; i++) {
		printf("%2x %2x %2x %2x \n", plain[i], plain[i+4], plain[i+8], plain[i+12]);
	}
	printf("Cipher End\n\n");

	// decryption
	decrypt(plain, roundkeys);

	printf("Plain text:\n");
	for (i = 0; i < 4; i++) {
		printf("%2x %2x %2x %2x \n", plain[i], plain[i+4], plain[i+8], plain[i+12]);
	}
	printf("Plain End\n\n");

	return 0;

}
