/*
 *
 * Chinese Academy of Sciences
 * State Key Laboratory of Information Security
 * Institute of Information Engineering
 *
 * Copyright (C) 2016 Chinese Academy of Sciences
 *
 * LuoPeng, luopeng@iie.ac.cn
 * Updated in May 2016
 *
 */
#ifndef AES
#define AES

#include <stdio.h>
#include <stdint.h>

#define BLOCK_SIZE_BYTE	16
#define ROUNDS		10 // 12, 14
#define ROUND_KEY_SIZE	176 // AES-128 has 10 rounds, and there is a AddRoundKey before first round. (10+1)x16=176.

/**
 * @purpose:		Key schedule for AES-128
 * @par[in]key:		16 bytes of master keys
 * @par[out]roundkeys:	176 bytes of round keys
 */
void key_expansion(const uint8_t *key, uint8_t *roundkeys);

/**
 * @purpose:		Encryption. Only one block is encrypted. After encryption, cipher text will override plain text.
 * @par[in/out]plain:	plain text and cipher text
 * @par[in]roundkeys:	round keys
 */
void encrypt(uint8_t *plain, const uint8_t *roundkeys);

/**
 * @purpose:		Decryption. Only one block is decrypted. After decrypiton, plain text will override cipher text
 * @par[in/out]cipher:	cipher text
 * @par[in]roundkeys:	round keys
 */
void decrypt(uint8_t *cipher, const uint8_t *roundkeys);

#endif
