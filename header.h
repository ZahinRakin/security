#ifndef HEADER_H
#define HEADER_H
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// methods for aes.
#define AES_BLOCK_SIZE 16
#define AES_ROUNDS 10
#define AES_ROUND_KEY_SIZE 176

unsigned char *cipher(char *, unsigned char *, unsigned char *);// input, output, key
unsigned char *invCipher(unsigned char *, unsigned char *, unsigned char *); // input, output, key

void subBytes(unsigned char *);
void addRoundKey(unsigned char *, unsigned char *, int *);
void shiftRows(unsigned char *);
void mixColumns(unsigned char *);
void keyExpansion(unsigned char *, unsigned char *);
void aesEncrypt(unsigned char *, unsigned char *);
// decrypt methods.
void aesDecrypt(unsigned char *, unsigned char *);
void invShiftRows(unsigned char *);
void invSubBytes(unsigned char *);
void invMixColumns(unsigned char *);
int padding(char *); // returns the length of padding.

extern unsigned char key[];
extern unsigned char SBOX[256];
extern unsigned char INV_SBOX[256];

extern unsigned char RC[];

#endif