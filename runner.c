#include "header.h"


int main(){
    unsigned char key[16];
    char plaintext[1000];
    unsigned char* ciphered;
    unsigned char* deciphered;


    printf("key: ");
    fgets(key, sizeof(key), stdin);
    key[strlen(key)-1] = '\0';

    printf("input: ");
    fgets(plaintext, sizeof(plaintext), stdin);
    plaintext[strlen(plaintext)-1] = '\0';
    
    ciphered = cipher(plaintext, ciphered, key);
    printf("\nciphered text: ");
    for(int i = 0; i < strlen(ciphered); i++) printf("%02x ", ciphered[i]);
    printf("\n\n\n");


    deciphered = invCipher(ciphered, deciphered, key);
    printf("deciphered text: ", deciphered);
    for(int i = 0; i < strlen(deciphered); i++) {
        if(deciphered[i] != '*'){
            printf("%c", deciphered[i]);
        } else break;
    }
    printf("\n\n\n");


    return 0;
}