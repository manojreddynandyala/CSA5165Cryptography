#include <stdio.h>
#include <string.h>

#define BLOCK_SIZE 8  // Block size for simplicity

// XOR-based encryption/decryption (substitute for S-DES)
unsigned char xor_encrypt(unsigned char plaintext, unsigned char key) {
    return plaintext ^ key;
}

// Counter Mode encryption and decryption
void ctr_mode(unsigned char *input, unsigned char *output, unsigned char key, int len, unsigned char start_counter) {
    for (int i = 0; i < len; i++) {
        unsigned char counter = start_counter + i;
        unsigned char keystream = xor_encrypt(counter, key); // Generate keystream by XORing counter with key
        output[i] = input[i] ^ keystream; // XOR plaintext with keystream to get ciphertext (or vice versa)
    }
}

int main() {
    unsigned char plaintext[] = {0x01, 0x10, 0x20}; // Binary plaintext
    unsigned char key = 0x7D; // Binary key
    unsigned char start_counter = 0x00; // Counter starting value

    unsigned char ciphertext[sizeof(plaintext)];
    unsigned char decrypted_text[sizeof(plaintext)];

    // Encrypt using CTR mode
    ctr_mode(plaintext, ciphertext, key, sizeof(plaintext), start_counter);
    
    printf("Ciphertext: ");
    for (int i = 0; i < sizeof(ciphertext); i++) {
        printf("%02X ", ciphertext[i]);
    }
    printf("\n");

    // Decrypt using CTR mode (same function as encryption)
    ctr_mode(ciphertext, decrypted_text, key, sizeof(ciphertext), start_counter);
    
    printf("Decrypted text: ");
    for (int i = 0; i < sizeof(decrypted_text); i++) {
        printf("%02X ", decrypted_text[i]);
    }
    printf("\n");

    return 0;
}
