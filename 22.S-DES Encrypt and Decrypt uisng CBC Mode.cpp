#include <stdio.h>
#include <string.h>

#define BLOCK_SIZE 8  // 8-bit block size for S-DES

// Function prototypes
void generate_keys(unsigned char key, unsigned char *key1, unsigned char *key2);
unsigned char sdes_encrypt(unsigned char plaintext, unsigned char key1, unsigned char key2);
unsigned char sdes_decrypt(unsigned char ciphertext, unsigned char key1, unsigned char key2);

// XOR function for CBC mode
unsigned char xor_block(unsigned char block, unsigned char iv) {
    return block ^ iv;
}

// Key generation for S-DES (simplified version)
void generate_keys(unsigned char key, unsigned char *key1, unsigned char *key2) {
    // For simplicity, we'll use the input key directly as the two subkeys
    *key1 = (key & 0xF0) >> 4;  // Use upper 4 bits as key1
    *key2 = key & 0x0F;         // Use lower 4 bits as key2
}

// S-DES encryption (simplified)
unsigned char sdes_encrypt(unsigned char plaintext, unsigned char key1, unsigned char key2) {
    // Perform simple XOR encryption with the subkeys (S-DES is much more complex, but this is simplified)
    unsigned char temp = plaintext ^ key1;  // XOR with key1
    unsigned char ciphertext = temp ^ key2; // XOR with key2
    return ciphertext;
}

// S-DES decryption (simplified)
unsigned char sdes_decrypt(unsigned char ciphertext, unsigned char key1, unsigned char key2) {
    // Reverse the XOR operations for decryption
    unsigned char temp = ciphertext ^ key2;  // XOR with key2
    unsigned char plaintext = temp ^ key1;   // XOR with key1
    return plaintext;
}

// CBC mode encryption
void cbc_encrypt(unsigned char *plaintext, unsigned char *ciphertext, int len, unsigned char iv, unsigned char key1, unsigned char key2) {
    unsigned char temp_iv = iv;  // Initialize with the IV

    for (int i = 0; i < len; i++) {
        unsigned char block = xor_block(plaintext[i], temp_iv); // XOR with previous ciphertext (or IV)
        ciphertext[i] = sdes_encrypt(block, key1, key2);        // Encrypt the block
        temp_iv = ciphertext[i];                                // Update the IV with the current ciphertext
    }
}

// CBC mode decryption
void cbc_decrypt(unsigned char *ciphertext, unsigned char *decrypted_text, int len, unsigned char iv, unsigned char key1, unsigned char key2) {
    unsigned char temp_iv = iv;  // Initialize with the IV

    for (int i = 0; i < len; i++) {
        unsigned char decrypted_block = sdes_decrypt(ciphertext[i], key1, key2); // Decrypt the block
        decrypted_text[i] = xor_block(decrypted_block, temp_iv);                 // XOR with previous ciphertext (or IV)
        temp_iv = ciphertext[i];                                                 // Update the IV with the current ciphertext
    }
}

int main() {
    // Binary plaintext of "0000 0001 0010 0011" (in two 8-bit blocks)
    unsigned char plaintext[] = {0x01, 0x23};
    // Binary key of "01111 11101"
    unsigned char key = 0x7D;  // 01111 11101 in hex
    // Binary initialization vector (IV) of "1010 1010"
    unsigned char iv = 0xAA;   // 10101010 in hex

    // Generate the S-DES subkeys
    unsigned char key1, key2;
    generate_keys(key, &key1, &key2);

    // Array to store the ciphertext and decrypted text
    unsigned char ciphertext[2], decrypted_text[2];

    // Encrypt using CBC mode
    cbc_encrypt(plaintext, ciphertext, 2, iv, key1, key2);

    // Output the ciphertext
    printf("Ciphertext: ");
    for (int i = 0; i < 2; i++) {
        printf("%02X ", ciphertext[i]);
    }
    printf("\n");

    // Decrypt using CBC mode
    cbc_decrypt(ciphertext, decrypted_text, 2, iv, key1, key2);

    // Output the decrypted text
    printf("Decrypted text: ");
    for (int i = 0; i < 2; i++) {
        printf("%02X ", decrypted_text[i]);
    }
    printf("\n");

    return 0;
}
