#include <stdio.h>

// Function to calculate (base^exp) % mod
int powerMod(int base, int exp, int mod) {
    int result = 1;
    base = base % mod;
    while (exp > 0) {
        if (exp % 2 == 1)
            result = (result * base) % mod;
        exp = exp >> 1;
        base = (base * base) % mod;
    }
    return result;
}

int main() {
    int p = 61, q = 53, n = p * q, phi = (p - 1) * (q - 1), e = 17, d = 2753;
    int message = 65;

    int ciphertext = powerMod(message, e, n);
    printf("Encrypted message: %d\n", ciphertext);

    int decryptedMessage = powerMod(ciphertext, d, n);
    printf("Decrypted message: %d\n", decryptedMessage);

    return 0;
}
