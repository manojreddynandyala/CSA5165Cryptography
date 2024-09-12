#include <stdio.h>

// Function to find the greatest common divisor and coefficients using Extended Euclidean Algorithm
int extended_gcd(int a, int b, int *x, int *y) {
    if (a == 0) {
        *x = 0; *y = 1; return b;
    }
    int x1, y1, gcd = extended_gcd(b % a, a, &x1, &y1);
    *x = y1 - (b / a) * x1; *y = x1; return gcd;
}

// Function to find modular inverse of a under modulo m
int mod_inverse(int a, int m) {
    int x, y;
    int gcd = extended_gcd(a, m, &x, &y);
    if (gcd != 1) return -1;
    return (x % m + m) % m;
}

int main() {
    int e = 31, n = 3599, p, q;

    // Find p and q (trial division)
    for (int i = 2; i * i <= n; i++) {
        if (n % i == 0) {
            p = i; q = n / i;
            break;
        }
    }
    printf("p = %d, q = %d\n", p, q);

    // Compute phi(n) and modular inverse of e
    int phi_n = (p - 1) * (q - 1);
    int d = mod_inverse(e, phi_n);

    printf("phi(n) = %d\n", phi_n);
    printf("Private key (d) = %d\n", d);

    return 0;
}
 
