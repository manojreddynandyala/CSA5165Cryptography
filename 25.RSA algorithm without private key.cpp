#include <stdio.h>

int gcd(int a, int b) {
    if (b == 0)
        return a;	 
    return gcd(b, a % b);
}

int main() {
    int m, n, result;
    printf("Enter the plaintext block (m): ");
    scanf("%d", &m);
    printf("Enter the RSA modulus (n): ");
    scanf("%d", &n);
    result = gcd(m, n);
    if (result > 1) {
        printf("GCD of %d and %d is %d.\n", m, n, result);
        printf("A factor of n has been found: %d\n", result);
    } else {
        printf("No factor of n found. GCD is 1.\n");
    }
    return 0;
}
