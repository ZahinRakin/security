import math
import random


def is_prime(n):
    if n <= 1:
        return False
    if n <= 3:
        return True
    if n % 2 == 0 or n % 3 == 0:
        return False
    i = 5
    while i * i <= n:
        if n % i == 0 or n % (i + 2) == 0:
            return False
        i += 6
    return True


def generate_prime_candidate(length):
    p = random.getrandbits(length)
    p |= (1 << length - 1) | 1  # Ensure p has desired length and is odd
    return p


def generate_prime(length):
    while True:
        p = generate_prime_candidate(length)
        if is_prime(p):
            return p


def mod_inverse(a, m):
    m0, x0, x1 = m, 0, 1
    while a > 1:
        q = a // m
        m, a = a % m, m
        x0, x1 = x1 - q * x0, x0
    return x1 + m0 if x1 < 0 else x1


def generate_keypair(bit_length):
    p = generate_prime(bit_length)
    q = generate_prime(bit_length)
    n = p * q
    phi = (p - 1) * (q - 1)

    while True:
        e = random.randrange(2, phi)
        if math.gcd(e, phi) == 1:
            break

    d = mod_inverse(e, phi)

    return ((n, e), (n, d))

# Example usage
bit_length = 128  # Adjust as needed
public_key, private_key = generate_keypair(bit_length)
print("Public key:", public_key)
print("Private key:", private_key)
