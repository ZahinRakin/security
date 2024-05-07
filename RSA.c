#include <time.h>
#include <stdlib.h>
#include "header.h"

int primeNumbers[MAX];
long numberOfPrimeNumbers = 0;

double SQRT(double n)
{
	double lo = (1 < n) ? 1 : n, hi = (1 > n) ? 1 : n, mid;
	while (100 * lo * lo < n)
		lo *= 10;
	while (0.01 * hi * hi > n)
		hi *= 0.1;

	for (int i = 0; i < 100; i++)
	{
		mid = (lo + hi) / 2;
		if (mid * mid == n)
			return mid;
		if (mid * mid > n)
			hi = mid;
		else
			lo = mid;
	}
	return mid;
}

void primeFiller()
{
	for (int i = 2; i < MAX; i++)
	{
		primeNumbers[i] = 1;
	}
	int limit = (int)SQRT(MAX - 1);
	for (int i = 2; i <= limit; i++)
	{
		if (primeNumbers[i])
		{
			for (int j = i * i; j < MAX; j += i)
			{
				primeNumbers[j] = 0;
			}
		}
	}
	for (int i = 0; i < MAX; i++)
		if (primeNumbers[i])
			numberOfPrimeNumbers++;

	// printf("number of primes: %ld\n",numberOfPrimeNumbers);
}

long pickRandomPrime()
{
	long randomNumber = rand() % numberOfPrimeNumbers + 1;
	// printf("chosen random number => %ld\n",randomNumber);//was used for testing
	long counter = 0;
	for (int i = 0; i < MAX; i++)
	{
		if (primeNumbers[i])
		{
			counter++;
		}
		if (counter == randomNumber)
		{
			return i;
		}
	}
}

void keyGenerator()
{
	primeFiller();
	long p = pickRandomPrime();
	long q = pickRandomPrime();
	long n = p * q;
	long phi = (p - 1) * (q - 1);
	long e = 2;
	long d = 2;
	while (1)
	{
		if (gcd(e, phi) == 1)
		{
			break;
		}
		e += 1;
	}

	while (1)
	{
		if ((d * e) % phi == 1)
		{
			break;
		}
		d += 1;
	}
	printf("Please note these once lost cann't be recovered in the future.\n");
	printf("Public keys: {n, e} = {%ld, %ld}\n", n, e);
	printf("Private keys: {n, d} = {%ld, %ld}\n", n, d);
}

long gcd(long a, long b)
{
	if (b == 0)
	{
		return a;
	}
	return gcd(b, a % b);
}

long encrypt(int ascii, long n, long e)
{
	long encrypted_text = 1;
	while (e > 0)
	{
		encrypted_text *= ascii;
		encrypted_text %= n;
		e -= 1;
	}
	return encrypted_text;
}

void encoder(char *message, long *encoded, long n, long e)
{
	for (int i = 0; i < strlen(message); i++)
	{
		encoded[i] = encrypt((int)message[i], n, e);
	}
}

int decrypt(long encrypted_text, long n, long d)
{
	long decrypted = 1;
	while (d > 0)
	{
		decrypted *= encrypted_text;
		decrypted %= n;
		d -= 1;
	}
	return (int)decrypted;
}

void decoder(long *encoded, int size, char *output, long n, long d)
{ // size of encoded message is important.
	for (int i = 0; i < size; i++)
	{
		output[i] = (char)decrypt(encoded[i], n, d);
	}
}

void decryptRsaEncryptedFile()
{
	FILE *fp;
	char file[30000];
	long encoded[30000];
	char filename[100];
	char password[100];
	int numberOfEncodedMsg = 0;
	char *pointer;
	long n, d;
	printf("Enter the file name that is RSA encrypted: ");
	scanf("%s", filename);
	strcat(filename, ".txt");
	getchar();
	printf("Enter private keys.\nn : ");
	scanf("%ld", &n);
	getchar();

	printf("d : ");
	scanf("%ld", &d);
	getchar();

	if ((fp = fopen(filename, "r")) == NULL)
	{
		perror("error opening file\n");
		exit(1);
	}
	fgets(password, sizeof(password), fp);
	fgets(file, sizeof(file), fp);
	fclose(fp);

	pointer = strtok(file, ",");
	while (pointer)
	{
		encoded[numberOfEncodedMsg] = strtol(pointer, NULL, 10);
		pointer = strtok(NULL, ",");
		numberOfEncodedMsg++;
	}
	bzero(file, sizeof(file)); // this might cause bug...........
	decoder(encoded, numberOfEncodedMsg, file, n, d);
	char newfile[100] = "enc";
	strcat(newfile, filename);
	if ((fp = fopen(newfile, "w")) == NULL)
	{
		perror("error file opening.\n");
		exit(1);
	}
	fprintf(fp, "%s", password);
	fprintf(fp, "%s", file);
	fclose(fp);
}