#define MAX 10000
extern int primeNumbers[MAX];
extern long numberOfPrimeNumbers;
void primeFiller();
long pickRandomPrime();
double SQRT(double);
void keyGenerator();
long gcd(long, long);
long encrypt(int, long, long);
void encoder(char *, long *, long, long);
int decrypt(long, long, long);
void decoder(long *, int, char *, long, long);
void decryptRsaEncryptedFile();