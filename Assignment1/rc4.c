#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define SIZE 256

void swap(unsigned char *a, unsigned char *b)
{
    int tmp = *a;
    *a = *b;
    *b = tmp;
}

void rc4_init(unsigned char *key, size_t key_len, unsigned char *S)
{

    for (size_t i = 0; i < SIZE; i++)
        S[i] = i;

    size_t j = 0;
    for (size_t i = 0; i < SIZE; i++)
    {
        j = (j + S[i] + key[i % key_len]) % SIZE;
        swap(&S[i], &S[j]);
    }
}

void key_stream_gen(unsigned char *S, int plain_text_len, unsigned char *key_stream)
{

    size_t i = 0, j = 0;

    for (size_t n = 0; n < plain_text_len; n++)
    {
        i = (i + 1) % SIZE;
        j = (j + S[i]) % SIZE;
        swap(&S[i], &S[j]);

        key_stream[n] = S[(S[i] + S[j]) % SIZE];
    }
}

void encrypt(char *plain_text, int len, unsigned char *cipher_text, unsigned char *key_stream)
{
    for (size_t n = 0; n < len; n++)
    {
        cipher_text[n] = plain_text[n] ^ key_stream[n];
    }
}

void decrypt(char *decrypted_text, int len, unsigned char *cipher_text, unsigned char *key_stream)
{
    for (size_t n = 0; n < len; n++)
    {
        decrypted_text[n] = cipher_text[n] ^ key_stream[n];
    }
}

void RC4(unsigned char *key, int key_len,int plain_text_len)
{
    unsigned char S[SIZE];
    unsigned char key_stream[plain_text_len];

    rc4_init(key, key_len, S);
    key_stream_gen(S, plain_text_len, key_stream);

    // printf("Bytes :");

    // for (int i = 0; i < plain_text_len; i++)
    // {
    //     printf("%d %02hhX\t", i, key_stream[i]);
    //     // printf("%p ", key_stream[i]);
    //     // printf("%p ", key_stream[i]);
    // }

    FILE *f;

    // write byte to file
    if ((f = fopen("./bytes", "wb")) != NULL)
    {
        fwrite(key_stream, 1, plain_text_len, f);
        fclose(f);
    }
    else
    {
        printf("Error writing the bytes");
        exit(0);
    }

    // encrypt(plain_text, plain_text_len, cipher_text, key_stream);

    // printf("\ncipher text: ");
    // for (int i = 0; i < plain_text_len; i++)
    // {
    //     printf("%02hhX", cipher_text[i]);
    // }

    // decrypt(decrypted_text, plain_text_len, cipher_text, key_stream);
    // printf("\nplain text: ");
    // for (int i = 0; i < plain_text_len; i++)
    // {
    //     printf("%c", decrypted_text[i]);
    // }
    // printf("\n");
}

int main(int argc, char *argv[])
{

    if (argc < 3)
    {
        printf("Usage: %s <key_file> <key_size=256> <plain_text_len>", argv[0]);
        return -1;
    }

    // Size of key in bytes
    int key_len = 256;
    // declare the key byte array
    unsigned char key[key_len];
    // char plain_text[SIZE + 1];
    // memset(plain_text, 0, SIZE + 1);

    FILE *f;

    // read the key from the file
    if ((f = fopen(argv[1], "rb")) != NULL)
    {
        fread(key, 1, key_len, f);
        fclose(f);
    }
    else
    {
        printf("Error opening file: %s", argv[1]);
        exit(0);
    }

    // // read plain text from the file
    // if ((f = fopen(argv[3], "r")) != NULL)
    // {
    //     fscanf(f, "%[^\n]", plain_text);
    //     fclose(f);
    // }
    // else
    // {
    //     printf("Error opening file: %s", argv[1]);
    //     exit(0);
    // }



    // declare the cipher text array
    int plain_text_len = atoi(argv[2]);
    unsigned char cipher_text[plain_text_len];
    memset(cipher_text, 0, plain_text_len);

    RC4(key, key_len, plain_text_len);

    return 0;
}