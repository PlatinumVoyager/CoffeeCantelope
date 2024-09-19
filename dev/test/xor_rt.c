#include <Windows.h>
#include <stdio.h>
#include <stdlib.h>

/* basic function to encrypt and decrypt data using XOR cipher */
void xorEnc(char *d, size_t sz, const char *k);

#define ENCRYPT_DECRYPT_ROUTINE for (size_t char_len = 0; char_len < size_targ; char_len++)\
    {\
        data[char_len] = data[char_len] ^ k[char_len % key_len] >> 2;\
        xor_len++;\
    }\

#define DECRYPT_ENCRYPT_ROUTINE ENCRYPT_DECRYPT_ROUTINE

void xorEnc(char *d, size_t sz, const char *k)
{
    printf("\n");

    // data
    char *data = NULL;
    size_t size_targ = snprintf(NULL, 0, "%s", d); // user data string

    data = (char *) malloc(size_targ * sizeof(char));

    if (data == NULL)
    {
        fwprintf(stderr, L"\"data\" variable with error: failed to allocate %zd bytes of memory with current process...\n", sz);
    
        exit(-1);
    }
    else 
    {
        printf("++ allocated %zd bytes of memory...\n", sizeof(data));
    }

    snprintf(data, strlen(d) + 1, "%s", d);

    // get key len
    size_t key_len = strlen(k);

    // print size at end
    int xor_len = 0;

    // perform XOR encryption
    ENCRYPT_DECRYPT_ROUTINE

    printf("\nENCRYPTED_ROUTINE_OUTPUT => %s (LEN=%d)\n", data, xor_len);

    xor_len = 0;

    DECRYPT_ENCRYPT_ROUTINE

    printf("DECRYPTED_ROUTINE_OUTPUT => %s (LEN=%d)\n", data, xor_len);

    free(data);

    // EOFE
}


int main(int argc, char *argv[])
{
    if (!argv[1])
    {
        fwprintf(stderr, L"Error > pass key string for param[in] *d!\n");

        return -1;
    }

    if (argv[1])
    {
        /* why allocate key here even if argv[1] is defined? */
        if (!argv[2])
        {
            // oops, user didn't supply xor key
            fwprintf(stderr, L"Error > pass xor key character for param[in] *k!\n");

            return -1;
        }
        else
        {
            // generic length test
            if (strlen(argv[2]) < 2)
            {
                printf("Error > pass a proper xor key length for param[in] *k!");

                return -1;
            }
        }

        /* keep below to reduce memory waste, possible heap fragmentation */
        char *data = (char *)argv[1];

        /* key can also be "pseudorandomly" generated as well */
        char *xor_key = (char *)argv[2];

        printf("Status > success: got data string for encryption target => \"%s\"\n", data);

        // have xor key and key string, jmp to function
        printf("Status > success: got key character for xor encryption target => \"%s\"\n", xor_key);
    
        xorEnc(data, strlen(data), xor_key);
    }

    return 0;
}