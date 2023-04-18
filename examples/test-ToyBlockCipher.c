
#include <stdint.h>
#include <stdbool.h>
#include <inttypes.h>

#include <stdio.h>

#include <fcntl.h>

#include "WCC_2023.h"
#include "ToyBlockCipher.h"

int main()
{
        struct entry_TBC_state state;
        uint64_t correctPlaintext[8];
        int randFD;
        uint_fast8_t idx;

        randFD = open("/dev/urandom", O_RDONLY); /* urandom for debug testing */

        read(randFD, &(state.plaintext), sizeof(state.plaintext));
        read(randFD, &(state.key), sizeof(state.key));
        read(randFD, &(state.nonce), sizeof(state.nonce));

        fputs("Plaintext:", stdout); for (idx = 0; idx < 8; idx++) { printf(" 0x%.16" PRIx64, state.plaintext[idx]); } putchar('\n');
        fputs("Key:", stdout); for (idx = 0; idx < 8; idx++) { printf(" 0x%.16" PRIx64, state.key[idx]); } putchar('\n');
        fputs("Nonce:", stdout); for (idx = 0; idx < 3; idx++) { printf(" 0x%.16" PRIx64, state.nonce[idx]); } putchar('\n');

        for (idx = 0; idx < 8; idx++) { correctPlaintext[idx] = state.plaintext[idx]; }

        puts("DEBUG: entry_TBC_ENC()");
        entry_TBC_ENC(&state);

        puts("DEBUG: entry_TBC_DEC()");
        entry_TBC_DEC(&state);

        for (idx = 0; idx < 8; idx++) {
                if (state.plaintext[idx] == correctPlaintext[idx]) {
                        printf("Plaintext Word %" PRIuFAST8 " OK, word = 0x%.16" PRIx64 "\n", idx, state.plaintext[idx]);
                } else {
                        printf("Plaintext Word %" PRIuFAST8 " FAILED, word = 0x%.16" PRIx64 " (!!!)\n", idx, state.plaintext[idx]);
                }
        }

        return 0;
}

