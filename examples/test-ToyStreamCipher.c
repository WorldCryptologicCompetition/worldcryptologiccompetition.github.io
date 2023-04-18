#include <stdint.h>
#include <stdbool.h>
#include <inttypes.h>

#include <stdio.h>

#include <fcntl.h>

#include <math.h>
#include <stdlib.h>

#include "WCC_2023.h"
#include "ToyStreamCipher.h"

int main()
{
        struct entry_TSC_state state;
        int randFD;
        uint_fast8_t idx;

        randFD = open("/dev/urandom", O_RDONLY); /* urandom for debug testing */

        read(randFD, &(state.key), sizeof(state.key));
        read(randFD, &(state.nonce), sizeof(state.nonce));

        state.outputStreamLengthInBits = (64 * 64);

        fputs("Key:", stdout); for (idx = 0; idx < 8; idx++) { printf(" 0x%.16" PRIx64, state.key[idx]); } putchar('\n');
        fputs("Nonce:", stdout); for (idx = 0; idx < 3; idx++) { printf(" 0x%.16" PRIx64, state.nonce[idx]); } putchar('\n');

        puts("DEBUG: entry_TSC_produceStream()");
        entry_TSC_produceStream(&state);

        for (idx = 0; idx < 64; idx++) {
                printf("0x%.16" PRIx64 "\n", state.outputStream[idx]);
        }

        return 0;
}
