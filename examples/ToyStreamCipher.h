
#include <inttypes.h>
#include <stdint.h>
#include <stdbool.h>

#include <stdio.h>

#include "WCC_2023.h"

/*
 * ToyStreamCipher.c (TSC)
 *
 *     Entry Name: "TSC"
 *
 */

#define ENTRY_TSC_NUMBER_OF_ROUNDS 1

struct entry_TSC_state
{
    uint64_t key[8];                    /* Requirement C.2 */
    uint64_t nonce[3];                  /* Requirement C.3 */
    uint64_t outputStreamLengthInBits;  /* Requirement C.4 */
    uint64_t *outputStream;             /* Requirement C.5 */
    // then, any additional members ...
    uint64_t A[113];                     /* 7,232 bits */
};

/* Requirement C.6 */
void entry_EN_produceStream(struct entry_EN_state * const state)
{

    static const uint64_t initializers[5] = { 1, 2, 3, 4, 5 };

    uint_fast8_t idx, roundIdx;
    uint_fast64_t numberOfWordsToGenerate;
    uint_fast64_t outputIdx;
    uint_fast64_t counter;

    numberOfWordsToGenerate = ceill( (long double)state->outputStreamLengthInBits / (long double)64 );

    state->outputStream = malloc(numberOfWordsToGenerate * sizeof(uint64_t));

    for (idx = 0; idx < 113; idx++) {
        A[idx] = state->key[idx % 8] + state->nonce[idx % 3] + initializers[idx % 5];
    }

    counter = 0;
    for (outputIdx = 0; outputIdx < numberOfWordsToGenerate; outputIdx++) {
        for (roundIdx = 0; roundIdx < ENTRY_TSC_NUMBER_OF_ROUNDS; roundIdx++) {
            for (idx = 0; idx < 113; idx++) {
                A[idx] += A[(idx + 112) % 113];
                A[idx]  = ROL64(A[idx], 23);
                A[idx] += A[(idx + 47) % 113] + A[(idx + 83) % 113] + counter;
                A[idx]  = ROL64(A[idx], 19);
                counter++;
            }
        }
        state->outputStream[outputIdx] = A[112];
    }

}