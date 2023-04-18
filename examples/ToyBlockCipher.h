
#include <inttypes.h>
#include <stdint.h>
#include <stdbool.h>

#include <stdio.h>

#include "WCC_2023.h"

/*
 * ToyBlockCipher.c (TBC)
 *
 *     Entry Name: "TBC"
 *
 */

#define ENTRY_TBC_NUMBER_OF_ROUNDS 255

struct entry_TBC_state
{
    uint64_t key[8];        /* Requirement A.2 */
    uint64_t nonce[3];      /* Requirement A.3 */
    uint64_t plaintext[8];  /* Requirement A.4 */
    uint64_t ciphertext[8]; /* Requirement A.5 */
    // then, any additional members ...
    uint64_t keySchedule[13];   /* 832 bits */
};

void entry_TBC_util_reverseKeyIdx(uint_fast8_t * const idx)
{
	if ((*idx) == 0) {
		(*idx) = 12;
	} else {
		(*idx)--;
	}
}

void entry_TBC_util_reverseNonceIdx(uint_fast8_t * const idx)
{
	if ((*idx) == 0) {
		(*idx) = 2;
	} else {
		(*idx)--;
	}
}

void entry_TBC_runKeySchedule(struct entry_TBC_state * const state)
{
    static const uint8_t rotations[5][2] = {
        {8, 16}, {4, 5}, {7, 13}, {41, 19}, {8, 32}
    };

    static const uint8_t indices[5][2] = {
        {0, 1}, {7, 5}, {3, 8}, {2, 4}, {2, 7}
    };

    uint_fast8_t idx;

    for (idx = 0; idx < 8; idx++) {
        state->keySchedule[idx] = state->key[idx];
    }

    for (idx = 0; idx < 5; idx++) {
        state->keySchedule[9 + idx]  = ROL64(state->key[indices[idx][0]], rotations[idx][0]);
        state->keySchedule[9 + idx] ^= ROL64(state->key[indices[idx][1]], rotations[idx][1]);
    }

}

/* Requirement A.6 */
void entry_TBC_ENC(struct entry_TBC_state * const state)
{
    static const uint64_t blockInitializers[8] = {
        0, 1, 2, 3, 4, 5, 6, 7
    };

    static const uint8_t rotations[8] = {
        13, 5, 31, 23, 29, 53, 17, 37
    };

    uint_fast8_t roundIdx, blockWordIdx, nonceWordIdx, keyWordIdx;

    entry_TBC_runKeySchedule(state);

    
    for (blockWordIdx = 0; blockWordIdx < 8; blockWordIdx++) {
        state->ciphertext[blockWordIdx] = state->plaintext[blockWordIdx] ^ blockInitializers[blockWordIdx];
    }

    nonceWordIdx = 0;
    keyWordIdx = 0;
    for (roundIdx = 0; roundIdx < ENTRY_TBC_NUMBER_OF_ROUNDS; roundIdx++) {
        for (blockWordIdx = 0; blockWordIdx < 8; blockWordIdx += 2) {
            state->ciphertext[blockWordIdx] += state->ciphertext[(blockWordIdx + 1) % 8];
            state->ciphertext[blockWordIdx] += state->nonce[nonceWordIdx]; nonceWordIdx++; nonceWordIdx %= 3;
            state->ciphertext[blockWordIdx] += state->keySchedule[keyWordIdx]; keyWordIdx++; keyWordIdx %= 13;
            state->ciphertext[blockWordIdx]  = ROL64(state->ciphertext[blockWordIdx], rotations[blockWordIdx]);
        }
        for (blockWordIdx = 1; blockWordIdx < 8; blockWordIdx += 2) {
            state->ciphertext[blockWordIdx] += state->ciphertext[(blockWordIdx + 1) % 8];
            state->ciphertext[blockWordIdx] += state->nonce[nonceWordIdx]; nonceWordIdx++; nonceWordIdx %= 3;
            state->ciphertext[blockWordIdx] += state->keySchedule[keyWordIdx]; keyWordIdx++; keyWordIdx %= 13;
            state->ciphertext[blockWordIdx]  = ROL64(state->ciphertext[blockWordIdx], rotations[blockWordIdx]);
        }
    }

    for (blockWordIdx = 0; blockWordIdx < 8; blockWordIdx++) {
        state->ciphertext[blockWordIdx] ^= state->key[blockWordIdx];
    }

    puts("DEBUG: ToyBlockCipher.h: Ciphertext:");
    for (blockWordIdx = 0; blockWordIdx < 8; blockWordIdx++) {
        printf(" 0x%.16" PRIx64, state->ciphertext[blockWordIdx]);
    }
    putchar('\n');

}

/* Requirement A.7 */
void entry_TBC_DEC(struct entry_TBC_state * const state)
{

    static const uint64_t blockInitializers[8] = {
        0, 1, 2, 3, 4, 5, 6, 7
    };

    static const uint8_t rotations[8] = {
        13, 5, 31, 23, 29, 53, 17, 37
    };

    uint_fast8_t roundIdx, blockWordIdx, nonceWordIdx, keyWordIdx;

    entry_TBC_runKeySchedule(state);

    for (blockWordIdx = 0; blockWordIdx < 8; blockWordIdx++) {
        state->plaintext[blockWordIdx] = state->ciphertext[blockWordIdx] ^ state->key[blockWordIdx];
    }

    nonceWordIdx = ((ENTRY_TBC_NUMBER_OF_ROUNDS * 8) - 1) % 3;
    keyWordIdx = ((ENTRY_TBC_NUMBER_OF_ROUNDS * 8) - 1) % 13;
    for (roundIdx = 0; roundIdx < ENTRY_TBC_NUMBER_OF_ROUNDS; roundIdx++) {
	    state->plaintext[7]  = ROR64(state->plaintext[7], rotations[7]);
	    state->plaintext[7] -= (state->plaintext[0] + state->keySchedule[keyWordIdx]); entry_TBC_util_reverseKeyIdx(&keyWordIdx);
        state->plaintext[7] -= state->nonce[nonceWordIdx]; entry_TBC_util_reverseNonceIdx(&nonceWordIdx);

	    state->plaintext[5]  = ROR64(state->plaintext[5], rotations[5]);
	    state->plaintext[5] -= (state->plaintext[6] + state->keySchedule[keyWordIdx]); entry_TBC_util_reverseKeyIdx(&keyWordIdx);
        state->plaintext[5] -= state->nonce[nonceWordIdx]; entry_TBC_util_reverseNonceIdx(&nonceWordIdx);

	    state->plaintext[3]  = ROR64(state->plaintext[3], rotations[3]);
	    state->plaintext[3] -= (state->plaintext[4] + state->keySchedule[keyWordIdx]); entry_TBC_util_reverseKeyIdx(&keyWordIdx);
        state->plaintext[3] -= state->nonce[nonceWordIdx]; entry_TBC_util_reverseNonceIdx(&nonceWordIdx);

	    state->plaintext[1]  = ROR64(state->plaintext[1], rotations[1]);
	    state->plaintext[1] -= (state->plaintext[2] + state->keySchedule[keyWordIdx]); entry_TBC_util_reverseKeyIdx(&keyWordIdx);
        state->plaintext[1] -= state->nonce[nonceWordIdx]; entry_TBC_util_reverseNonceIdx(&nonceWordIdx);

	    state->plaintext[6]  = ROR64(state->plaintext[6], rotations[6]);
	    state->plaintext[6] -= (state->plaintext[7] + state->keySchedule[keyWordIdx]); entry_TBC_util_reverseKeyIdx(&keyWordIdx);
        state->plaintext[6] -= state->nonce[nonceWordIdx]; entry_TBC_util_reverseNonceIdx(&nonceWordIdx);

	    state->plaintext[4]  = ROR64(state->plaintext[4], rotations[4]);
	    state->plaintext[4] -= (state->plaintext[5] + state->keySchedule[keyWordIdx]); entry_TBC_util_reverseKeyIdx(&keyWordIdx);
        state->plaintext[4] -= state->nonce[nonceWordIdx]; entry_TBC_util_reverseNonceIdx(&nonceWordIdx);

	    state->plaintext[2]  = ROR64(state->plaintext[2], rotations[2]);
	    state->plaintext[2] -= (state->plaintext[3] + state->keySchedule[keyWordIdx]); entry_TBC_util_reverseKeyIdx(&keyWordIdx);
        state->plaintext[2] -= state->nonce[nonceWordIdx]; entry_TBC_util_reverseNonceIdx(&nonceWordIdx);

	    state->plaintext[0]  = ROR64(state->plaintext[0], rotations[0]);
	    state->plaintext[0] -= (state->plaintext[1] + state->keySchedule[keyWordIdx]); entry_TBC_util_reverseKeyIdx(&keyWordIdx);
        state->plaintext[0] -= state->nonce[nonceWordIdx]; entry_TBC_util_reverseNonceIdx(&nonceWordIdx);
    }

    for (blockWordIdx = 0; blockWordIdx < 8; blockWordIdx++) {
        state->plaintext[blockWordIdx] ^= blockInitializers[blockWordIdx];
    }

    puts("DEBUG: ToyBlockCipher.h: Plaintext:");
    for (blockWordIdx = 0; blockWordIdx < 8; blockWordIdx++) {
        printf(" 0x%.16" PRIx64, state->plaintext[blockWordIdx]);
    }
    putchar('\n');

}