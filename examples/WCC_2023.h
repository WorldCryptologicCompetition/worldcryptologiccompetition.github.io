
#ifndef __WCC_2023_HEADER__
#define __WCC_2023_HEADER__ 

/*
 * WCC_2023.h
 *
 * Entrants are encouraged to use this library, but it is not a requirement.
 *
 */

#define ROR(x, r) ((x >> r) | (x << (64 - r)))
#define ROL(x, r) ((x << r) | (x >> (64 - r)))

uint64_t ROL64(uint64_t word, const uint8_t rotation)
{
    return ((word << rotation) | (word >> (64 - rotation)));
}
            
uint64_t ROR64(uint64_t word, const uint8_t rotation)
{
    return ((word >> rotation) | (word << (64 - rotation)));
}
            
            
#endif
