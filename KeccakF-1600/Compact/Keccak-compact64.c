/*
The Keccak sponge function, designed by Guido Bertoni, Joan Daemen,
Michaël Peeters and Gilles Van Assche. For more information, feedback or
questions, please refer to our website: http://keccak.noekeon.org/

Implementation by the designers and Ronny Van Keer,
hereby denoted as "the implementer".

To the extent possible under law, the implementer has waived all copyright
and related or neighboring rights to the source code in this file.
http://creativecommons.org/publicdomain/zero/1.0/
*/

#include <string.h>
#include <stdlib.h>
#include "brg_endian.h"
#include "KeccakF-1600-interface.h"

#define USE_MEMSET
//#define DIVISION_INSTRUCTION    //comment if no division instruction or more compact when not using division
#define UNROLL_CHILOOP        //comment more compact using for loop


typedef unsigned char UINT8;
typedef unsigned long long int UINT64;
typedef unsigned int tSmallUInt; /*INFO It could be more optimized to use "unsigned char" on an 8-bit CPU    */
typedef UINT64 tKeccakLane;

#if defined(_MSC_VER) || defined(__INTEL_COMPILER)
    #define ALIGN __declspec(align(32))
#elif defined(__GNUC__)
    #define ALIGN __attribute__ ((aligned(32)))
#else
    #define ALIGN
#endif

#if defined(_MSC_VER)
	#define ROL64(a, offset) _rotl64(a, offset)
#elif defined(UseSHLD)
    #define ROL64(x,N) ({ \
    register UINT64 __out; \
    register UINT64 __in = x; \
    __asm__ ("shld %2,%0,%0" : "=r"(__out) : "0"(__in), "i"(N)); \
    __out; \
    })
#elif defined(__INTEL_COMPILER)
    #define ROL64(a, offset) _lrotl(a, offset)
#else
	#define ROL64(a, offset) ((((UINT64)a) << offset) ^ (((UINT64)a) >> (64-offset)))
#endif

#define    cKeccakNumberOfRounds    24

const UINT8 KeccakF_RotationConstants[25] = 
{
     1,  3,  6, 10, 15, 21, 28, 36, 45, 55,  2, 14, 27, 41, 56,  8, 25, 43, 62, 18, 39, 61, 20, 44
};

const UINT8 KeccakF_PiLane[25] = 
{
    10,  7, 11, 17, 18,  3,  5, 16,  8, 21, 24,  4, 15, 23, 19, 13, 12,  2, 20, 14, 22,  9,  6,  1 
};

#if    defined(DIVISION_INSTRUCTION)
#define    MOD5(argValue)    ((argValue) % 5)
#else
const UINT8 KeccakF_Mod5[10] = 
{
    0, 1, 2, 3, 4, 0, 1, 2, 3, 4
};
#define    MOD5(argValue)    KeccakF_Mod5[argValue]
#endif

/* ---------------------------------------------------------------- */

static tKeccakLane KeccakF1600_GetNextRoundConstant( UINT8 *LFSR );
static tKeccakLane KeccakF1600_GetNextRoundConstant( UINT8 *LFSR )
{
    tSmallUInt i;
    tKeccakLane    roundConstant;
    tSmallUInt doXOR;
    tSmallUInt tempLSFR;

    roundConstant = 0;
    tempLSFR = *LFSR;
    for(i=1; i<128; i <<= 1) 
    {
        doXOR = tempLSFR & 1;
        if ((tempLSFR & 0x80) != 0)
            // Primitive polynomial over GF(2): x^8+x^6+x^5+x^4+1
            tempLSFR = (tempLSFR << 1) ^ 0x71;
        else
            tempLSFR <<= 1;

        if ( doXOR != 0 )
            roundConstant ^= (tKeccakLane)1ULL << (i - 1);
    }
    *LFSR = (UINT8)tempLSFR;
    return ( roundConstant );
}


/* ---------------------------------------------------------------- */

void KeccakF1600_Initialize( void )
{
}

/* ---------------------------------------------------------------- */

void KeccakF1600_StateInitialize(void *argState)
{
    #if defined(USE_MEMSET)
    memset( argState, 0, 25 * 8 );
    #else
    tSmallUInt i;
    tKeccakLane *state;

    state = argState;
    i = 25;
    do
    {
        *(state++) = 0;
    }
    while ( --i != 0 );
    #endif
}

/* ---------------------------------------------------------------- */

void KeccakF1600_StateXORBytesInLane(void *argState, unsigned int lanePosition, const unsigned char *data, unsigned int offset, unsigned int length)
{
    unsigned int i;
    #if (PLATFORM_BYTE_ORDER == IS_LITTLE_ENDIAN)
    unsigned char * state = (unsigned char*)argState + lanePosition * sizeof(tKeccakLane) + offset;
    for(i=0; i<length; i++)
        ((unsigned char *)state)[i] ^= data[i];
    #else
    tKeccakLane lane = 0;
    for(i=0; i<length; i++)
        lane |= ((tKeccakLane)data[i]) << ((i+offset)*8);
    ((tKeccakLane*)state)[lanePosition] ^= lane;
    #endif
}

/* ---------------------------------------------------------------- */

void KeccakF1600_StateXORLanes(void *state, const unsigned char *data, unsigned int laneCount)
{
#if (PLATFORM_BYTE_ORDER == IS_LITTLE_ENDIAN)
    tSmallUInt i;
    laneCount *= sizeof(tKeccakLane);
    for( i = 0; i < laneCount; ++i) {
        ((unsigned char*)state)[i] ^= data[i];
    }
#else
    tSmallUInt i;
    UINT8 *curData = data;
    for(i=0; i<laneCount; i++, curData+=8) {
        tKeccakLane lane = (tKeccakLane)curData[0]
            | ((tKeccakLane)curData[1] << 8)
            | ((tKeccakLane)curData[2] << 16)
            | ((tKeccakLane)curData[3] << 24)
            | ((tKeccakLane)curData[4] << 32)
            | ((tKeccakLane)curData[5] << 40)
            | ((tKeccakLane)curData[6] << 48)
            | ((tKeccakLane)curData[7] << 56);
        ((tKeccakLane*)state)[i] ^= lane;
    }
#endif
}

/* ---------------------------------------------------------------- */

void KeccakF1600_StateComplementBit(void *state, unsigned int position)
{
    tKeccakLane lane = (tKeccakLane)1 << (position%64);
    ((tKeccakLane*)state)[position/64] ^= lane;
}

/* ---------------------------------------------------------------- */

void KeccakF1600_StatePermute(void *argState)
{
    tSmallUInt x, y, round;
    tKeccakLane        temp;
    tKeccakLane        BC[5];
    tKeccakLane     *state;
    UINT8             LFSRstate;

    state = argState;
    LFSRstate = 0x01;
    round = cKeccakNumberOfRounds;
    do
    {
        // Theta
        for ( x = 0; x < 5; ++x )
        {
            BC[x] = state[x] ^ state[5 + x] ^ state[10 + x] ^ state[15 + x] ^ state[20 + x];
        }
        for ( x = 0; x < 5; ++x )
        {
            temp = BC[MOD5(x+4)] ^ ROL64(BC[MOD5(x+1)], 1);
            for ( y = 0; y < 25; y += 5 )
            {
                state[y + x] ^= temp;
            }
        }

        // Rho Pi
        temp = state[1];
        for ( x = 0; x < 24; ++x )
        {
            BC[0] = state[KeccakF_PiLane[x]];
            state[KeccakF_PiLane[x]] = ROL64( temp, KeccakF_RotationConstants[x] );
            temp = BC[0];
        }

        //    Chi
        for ( y = 0; y < 25; y += 5 )
        {
#if defined(UNROLL_CHILOOP)
            BC[0] = state[y + 0];
            BC[1] = state[y + 1];
            BC[2] = state[y + 2];
            BC[3] = state[y + 3];
            BC[4] = state[y + 4];
#else
            for ( x = 0; x < 5; ++x )
            {
                BC[x] = state[y + x];
            }
#endif
            for ( x = 0; x < 5; ++x )
            {
                state[y + x] = BC[x] ^((~BC[MOD5(x+1)]) & BC[MOD5(x+2)]);
            }
        }

        //    Iota
        state[0] ^= KeccakF1600_GetNextRoundConstant(&LFSRstate);
    }
    while( --round != 0 );
}

/* ---------------------------------------------------------------- */

void KeccakF1600_StateExtractBytesInLane(const void *state, unsigned int lanePosition, unsigned char *data, unsigned int offset, unsigned int length)
{
#if (PLATFORM_BYTE_ORDER == IS_LITTLE_ENDIAN)
    memcpy(data, ((UINT8*)&((tKeccakLane*)state)[lanePosition])+offset, length);
#else
    tSmallUInt i;
    tKeccakLane lane = ((tKeccakLane*)state)[lanePosition];
    lane >>= offset*8;
    for(i=0; i<length; i++) {
        data[i] = lane & 0xFF;
        lane >>= 8;
    }
#endif
}

/* ---------------------------------------------------------------- */

void KeccakF1600_StateExtractLanes(const void *state, unsigned char *data, unsigned int laneCount)
{
#if (PLATFORM_BYTE_ORDER == IS_LITTLE_ENDIAN)
    memcpy(data, state, laneCount*8);
#else
    tSmallUInt i, j;
    for(i=0; i<laneCount; i++)
    {
        for(j=0; j<(64/8); j++)
        {
            bytes[data+(i*8] = state[i] >> (8*j)) & 0xFF;
        }
    }
#endif
}

/* ---------------------------------------------------------------- */

void KeccakF1600_StateXORPermuteExtract(void *state, const unsigned char *inData, unsigned int inLaneCount, unsigned char *outData, unsigned int outLaneCount)
{
    KeccakF1600_StateXORLanes(state, inData, inLaneCount);
    KeccakF1600_StatePermute(state);
    KeccakF1600_StateExtractLanes(state, outData, outLaneCount);
}

/* ---------------------------------------------------------------- */
