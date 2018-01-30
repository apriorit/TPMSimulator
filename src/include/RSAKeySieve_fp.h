/******************************************************************************************************************/
/*                                                                                                                */
/*                                                                                                                */
/*  Licenses and Notices                                                                                          */
/*                                                                                                                */
/*  1.  Copyright Licenses:                                                                                       */
/*     Trusted Computing Group (TCG) grants to the user of the source code in this specification (the             */
/*     "Source Code") a worldwide, irrevocable, nonexclusive, royalty free, copyright license to                  */
/*     reproduce, create derivative works, distribute, display and perform the Source Code and                    */
/*     derivative works thereof, and to grant others the rights granted herein.                                   */
/*     The TCG grants to the user of the other parts of the specification (other than the Source Code)            */
/*     the rights to reproduce, distribute, display, and perform the specification solely for the purpose         */
/*     of developing products based on such documents.                                                            */
/*                                                                                                                */
/*  2.  Source Code Distribution Conditions:                                                                      */
/*     Redistributions of Source Code must retain the above copyright licenses, this list of conditions           */
/*     and the following disclaimers.                                                                             */
/*     Redistributions in binary form must reproduce the above copyright licenses, this list of                   */
/*     conditions and the following disclaimers in the documentation and/or other materials provided              */
/*     with the distribution.                                                                                     */
/*                                                                                                                */
/*  3.  Disclaimers:                                                                                              */
/*     THE COPYRIGHT LICENSES SET FORTH ABOVE DO NOT REPRESENT ANY FORM OF LICENSE OR                             */
/*     WAIVER, EXPRESS OR IMPLIED, BY ESTOPPEL OR OTHERWISE, WITH RESPECT TO PATENT RIGHTS                        */
/*     HELD BY TCG MEMBERS (OR OTHER THIRD PARTIES) THAT MAY BE NECESSARY TO IMPLEMENT                            */
/*     THIS SPECIFICATION OR OTHERWISE. Contact TCG Administration                                                */
/*     (admin@trustedcomputinggroup.org) for information on specification licensing rights available              */
/*     through TCG membership agreements.                                                                         */
/*     THIS SPECIFICATION IS PROVIDED "AS IS" WITH NO EXPRESS OR IMPLIED WARRANTIES                               */
/*     WHATSOEVER, INCLUDING ANY WARRANTY OF MERCHANTABILITY OR FITNESS FOR A                                     */
/*     PARTICULAR PURPOSE, ACCURACY, COMPLETENESS, OR NONINFRINGEMENT OF INTELLECTUAL                             */
/*     PROPERTY RIGHTS, OR ANY WARRANTY OTHERWISE ARISING OUT OF ANY PROPOSAL,                                    */
/*     SPECIFICATION OR SAMPLE.                                                                                   */
/*     Without limitation, TCG and its members and licensors disclaim all liability, including liability for      */
/*     infringement of any proprietary rights, relating to use of information in this specification and to        */
/*     the implementation of this specification, and TCG disclaims all liability for cost of procurement          */
/*     of substitute goods or services, lost profits, loss of use, loss of data or any incidental,                */
/*     consequential, direct, indirect, or special damages, whether under contract, tort, warranty or             */
/*     otherwise, arising in any way out of use or reliance upon this specification or any information            */
/*     herein.                                                                                                    */
/*     Any marks and brands contained herein are the property of their respective owner.                          */
/*                                                                                                                */
/******************************************************************************************************************/

#ifndef _RSAKEYSIEVE_FP_H_
#define _RSAKEYSIEVE_FP_H_

#ifdef TPM_ALG_RSA
#ifdef RSA_KEY_SIEVE                                 //%
#ifdef RSA_DEBUG
void
ClearBit(
    unsigned char *a,                       // IN: A pointer to an array of byte
    int i                       // IN: the number of the bit to CLEAR
);

void
SetBit(
    unsigned char *a,                       // IN: A pointer to an array of byte
    int i                       // IN: the number of the bit to SET
);

UINT32
IsBitSet(
    unsigned char *a,                                // IN: A pointer to an array of byte
    int i                              // IN: the number of the bit to test
);

int
BitsInArray(
    unsigned char *a,                                // IN: A pointer to an array of byte
    int i                              // IN: the number of bytes to sum
);

UINT32
FindNthSetBit(
    const UINT16 aSize,                         // IN: the size of the array to check
    const BYTE *a,                                // IN: the array to check
    const UINT32 n                              // IN, the number of the SET bit
);

UINT32
NextPrime(
    PRIME_ITERATOR *iter
);

UINT32
AdjustNumberOfPrimes(
    UINT32 p
);

UINT32
PrimeInit(
    UINT32 first,                // IN: the initial prime
    PRIME_ITERATOR *iter,                   // IN/OUT: the iterator structure
    UINT32 primes                // IN: the table length
);

#define SetDefaultNumberOfPrimes(p) (primeTableBytes = AdjustNumberOfPrimes(p))
BOOL
IsPrimeWord(
    UINT32 p                     // IN: number to test
);

UINT32
PrimeSieve(
    BIGNUM *bnN,                   // IN/OUT: number to sieve
    UINT32 fieldSize,          // IN: size of the field area in bytes
    BYTE *field,                 // IN: field
    UINT32 primes              // IN: the number of primes to use
);

// Mask the first bits in the field and the last byte in order to eliminate
// bytes not in the field from consideration.
field[0] &= 0xff << adjust;
field[fieldSize-1] &= 0xff >> (8 - adjust);

// Cycle through the primes, clearing bits
// Have already done 3, 5, and 7
PrimeInit(7, &iter, primes);

// Get the next N primes where N is determined by the mark in the sieveMarks
while((composite = NextPrime(&iter)) != 0);

BOOL
PrimeSelectWithSieve(
    BIGNUM *bnP,                                // IN/OUT: The candidate to filter
    KDFa_CONTEXT *ktx,                                // IN: KDFa iterator structure
    UINT32 e,                               // IN: the exponent
    BN_CTX *context                             // IN: the big number context to play in
#ifdef RSA_DEBUG                                                     //%
    ,UINT16 fieldSize,                       // IN: number of bytes in the field, as
    // determined by the caller
    UINT16 primes                           // IN: number of primes to use.
#endif                                                                     //%
);

// Ran out of bits and couldn't find a prime in this field
INSTRUMENT_INC(noPrimeFields);
return FALSE;
}
void
AdjustPrimeCandidate(
    BYTE *a,
    UINT16 len
);

void
GenerateRandomPrime(
    TPM2B *p,
    BN_CTX *ctx
#ifdef RSA_DEBUG                  //%
    ,UINT16 field,
    UINT16 primes
#endif                                 //%
);

KDFa_CONTEXT *
KDFaContextStart(
    KDFa_CONTEXT *ktx,                // IN/OUT: the context structure to initialize
    TPM2B *seed,               // IN: the seed for the digest proce
    TPM_ALG_ID hashAlg,             // IN: the hash algorithm
    TPM2B *extra,              // IN: the extra data
    UINT32 *outer,              // IN: the outer iteration counter
    UINT16 keySizeInBit
);

void
KDFaContextEnd(
    KDFa_CONTEXT *ktx                 // IN/OUT: the context structure to close
);

#endif
LIB_EXPORT CRYPT_RESULT
_cpri__GenerateKeyRSA(
    TPM2B *n,                        // OUT: The public modulus
    TPM2B *p,                        // OUT: One of the prime factors of n
    UINT16 keySizeInBits,         // IN: Size of the public modulus in bits
    UINT32 e,                     // IN: The public exponent
    TPM_ALG_ID hashAlg,               // IN: hash algorithm to use in the key
    // generation process
    TPM2B *seed,                     // IN: the seed to use
    const char *label,                    // IN: A label for the generation process.
    TPM2B *extra,                    // IN: Party 1 data for the KDF
    UINT32 *counter                   // IN/OUT: Counter value to allow KDF
    // iteration to be propagated across
    // multiple routines
#ifdef RSA_DEBUG                                          //%
    ,UINT16 primes,                // IN: number of primes to test
    UINT16 fieldSize              // IN: the field size to use
#endif                                                      //%
);

#else
#endif                             //%
#endif    // TPM_ALG_RSA
#endif  // _RSAKEYSIEVE_FP_H_
