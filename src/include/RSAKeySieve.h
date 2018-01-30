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

// B.12.2.1. Introduction
// The files in this clause implement an alternative RSA key generation method that is about an order of
// magnitude faster than the regular method in B.14.1 and is provided simply to speed testing of the test
// functions. The method implemented in this clause uses a sieve rather than choosing prime candidates at
// random and testing for primeness. In this alternative, the sieve filed starting address is chosen at random
// and a sieve operation is performed on the field using small prime values. After sieving, the
// bits
// representing values that are not divisible by the small primes tested, will be checked in a pseudo-random
// order until a prime is found.
// The size of the sieve field is tunable as is the value indicating the number of primes that should be
// checked. As the size of the prime increases, the density of primes is reduced so the size of the sieve field
// should be increased to improve the probability that the field will contain at least one prime. In addition, as
// the sieve field increases the number of small primes that should be checked increases. Eliminating a
// number from consideration by using division is considerably faster than eliminating the number with a
// Miller-Rabin test.
// B.12.2.2. RSAKeySieve.h
// This header file is used to for parameterization of the Sieve and RNG used by the RSA module
#ifndef RSA_H
#define RSA_H
extern const UINT16 primeTableBytes;
#define PRIME_DIFF_TABLE_512_BYTE_PAGES 13
#ifndef PRIME_DIFF_TABLE_512_BYTE_PAGES
# define PRIME_DIFF_TABLE_512_BYTE_PAGES 4
#endif
#ifdef PRIME_DIFF_TABLE_512_BYTE_PAGES
# if PRIME_DIFF_TABLE_512_BYTE_PAGES > 12
# define PRIME_DIFF_TABLE_BYTES 6542
# else
# if PRIME_DIFF_TABLE_512_BYTE_PAGES <= 0
# define PRIME_DIFF_TABLE_BYTES 512
# else
# define PRIME_DIFF_TABLE_BYTES (PRIME_DIFF_TABLE_512_BYTE_PAGES * 512)
# endif
# endif
#endif
extern const BYTE primeDiffTable [PRIME_DIFF_TABLE_BYTES];
#define FIELD_POWER 14       // This is the only value in this group that should be
// changed
#define FIELD_BITS (1 << FIELD_POWER)
#define MAX_FIELD_SIZE ((FIELD_BITS         / 8) + 1)
#define SEED_VALUES_SIZE 105
const extern BYTE seedValues[SEED_VALUES_SIZE];
const extern BYTE bitsInByte[256];
typedef struct {
    UINT32 lastPrime;
    UINT32 index;
    UINT32 final;
} PRIME_ITERATOR;
#ifdef RSA_INSTRUMENT
# define INSTRUMENT_SET(a, b) ((a) = (b))
# define INSTRUMENT_ADD(a, b) (a) = (a) + (b)
# define INSTRUMENT_INC(a) (a) = (a) + 1
extern UINT32 failedAtIteration[10];
extern UINT32 MillerRabinTrials;
extern UINT32 totalFieldsSieved;
extern UINT32 emptyFieldsSieved;
extern UINT32 noPrimeFields;
extern UINT32 primesChecked;
extern UINT16 lastSievePrime;
#else
# define INSTRUMENT_SET(a, b)
# define INSTRUMENT_ADD(a, b)
# define INSTRUMENT_INC(a)
#endif
#ifdef RSA_DEBUG
extern UINT16 defaultFieldSize;
#define NUM_PRIMES 2047
extern const __int16 primes[NUM_PRIMES];
#else
#define defaultFieldSize MAX_FIELD_SIZE
#endif
#endif
