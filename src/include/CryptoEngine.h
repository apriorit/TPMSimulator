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

// B.3.1. Introduction
// This file contains constant definition shared by CryptUtil() and the parts of the Crypto Engine.
#ifndef _CRYPT_PRI_H
#define _CRYPT_PRI_H
#include <stddef.h>
#include "TpmBuildSwitches.h"
#include "BaseTypes.h"
#include "TpmError.h"
#include "swap.h"
#include "Implementation.h"
#include    "TPM_Types.h"
//#include "TPMB.h"
#include "bool.h"
#include "Platform.h"
#ifndef NULL
#define NULL 0
#endif
typedef UINT16 NUMBYTES;               // When a size is a number of bytes
typedef UINT32 NUMDIGITS;              // When a size is a number of "digits"
#ifndef MAX
# define MAX(a, b) ((a) > (b) ? (a) : b)
#endif
typedef BYTE ALGORITHM_VECTOR[(ALG_LAST_VALUE + 7)       / 8];
typedef struct {
    UINT32 rng;
    UINT32 hash;
    UINT32 sym;
#ifdef TPM_ALG_RSA
    UINT32 rsa;
#endif
#ifdef TPM_ALG_ECC
    UINT32 ecc;
#endif
} CRYPTO_SELF_TEST_STATE;
typedef struct {
    const TPM_ALG_ID alg;
    const NUMBYTES digestSize;
    const NUMBYTES blockSize;
    const NUMBYTES derSize;
    const BYTE der[20];
} HASH_INFO;
#define ALIGNED_SIZE(x, b) ((((x) + (b) - 1)    / (b)) * (b))
#define MAX_HASH_STATE_SIZE ((2 * MAX_HASH_BLOCK_SIZE) + 16)
#define MAX_HASH_STATE_SIZE_ALIGNED \
 ALIGNED_SIZE(MAX_HASH_STATE_SIZE, CRYPTO_ALIGNMENT)
typedef CRYPTO_ALIGNED BYTE ALIGNED_HASH_STATE[MAX_HASH_STATE_SIZE_ALIGNED];
#define AlignPointer(address, align) \
 ((((intptr_t)&(address)) + (align - 1)) & ~(align - 1))
#define IsAddressAligned(address, align) \
 (((intptr_t)(address) & (align - 1)) == 0)
typedef struct _HASH_STATE
{
    ALIGNED_HASH_STATE state;
    TPM_ALG_ID hashAlg;
} CPRI_HASH_STATE, *PCPRI_HASH_STATE;
extern const HASH_INFO g_hashData[HASH_COUNT + 1];
typedef struct {
    ALIGNED_HASH_STATE buffer;
    TPM_ALG_ID hashAlg;
} EXPORT_HASH_STATE;
typedef enum {
    IMPORT_STATE,                    // Converts externally formatted state to internal
    EXPORT_STATE                     // Converts internal formatted state to external
} IMPORT_EXPORT;
typedef enum {
    GET_STATE,               // Get the state to save to NV
    PUT_STATE                // Restore the state from NV
} GET_PUT;
#define DRBG_KEY_SIZE_BITS MAX_AES_KEY_BITS
#define DRBG_IV_SIZE_BITS (MAX_AES_BLOCK_SIZE_BYTES * 8)
#define DRBG_ALGORITHM TPM_ALG_AES
#if ((DRBG_KEY_SIZE_BITS % 8) != 0) || ((DRBG_IV_SIZE_BITS % 8) != 0)
#error "Key size and IV for DRBG must be even multiples of 8"
#endif
#if (DRBG_KEY_SIZE_BITS % DRBG_IV_SIZE_BITS) != 0
#error "Key size for DRBG must be even multiple of the cypher block size"
#endif
typedef UINT32 DRBG_SEED[(DRBG_KEY_SIZE_BITS + DRBG_IV_SIZE_BITS)                / 32];
typedef struct {
    UINT64 reseedCounter;
    UINT32 magic;
    DRBG_SEED seed;    // contains the key and IV for the counter mode DRBG
    UINT32 lastValue[4];                // used when the TPM does continuous self-test
    // for FIPS compliance of DRBG
} DRBG_STATE, *pDRBG_STATE;
#ifdef TPM_ALG_ECC
typedef struct {
    UINT32 curveID;           // The curve identifier
    TPMS_ECC_POINT *publicPoint;      // Pointer to the public point
    TPM2B_ECC_PARAMETER *privateKey;       // Pointer to the private key
} ECC_KEY;
#endif    // TPM_ALG_ECC
#ifdef TPM_ALG_RSA
typedef struct {
    UINT32 exponent;              // The public exponent pointer
    TPM2B *publicKey;            // Pointer to the public modulus
    TPM2B *privateKey;           // The private exponent (not a prime)
} RSA_KEY;
#endif    // TPM_ALG_RSA
#ifdef TPM_ALG_RSA
# ifdef TPM_ALG_ECC
# if MAX_RSA_KEY_BYTES > MAX_ECC_KEY_BYTES
# define MAX_NUMBER_SIZE MAX_RSA_KEY_BYTES
# else
# define MAX_NUMBER_SIZE MAX_ECC_KEY_BYTES
# endif
# else      // RSA but no ECC
# define MAX_NUMBER_SIZE MAX_RSA_KEY_BYTES
# endif
#elif defined TPM_ALG_ECC
# define MAX_NUMBER_SIZE MAX_ECC_KEY_BYTES
#else
# error No assymmetric algorithm implemented.
#endif
typedef INT16 CRYPT_RESULT;
#define CRYPT_RESULT_MIN INT16_MIN
#define CRYPT_RESULT_MAX INT16_MAX
#define CRYPT_FAIL ((CRYPT_RESULT) 1)
#define CRYPT_SUCCESS ((CRYPT_RESULT) 0)
#define CRYPT_NO_RESULT ((CRYPT_RESULT) -1)
#define CRYPT_SCHEME ((CRYPT_RESULT) -2)
#define CRYPT_PARAMETER ((CRYPT_RESULT) -3)
#define CRYPT_UNDERFLOW ((CRYPT_RESULT) -4)
#define CRYPT_POINT ((CRYPT_RESULT) -5)
#define CRYPT_CANCEL ((CRYPT_RESULT) -6)
typedef UINT64 HASH_CONTEXT[MAX_HASH_STATE_SIZE/sizeof(UINT64)];
#include "CpriCryptPri_fp.h"
#ifdef TPM_ALG_ECC
# include "CpriDataEcc.h"
# include "CpriECC_fp.h"
#endif
#include "MathFunctions_fp.h"
#include "CpriRNG_fp.h"
#include "CpriHash_fp.h"
#include "CpriSym_fp.h"
#ifdef TPM_ALG_RSA
# include "CpriRSA_fp.h"
#endif
#endif   // !_CRYPT_PRI_H
