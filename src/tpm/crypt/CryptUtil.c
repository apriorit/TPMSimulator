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

// 10.2.1 Includes
#include "TPM_Types.h"
#include "CryptoEngine.h"         // types shared by CryptUtil and CryptoEngine.
// Includes the function prototypes for the
// CryptoEngine functions.
#include "Global.h"
#include "InternalRoutines.h"
#include "MemoryLib_fp.h"
//#include "CryptSelfTest_fp.h"

// M e
// TPM_RC_VALUE CRYPT_FAIL
// TPM_RC_NO_RESULT CRYPT_NO_RESULT
// TPM_RC_SCHEME CRYPT_SCHEME
// TPM_RC_VALUE CRYPT_PARAMETER
// TPM_RC_SIZE CRYPT_UNDERFLOW
// TPM_RC_ECC_POINT CRYPT_POINT
// TPM_RC_CANCELLED CRYPT_CANCEL

static TPM_RC
TranslateCryptErrors (
    CRYPT_RESULT retVal                // IN: crypt error to evaluate
)
{
    switch (retVal)
    {
    case CRYPT_SUCCESS:
        return TPM_RC_SUCCESS;
    case CRYPT_FAIL:
        return TPM_RC_VALUE;
    case CRYPT_NO_RESULT:
        return TPM_RC_NO_RESULT;
    case CRYPT_SCHEME:
        return TPM_RC_SCHEME;
    case CRYPT_PARAMETER:
        return TPM_RC_VALUE;
    case CRYPT_UNDERFLOW:
        return TPM_RC_SIZE;
    case CRYPT_POINT:
        return TPM_RC_ECC_POINT;
    case CRYPT_CANCEL:
        return TPM_RC_CANCELED;
    default:   // Other unknown warnings
        return TPM_RC_FAILURE;
    }
}
#ifdef TPM_ALG_NULL       //%
#ifdef _DRBG_STATE_SAVE        //%
void
CryptDrbgGetPutState(
    GET_PUT direction            // IN: Get from or put to DRBG
)
{
    _cpri__DrbgGetPutState(direction,
                           sizeof(go.drbgState),
                           (BYTE *)&go.drbgState);
}
#else       //% 00
//%#define CryptDrbgGetPutState(ignored)              // If not doing state save, turn this
//%                                                          // into a null macro
#endif      //%
void
CryptStirRandom(
    UINT32 entropySize,         // IN: size of entropy buffer
    BYTE *buffer               // IN: entropy buffer
)
{
    // RNG self testing code may be inserted here

    // Call crypto engine random number stirring function
    _cpri__StirRandom(entropySize, buffer);

    return;
}
UINT16
CryptGenerateRandom(
    UINT16 randomSize,          // IN: size of random number
    BYTE *buffer               // OUT: buffer of random number
)
{
    UINT16 result;
    pAssert(randomSize <= MAX_RSA_KEY_BYTES || randomSize <= PRIMARY_SEED_SIZE);
    if(randomSize == 0)
        return 0;

    // Call crypto engine random number generation
    result = _cpri__GenerateRandom(randomSize, buffer);
    if(result != randomSize)
        FAIL(FATAL_ERROR_INTERNAL);

    return result;
}
#endif    //TPM_ALG_NULL      //%
#ifdef TPM_ALG_KEYEDHASH                     //% 1
TPM_ALG_ID
CryptGetContextAlg(
    void *state                     // IN: the context to check
)
{
    HASH_STATE *context = (HASH_STATE *)state;
    return _cpri__GetContextAlg(&context->state);
}
UINT16
CryptStartHash(
    TPMI_ALG_HASH hashAlg,                // IN: hash algorithm
    HASH_STATE *hashState                 // OUT: the state of hash stack. It will be used
    // in hash update and completion
)
{
    CRYPT_RESULT retVal = 0;

    pAssert(hashState != NULL);

    TEST_HASH(hashAlg);

    hashState->type = HASH_STATE_EMPTY;

    // Call crypto engine start hash function
    if((retVal = _cpri__StartHash(hashAlg, FALSE, &hashState->state)) > 0)
        hashState->type = HASH_STATE_HASH;

    return retVal;
}
UINT16
CryptStartHashSequence(
    TPMI_ALG_HASH hashAlg,                    // IN: hash algorithm
    HASH_STATE *hashState                     // OUT: the state of hash stack. It will be used
    // in hash update and completion
)
{
    CRYPT_RESULT retVal = 0;

    pAssert(hashState != NULL);

    TEST_HASH(hashAlg);

    hashState->type = HASH_STATE_EMPTY;

    // Call crypto engine start hash function
    if((retVal = _cpri__StartHash(hashAlg, TRUE, &hashState->state)) > 0)
        hashState->type = HASH_STATE_HASH;

    return retVal;

}
UINT16
CryptStartHMAC(
    TPMI_ALG_HASH hashAlg,                    // IN: hash algorithm
    UINT16 keySize,                    // IN: the size of HMAC key in byte
    BYTE *key,                          // IN: HMAC key
    HMAC_STATE *hmacState                     // OUT: the state of HMAC stack. It will be used
    // in HMAC update and completion
)
{
    HASH_STATE *hashState = (HASH_STATE *)hmacState;
    CRYPT_RESULT retVal;

    // This has to come before the pAssert in case we all calling this function
    // during testing. If so, the first instance will have no arguments but the
    // hash algorithm. The call from the test routine will have arguments. When
    // the second call is done, then we return to the test dispatcher.
    TEST_HASH(hashAlg);

    pAssert(hashState != NULL);

    hashState->type = HASH_STATE_EMPTY;

    if((retVal = _cpri__StartHMAC(hashAlg, FALSE, &hashState->state, keySize, key,
                                  &hmacState->hmacKey.b)) > 0)
        hashState->type = HASH_STATE_HMAC;

    return retVal;
}
UINT16
CryptStartHMACSequence(
    TPMI_ALG_HASH hashAlg,          // IN: hash algorithm
    UINT16 keySize,          // IN: the size of HMAC key in byte
    BYTE *key,                // IN: HMAC key
    HMAC_STATE *hmacState           // OUT: the state of HMAC stack. It will be used
    // in HMAC update and completion
)
{
    HASH_STATE *hashState = (HASH_STATE *)hmacState;
    CRYPT_RESULT retVal;

    TEST_HASH(hashAlg);

    hashState->type = HASH_STATE_EMPTY;

    if((retVal = _cpri__StartHMAC(hashAlg, TRUE, &hashState->state,
                                  keySize, key, &hmacState->hmacKey.b)) > 0)
        hashState->type = HASH_STATE_HMAC;

    return retVal;
}
LIB_EXPORT UINT16
CryptStartHMAC2B(
    TPMI_ALG_HASH hashAlg,       // IN: hash algorithm
    TPM2B *key,               // IN: HMAC key
    HMAC_STATE *hmacState          // OUT: the state of HMAC stack. It will be used
    // in HMAC update and completion
)
{
    return CryptStartHMAC(hashAlg, key->size, key->buffer, hmacState);
}
UINT16
CryptStartHMACSequence2B(
    TPMI_ALG_HASH hashAlg,       // IN: hash algorithm
    TPM2B *key,               // IN: HMAC key
    HMAC_STATE *hmacState          // OUT: the state of HMAC stack. It will be used
    // in HMAC update and completion
)
{
    return CryptStartHMACSequence(hashAlg, key->size, key->buffer, hmacState);
}
LIB_EXPORT void
CryptUpdateDigest(
    void *digestState,       // IN: the state of hash stack
    UINT32 dataSize,      // IN: the size of data
    BYTE *data               // IN: data to be hashed
)
{
    HASH_STATE *hashState = (HASH_STATE *)digestState;

    pAssert(digestState != NULL);

    if(hashState->type != HASH_STATE_EMPTY && data != NULL && dataSize != 0)
    {
        // Call crypto engine update hash function
        _cpri__UpdateHash(&hashState->state, dataSize, data);
    }
    return;
}
LIB_EXPORT void
CryptUpdateDigest2B(
    void *digestState,             // IN: the digest state
    TPM2B *bIn                      // IN: 2B containing the data
)
{
    // Only compute the digest if a pointer to the 2B is provided.
    // In CryptUpdateDigest(), if size is zero or buffer is NULL, then no change
    // to the digest occurs. This function should not provide a buffer if bIn is
    // not provided.
    if(bIn != NULL)
        CryptUpdateDigest(digestState, bIn->size, bIn->buffer);
    return;
}
LIB_EXPORT void
CryptUpdateDigestInt(
    void *state,                   // IN: the state of hash stack
    UINT32 intSize,                 // IN: the size of 'intValue' in byte
    void *intValue                 // IN: integer value to be hashed
)
{

#if BIG_ENDIAN_TPM == YES
    pAssert( intValue != NULL && (intSize == 1 || intSize == 2
                                  || intSize == 4 || intSize == 8));
    CryptUpdateHash(state, inSize, (BYTE *)intValue);
#else

    BYTE marshalBuffer[8];
    // Point to the big end of an little-endian value
    BYTE *p = &((BYTE *)intValue)[intSize - 1];
    // Point to the big end of an big-endian value
    BYTE *q = marshalBuffer;

    pAssert(intValue != NULL);
    switch (intSize)
    {
    case 8:
        *q++ = *p--;
        *q++ = *p--;
        *q++ = *p--;
        *q++ = *p--;
    case 4:
        *q++ = *p--;
        *q++ = *p--;
    case 2:
        *q++ = *p--;
    case 1:
        *q = *p;
        // Call update the hash
        CryptUpdateDigest(state, intSize, marshalBuffer);
        break;
    default:
        FAIL(0);
    }

#endif
    return;
}
LIB_EXPORT UINT16
CryptCompleteHash(
    void *state,                 // IN: the state of hash stack
    UINT16 digestSize,          // IN: size of digest buffer
    BYTE *digest                 // OUT: hash digest
)
{
    HASH_STATE *hashState = (HASH_STATE *)state;              // local value

    // If the session type is HMAC, then could forward this to
    // the HMAC processing and not cause an error. However, if no
    // function calls this routine to forward it, then we can't get
    // test coverage. The decision is to assert if this is called with
    // the type == HMAC and fix anything that makes the wrong call.
    pAssert(hashState->type == HASH_STATE_HASH);

    // Set the state to empty so that it doesn't get used again
    hashState->type = HASH_STATE_EMPTY;

    // Call crypto engine complete hash function
    return _cpri__CompleteHash(&hashState->state, digestSize, digest);
}
LIB_EXPORT UINT16
CryptCompleteHash2B(
    void *state,                    // IN: the state of hash stack
    TPM2B *digest                    // IN: the size of the buffer Out: requested
    // number of byte
)
{
    UINT16 retVal = 0;

    if(digest != NULL)
        retVal = CryptCompleteHash(state, digest->size, digest->buffer);

    return retVal;
}
LIB_EXPORT UINT16
CryptHashBlock(
    TPM_ALG_ID algId,                    // IN: the hash algorithm to use
    UINT16 blockSize,                // IN: size of the data block
    BYTE *block,                    // IN: address of the block to hash
    UINT16 retSize,                  // IN: size of the return buffer
    BYTE *ret                       // OUT: address of the buffer
)
{
    TEST_HASH(algId);

    return _cpri__HashBlock(algId, blockSize, block, retSize, ret);
}
LIB_EXPORT UINT16
CryptCompleteHMAC(
    HMAC_STATE *hmacState,                // IN: the state of HMAC stack
    UINT32 digestSize,               // IN: size of digest buffer
    BYTE *digest                    // OUT: HMAC digest
)
{
    HASH_STATE *hashState;

    pAssert(hmacState != NULL);
    hashState = &hmacState->hashState;

    pAssert(hashState->type == HASH_STATE_HMAC);

    hashState->type = HASH_STATE_EMPTY;

    return _cpri__CompleteHMAC(&hashState->state, &hmacState->hmacKey.b,
                               digestSize, digest);

}
LIB_EXPORT UINT16
CryptCompleteHMAC2B(
    HMAC_STATE *hmacState,           // IN: the state of HMAC stack
    TPM2B *digest               // OUT: HMAC
)
{
    UINT16 retVal = 0;
    if(digest != NULL)
        retVal = CryptCompleteHMAC(hmacState, digest->size, digest->buffer);
    return retVal;
}
void
CryptHashStateImportExport(
    HASH_STATE *internalFmt,         // IN: state to LIB_EXPORT
    HASH_STATE *externalFmt,         // OUT: exported state
    IMPORT_EXPORT direction
)
{
    _cpri__ImportExportHashState(&internalFmt->state,
                                 (EXPORT_HASH_STATE *)&externalFmt->state,
                                 direction);
}
LIB_EXPORT UINT16
CryptGetHashDigestSize(
    TPM_ALG_ID hashAlg            // IN: hash algorithm
)
{
    return _cpri__GetDigestSize(hashAlg);
}
LIB_EXPORT UINT16
CryptGetHashBlockSize(
    TPM_ALG_ID hash               // IN: hash algorithm to look up
)
{
    return _cpri__GetHashBlockSize(hash);
}
LIB_EXPORT TPM_ALG_ID
CryptGetHashAlgByIndex(
    UINT32 index              // IN: the index
)
{
    return _cpri__GetHashAlgByIndex(index);
}

// E r
// M e

static TPM_RC
CryptSignHMAC(
    OBJECT *signKey,                // IN: HMAC key sign the hash
    TPMT_SIG_SCHEME *scheme,                 // IN: signing scheme
    TPM2B_DIGEST *hashData,               // IN: hash to be signed
    TPMT_SIGNATURE *signature               // OUT: signature
)
{
    HMAC_STATE hmacState;
    UINT32 digestSize;

    // HMAC algorithm self testing code may be inserted here

    digestSize = CryptStartHMAC2B(scheme->details.hmac.hashAlg,
                                  &signKey->sensitive.sensitive.bits.b,
                                  &hmacState);

    // The hash algorithm must be a valid one.
    pAssert(digestSize > 0);

    CryptUpdateDigest2B(&hmacState, &hashData->b);

    CryptCompleteHMAC(&hmacState, digestSize,
                      (BYTE *) &signature->signature.hmac.digest);

    // Set HMAC algorithm
    signature->signature.hmac.hashAlg = scheme->details.hmac.hashAlg;

    return TPM_RC_SUCCESS;
}

// E r
// M e
// TPM_RC_SIGNATURE

static TPM_RC
CryptHMACVerifySignature(
    OBJECT *signKey,                    // IN: HMAC key signed the hash
    TPM2B_DIGEST *hashData,                   // IN: digest being verified
    TPMT_SIGNATURE *signature                   // IN: signature to be verified
)
{
    HMAC_STATE hmacState;
    TPM2B_DIGEST digestToCompare;

    digestToCompare.t.size = CryptStartHMAC2B(signature->signature.hmac.hashAlg,
                             &signKey->sensitive.sensitive.bits.b, &hmacState);

    CryptUpdateDigest2B(&hmacState, &hashData->b);

    CryptCompleteHMAC2B(&hmacState, &digestToCompare.b);

    // Compare digest
    if(MemoryEqual(digestToCompare.t.buffer,
                   (BYTE *) &signature->signature.hmac.digest,
                   digestToCompare.t.size))
        return TPM_RC_SUCCESS;
    else
        return TPM_RC_SIGNATURE;

}

// E r
// M e
// TPM_RC_SIZE

static TPM_RC
CryptGenerateKeyedHash(
    TPMT_PUBLIC *publicArea,                     // IN/OUT: the public area template
    // for the new key.
    TPMS_SENSITIVE_CREATE *sensitiveCreate,                // IN: sensitive creation data
    TPMT_SENSITIVE *sensitive,                      // OUT: sensitive area
    TPM_ALG_ID kdfHashAlg,                  // IN: algorithm for the KDF
    TPM2B_SEED *seed,                           // IN: the seed
    TPM2B_NAME *name                            // IN: name of the object
)
{
    TPMT_KEYEDHASH_SCHEME *scheme;
    TPM_ALG_ID hashAlg;
    UINT16 hashBlockSize;

    scheme = &publicArea->parameters.keyedHashDetail.scheme;

    pAssert(publicArea->type == TPM_ALG_KEYEDHASH);

    // Pick the limiting hash algorithm
    if(scheme->scheme == TPM_ALG_NULL)
        hashAlg = publicArea->nameAlg;
    else if(scheme->scheme == TPM_ALG_XOR)
        hashAlg = scheme->details.xor.hashAlg;
    else
        hashAlg = scheme->details.hmac.hashAlg;
    hashBlockSize = CryptGetHashBlockSize(hashAlg);

    // if this is a signing or a decryption key, then then the limit
    // for the data size is the block size of the hash. This limit
    // is set because larger values have lower entropy because of the
    // HMAC function.
    if(publicArea->objectAttributes.sensitiveDataOrigin == CLEAR)
    {
        if( ( publicArea->objectAttributes.decrypt
                || publicArea->objectAttributes.sign)
                && sensitiveCreate->data.t.size > hashBlockSize)

            return TPM_RC_SIZE;
    }
    else
    {
        // If the TPM is going to generate the data, then set the size to be the
        // size of the digest of the algorithm
        sensitive->sensitive.sym.t.size = CryptGetHashDigestSize(hashAlg);
        sensitiveCreate->data.t.size = 0;
    }

    // Fill in the sensitive area
    CryptGenerateNewSymmetric(sensitiveCreate, sensitive, kdfHashAlg,
                              seed, name);

    // Create unique area in public
    CryptComputeSymmetricUnique(publicArea->nameAlg,
                                sensitive, &publicArea->unique.sym);

    return TPM_RC_SUCCESS;
}
//%#define CryptKDFa(hashAlg, key, label, contextU, contextV, \
//% sizeInBits, keyStream, counterInOut) \
//% TEST_HASH(hashAlg); \
//% _cpri__KDFa( \
//% ((TPM_ALG_ID)hashAlg), \
//% ((TPM2B *)key), \
//% ((const char *)label), \
//% ((TPM2B *)contextU), \
//% ((TPM2B *)contextV), \
//% ((UINT32)sizeInBits), \
//% ((BYTE *)keyStream), \
//% ((UINT32 *)counterInOut), \
//% ((BOOL) FALSE) \
//% )
//%
//%#define CryptKDFaOnce(hashAlg, key, label, contextU, contextV, \
//% sizeInBits, keyStream, counterInOut) \
//% TEST_HASH(hashAlg); \
//% _cpri__KDFa( \
//% ((TPM_ALG_ID)hashAlg), \
//% ((TPM2B *)key), \
//% ((const char *)label), \
//% ((TPM2B *)contextU), \
//% ((TPM2B *)contextV), \
//% ((UINT32)sizeInBits), \
//% ((BYTE *)keyStream), \
//% ((UINT32 *)counterInOut), \
//% ((BOOL) TRUE) \
//% )
//%
void
KDFa(
    TPM_ALG_ID hash,                  // IN: hash algorithm used in HMAC
    TPM2B *key,                  // IN: HMAC key
    const char *label,                // IN: a null-terminated label for KDF
    TPM2B *contextU,             // IN: context U
    TPM2B *contextV,             // IN: context V
    UINT32 sizeInBits,            // IN: size of generated key in bit
    BYTE *keyStream,            // OUT: key buffer
    UINT32 *counterInOut          // IN/OUT: caller may provide the iteration
    // counter for incremental operations to
    // avoid large intermediate buffers.
)
{
    CryptKDFa(hash, key, label, contextU, contextV, sizeInBits,
              keyStream, counterInOut);
}
//%#define CryptKDFe(hashAlg, Z, label, partyUInfo, partyVInfo, \
//% sizeInBits, keyStream) \
//% TEST_HASH(hashAlg); \
//% _cpri__KDFe( \
//% ((TPM_ALG_ID)hashAlg), \
//% ((TPM2B *)Z), \
//% ((const char *)label), \
//% ((TPM2B *)partyUInfo), \
//% ((TPM2B *)partyVInfo), \
//% ((UINT32)sizeInBits), \
//% ((BYTE *)keyStream) \
//% )
//%
#endif    //TPM_ALG_KEYEDHASH             //% 1
#ifdef TPM_ALG_RSA                    //% 2
static void
BuildRSA(
    OBJECT *rsaKey,
    RSA_KEY *key
)
{
    key->exponent = rsaKey->publicArea.parameters.rsaDetail.exponent;
    if(key->exponent == 0)
        key->exponent = RSA_DEFAULT_PUBLIC_EXPONENT;
    key->publicKey = &rsaKey->publicArea.unique.rsa.b;

    if(rsaKey->attributes.publicOnly || rsaKey->privateExponent.t.size == 0)
        key->privateKey = NULL;
    else
        key->privateKey = &(rsaKey->privateExponent.b);
}

// E r
// M e
// TPM_RC_BINDING

TPM_RC
CryptTestKeyRSA(
    TPM2B *d,                       // OUT: receives the private exponent
    UINT32 e,                  // IN: public exponent
    TPM2B *n,                       // IN/OUT: public modulu
    TPM2B *p,                       // IN: a first prime
    TPM2B *q                        // IN: an optional second prime
)
{
    CRYPT_RESULT retVal;

    TEST(ALG_NULL_VALUE);

    pAssert(d != NULL && n != NULL && p != NULL);
    // Set the exponent
    if(e == 0)
        e = RSA_DEFAULT_PUBLIC_EXPONENT;
    // CRYPT_PARAMETER
    retVal =_cpri__TestKeyRSA(d, e, n, p, q);
    if(retVal == CRYPT_SUCCESS)
        return TPM_RC_SUCCESS;
    else
        return TPM_RC_BINDING;         // convert CRYPT_PARAMETER
}

// E r
// M e
// TPM_RC_RANGE
// TPM_RC_CANCELLED
// TPM_RC_VALUE


static TPM_RC
CryptGenerateKeyRSA(
    TPMT_PUBLIC *publicArea,                    // IN/OUT: The public area template for
    // the new key. The public key
    // area will be replaced by the
    // product of two primes found by
    // this function
    TPMT_SENSITIVE *sensitive,                     // OUT: the sensitive area will be
    // updated to contain the first
    // prime and the symmetric
    // encryption key
    TPM_ALG_ID hashAlg,                        // IN: the hash algorithm for the KDF
    TPM2B_SEED *seed,                          // IN: Seed for the creation
    TPM2B_NAME *name,                          // IN: Object name
    UINT32 *counter                        // OUT: last iteration of the counter
)
{
    CRYPT_RESULT retVal;
    UINT32 exponent = publicArea->parameters.rsaDetail.exponent;

    TEST_HASH(hashAlg);
    TEST(ALG_NULL_VALUE);

    // In this implementation, only the default exponent is allowed
    if(exponent != 0 && exponent != RSA_DEFAULT_PUBLIC_EXPONENT)
        return TPM_RC_RANGE;
    exponent = RSA_DEFAULT_PUBLIC_EXPONENT;

    *counter = 0;

    // _cpri_GenerateKeyRSA can return CRYPT_CANCEL or CRYPT_FAIL
    retVal = _cpri__GenerateKeyRSA(&publicArea->unique.rsa.b,
                                   &sensitive->sensitive.rsa.b,
                                   publicArea->parameters.rsaDetail.keyBits,
                                   exponent,
                                   hashAlg,
                                   &seed->b,
                                   "RSA key by vendor",
                                   &name->b,
                                   counter);

    // CRYPT_CANCEL -> TPM_RC_CANCELLED; CRYPT_FAIL -> TPM_RC_VALUE
    return TranslateCryptErrors(retVal);

}

// E r
// M e
// TPM_RC_BINDING

TPM_RC
CryptLoadPrivateRSA(
    OBJECT *rsaKey                 // IN: the RSA key object
)
{
    TPM_RC result;
    TPMT_PUBLIC *publicArea = &rsaKey->publicArea;
    TPMT_SENSITIVE *sensitive = &rsaKey->sensitive;

    // Load key by computing the private exponent
    // TPM_RC_BINDING
    result = CryptTestKeyRSA(&(rsaKey->privateExponent.b),
                             publicArea->parameters.rsaDetail.exponent,
                             &(publicArea->unique.rsa.b),
                             &(sensitive->sensitive.rsa.b),
                             NULL);
    if(result == TPM_RC_SUCCESS)
        rsaKey->attributes.privateExp = SET;

    return result;
}
TPMT_RSA_DECRYPT*
CryptSelectRSAScheme(
    TPMI_DH_OBJECT rsaHandle,               // IN: handle of sign key
    TPMT_RSA_DECRYPT *scheme                  // IN: a sign or decrypt scheme
)
{
    OBJECT *rsaObject;
    TPMT_ASYM_SCHEME *keyScheme;
    TPMT_RSA_DECRYPT *retVal = NULL;

    // Get sign object pointer
    rsaObject = ObjectGet(rsaHandle);
    keyScheme = &rsaObject->publicArea.parameters.asymDetail.scheme;

    // if the default scheme of the object is TPM_ALG_NULL, then select the
    // input scheme
    if(keyScheme->scheme == TPM_ALG_NULL)
    {
        retVal = scheme;
    }
    // if the object scheme is not TPM_ALG_NULL and the input scheme is
    // TPM_ALG_NULL, then select the default scheme of the object.
    else if(scheme->scheme == TPM_ALG_NULL)
    {
        // if input scheme is NULL
        retVal = (TPMT_RSA_DECRYPT *)keyScheme;
    }
    // get here if both the object scheme and the input scheme are
    // not TPM_ALG_NULL. Need to insure that they are the same.
    // IMPLEMENTATION NOTE: This could cause problems if future versions have
    // schemes that have more values than just a hash algorithm. A new function
    // (IsSchemeSame()) might be needed then.
    else if( keyScheme->scheme == scheme->scheme
             && keyScheme->details.anySig.hashAlg == scheme->details.anySig.hashAlg)
    {
        retVal = scheme;
    }
    // two different, incompatible schemes specified will return NULL
    return retVal;
}

// E r
// M e
// TPM_RC_BINDING
// TPM_RC_SIZE
// TPM_RC_VALUE


TPM_RC
CryptDecryptRSA(
    UINT16 *dataOutSize,            // OUT: size of plain text in byte
    BYTE *dataOut,                       // OUT: plain text
    OBJECT *rsaKey,                        // IN: internal RSA key
    TPMT_RSA_DECRYPT *scheme,                        // IN: selects the padding scheme
    UINT16 cipherInSize,                // IN: size of cipher text in byte
    BYTE *cipherIn,                      // IN: cipher text
    const char *label                          // IN: a label, when needed
)
{
    RSA_KEY key;
    CRYPT_RESULT retVal = CRYPT_SUCCESS;
    UINT32 dSize;                                        // Place to put temporary value for the
    // returned data size
    TPMI_ALG_HASH hashAlg = TPM_ALG_NULL;              // hash algorithm in the selected
    // padding scheme
    TPM_RC result = TPM_RC_SUCCESS;

    // pointer checks
    pAssert( (dataOutSize != NULL) && (dataOut != NULL)
             && (rsaKey != NULL) && (cipherIn != NULL));

    // The public type is a RSA decrypt key
    pAssert( (rsaKey->publicArea.type == TPM_ALG_RSA
              && rsaKey->publicArea.objectAttributes.decrypt == SET));

    // Must have the private portion loaded. This check is made before this
    // function is called.
    pAssert(rsaKey->attributes.publicOnly == CLEAR);

    // decryption requires that the private modulus be present
    if(rsaKey->attributes.privateExp == CLEAR)
    {

        // Load key by computing the private exponent
        // CryptLoadPrivateRSA may return TPM_RC_BINDING
        result = CryptLoadPrivateRSA(rsaKey);
    }

    // the input buffer must be the size of the key
    if(result == TPM_RC_SUCCESS)
    {
        if(cipherInSize != rsaKey->publicArea.unique.rsa.t.size)
            result = TPM_RC_SIZE;
        else
        {
            BuildRSA(rsaKey, &key);

            // Initialize the dOutSize parameter
            dSize = *dataOutSize;

            // For OAEP scheme, initialize the hash algorithm for padding
            if(scheme->scheme == TPM_ALG_OAEP)
            {
                hashAlg = scheme->details.oaep.hashAlg;
                TEST_HASH(hashAlg);
            }
            // See if the padding mode needs to be tested
            TEST(scheme->scheme);

            // _cpri__DecryptRSA may return CRYPT_PARAMETER CRYPT_FAIL CRYPT_SCHEME
            retVal = _cpri__DecryptRSA(&dSize, dataOut, &key, scheme->scheme,
                                       cipherInSize, cipherIn, hashAlg, label);

            // Scheme must have been validated when the key was loaded/imported
            pAssert(retVal != CRYPT_SCHEME);

            // Set the return size
            pAssert(dSize <= UINT16_MAX);
            *dataOutSize = (UINT16)dSize;

            // CRYPT_PARAMETER -> TPM_RC_VALUE, CRYPT_FAIL -> TPM_RC_VALUE
            result = TranslateCryptErrors(retVal);
        }
    }
    return result;
}

// E r
// M e
// TPM_RC_SCHEME
// TPM_RC_VALUE

TPM_RC
CryptEncryptRSA(
    UINT16 *cipherOutSize,              // OUT: size of cipher text in byte
    BYTE *cipherOut,                  // OUT: cipher text
    OBJECT *rsaKey,                     // IN: internal RSA key
    TPMT_RSA_DECRYPT *scheme,                     // IN: selects the padding scheme
    UINT16 dataInSize,                // IN: size of plain text in byte
    BYTE *dataIn,                     // IN: plain text
    const char *label                       // IN: an optional label
)
{
    RSA_KEY key;
    CRYPT_RESULT retVal;
    UINT32 cOutSize;                                      // Conversion variable
    TPMI_ALG_HASH hashAlg = TPM_ALG_NULL;            // hash algorithm in selected
    // padding scheme

    // must have a pointer to a key and some data to encrypt
    pAssert(rsaKey != NULL && dataIn != NULL);

    // The public type is a RSA decryption key
    pAssert( rsaKey->publicArea.type == TPM_ALG_RSA
             && rsaKey->publicArea.objectAttributes.decrypt == SET);

    // If the cipher buffer must be provided and it must be large enough
    // for the result
    pAssert( cipherOut != NULL
             && cipherOutSize != NULL
             && *cipherOutSize >= rsaKey->publicArea.unique.rsa.t.size);

    // Only need the public key and exponent for encryption
    BuildRSA(rsaKey, &key);

    // Copy the size to the conversion buffer
    cOutSize = *cipherOutSize;

    // For OAEP scheme, initialize the hash algorithm for padding
    if(scheme->scheme == TPM_ALG_OAEP)
    {
        hashAlg = scheme->details.oaep.hashAlg;
        TEST_HASH(hashAlg);
    }

    // This is a public key operation and does not require that the private key
    // be loaded. To verify this, need to do the full algorithm
    TEST(scheme->scheme);

    // Encrypt the data with the public exponent
    // _cpri__EncryptRSA may return CRYPT_PARAMETER or CRYPT_SCHEME
    retVal = _cpri__EncryptRSA(&cOutSize,cipherOut, &key, scheme->scheme,
                               dataInSize, dataIn, hashAlg, label);

    pAssert (cOutSize <= UINT16_MAX);
    *cipherOutSize = (UINT16)cOutSize;
    // CRYPT_PARAMETER -> TPM_RC_VALUE, CRYPT_SCHEME -> TPM_RC_SCHEME
    return TranslateCryptErrors(retVal);
}

// E r
// M e
// TPM_RC_BINDING
// TPM_RC_SCHEME
// TPM_RC_VALUE


static TPM_RC
CryptSignRSA(
    OBJECT *signKey,                 // IN: RSA key signs the hash
    TPMT_SIG_SCHEME *scheme,                  // IN: sign scheme
    TPM2B_DIGEST *hashData,                // IN: hash to be signed
    TPMT_SIGNATURE *sig                      // OUT: signature
)
{
    UINT32 signSize;
    RSA_KEY key;
    CRYPT_RESULT retVal;
    TPM_RC result = TPM_RC_SUCCESS;

    pAssert( (signKey != NULL) && (scheme != NULL)
             && (hashData != NULL) && (sig != NULL));

    // assume that the key has private part loaded and that it is a signing key.
    pAssert( (signKey->attributes.publicOnly == CLEAR)
             && (signKey->publicArea.objectAttributes.sign == SET));

    // check if the private exponent has been computed
    if(signKey->attributes.privateExp == CLEAR)
        // May return TPM_RC_BINDING
        result = CryptLoadPrivateRSA(signKey);

    if(result == TPM_RC_SUCCESS)
    {
        BuildRSA(signKey, &key);

        // Make sure that the hash is tested
        TEST_HASH(sig->signature.any.hashAlg);

        // Run a test of the RSA sign
        TEST(scheme->scheme);

        // _crypi__SignRSA can return CRYPT_SCHEME and CRYPT_PARAMETER
        retVal = _cpri__SignRSA(&signSize,
                                sig->signature.rsassa.sig.t.buffer,
                                &key,
                                sig->sigAlg,
                                sig->signature.any.hashAlg,
                                hashData->t.size, hashData->t.buffer);
        pAssert(signSize <= UINT16_MAX);
        sig->signature.rsassa.sig.t.size = (UINT16)signSize;

        // CRYPT_SCHEME -> TPM_RC_SCHEME; CRYPT_PARAMTER -> TPM_RC_VALUE
        result = TranslateCryptErrors(retVal);
    }
    return result;
}

// E r
// M e
// TPM_RC_SIGNATURE
// TPM_RC_SCHEME

static TPM_RC
CryptRSAVerifySignature(
    OBJECT *signKey,                 // IN: RSA key signed the hash
    TPM2B_DIGEST *digestData,              // IN: digest being signed
    TPMT_SIGNATURE *sig                      // IN: signature to be verified
)
{
    RSA_KEY key;
    CRYPT_RESULT retVal;
    TPM_RC result;

    // Validate parameter assumptions
    pAssert((signKey != NULL) && (digestData != NULL) && (sig != NULL));

    TEST_HASH(sig->signature.any.hashAlg);
    TEST(sig->sigAlg);

    // This is a public-key-only operation
    BuildRSA(signKey, &key);

    // Call crypto engine to verify signature
    // _cpri_ValidateSignaturRSA may return CRYPT_FAIL or CRYPT_SCHEME
    retVal = _cpri__ValidateSignatureRSA(&key,
                                         sig->sigAlg,
                                         sig->signature.any.hashAlg,
                                         digestData->t.size,
                                         digestData->t.buffer,
                                         sig->signature.rsassa.sig.t.size,
                                         sig->signature.rsassa.sig.t.buffer,
                                         0);
    // _cpri__ValidateSignatureRSA can return CRYPT_SUCCESS, CRYPT_FAIL, or
    // CRYPT_SCHEME. Translate CRYPT_FAIL to TPM_RC_SIGNATURE
    if(retVal == CRYPT_FAIL)
        result = TPM_RC_SIGNATURE;
    else
        // CRYPT_SCHEME -> TPM_RC_SCHEME
        result = TranslateCryptErrors(retVal);

    return result;
}
#endif    //TPM_ALG_RSA                 //% 2
#ifdef TPM_ALG_ECC    //% 3
static const ECC_CURVE *
CryptEccGetCurveDataPointer(
    TPM_ECC_CURVE curveID                       // IN: id of the curve
)
{
    return _cpri__EccGetParametersByCurveId(curveID);
}
UINT16
CryptEccGetKeySizeInBits(
    TPM_ECC_CURVE curveID                       // IN: id of the curve
)
{
    const ECC_CURVE *curve = CryptEccGetCurveDataPointer(curveID);
    UINT16 keySizeInBits = 0;

    if(curve != NULL)
        keySizeInBits = curve->keySizeBits;

    return keySizeInBits;
}
// The next lines will be placed in CyrptUtil_fp.h with the  //% removed
//% #define CryptEccGetKeySizeInBytes(curve) \
//% ((CryptEccGetKeySizeInBits(curve)+7)/8)
LIB_EXPORT const TPM2B *
CryptEccGetParameter(
    char p,                            // IN: the parameter selector
    TPM_ECC_CURVE curveId                       // IN: the curve id
)
{
    const ECC_CURVE *curve = _cpri__EccGetParametersByCurveId(curveId);
    const TPM2B *parameter = NULL;

    if(curve != NULL)
    {
        switch (p)
        {
        case 'p':
            parameter = curve->curveData->p;
            break;
        case 'n':
            parameter = curve->curveData->n;
            break;
        case 'a':
            parameter = curve->curveData->a;
            break;
        case 'b':
            parameter = curve->curveData->b;
            break;
        case 'x':
            parameter = curve->curveData->x;
            break;
        case 'y':
            parameter = curve->curveData->y;
            break;
        case 'h':
            parameter = curve->curveData->h;
            break;
        default:
            break;
        }
    }
    return parameter;
}
const TPMT_ECC_SCHEME *
CryptGetCurveSignScheme(
    TPM_ECC_CURVE curveId              // IN: The curve selector
)
{
    const ECC_CURVE *curve = _cpri__EccGetParametersByCurveId(curveId);
    const TPMT_ECC_SCHEME *scheme = NULL;

    if(curve != NULL)
        scheme = &(curve->sign);
    return scheme;
}
BOOL
CryptEccIsPointOnCurve(
    TPM_ECC_CURVE curveID,             // IN: ECC curve ID
    TPMS_ECC_POINT *Q                        // IN: ECC point
)
{
    // Make sure that point multiply is working
    TEST(TPM_ALG_ECC);
    // Check point on curve logic by seeing if the test key is on the curve

    // Call crypto engine function to check if a ECC public point is on the
    // given curve
    if(_cpri__EccIsPointOnCurve(curveID, Q))
        return TRUE;
    else
        return FALSE;
}
TPM_RC
CryptNewEccKey(
    TPM_ECC_CURVE curveID,               // IN: ECC curve
    TPMS_ECC_POINT *publicPoint,             // OUT: public point
    TPM2B_ECC_PARAMETER *sensitive                // OUT: private area
)
{
    TPM_RC result = TPM_RC_SUCCESS;
    // _cpri__GetEphemeralECC may return CRYPT_PARAMETER
    if(_cpri__GetEphemeralEcc(publicPoint, sensitive, curveID) != CRYPT_SUCCESS)
        // Something is wrong with the key.
        result = TPM_RC_KEY;

    return result;
}

// E r
// M e
// TPM_RC_ECC_POINT
// TPM_RC_NO_RESULT
// TPM_RC_CANCELED

TPM_RC
CryptEccPointMultiply(
    TPMS_ECC_POINT *pOut,                    // OUT: output point
    TPM_ECC_CURVE curveId,               // IN: curve selector
    TPM2B_ECC_PARAMETER *dIn,                     // IN: public scalar
    TPMS_ECC_POINT *pIn                      // IN: optional point
)
{
    TPM2B_ECC_PARAMETER *n = NULL;
    CRYPT_RESULT retVal;

    pAssert(pOut != NULL && dIn != NULL);

    if(pIn != NULL)
    {
        n = dIn;
        dIn = NULL;
    }
    // Do a test of point multiply
    TEST(TPM_ALG_ECC);

    // _cpri__EccPointMultiply may return CRYPT_POINT or CRYPT_NO_RESULT
    retVal = _cpri__EccPointMultiply(pOut, curveId, dIn, pIn, n);

    // CRYPT_POINT->TPM_RC_ECC_POINT and CRYPT_NO_RESULT->TPM_RC_NO_RESULT
    return TranslateCryptErrors(retVal);
}

// E r
// M e
// TPM_RC_VALUE

static TPM_RC
CryptGenerateKeyECC(
    TPMT_PUBLIC *publicArea,             // IN/OUT: The public area template for the new
    // key.
    TPMT_SENSITIVE *sensitive,              // IN/OUT: the sensitive area
    TPM_ALG_ID hashAlg,                 // IN: algorithm for the KDF
    TPM2B_SEED *seed,                   // IN: the seed value
    TPM2B_NAME *name,                   // IN: the name of the object
    UINT32 *counter                 // OUT: the iteration counter
)
{
    CRYPT_RESULT retVal;

    TEST_HASH(hashAlg);
    TEST(ALG_ECDSA_VALUE);             // ECDSA is used to verify each key

    // The iteration counter has no meaning for ECC key generation. The parameter
    // will be overloaded for those implementations that have a requirement for
    // doing pair-wise consistency checks on signing keys. If the counter parameter
    // is 0 or NULL, then no consistency check is done. If it is other than 0, then
    // a consistency check is run. This modification allow this code to work with
    // the existing versions of the CrytpoEngine and with FIPS-compliant versions
    // as well.
    *counter = (UINT32)(publicArea->objectAttributes.sign == SET);

    // _cpri__GenerateKeyEcc only has one error return (CRYPT_PARAMETER) which means
    // that the hash algorithm is not supported. This should not be possible
    retVal = _cpri__GenerateKeyEcc(&publicArea->unique.ecc,
                                   &sensitive->sensitive.ecc,
                                   publicArea->parameters.eccDetail.curveID,
                                   hashAlg, &seed->b, "ECC key by vendor",
                                   &name->b, counter);
    // This will only be useful if _cpri__GenerateKeyEcc return CRYPT_CANCEL
    return TranslateCryptErrors(retVal);
}

// E r
// M e
// TPM_RC_SCHEME
// TPM_RC_VALUE


static TPM_RC
CryptSignECC(
    OBJECT *signKey,              // IN: ECC key to sign the hash
    TPMT_SIG_SCHEME *scheme,               // IN: sign scheme
    TPM2B_DIGEST *hashData,             // IN: hash to be signed
    TPMT_SIGNATURE *signature             // OUT: signature
)
{
    TPM2B_ECC_PARAMETER r;
    TPM2B_ECC_PARAMETER *pr = NULL;
    CRYPT_RESULT retVal;

    // Run a test of the ECC sign and verify if it has not already been run
    TEST_HASH(scheme->details.any.hashAlg);
    TEST(scheme->scheme);

    if(CryptIsSplitSign(scheme->scheme))
    {
        // When this code was written, the only split scheme was ECDAA
        // (which can also be used for U-Prove).
        if(!CryptGenerateR(&r,
                           &scheme->details.ecdaa.count,
                           signKey->publicArea.parameters.eccDetail.curveID,
                           &signKey->name))
            return TPM_RC_VALUE;
        pr = &r;
    }
    // Call crypto engine function to sign
    // _cpri__SignEcc may return CRYPT_SCHEME
    retVal = _cpri__SignEcc(&signature->signature.ecdsa.signatureR,
                            &signature->signature.ecdsa.signatureS,
                            scheme->scheme,
                            scheme->details.any.hashAlg,
                            signKey->publicArea.parameters.eccDetail.curveID,
                            &signKey->sensitive.sensitive.ecc,
                            &hashData->b,
                            pr
                           );
    if(CryptIsSplitSign(scheme->scheme) && retVal == CRYPT_SUCCESS)
        CryptEndCommit(scheme->details.ecdaa.count);
    // CRYPT_SCHEME->TPM_RC_SCHEME
    return TranslateCryptErrors(retVal);
}

// E r
// M e
// TPM_RC_SIGNATURE
// TPM_RC_SCHEME

static TPM_RC
CryptECCVerifySignature(
    OBJECT *signKey,             // IN: ECC key signed the hash
    TPM2B_DIGEST *digestData,                 // IN: digest being signed
    TPMT_SIGNATURE *signature                   // IN: signature to be verified
)
{
    CRYPT_RESULT retVal;

    TEST_HASH(signature->signature.any.hashAlg);
    TEST(signature->sigAlg);

    // This implementation uses the fact that all the defined ECC signing
    // schemes have the hash as the first parameter.
    // _cpriValidateSignatureEcc may return CRYPT_FAIL or CRYP_SCHEME
    retVal = _cpri__ValidateSignatureEcc(&signature->signature.ecdsa.signatureR,
                                         &signature->signature.ecdsa.signatureS,
                                         signature->sigAlg,
                                         signature->signature.any.hashAlg,
                                         signKey->publicArea.parameters.eccDetail.curveID,
                                         &signKey->publicArea.unique.ecc,
                                         &digestData->b);
    if(retVal == CRYPT_FAIL)
        return TPM_RC_SIGNATURE;
    // CRYPT_SCHEME->TPM_RC_SCHEME
    return TranslateCryptErrors(retVal);
}
BOOL
CryptGenerateR(
    TPM2B_ECC_PARAMETER *r,                        // OUT: the generated random value
    UINT16 *c,                        // IN/OUT: count value.
    TPMI_ECC_CURVE curveID,                  // IN: the curve for the value
    TPM2B_NAME *name                      // IN: optional name of a key to
    // associate with 'r'
)
{
    // This holds the marshaled g_commitCounter.
    TPM2B_TYPE(8B, 8);
    TPM2B_8B cntr = {8,{0}};

    UINT32 iterations;
    const TPM2B *n;
    UINT64 currentCount = gr.commitCounter;
    // This is just to suppress a compiler warning about a conditional expression
    // being a constant. This is because of the macro expansion of ryptKDFa
    TPMI_ALG_HASH hashAlg = CONTEXT_INTEGRITY_HASH_ALG;

    n = CryptEccGetParameter('n', curveID);
    pAssert(r != NULL && n != NULL);

    // If this is the commit phase, use the current value of the commit counter
    if(c != NULL)
    {

        UINT16 t1;
        // if the array bit is not set, can't use the value.
        if(!BitIsSet((*c & COMMIT_INDEX_MASK), gr.commitArray,
                     sizeof(gr.commitArray)))
            return FALSE;

        // If it is the sign phase, figure out what the counter value was
        // when the commitment was made.
        //
        // When gr.commitArray has less than 64K bits, the extra
        // bits of 'c' are used as a check to make sure that the
        // signing operation is not using an out of range count value
        t1 = (UINT16)currentCount;

        // If the lower bits of c are greater or equal to the lower bits of t1
        // then the upper bits of t1 must be one more than the upper bits
        // of c
        if((*c & COMMIT_INDEX_MASK) >= (t1 & COMMIT_INDEX_MASK))
            // Since the counter is behind, reduce the current count
            currentCount = currentCount - (COMMIT_INDEX_MASK + 1);

        t1 = (UINT16)currentCount;
        if((t1 & ~COMMIT_INDEX_MASK) != (*c & ~COMMIT_INDEX_MASK))
            return FALSE;
        // set the counter to the value that was
        // present when the commitment was made
        currentCount = (currentCount & 0xffffffffffff0000) | *c;

    }
    // Marshal the count value to a TPM2B buffer for the KDF
    cntr.t.size = sizeof(currentCount);
    UINT64_TO_BYTE_ARRAY(currentCount, cntr.t.buffer);

    // Now can do the KDF to create the random value for the signing operation
    // During the creation process, we may generate an r that does not meet the
    // requirements of the random value.
    // want to generate a new r.

    r->t.size = n->size;

    // Arbitrary upper limit on the number of times that we can look for
    // a suitable random value. The normally number of tries will be 1.
    for(iterations = 1; iterations < 1000000;)
    {
        BYTE *pr = &r->b.buffer[0];
        int i;
        CryptKDFa(hashAlg, &gr.commitNonce.b, "ECDAA Commit",
                  name, &cntr.b, n->size * 8, r->t.buffer, &iterations);

        // random value must be less than the prime
        if(CryptCompare(r->b.size, r->b.buffer, n->size, n->buffer) >= 0)
            continue;

        // in this implementation it is required that at least bit
        // in the upper half of the number be set
        for(i = n->size/2; i > 0; i--)
            if(*pr++ != 0)
                return TRUE;
    }
    return FALSE;
}
UINT16
CryptCommit(
    void
)
{
    UINT16 oldCount = (UINT16)gr.commitCounter;
    gr.commitCounter++;
    BitSet(oldCount & COMMIT_INDEX_MASK, gr.commitArray, sizeof(gr.commitArray));
    return oldCount;
}
void
CryptEndCommit(
    UINT16 c               // IN: the counter value of the commitment
)
{
    BitClear((c & COMMIT_INDEX_MASK), gr.commitArray, sizeof(gr.commitArray));
}

// E r
// M e
// TPM_RC_NO_RESULT
// TPM_RC_CANCELLED

TPM_RC
CryptCommitCompute(
    TPMS_ECC_POINT *K,                   // OUT: [d]B
    TPMS_ECC_POINT *L,                   // OUT: [r]B
    TPMS_ECC_POINT *E,                   // OUT: [r]M
    TPM_ECC_CURVE curveID,              // IN: The curve for the computation
    TPMS_ECC_POINT *M,                   // IN: M (P1)
    TPMS_ECC_POINT *B,                   // IN: B (x2, y2)
    TPM2B_ECC_PARAMETER *d,                   // IN: the private scalar
    TPM2B_ECC_PARAMETER *r                    // IN: the computed r value
)
{
    TEST(ALG_ECDH_VALUE);
    // CRYPT_NO_RESULT->TPM_RC_NO_RESULT CRYPT_CANCEL->TPM_RC_CANCELLED
    return TranslateCryptErrors(
               _cpri__EccCommitCompute(K, L , E, curveID, M, B, d, r));
}
BOOL
CryptEccGetParameters(
    TPM_ECC_CURVE curveId,                // IN: ECC curve ID
    TPMS_ALGORITHM_DETAIL_ECC *parameters             // OUT: ECC parameter
)
{
    const ECC_CURVE *curve = _cpri__EccGetParametersByCurveId(curveId);
    const ECC_CURVE_DATA *data;
    BOOL found = curve != NULL;

    if(found)
    {

        data = curve->curveData;

        parameters->curveID = curve->curveId;

        // Key size in bit
        parameters->keySize = curve->keySizeBits;

        // KDF
        parameters->kdf = curve->kdf;

        // Sign
        parameters->sign = curve->sign;

        // Copy p value
        MemoryCopy2B(&parameters->p.b, data->p, sizeof(parameters->p.t.buffer));

        // Copy a value
        MemoryCopy2B(&parameters->a.b, data->a, sizeof(parameters->a.t.buffer));

        // Copy b value
        MemoryCopy2B(&parameters->b.b, data->b, sizeof(parameters->b.t.buffer));

        // Copy Gx value
        MemoryCopy2B(&parameters->gX.b, data->x, sizeof(parameters->gX.t.buffer));

        // Copy Gy value
        MemoryCopy2B(&parameters->gY.b, data->y, sizeof(parameters->gY.t.buffer));

        // Copy n value
        MemoryCopy2B(&parameters->n.b, data->n, sizeof(parameters->n.t.buffer));

        // Copy h value
        MemoryCopy2B(&parameters->h.b, data->h, sizeof(parameters->h.t.buffer));
    }
    return found;
}
#if CC_ZGen_2Phase == YES
TPM_RC
CryptEcc2PhaseKeyExchange(
    TPMS_ECC_POINT *outZ1,                   // OUT: the computed point
    TPMS_ECC_POINT *outZ2,                   // OUT: optional second point
    TPM_ALG_ID scheme,                   // IN: the key exchange scheme
    TPM_ECC_CURVE curveId,                  // IN: the curve for the computation
    TPM2B_ECC_PARAMETER *dsA,                     // IN: static private TPM key
    TPM2B_ECC_PARAMETER *deA,                     // IN: ephemeral private TPM key
    TPMS_ECC_POINT *QsB,                     // IN: static public party B key
    TPMS_ECC_POINT *QeB                      // IN: ephemeral public party B key
)
{
    return (TranslateCryptErrors(_cpri__C_2_2_KeyExchange(outZ1,
                                 outZ2,
                                 scheme,
                                 curveId,
                                 dsA,
                                 deA,
                                 QsB,
                                 QeB)));
}
#endif    // CC_ZGen_2Phase
#endif    //TPM_ALG_ECC      //% 3
BOOL
CryptIsSchemeAnonymous(
    TPM_ALG_ID scheme                // IN: the scheme algorithm to test
)
{
#ifdef TPM_ALG_ECDAA
    return (scheme == TPM_ALG_ECDAA);
#else
    UNREFERENCED(scheme);
    return 0;
#endif
}
void
ParmDecryptSym(
    TPM_ALG_ID symAlg,               // IN: the symmetric algorithm
    TPM_ALG_ID hash,                 // IN: hash algorithm for KDFa
    UINT16 keySizeInBits,        // IN: key key size in bit
    TPM2B *key,                     // IN: KDF HMAC key
    TPM2B *nonceCaller,             // IN: nonce caller
    TPM2B *nonceTpm,                // IN: nonce TPM
    UINT32 dataSize,             // IN: size of parameter buffer
    BYTE *data                     // OUT: buffer to be decrypted
)
{
    // KDF output buffer
    // It contains parameters for the CFB encryption
    // From MSB to LSB, they are the key and iv
    BYTE symParmString[MAX_SYM_KEY_BYTES + MAX_SYM_BLOCK_SIZE];
    // Symmetric key size in byte
    UINT16 keySize = (keySizeInBits + 7)    / 8;
    TPM2B_IV iv;

    iv.t.size = CryptGetSymmetricBlockSize(symAlg, keySizeInBits);
    // If there is decryption to do...
    if(iv.t.size > 0)
    {
        // Generate key and iv
        CryptKDFa(hash, key, "CFB", nonceCaller, nonceTpm,
                  keySizeInBits + (iv.t.size * 8), symParmString, NULL);
        MemoryCopy(iv.t.buffer, &symParmString[keySize], iv.t.size,
                   sizeof(iv.t.buffer));

        CryptSymmetricDecrypt(data, symAlg, keySizeInBits, TPM_ALG_CFB,
                              symParmString, &iv, dataSize, data);
    }
    return;
}
void
ParmEncryptSym(
    TPM_ALG_ID symAlg,                // IN: symmetric algorithm
    TPM_ALG_ID hash,                  // IN: hash algorithm for KDFa
    UINT16 keySizeInBits,         // IN: AES key size in bit
    TPM2B *key,                    // IN: KDF HMAC key
    TPM2B *nonceCaller,            // IN: nonce caller
    TPM2B *nonceTpm,               // IN: nonce TPM
    UINT32 dataSize,              // IN: size of parameter buffer
    BYTE *data                    // OUT: buffer to be encrypted
)
{
    // KDF output buffer
    // It contains parameters for the CFB encryption
    BYTE symParmString[MAX_SYM_KEY_BYTES + MAX_SYM_BLOCK_SIZE];

    // Symmetric key size in bytes
    UINT16 keySize = (keySizeInBits + 7)    / 8;

    TPM2B_IV iv;

    iv.t.size = CryptGetSymmetricBlockSize(symAlg, keySizeInBits);
    // See if there is any encryption to do
    if(iv.t.size > 0)
    {
        // Generate key and iv
        CryptKDFa(hash, key, "CFB", nonceTpm, nonceCaller,
                  keySizeInBits + (iv.t.size * 8), symParmString, NULL);

        MemoryCopy(iv.t.buffer, &symParmString[keySize], iv.t.size,
                   sizeof(iv.t.buffer));

        CryptSymmetricEncrypt(data, symAlg, keySizeInBits, TPM_ALG_CFB,
                              symParmString, &iv, dataSize, data);
    }
    return;
}
void
CryptGenerateNewSymmetric(
    TPMS_SENSITIVE_CREATE *sensitiveCreate,                     // IN: sensitive creation data
    TPMT_SENSITIVE *sensitive,                           // OUT: sensitive area
    TPM_ALG_ID hashAlg,                           // IN: hash algorithm for the KDF
    TPM2B_SEED *seed,                                // IN: seed used in creation
    TPM2B_NAME *name                                 // IN: name of the object
)
{
    // This function is called to create a key and obfuscation value for a
    // symmetric key that can either be a block cipher or an XOR key. The buffer
    // in sensitive->sensitive will hold either. When we call the function
    // to copy the input value or generated value to the sensitive->sensitive
    // buffer we will need to have a size for the output buffer. This define
    // computes the maximum that it might need to be and uses that. It will always
    // be smaller than the largest value that will fit.
#define MAX_SENSITIVE_SIZE \
 (MAX(sizeof(sensitive->sensitive.bits.t.buffer), \
 sizeof(sensitive->sensitive.sym.t.buffer)))

    // set the size of the obfuscation value
    sensitive->seedValue.t.size = CryptGetHashDigestSize(hashAlg);

    // If the input sensitive size is zero, then create both the sensitive data
    // and the obfuscation value
    if(sensitiveCreate->data.t.size == 0)
    {
        BYTE symValues[MAX(MAX_DIGEST_SIZE, MAX_SYM_KEY_BYTES)
                       + MAX_DIGEST_SIZE];
        UINT16 requestSize;

        // Set the size of the request to be the size of the key and the
        // obfuscation value
        requestSize = sensitive->sensitive.sym.t.size
                      + sensitive->seedValue.t.size;
        pAssert(requestSize <= sizeof(symValues));

        requestSize = _cpri__GenerateSeededRandom(requestSize, symValues, hashAlg,
                      &seed->b,
                      "symmetric sensitive", &name->b,
                      NULL);
        pAssert(requestSize != 0);

        // Copy the new key
        MemoryCopy(sensitive->sensitive.sym.t.buffer,
                   symValues, sensitive->sensitive.sym.t.size,
                   MAX_SENSITIVE_SIZE);

        // copy the obfuscation value
        MemoryCopy(sensitive->seedValue.t.buffer,
                   &symValues[sensitive->sensitive.sym.t.size],
                   sensitive->seedValue.t.size,
                   sizeof(sensitive->seedValue.t.buffer));
    }
    else
    {
        // Copy input symmetric key to sensitive area as long as it will fit
        MemoryCopy2B(&sensitive->sensitive.sym.b, &sensitiveCreate->data.b,
                     MAX_SENSITIVE_SIZE);

        // Create the obfuscation value
        _cpri__GenerateSeededRandom(sensitive->seedValue.t.size,
                                    sensitive->seedValue.t.buffer,
                                    hashAlg, &seed->b,
                                    "symmetric obfuscation", &name->b, NULL);
    }
    return;
}

// E r
// M e
// TPM_RC_KEY_SIZE


static TPM_RC
CryptGenerateKeySymmetric(
    TPMT_PUBLIC *publicArea,                 // IN/OUT: The public area template
    // for the new key.
    TPMS_SENSITIVE_CREATE *sensitiveCreate,            // IN: sensitive creation data
    TPMT_SENSITIVE *sensitive,                  // OUT: sensitive area
    TPM_ALG_ID hashAlg,                    // IN: hash algorithm for the KDF
    TPM2B_SEED *seed,                       // IN: seed used in creation
    TPM2B_NAME *name                        // IN: name of the object
)
{
    // If this is not a new key, then the provided key data must be the right size
    if(publicArea->objectAttributes.sensitiveDataOrigin == CLEAR)
    {
        if( (sensitiveCreate->data.t.size * 8)
                != publicArea->parameters.symDetail.sym.keyBits.sym)
            return TPM_RC_KEY_SIZE;
        // Make sure that the key size is OK.
        // This implementation only supports symmetric key sizes that are
        // multiples of 8
        if(publicArea->parameters.symDetail.sym.keyBits.sym % 8 != 0)
            return TPM_RC_KEY_SIZE;
    }
    else
    {
        // TPM is going to generate the key so set the size
        sensitive->sensitive.sym.t.size
            = publicArea->parameters.symDetail.sym.keyBits.sym                             / 8;
        sensitiveCreate->data.t.size = 0;
    }
    // Fill in the sensitive area
    CryptGenerateNewSymmetric(sensitiveCreate, sensitive, hashAlg,
                              seed, name);

    // Create unique area in public
    CryptComputeSymmetricUnique(publicArea->nameAlg,
                                sensitive, &publicArea->unique.sym);

    return TPM_RC_SUCCESS;
}
#ifdef TPM_ALG_KEYEDHASH                 //% 5
void
CryptXORObfuscation(
    TPM_ALG_ID hash,                         // IN: hash algorithm for KDF
    TPM2B *key,                          // IN: KDF key
    TPM2B *contextU,                     // IN: contextU
    TPM2B *contextV,                     // IN: contextV
    UINT32 dataSize,                     // IN: size of data buffer
    BYTE *data                          // IN/OUT: data to be XORed in place
)
{
    BYTE mask[MAX_DIGEST_SIZE];                     // Allocate a digest sized buffer
    BYTE *pm;
    UINT32 i;
    UINT32 counter = 0;
    UINT16 hLen = CryptGetHashDigestSize(hash);
    UINT32 requestSize = dataSize * 8;
    INT32 remainBytes = (INT32) dataSize;

    pAssert((key != NULL) && (data != NULL) && (hLen != 0));

    // Call KDFa to generate XOR mask
    for(; remainBytes > 0; remainBytes -= hLen)
    {
        // Make a call to KDFa to get next iteration
        CryptKDFaOnce(hash, key, "XOR", contextU, contextV,
                      requestSize, mask, &counter);

        // XOR next piece of the data
        pm = mask;
        for(i = hLen < remainBytes ? hLen : remainBytes; i > 0; i--)
            *data++ ^= *pm++;
    }
    return;
}
#endif    //TPM_ALG_KEYED_HASH                   //%5
void
CryptInitUnits(
    void
)
{
    // Initialize the vector of implemented algorithms
    AlgorithmGetImplementedVector(&g_implementedAlgorithms);

    // Indicate that all test are necessary
    CryptInitializeToTest();

    // Call crypto engine unit initialization
    // It is assumed that crypt engine initialization should always succeed.
    // Otherwise, TPM should go to failure mode.
    if(_cpri__InitCryptoUnits(&TpmFail) != CRYPT_SUCCESS)
        FAIL(FATAL_ERROR_INTERNAL);
    return;
}
void
CryptStopUnits(
    void
)
{
    // Call crypto engine unit stopping
    _cpri__StopCryptoUnits();

    return;
}
BOOL
CryptUtilStartup(
    STARTUP_TYPE type                           // IN: the startup type
)
{
    // Make sure that the crypto library functions are ready.
    // NOTE: need to initialize the crypto before loading
    // the RND state may trigger a self-test which
    // uses the
    if( !_cpri__Startup())
        return FALSE;

    // Initialize the state of the RNG.
    CryptDrbgGetPutState(PUT_STATE);

    if(type == SU_RESET)
    {
#ifdef TPM_ALG_ECC
        // Get a new random commit nonce
        gr.commitNonce.t.size = sizeof(gr.commitNonce.t.buffer);
        _cpri__GenerateRandom(gr.commitNonce.t.size, gr.commitNonce.t.buffer);
        // Reset the counter and commit array
        gr.commitCounter = 0;
        MemorySet(gr.commitArray, 0, sizeof(gr.commitArray));
#endif     // TPM_ALG_ECC
    }

    // If the shutdown was orderly, then the values recovered from NV will
    // be OK to use. If the shutdown was not orderly, then a TPM Reset was required
    // and we would have initialized in the code above.

    return TRUE;
}
BOOL
CryptIsAsymAlgorithm(
    TPM_ALG_ID algID               // IN: algorithm ID
)
{
    return (
#ifdef TPM_ALG_RSA
               algID == TPM_ALG_RSA
#endif
#if defined TPM_ALG_RSA && defined TPM_ALG_ECC
               ||
#endif
#ifdef TPM_ALG_ECC
               algID == TPM_ALG_ECC
#endif
           );
}
INT16
CryptGetSymmetricBlockSize(
    TPMI_ALG_SYM algorithm,          // IN: symmetric algorithm
    UINT16 keySize             // IN: key size in bit
)
{
    return _cpri__GetSymmetricBlockSize(algorithm, keySize);
}
void
CryptSymmetricEncrypt(
    BYTE *encrypted,                 // OUT: the encrypted data
    TPM_ALG_ID algorithm,                  // IN: algorithm for encryption
    UINT16 keySizeInBits,              // IN: key size in bit
    TPMI_ALG_SYM_MODE mode,                       // IN: symmetric encryption mode
    BYTE *key,                       // IN: encryption key
    TPM2B_IV *ivIn,                      // IN/OUT: Input IV and output chaining
    // value for the next block
    UINT32 dataSize,                   // IN: data size in byte
    BYTE *data                       // IN/OUT: data buffer
)
{

    TPM2B_IV defaultIv = {0};
    TPM2B_IV *iv = (ivIn != NULL) ? ivIn : &defaultIv;

    TEST(algorithm);

    pAssert(encrypted != NULL && key != NULL);

    // this check can pass but the case below can fail. ALG_xx_VALUE values are
    // defined for all algorithms but the TPM_ALG_xx might not be.
    if(algorithm == ALG_AES_VALUE || algorithm == ALG_SM4_VALUE)
    {
        if(mode != TPM_ALG_ECB)
            defaultIv.t.size = 16;
        // A provided IV has to be the right size
        pAssert(mode == TPM_ALG_ECB || iv->t.size == 16);
    }
    switch(algorithm)
    {
#ifdef TPM_ALG_AES
    case TPM_ALG_AES:
    {
        switch (mode)
        {
        case TPM_ALG_CTR:
            _cpri__AESEncryptCTR(encrypted, keySizeInBits, key,
                                 iv->t.buffer, dataSize, data);
            break;
        case TPM_ALG_OFB:
            _cpri__AESEncryptOFB(encrypted, keySizeInBits, key,
                                 iv->t.buffer, dataSize, data);
            break;
        case TPM_ALG_CBC:
            _cpri__AESEncryptCBC(encrypted, keySizeInBits, key,
                                 iv->t.buffer, dataSize, data);
            break;
        case TPM_ALG_CFB:
            _cpri__AESEncryptCFB(encrypted, keySizeInBits, key,
                                 iv->t.buffer, dataSize, data);
            break;
        case TPM_ALG_ECB:
            _cpri__AESEncryptECB(encrypted, keySizeInBits, key,
                                 dataSize, data);
            break;
        default:
            pAssert(0);
        }
    }
    break;
#endif
#ifdef TPM_ALG_SM4
    case TPM_ALG_SM4:
    {
        switch (mode)
        {
        case TPM_ALG_CTR:
            _cpri__SM4EncryptCTR(encrypted, keySizeInBits, key,
                                 iv->t.buffer, dataSize, data);
            break;
        case TPM_ALG_OFB:
            _cpri__SM4EncryptOFB(encrypted, keySizeInBits, key,
                                 iv->t.buffer, dataSize, data);
            break;
        case TPM_ALG_CBC:
            _cpri__SM4EncryptCBC(encrypted, keySizeInBits, key,
                                 iv->t.buffer, dataSize, data);
            break;

        case TPM_ALG_CFB:
            _cpri__SM4EncryptCFB(encrypted, keySizeInBits, key,
                                 iv->t.buffer, dataSize, data);
            break;
        case TPM_ALG_ECB:
            _cpri__SM4EncryptECB(encrypted, keySizeInBits, key,
                                 dataSize, data);
            break;
        default:
            pAssert(0);
        }
    }
    break;

#endif
    default:
        pAssert(FALSE);
        break;
    }

    return;

}
void
CryptSymmetricDecrypt(
    BYTE *decrypted,
    TPM_ALG_ID algorithm,      // IN: algorithm for encryption
    UINT16 keySizeInBits,  // IN: key size in bit
    TPMI_ALG_SYM_MODE mode,           // IN: symmetric encryption mode
    BYTE *key,              // IN: encryption key
    TPM2B_IV *ivIn,             // IN/OUT: IV for next block
    UINT32 dataSize,       // IN: data size in byte
    BYTE *data              // IN/OUT: data buffer
)
{
    BYTE *iv = NULL;
    BYTE defaultIV[sizeof(TPMT_HA)];

    TEST(algorithm);

    if(
#ifdef TPM_ALG_AES
        algorithm == TPM_ALG_AES
#endif
#if defined TPM_ALG_AES && defined TPM_ALG_SM4
        ||
#endif
#ifdef TPM_ALG_SM4
        algorithm == TPM_ALG_SM4
#endif
    )
    {
        // Both SM4 and AES have block size of 128 bits
        // If the iv is not provided, create a default of 0
        if(ivIn == NULL)
        {
            // Initialize the default IV
            iv = defaultIV;
            MemorySet(defaultIV, 0, 16);
        }
        else
        {
            // A provided IV has to be the right size
            pAssert(mode == TPM_ALG_ECB || ivIn->t.size == 16);
            iv = &(ivIn->t.buffer[0]);
        }
    }

    switch(algorithm)
    {
#ifdef TPM_ALG_AES
    case TPM_ALG_AES:
    {

        switch (mode)
        {
        case TPM_ALG_CTR:
            _cpri__AESDecryptCTR(decrypted, keySizeInBits, key, iv,
                                 dataSize, data);
            break;
        case TPM_ALG_OFB:
            _cpri__AESDecryptOFB(decrypted, keySizeInBits, key, iv,
                                 dataSize, data);
            break;
        case TPM_ALG_CBC:
            _cpri__AESDecryptCBC(decrypted, keySizeInBits, key, iv,
                                 dataSize, data);
            break;
        case TPM_ALG_CFB:
            _cpri__AESDecryptCFB(decrypted, keySizeInBits, key, iv,
                                 dataSize, data);
            break;
        case TPM_ALG_ECB:
            _cpri__AESDecryptECB(decrypted, keySizeInBits, key,
                                 dataSize, data);
            break;
        default:
            pAssert(0);
        }
        break;
    }
#endif     //TPM_ALG_AES
#ifdef TPM_ALG_SM4
    case TPM_ALG_SM4 :
        switch (mode)
        {
        case TPM_ALG_CTR:
            _cpri__SM4DecryptCTR(decrypted, keySizeInBits, key, iv,
                                 dataSize, data);
            break;
        case TPM_ALG_OFB:
            _cpri__SM4DecryptOFB(decrypted, keySizeInBits, key, iv,
                                 dataSize, data);
            break;
        case TPM_ALG_CBC:
            _cpri__SM4DecryptCBC(decrypted, keySizeInBits, key, iv,
                                 dataSize, data);
            break;
        case TPM_ALG_CFB:
            _cpri__SM4DecryptCFB(decrypted, keySizeInBits, key, iv,
                                 dataSize, data);
            break;
        case TPM_ALG_ECB:
            _cpri__SM4DecryptECB(decrypted, keySizeInBits, key,
                                 dataSize, data);
            break;
        default:
            pAssert(0);
        }
        break;
#endif    //TPM_ALG_SM4

    default:
        pAssert(FALSE);
        break;
    }
    return;
}

// E r
// M e
// TPM_RC_ATTRIBUTES
// TPM_RC_KEY
// TPM_RC_SCHEME
// TPM_RC_VALUE


TPM_RC
CryptSecretEncrypt(
    TPMI_DH_OBJECT keyHandle,        // IN: encryption key handle
    const char *label,              // IN: a null-terminated string as L
    TPM2B_DATA *data,               // OUT: secret value
    TPM2B_ENCRYPTED_SECRET *secret              // OUT: secret structure
)
{
    TPM_RC result = TPM_RC_SUCCESS;
    OBJECT *encryptKey = ObjectGet(keyHandle);          // TPM key used for encrypt

    pAssert(data != NULL && secret != NULL);

// The output secret value has the size of the digest produced by the nameAlg.
    data->t.size = CryptGetHashDigestSize(encryptKey->publicArea.nameAlg);

    pAssert(encryptKey->publicArea.objectAttributes.decrypt == SET);

    switch(encryptKey->publicArea.type)
    {
#ifdef TPM_ALG_RSA
    case TPM_ALG_RSA:
    {
        TPMT_RSA_DECRYPT scheme;

        // Use OAEP scheme
        scheme.scheme = TPM_ALG_OAEP;
        scheme.details.oaep.hashAlg = encryptKey->publicArea.nameAlg;

        // Create secret data from RNG
        CryptGenerateRandom(data->t.size, data->t.buffer);

        // Encrypt the data by RSA OAEP into encrypted secret
        result = CryptEncryptRSA(&secret->t.size, secret->t.secret,
                                 encryptKey, &scheme,
                                 data->t.size, data->t.buffer, label);
    }
    break;
#endif  //TPM_ALG_RSA

#ifdef TPM_ALG_ECC
    case TPM_ALG_ECC:
    {
        TPMS_ECC_POINT eccPublic;
        TPM2B_ECC_PARAMETER eccPrivate;
        TPMS_ECC_POINT eccSecret;
        BYTE *buffer = secret->t.secret;

        // Need to make sure that the public point of the key is on the
        // curve defined by the key.
        if(!_cpri__EccIsPointOnCurve(
                    encryptKey->publicArea.parameters.eccDetail.curveID,
                    &encryptKey->publicArea.unique.ecc))
            result = TPM_RC_KEY;
        else
        {

            // Call crypto engine to create an auxiliary ECC key
            // We assume crypt engine initialization should always success.
            // Otherwise, TPM should go to failure mode.
            CryptNewEccKey(encryptKey->publicArea.parameters.eccDetail.curveID,
                           &eccPublic, &eccPrivate);

            // Marshal ECC public to secret structure. This will be used by the
            // recipient to decrypt the secret with their private key.
            secret->t.size = TPMS_ECC_POINT_Marshal(&eccPublic, &buffer, NULL);

            // Compute ECDH shared secret which is R = [d]Q where d is the
            // private part of the ephemeral key and Q is the public part of a
            // TPM key. TPM_RC_KEY error return from CryptComputeECDHSecret
            // because the auxiliary ECC key is just created according to the
            // parameters of input ECC encrypt key.
            if( CryptEccPointMultiply(&eccSecret,
                                      encryptKey->publicArea.parameters.eccDetail.curveID,
                                      &eccPrivate,
                                      &encryptKey->publicArea.unique.ecc)
                    != CRYPT_SUCCESS)
                result = TPM_RC_KEY;
            else

                // The secret value is computed from Z using KDFe as:
                // secret := KDFe(HashID, Z, Use, PartyUInfo, PartyVInfo, bits)
                // Where:
                // HashID the nameAlg of the decrypt key
                // Z the x coordinate (Px) of the product (P) of the point
                // (Q) of the secret and the private x coordinate (de,V)
                // of the decryption key
                // Use a null-terminated string containing "SECRET"
                // PartyUInfo the x coordinate of the point in the secret
                // (Qe,U )
                // PartyVInfo the x coordinate of the public key (Qs,V )
                // bits the number of bits in the digest of HashID
                // Retrieve seed from KDFe

                CryptKDFe(encryptKey->publicArea.nameAlg, &eccSecret.x.b,
                          label, &eccPublic.x.b,
                          &encryptKey->publicArea.unique.ecc.x.b,
                          data->t.size * 8, data->t.buffer);
        }
    }
    break;
#endif    //TPM_ALG_ECC

    default:
        FAIL(FATAL_ERROR_INTERNAL);
        break;
    }

    return result;
}

// E r
// M e
// TPM_RC_ATTRIBUTES
// TPM_RC_BINDING

// TPM_RC_ECC_POINT
// TPM_RC_INSUFFICIENT
// TPM_RC_NO_RESULT
// TPM_RC_SIZE
// TPM_RC_VALUE



// TPM_RC_FAILURE

TPM_RC
CryptSecretDecrypt(
    TPM_HANDLE tpmKey,                    // IN: decrypt key
    TPM2B_NONCE *nonceCaller,                 // IN: nonceCaller. It is needed for
    // symmetric decryption. For
    // asymmetric decryption, this
    // parameter is NULL
    const char *label,                  // IN: a null-terminated string as L
    TPM2B_ENCRYPTED_SECRET *secret,                 // IN: input secret
    TPM2B_DATA *data                    // OUT: decrypted secret value
)
{
    TPM_RC result = TPM_RC_SUCCESS;
    OBJECT *decryptKey = ObjectGet(tpmKey);             //TPM key used for decrypting

    // Decryption for secret
    switch(decryptKey->publicArea.type)
    {

#ifdef TPM_ALG_RSA
    case TPM_ALG_RSA:
    {
        TPMT_RSA_DECRYPT scheme;

        // Use OAEP scheme
        scheme.scheme = TPM_ALG_OAEP;
        scheme.details.oaep.hashAlg = decryptKey->publicArea.nameAlg;

        // Set the output buffer capacity
        data->t.size = sizeof(data->t.buffer);

        // Decrypt seed by RSA OAEP
        result = CryptDecryptRSA(&data->t.size, data->t.buffer, decryptKey,
                                 &scheme,
                                 secret->t.size, secret->t.secret,label);
        if( (result == TPM_RC_SUCCESS)
                && (data->t.size
                    > CryptGetHashDigestSize(decryptKey->publicArea.nameAlg)))
            result = TPM_RC_VALUE;
    }
    break;
#endif  //TPM_ALG_RSA

#ifdef TPM_ALG_ECC
    case TPM_ALG_ECC:
    {
        TPMS_ECC_POINT eccPublic;
        TPMS_ECC_POINT eccSecret;
        BYTE *buffer = secret->t.secret;
        INT32 size = secret->t.size;

        // Retrieve ECC point from secret buffer
        result = TPMS_ECC_POINT_Unmarshal(&eccPublic, &buffer, &size);
        if(result == TPM_RC_SUCCESS)
        {
            result = CryptEccPointMultiply(&eccSecret,
                                           decryptKey->publicArea.parameters.eccDetail.curveID,
                                           &decryptKey->sensitive.sensitive.ecc,
                                           &eccPublic);

            if(result == TPM_RC_SUCCESS)
            {

                // Set the size of the "recovered" secret value to be the size
                // of the digest produced by the nameAlg.
                data->t.size =
                    CryptGetHashDigestSize(decryptKey->publicArea.nameAlg);

                // The secret value is computed from Z using KDFe as:
                // secret := KDFe(HashID, Z, Use, PartyUInfo, PartyVInfo, bits)
                // Where:
                // HashID -- the nameAlg of the decrypt key
                // Z -- the x coordinate (Px) of the product (P) of the point
                // (Q) of the secret and the private x coordinate (de,V)
                // of the decryption key
                // Use -- a null-terminated string containing "SECRET"
                // PartyUInfo -- the x coordinate of the point in the secret
                // (Qe,U )
                // PartyVInfo -- the x coordinate of the public key (Qs,V )
                // bits -- the number of bits in the digest of HashID
                // Retrieve seed from KDFe
                CryptKDFe(decryptKey->publicArea.nameAlg, &eccSecret.x.b, label,
                          &eccPublic.x.b,
                          &decryptKey->publicArea.unique.ecc.x.b,
                          data->t.size * 8, data->t.buffer);
            }
        }
    }
    break;
#endif  //TPM_ALG_ECC

    case TPM_ALG_KEYEDHASH:
        // The seed size can not be bigger than the digest size of nameAlg
        if(secret->t.size >
                CryptGetHashDigestSize(decryptKey->publicArea.nameAlg))
            result = TPM_RC_VALUE;
        else
        {
            // Retrieve seed by XOR Obfuscation:
            // seed = XOR(secret, hash, key, nonceCaller, nullNonce)
            // where:
            // secret the secret parameter from the TPM2_StartAuthHMAC
            // command
            // which contains the seed value
            // hash nameAlg of tpmKey
            // key the key or data value in the object referenced by
            // entityHandle in the TPM2_StartAuthHMAC command
            // nonceCaller the parameter from the TPM2_StartAuthHMAC command
            // nullNonce a zero-length nonce
            // XOR Obfuscation in place
            CryptXORObfuscation(decryptKey->publicArea.nameAlg,
                                &decryptKey->sensitive.sensitive.bits.b,
                                &nonceCaller->b, NULL,
                                secret->t.size, secret->t.secret);
            // Copy decrypted seed
            MemoryCopy2B(&data->b, &secret->b, sizeof(data->t.buffer));
        }
        break;
    case TPM_ALG_SYMCIPHER:
    {
        TPM2B_IV iv = {0};
        TPMT_SYM_DEF_OBJECT *symDef;
        // The seed size can not be bigger than the digest size of nameAlg
        if(secret->t.size >
                CryptGetHashDigestSize(decryptKey->publicArea.nameAlg))
            result = TPM_RC_VALUE;
        else
        {
            symDef = &decryptKey->publicArea.parameters.symDetail.sym;
            iv.t.size = CryptGetSymmetricBlockSize(symDef->algorithm,
                                                   symDef->keyBits.sym);
            pAssert(iv.t.size != 0);
            if(nonceCaller->t.size >= iv.t.size)
                MemoryCopy(iv.t.buffer, nonceCaller->t.buffer, iv.t.size,
                           sizeof(iv.t.buffer));
            else
                MemoryCopy(iv.b.buffer, nonceCaller->t.buffer,
                           nonceCaller->t.size, sizeof(iv.t.buffer));
            // CFB decrypt in place, using nonceCaller as iv
            CryptSymmetricDecrypt(secret->t.secret, symDef->algorithm,
                                  symDef->keyBits.sym, TPM_ALG_CFB,
                                  decryptKey->sensitive.sensitive.sym.t.buffer,
                                  &iv, secret->t.size, secret->t.secret);

            // Copy decrypted seed
            MemoryCopy2B(&data->b, &secret->b, sizeof(data->t.buffer));
        }
    }
    break;
    default:
        pAssert(0);
        break;
    }
    return result;
}
void
CryptParameterEncryption(
    TPM_HANDLE handle,                         // IN: encrypt session handle
    TPM2B *nonceCaller,                   // IN: nonce caller
    UINT16 leadingSizeInByte,              // IN: the size of the leading size field in
    // byte
    TPM2B_AUTH *extraKey,                      // IN: additional key material other than
    // session auth
    BYTE *buffer                         // IN/OUT: parameter buffer to be encrypted
)
{
    SESSION *session = SessionGet(handle);           // encrypt session
    TPM2B_TYPE(SYM_KEY, ( sizeof(extraKey->t.buffer)
                          + sizeof(session->sessionKey.t.buffer)));
    TPM2B_SYM_KEY key;                         // encryption key
    UINT32 cipherSize = 0;      // size of cipher text

    pAssert(session->sessionKey.t.size + extraKey->t.size <= sizeof(key.t.buffer));

    // Retrieve encrypted data size.
    if(leadingSizeInByte == 2)
    {
        // Extract the first two bytes as the size field as the data size
        // encrypt
        cipherSize = (UINT32)BYTE_ARRAY_TO_UINT16(buffer);
        // advance the buffer
        buffer = &buffer[2];
    }
#ifdef TPM4B
    else if(leadingSizeInByte == 4)
    {
        // use the first four bytes to indicate the number of bytes to encrypt
        cipherSize = BYTE_ARRAY_TO_UINT32(buffer);
        //advance pointer
        buffer = &buffer[4];
    }
#endif
    else
    {
        pAssert(FALSE);
    }

    // Compute encryption key by concatenating sessionAuth with extra key
    MemoryCopy2B(&key.b, &session->sessionKey.b, sizeof(key.t.buffer));
    MemoryConcat2B(&key.b, &extraKey->b, sizeof(key.t.buffer));

    if (session->symmetric.algorithm == TPM_ALG_XOR)

        // XOR parameter encryption formulation:
        // XOR(parameter, hash, sessionAuth, nonceNewer, nonceOlder)
        CryptXORObfuscation(session->authHashAlg, &(key.b),
                            &(session->nonceTPM.b),
                            nonceCaller, cipherSize, buffer);
    else
        ParmEncryptSym(session->symmetric.algorithm, session->authHashAlg,
                       session->symmetric.keyBits.aes, &(key.b),
                       nonceCaller, &(session->nonceTPM.b),
                       cipherSize, buffer);
    return;
}

// E r
// M e
// TPM_RC_SIZE


TPM_RC
CryptParameterDecryption(
    TPM_HANDLE handle,                                // IN: encrypted session handle
    TPM2B *nonceCaller,                           // IN: nonce caller
    UINT32 bufferSize,                            // IN: size of parameter buffer
    UINT16 leadingSizeInByte,                     // IN: the size of the leading size field in
    // byte
    TPM2B_AUTH *extraKey,                              // IN: the authValue
    BYTE *buffer                                 // IN/OUT: parameter buffer to be decrypted
)
{
    SESSION *session = SessionGet(handle);                     // encrypt session
    // The HMAC key is going to be the concatenation of the session key and any
    // additional key material (like the authValue). The size of both of these
    // is the size of the buffer which can contain a TPMT_HA.
    TPM2B_TYPE(HMAC_KEY, ( sizeof(extraKey->t.buffer)
                           + sizeof(session->sessionKey.t.buffer)));
    TPM2B_HMAC_KEY key;                             // decryption key
    UINT32 cipherSize = 0;      // size of cipher text

    pAssert(session->sessionKey.t.size + extraKey->t.size <= sizeof(key.t.buffer));

    // Retrieve encrypted data size.
    if(leadingSizeInByte == 2)
    {
        // The first two bytes of the buffer are the size of the
        // data to be decrypted
        cipherSize = (UINT32)BYTE_ARRAY_TO_UINT16(buffer);
        buffer = &buffer[2];                  // advance the buffer
    }
#ifdef TPM4B
    else if(leadingSizeInByte == 4)
    {
        // the leading size is four bytes so get the four byte size field
        cipherSize = BYTE_ARRAY_TO_UINT32(buffer);
        buffer = &buffer[4];           //advance pointer
    }
#endif
    else
    {
        pAssert(FALSE);
    }
    if(cipherSize > bufferSize)
        return TPM_RC_SIZE;

    // Compute decryption key by concatenating sessionAuth with extra input key
    MemoryCopy2B(&key.b, &session->sessionKey.b, sizeof(key.t.buffer));
    MemoryConcat2B(&key.b, &extraKey->b, sizeof(key.t.buffer));

    if(session->symmetric.algorithm == TPM_ALG_XOR)
        // XOR parameter decryption formulation:
        // XOR(parameter, hash, sessionAuth, nonceNewer, nonceOlder)
        // Call XOR obfuscation function
        CryptXORObfuscation(session->authHashAlg, &key.b, nonceCaller,
                            &(session->nonceTPM.b), cipherSize, buffer);
    else
        // Assume that it is one of the symmetric block ciphers.
        ParmDecryptSym(session->symmetric.algorithm, session->authHashAlg,
                       session->symmetric.keyBits.sym,
                       &key.b, nonceCaller, &session->nonceTPM.b,
                       cipherSize, buffer);

    return TPM_RC_SUCCESS;

}
void
CryptComputeSymmetricUnique(
    TPMI_ALG_HASH nameAlg,             // IN: object name algorithm
    TPMT_SENSITIVE *sensitive,          // IN: sensitive area
    TPM2B_DIGEST *unique              // OUT: unique buffer
)
{
    HASH_STATE hashState;

    pAssert(sensitive != NULL && unique != NULL);

    // Compute the public value as the hash of sensitive.symkey || unique.buffer
    unique->t.size = CryptGetHashDigestSize(nameAlg);
    CryptStartHash(nameAlg, &hashState);

    // Add obfuscation value
    CryptUpdateDigest2B(&hashState, &sensitive->seedValue.b);

    // Add sensitive value
    CryptUpdateDigest2B(&hashState, &sensitive->sensitive.any.b);

    CryptCompleteHash2B(&hashState, &unique->b);

    return;
}
#if 0   //%
void
CryptComputeSymValue(
    TPM_HANDLE parentHandle,         // IN: parent handle of the object to be created
    TPMT_PUBLIC *publicArea,              // IN/OUT: the public area template
    TPMT_SENSITIVE *sensitive,               // IN: sensitive area
    TPM2B_SEED *seed,                    // IN: the seed
    TPMI_ALG_HASH hashAlg,              // IN: hash algorithm for KDFa
    TPM2B_NAME *name                     // IN: object name
)
{
    TPM2B_AUTH *proof = NULL;

    if(CryptIsAsymAlgorithm(publicArea->type))
    {
        // Generate seedValue only when an asymmetric key is a storage key
        if(publicArea->objectAttributes.decrypt == SET
                && publicArea->objectAttributes.restricted == SET)
        {
            // If this is a primary object in the endorsement hierarchy, use
            // ehProof in the creation of the symmetric seed so that child
            // objects in the endorsement hierarchy are voided on TPM2_Clear()
            // or TPM2_ChangeEPS()
            if( parentHandle == TPM_RH_ENDORSEMENT
                    && publicArea->objectAttributes.fixedTPM == SET)
                proof = &gp.ehProof;
        }
        else
        {
            sensitive->seedValue.t.size = 0;
            return;
        }
    }

    // For all object types, the size of seedValue is the digest size of nameAlg
    sensitive->seedValue.t.size = CryptGetHashDigestSize(publicArea->nameAlg);

    // Compute seedValue using implementation-dependent method
    _cpri__GenerateSeededRandom(sensitive->seedValue.t.size,
                                sensitive->seedValue.t.buffer,
                                hashAlg,
                                &seed->b,
                                "seedValue",
                                &name->b,
                                (TPM2B *)proof);
    return;
}
#endif    //%

// E r
// M e
// TPM_RC_KEY_SIZE

// TPM_RC_RANGE
// TPM_RC_SIZE

// TPM_RC_VALUE



TPM_RC
CryptCreateObject(
    TPM_HANDLE parentHandle,                   // IN/OUT: indication of the seed
    // source
    TPMT_PUBLIC *publicArea,                       // IN/OUT: public area
    TPMS_SENSITIVE_CREATE *sensitiveCreate,                  // IN: sensitive creation
    TPMT_SENSITIVE *sensitive                         // OUT: sensitive area
)
{
    // Next value is a placeholder for a random seed that is used in
    // key creation when the parent is not a primary seed. It has the same
    // size as the primary seed.

    TPM2B_SEED localSeed;                  // data to seed key creation if this
    // is not a primary seed

    TPM2B_SEED *seed = NULL;
    TPM_RC result = TPM_RC_SUCCESS;

    TPM2B_NAME name;
    TPM_ALG_ID hashAlg = CONTEXT_INTEGRITY_HASH_ALG;
    OBJECT *parent;
    UINT32 counter;

    // Set the sensitive type for the object
    sensitive->sensitiveType = publicArea->type;
    ObjectComputeName(publicArea, &name);

    // For all objects, copy the initial auth data
    sensitive->authValue = sensitiveCreate->userAuth;

    // If this is a permanent handle assume that it is a hierarchy
    if(HandleGetType(parentHandle) == TPM_HT_PERMANENT)
    {
        seed = HierarchyGetPrimarySeed(parentHandle);
    }
    else
    {
        // If not hierarchy handle, get parent
        parent = ObjectGet(parentHandle);
        hashAlg = parent->publicArea.nameAlg;

        // Use random value as seed for non-primary objects
        localSeed.t.size = PRIMARY_SEED_SIZE;
        CryptGenerateRandom(PRIMARY_SEED_SIZE, localSeed.t.buffer);
        seed = &localSeed;
    }

    switch(publicArea->type)
    {
#ifdef TPM_ALG_RSA
    // Create RSA key
    case TPM_ALG_RSA:
        result = CryptGenerateKeyRSA(publicArea, sensitive,
                                     hashAlg, seed, &name, &counter);
        break;
#endif  // TPM_ALG_RSA

#ifdef TPM_ALG_ECC
    // Create ECC key
    case TPM_ALG_ECC:
        result = CryptGenerateKeyECC(publicArea, sensitive,
                                     hashAlg, seed, &name, &counter);
        break;
#endif  // TPM_ALG_ECC

    // Collect symmetric key information
    case TPM_ALG_SYMCIPHER:
        return CryptGenerateKeySymmetric(publicArea, sensitiveCreate,
                                         sensitive, hashAlg, seed, &name);
        break;
    case TPM_ALG_KEYEDHASH:
        return CryptGenerateKeyedHash(publicArea, sensitiveCreate,
                                      sensitive, hashAlg, seed, &name);
        break;
    default:
        pAssert(0);
        break;
    }
    if(result == TPM_RC_SUCCESS)
    {
        TPM2B_AUTH *proof = NULL;

        if(publicArea->objectAttributes.decrypt == SET
                && publicArea->objectAttributes.restricted == SET)
        {
            // If this is a primary object in the endorsement hierarchy, use
            // ehProof in the creation of the symmetric seed so that child
            // objects in the endorsement hierarchy are voided on TPM2_Clear()
            // or TPM2_ChangeEPS()
            if( parentHandle == TPM_RH_ENDORSEMENT
                    && publicArea->objectAttributes.fixedTPM == SET)
                proof = &gp.ehProof;

            // For all object types, the size of seedValue is the digest size
            // of its nameAlg
            sensitive->seedValue.t.size
                = CryptGetHashDigestSize(publicArea->nameAlg);

            // Compute seedValue using implementation-dependent method
            _cpri__GenerateSeededRandom(sensitive->seedValue.t.size,
                                        sensitive->seedValue.t.buffer,
                                        hashAlg,
                                        &seed->b,
                                        "seedValuea",
                                        &name.b,
                                        (TPM2B *)proof);
        }
        else
        {
            sensitive->seedValue.t.size = 0;
        }
    }

    return result;

}
BOOL
CryptObjectIsPublicConsistent(
    TPMT_PUBLIC *publicArea                   // IN: public area
)
{
    BOOL OK = TRUE;
    switch (publicArea->type)
    {
#ifdef TPM_ALG_RSA
    case TPM_ALG_RSA:
        OK = CryptAreKeySizesConsistent(publicArea);
        break;
#endif   //TPM_ALG_RSA

#ifdef TPM_ALG_ECC
    case TPM_ALG_ECC:
    {
        const ECC_CURVE *curveValue;

        // Check that the public point is on the indicated curve.
        OK = CryptEccIsPointOnCurve(
                 publicArea->parameters.eccDetail.curveID,
                 &publicArea->unique.ecc);
        if(OK)
        {
            curveValue = CryptEccGetCurveDataPointer(
                             publicArea->parameters.eccDetail.curveID);
            pAssert(curveValue != NULL);

            // The input ECC curve must be a supported curve
            // IF a scheme is defined for the curve, then that scheme must
            // be used.
            OK = (curveValue->sign.scheme == TPM_ALG_NULL
                  || ( publicArea->parameters.eccDetail.scheme.scheme
                       == curveValue->sign.scheme));
            OK = OK && CryptAreKeySizesConsistent(publicArea);
        }
    }
    break;
#endif   //TPM_ALG_ECC

    default:
        // Symmetric object common checks
        // There is noting to check with a symmetric key that is public only.
        // Also not sure that there is anything useful to be done with it
        // either.
        break;
    }
    return OK;
}

// E r
// M e
// TPM_RC_TYPE
// TPM_RC_FAILURE
// TPM_RC_BINDING

TPM_RC
CryptObjectPublicPrivateMatch(
    OBJECT *object                   // IN: the object to check
)
{
    TPMT_PUBLIC *publicArea;
    TPMT_SENSITIVE *sensitive;
    TPM_RC result = TPM_RC_SUCCESS;
    BOOL isAsymmetric = FALSE;

    pAssert(object != NULL);
    publicArea = &object->publicArea;
    sensitive = &object->sensitive;
    if(publicArea->type != sensitive->sensitiveType)
        return TPM_RC_TYPE;

    switch(publicArea->type)
    {
#ifdef TPM_ALG_RSA
    case TPM_ALG_RSA:
        isAsymmetric = TRUE;
        // The public and private key sizes need to be consistent
        if(sensitive->sensitive.rsa.t.size != publicArea->unique.rsa.t.size/2)
            result = TPM_RC_BINDING;
        else
            // Load key by computing the private exponent
            result = CryptLoadPrivateRSA(object);
        break;
#endif
#ifdef TPM_ALG_ECC
    // This function is called from ObjectLoad() which has already checked to
    // see that the public point is on the curve so no need to repeat that
    // check.
    case TPM_ALG_ECC:
        isAsymmetric = TRUE;
        if( publicArea->unique.ecc.x.t.size
                != sensitive->sensitive.ecc.t.size)
            result = TPM_RC_BINDING;
        else if(publicArea->nameAlg != TPM_ALG_NULL)
        {
            TPMS_ECC_POINT publicToCompare;
            // Compute ECC public key
            CryptEccPointMultiply(&publicToCompare,
                                  publicArea->parameters.eccDetail.curveID,
                                  &sensitive->sensitive.ecc, NULL);
            // Compare ECC public key
            if( (!Memory2BEqual(&publicArea->unique.ecc.x.b,
                                &publicToCompare.x.b))
                    || (!Memory2BEqual(&publicArea->unique.ecc.y.b,
                                       &publicToCompare.y.b)))
                result = TPM_RC_BINDING;
        }
        break;
#endif
    case TPM_ALG_KEYEDHASH:
        break;
    case TPM_ALG_SYMCIPHER:
        if( (publicArea->parameters.symDetail.sym.keyBits.sym + 7)/8
                != sensitive->sensitive.sym.t.size)
            result = TPM_RC_BINDING;
        break;
    default:
        // The choice here is an assert or a return of a bad type for the object
        pAssert(0);
        break;
    }

    // For asymmetric keys, the algorithm for validating the linkage between
    // the public and private areas is algorithm dependent. For symmetric keys
    // the linkage is based on hashing the symKey and obfuscation values.
    if( result == TPM_RC_SUCCESS && !isAsymmetric
            && publicArea->nameAlg != TPM_ALG_NULL)
    {
        TPM2B_DIGEST uniqueToCompare;

        // Compute unique for symmetric key
        CryptComputeSymmetricUnique(publicArea->nameAlg, sensitive,
                                    &uniqueToCompare);
        // Compare unique
        if(!Memory2BEqual(&publicArea->unique.sym.b,
                          &uniqueToCompare.b))
            result = TPM_RC_BINDING;
    }
    return result;

}
TPMI_ALG_HASH
CryptGetSignHashAlg(
    TPMT_SIGNATURE *auth                 // IN: signature
)
{
    pAssert(auth->sigAlg != TPM_ALG_NULL);

    // Get authHash algorithm based on signing scheme
    switch(auth->sigAlg)
    {

#ifdef TPM_ALG_RSA
    case TPM_ALG_RSASSA:
        return auth->signature.rsassa.hash;

    case TPM_ALG_RSAPSS:
        return auth->signature.rsapss.hash;

#endif       //TPM_ALG_RSA

#ifdef TPM_ALG_ECC
    case TPM_ALG_ECDSA:
        return auth->signature.ecdsa.hash;

#endif       //TPM_ALG_ECC

    case TPM_ALG_HMAC:
        return auth->signature.hmac.hashAlg;

    default:
        return TPM_ALG_NULL;
    }
}
BOOL
CryptIsSplitSign(
    TPM_ALG_ID scheme             // IN: the algorithm selector
)
{
    if( scheme != scheme
# ifdef TPM_ALG_ECDAA
            || scheme == TPM_ALG_ECDAA
# endif       // TPM_ALG_ECDAA

      )
        return TRUE;
    return FALSE;
}
BOOL
CryptIsSignScheme(
    TPMI_ALG_ASYM_SCHEME scheme
)
{
    BOOL isSignScheme = FALSE;

    switch(scheme)
    {
#ifdef TPM_ALG_RSA
    // If RSA is implemented, then both signing schemes are required
    case TPM_ALG_RSASSA:
    case TPM_ALG_RSAPSS:
        isSignScheme = TRUE;
        break;
#endif      //TPM_ALG_RSA

#ifdef TPM_ALG_ECC
    // If ECC is implemented ECDSA is required
    case TPM_ALG_ECDSA:
#ifdef TPM_ALG_ECDAA
    // ECDAA is optional
    case TPM_ALG_ECDAA:
#endif
#ifdef TPM_ALG_ECSCHNORR
    // Schnorr is also optional
    case TPM_ALG_ECSCHNORR:
#endif
#ifdef TPM_ALG_SM2
    case TPM_ALG_SM2:
#endif
        isSignScheme = TRUE;
        break;
#endif   //TPM_ALG_ECC
    default:
        break;
    }
    return isSignScheme;
}
BOOL
CryptIsDecryptScheme(
    TPMI_ALG_ASYM_SCHEME scheme
)
{
    BOOL isDecryptScheme = FALSE;

    switch(scheme)
    {
#ifdef TPM_ALG_RSA
    // If RSA is implemented, then both decrypt schemes are required
    case TPM_ALG_RSAES:
    case TPM_ALG_OAEP:
        isDecryptScheme = TRUE;
        break;
#endif   //TPM_ALG_RSA

#ifdef TPM_ALG_ECC
    // If ECC is implemented ECDH is required
    case TPM_ALG_ECDH:
#ifdef TPM_ALG_SM2
    case TPM_ALG_SM2:
#endif
#ifdef TPM_ALG_ECMQV
    case TPM_ALG_ECMQV:
#endif
        isDecryptScheme = TRUE;
        break;
#endif   //TPM_ALG_ECC
    default:
        break;
    }
    return isDecryptScheme;
}

// E r
// M e
// TPM_RC_KEY
// TPM_RC_SCHEME



TPM_RC
CryptSelectSignScheme(
    TPMI_DH_OBJECT signHandle,                 // IN: handle of signing key
    TPMT_SIG_SCHEME *scheme                     // IN/OUT: signing scheme
)
{
    OBJECT *signObject;
    TPMT_SIG_SCHEME *objectScheme;
    TPMT_PUBLIC *publicArea;
    TPM_RC result = TPM_RC_SUCCESS;

    // If the signHandle is TPM_RH_NULL, then the NULL scheme is used, regardless
    // of the setting of scheme
    if(signHandle == TPM_RH_NULL)
    {
        scheme->scheme = TPM_ALG_NULL;
        scheme->details.any.hashAlg = TPM_ALG_NULL;
    }
    else
    {
        // sign handle is not NULL so...
        // Get sign object pointer
        signObject = ObjectGet(signHandle);
        publicArea = &signObject->publicArea;

        // is this a signing key?
        if(!publicArea->objectAttributes.sign)
            result = TPM_RC_KEY;
        else
        {
            // "parms" defined to avoid long code lines.
            TPMU_PUBLIC_PARMS *parms = &publicArea->parameters;
            if(CryptIsAsymAlgorithm(publicArea->type))
                objectScheme = (TPMT_SIG_SCHEME *)&parms->asymDetail.scheme;
            else
                objectScheme = (TPMT_SIG_SCHEME *)&parms->keyedHashDetail.scheme;

            // If the object doesn't have a default scheme, then use the
            // input scheme.
            if(objectScheme->scheme == TPM_ALG_NULL)
            {
                // Input and default can't both be NULL
                if(scheme->scheme == TPM_ALG_NULL)
                    result = TPM_RC_SCHEME;

                // Assume that the scheme is compatible with the key. If not,
                // we will generate an error in the signing operation.

            }
            else if(scheme->scheme == TPM_ALG_NULL)
            {
                // input scheme is NULL so use default

                // First, check to see if the default requires that the caller
                // provided scheme data
                if(CryptIsSplitSign(objectScheme->scheme))
                    result = TPM_RC_SCHEME;
                else
                {
                    scheme->scheme = objectScheme->scheme;
                    scheme->details.any.hashAlg
                        = objectScheme->details.any.hashAlg;
                }
            }
            else
            {
                // Both input and object have scheme selectors
                // If the scheme and the hash are not the same then...
                if( objectScheme->scheme != scheme->scheme
                        || ( objectScheme->details.any.hashAlg
                             != scheme->details.any.hashAlg))
                    result = TPM_RC_SCHEME;
            }
        }

    }
    return result;
}

// E r
// M e
// TPM_RC_SCHEME
// TPM_RC_VALUE




TPM_RC
CryptSign(
    TPMI_DH_OBJECT signHandle,               // IN: The handle of sign key
    TPMT_SIG_SCHEME *signScheme,                  // IN: sign scheme.
    TPM2B_DIGEST *digest,                      // IN: The digest being signed
    TPMT_SIGNATURE *signature                    // OUT: signature
)
{
    OBJECT *signKey = ObjectGet(signHandle);
    TPM_RC result = TPM_RC_SCHEME;

    // check if input handle is a sign key
    pAssert(signKey->publicArea.objectAttributes.sign == SET);

    // Must have the private portion loaded. This check is made during
    // authorization.
    pAssert(signKey->attributes.publicOnly == CLEAR);

    // Initialize signature scheme
    signature->sigAlg = signScheme->scheme;

    // If the signature algorithm is TPM_ALG_NULL, then we are done
    if(signature->sigAlg == TPM_ALG_NULL)
        return TPM_RC_SUCCESS;

    // All the schemes other than TPM_ALG_NULL have a hash algorithm
    TEST_HASH(signScheme->details.any.hashAlg);

    // Initialize signature hash
    // Note: need to do the check for alg null first because the null scheme
    // doesn't have a hashAlg member.
    signature->signature.any.hashAlg = signScheme->details.any.hashAlg;

    // perform sign operation based on different key type
    switch (signKey->publicArea.type)
    {

#ifdef TPM_ALG_RSA
    case TPM_ALG_RSA:
        result = CryptSignRSA(signKey, signScheme, digest, signature);
        break;
#endif    //TPM_ALG_RSA

#ifdef TPM_ALG_ECC
    case TPM_ALG_ECC:
        result = CryptSignECC(signKey, signScheme, digest, signature);
        break;
#endif    //TPM_ALG_ECC
    case TPM_ALG_KEYEDHASH:
        result = CryptSignHMAC(signKey, signScheme, digest, signature);
        break;
    default:
        break;
    }

    return result;
}

// E r
// M e
// TPM_RC_SIGNATURE
// TPM_RC_SCHEME
// TPM_RC_HANDLE


TPM_RC
CryptVerifySignature(
    TPMI_DH_OBJECT keyHandle,          // IN: The handle of sign key
    TPM2B_DIGEST *digest,               // IN: The digest being validated
    TPMT_SIGNATURE *signature             // IN: signature
)
{
    // NOTE: ObjectGet will either return a pointer to a loaded object or
    // will assert. It will never return a non-valid value. This makes it save
    // to initialize 'publicArea' with the return value from ObjectGet() without
    // checking it first.
    OBJECT *authObject = ObjectGet(keyHandle);
    TPMT_PUBLIC *publicArea = &authObject->publicArea;
    TPM_RC result = TPM_RC_SCHEME;

    // The input unmarshaling should prevent any input signature from being
    // a NULL signature, but just in case
    if(signature->sigAlg == TPM_ALG_NULL)
        return TPM_RC_SIGNATURE;

    switch (publicArea->type)
    {

#ifdef TPM_ALG_RSA
    case TPM_ALG_RSA:
        result = CryptRSAVerifySignature(authObject, digest, signature);
        break;
#endif   //TPM_ALG_RSA

#ifdef TPM_ALG_ECC
    case TPM_ALG_ECC:
        result = CryptECCVerifySignature(authObject, digest, signature);
        break;

#endif   // TPM_ALG_ECC

    case TPM_ALG_KEYEDHASH:
        if(authObject->attributes.publicOnly)
            result = TPM_RCS_HANDLE;
        else
            result = CryptHMACVerifySignature(authObject, digest, signature);
        break;

    default:
        break;
    }
    return result;

}

// E r
// M e
// TPM_RC_SIZE

TPM_RC
CryptDivide(
    TPM2B *numerator,                // IN: numerator
    TPM2B *denominator,              // IN: denominator
    TPM2B *quotient,                 // OUT: quotient = numerator     / denominator.
    TPM2B *remainder                 // OUT: numerator mod denominator.
)
{
    pAssert( numerator != NULL && denominator!= NULL
             && (quotient != NULL || remainder != NULL)
           );
    // assume denominator is not 0
    pAssert(denominator->size != 0);

    return TranslateCryptErrors(_math__Div(numerator,
                                           denominator,
                                           quotient,
                                           remainder)
                               );
}
LIB_EXPORT int
CryptCompare(
    const UINT32 aSize,        // IN: size of a
    const BYTE *a,             // IN: a buffer
    const UINT32 bSize,        // IN: size of b
    const BYTE *b              // IN: b buffer
)
{
    return _math__uComp(aSize, a, bSize, b);
}
int
CryptCompareSigned(
    UINT32 aSize,        // IN: size of a
    BYTE *a,             // IN: a buffer
    UINT32 bSize,        // IN: size of b
    BYTE *b              // IN: b buffer
)
{
    return _math__Comp(aSize, a, bSize, b);
}
TPM_RC
CryptGetTestResult(
    TPM2B_MAX_BUFFER *outData          // OUT: test result data
)
{
    outData->t.size = 0;
    return TPM_RC_SUCCESS;
}
#ifdef TPM_ALG_ECC              //% 5
TPMI_YES_NO
CryptCapGetECCCurve(
    TPM_ECC_CURVE curveID,                   // IN: the starting ECC curve
    UINT32 maxCount,                  // IN: count of returned curve
    TPML_ECC_CURVE *curveList                    // OUT: ECC curve list
)
{
    TPMI_YES_NO more = NO;
    UINT16 i;
    UINT32 count = _cpri__EccGetCurveCount();
    TPM_ECC_CURVE curve;

    // Initialize output property list
    curveList->count = 0;

    // The maximum count of curves we may return is MAX_ECC_CURVES
    if(maxCount > MAX_ECC_CURVES) maxCount = MAX_ECC_CURVES;

    // Scan the eccCurveValues array
    for(i = 0; i < count; i++)
    {
        curve = _cpri__GetCurveIdByIndex(i);
        // If curveID is less than the starting curveID, skip it
        if(curve < curveID)
            continue;

        if(curveList->count < maxCount)
        {
            // If we have not filled up the return list, add more curves to
            // it
            curveList->eccCurves[curveList->count] = curve;
            curveList->count++;
        }
        else
        {
            // If the return list is full but we still have curves
            // available, report this and stop iterating
            more = YES;
            break;
        }

    }

    return more;

}
UINT32
CryptCapGetEccCurveNumber(
    void
)
{
    // There is an array that holds the curve data. Its size divided by the
    // size of an entry is the number of values in the table.
    return _cpri__EccGetCurveCount();
}
#endif    //TPM_ALG_ECC       //% 5
BOOL
CryptAreKeySizesConsistent(
    TPMT_PUBLIC *publicArea                    // IN: the public area to check
)
{
    BOOL consistent = FALSE;

    switch (publicArea->type)
    {
#ifdef TPM_ALG_RSA
    case TPM_ALG_RSA:
        // The key size in bits is filtered by the unmarshaling
        consistent = ( ((publicArea->parameters.rsaDetail.keyBits+7)/8)
                       == publicArea->unique.rsa.t.size);
        break;
#endif    //TPM_ALG_RSA

#ifdef TPM_ALG_ECC
    case TPM_ALG_ECC:
    {
        UINT16 keySizeInBytes;
        TPM_ECC_CURVE curveId = publicArea->parameters.eccDetail.curveID;

        keySizeInBytes = CryptEccGetKeySizeInBytes(curveId);

        consistent = keySizeInBytes > 0
                     && publicArea->unique.ecc.x.t.size <= keySizeInBytes
                     && publicArea->unique.ecc.y.t.size <= keySizeInBytes;
    }
    break;
#endif    //TPM_ALG_ECC
    default:
        break;
    }

    return consistent;
}
void
CryptAlgsSetImplemented(
    void
)
{
    AlgorithmGetImplementedVector(&g_implementedAlgorithms);
}
