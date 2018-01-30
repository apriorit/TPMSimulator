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

// B.5.1. Introduction
// This file contains implementation of some of the big number primitives. This is used in order to reduce the
// overhead in dealing with data conversions to standard big number format.
// The simulator code uses the canonical form whenever possible in order to make the code in Part 3 more
// accessible. The canonical data formats are simple and not well suited for complex big
// number
// computations. This library provides functions that are found in typical big number libraries but they are
// written to handle the canonical data format of the reference TPM.
// In some cases, data is converted to a big number format used by a standard library, such as OpenSSL().
// This is done when the computations are complex enough warrant conversion. Vendors may replace the
// implementation in this file with a library that provides equivalent functions. A vendor may also rewrite the
// TPM code so that it uses a standard big number format instead of the canonical form and use the
// standard libraries instead of the code in this file.
// The implementation in this file makes use of the OpenSSL() library.
// Integer format: integers passed through the function interfaces in this library adopt the same format used
// in TPM 2.0 specification. It defines an integer as "an array of one or more octets with the most significant
// octet at the lowest index of the array." An additional value is needed to indicate the number of significant
// bytes.
#include "OsslCryptoEngine.h"
LIB_EXPORT UINT16
_math__Normalize2B(
    TPM2B *b                       // IN/OUT: number to normalize
)
{
    UINT16 from;
    UINT16 to;
    UINT16 size = b->size;

    for(from = 0; b->buffer[from] == 0 && from < size; from++);
    b->size -= from;
    for(to = 0; from < size; to++, from++ )
        b->buffer[to] = b->buffer[from];
    return b->size;
}
LIB_EXPORT BOOL
_math__Denormalize2B(
    TPM2B *in,                       // IN:OUT TPM2B number to de-normalize
    UINT32 size                    // IN: the desired size
)
{
    UINT32 to;
    UINT32 from;
    // If the current size is greater than the requested size, see if this can be
    // normalized to a value smaller than the requested size and then de-normalize
    if(in->size > size)
    {
        _math__Normalize2B(in);
        if(in->size > size)
            return FALSE;
    }
    // If the size is already what is requested, leave
    if(in->size == size)
        return TRUE;

    // move the bytes to the 'right'
    for(from = in->size, to = size; from > 0;)
        in->buffer[--to] = in->buffer[--from];

    // 'to' will always be greater than 0 because we checked for equal above.
    for(; to > 0;)
        in->buffer[--to] = 0;

    in->size = (UINT16)size;
    return TRUE;
}
LIB_EXPORT int
_math__sub(
    const UINT32 aSize,                  // IN: size of a
    const BYTE *a,                        // IN: a
    const UINT32 bSize,                  // IN: size of b
    const BYTE *b,                        // IN: b
    UINT16 *cSize,                    // OUT: set to MAX(aSize, bSize)
    BYTE *c                         // OUT: the difference
)
{
    int borrow = 0;
    int notZero = 0;
    int i;
    int i2;

    // set c to the longer of a or b
    *cSize = (UINT16)((aSize > bSize) ? aSize : bSize);
    // pick the shorter of a and b
    i = (aSize > bSize) ? bSize : aSize;
    i2 = *cSize - i;
    a = &a[aSize - 1];
    b = &b[bSize - 1];
    c = &c[*cSize - 1];
    for(; i > 0; i--)
    {
        borrow = *a-- - *b-- + borrow;
        *c-- = (BYTE)borrow;
        notZero = notZero || borrow;
        borrow >>= 8;
    }
    if(aSize > bSize)
    {
        for(; i2 > 0; i2--)
        {
            borrow = *a-- + borrow;
            *c-- = (BYTE)borrow;
            notZero = notZero || borrow;
            borrow >>= 8;
        }
    }
    else if(aSize < bSize)
    {
        for(; i2 > 0; i2--)
        {
            borrow = 0 - *b-- + borrow;
            *c-- = (BYTE)borrow;
            notZero = notZero || borrow;
            borrow >>= 8;
        }
    }
    // if there is a borrow, then b > a
    if(borrow)
        return -1;
    // either a > b or they are the same
    return notZero;
}
LIB_EXPORT int
_math__Inc(
    UINT32 aSize,                                   // IN: size of a
    BYTE *a                                          // IN: a
)
{

    for(a = &a[aSize-1]; aSize > 0; aSize--)
    {
        if((*a-- += 1) != 0)
            return 1;
    }
    return 0;
}
LIB_EXPORT void
_math__Dec(
    UINT32 aSize,                      // IN: size of a
    BYTE *a                           // IN: a
)
{
    for(a = &a[aSize-1]; aSize > 0; aSize--)
    {
        if((*a-- -= 1) != 0xff)
            return;
    }
    return;
}
LIB_EXPORT int
_math__Mul(
    const UINT32 aSize,                      // IN: size of a
    const BYTE *a,                          // IN: a
    const UINT32 bSize,                      // IN: size of b
    const BYTE *b,                          // IN: b
    UINT32 *pSize,                      // IN/OUT: size of the product
    BYTE *p                           // OUT: product. length of product = aSize +
    // bSize
)
{
    BIGNUM *bnA;
    BIGNUM *bnB;
    BIGNUM *bnP;
    BN_CTX *context;
    int retVal = 0;

    // First check that pSize is large enough if present
    if((pSize != NULL) && (*pSize < (aSize + bSize)))
        return CRYPT_PARAMETER;
    pAssert(pSize == NULL || *pSize <= MAX_2B_BYTES);
    //
    // Allocate space for BIGNUM context
    //
    context = BN_CTX_new();
    if(context == NULL)
        FAIL(FATAL_ERROR_ALLOCATION);
    bnA = BN_CTX_get(context);
    bnB = BN_CTX_get(context);
    bnP = BN_CTX_get(context);
    if (bnP == NULL)
        FAIL(FATAL_ERROR_ALLOCATION);

    // Convert the inputs to BIGNUMs
    //
    if (BN_bin2bn(a, aSize, bnA) == NULL || BN_bin2bn(b, bSize, bnB) == NULL)
        FAIL(FATAL_ERROR_INTERNAL);

    // Perform the multiplication
    //
    if (BN_mul(bnP, bnA, bnB, context) != 1)
        FAIL(FATAL_ERROR_INTERNAL);

    // If the size of the results is allowed to float, then set the return
    // size. Otherwise, it might be necessary to de-normalize the results
    retVal = BN_num_bytes(bnP);
    if(pSize == NULL)
    {
        BN_bn2bin(bnP, &p[aSize + bSize - retVal]);
        memset(p, 0, aSize + bSize - retVal);
        retVal = aSize + bSize;
    }
    else
    {
        BN_bn2bin(bnP, p);
        *pSize = retVal;
    }

    BN_CTX_end(context);
    BN_CTX_free(context);
    return retVal;
}
LIB_EXPORT CRYPT_RESULT
_math__Div(
    const TPM2B *n,                             // IN: numerator
    const TPM2B *d,                             // IN: denominator
    TPM2B *q,                             // OUT: quotient
    TPM2B *r                              // OUT: remainder
)
{
    BIGNUM *bnN;
    BIGNUM *bnD;
    BIGNUM *bnQ;
    BIGNUM *bnR;
    BN_CTX *context;
    CRYPT_RESULT retVal = CRYPT_SUCCESS;

    // Get structures for the big number representations
    context = BN_CTX_new();
    if(context == NULL)
        FAIL(FATAL_ERROR_ALLOCATION);
    BN_CTX_start(context);
    bnN = BN_CTX_get(context);
    bnD = BN_CTX_get(context);
    bnQ = BN_CTX_get(context);
    bnR = BN_CTX_get(context);

    // Errors in BN_CTX_get() are sticky so only need to check the last allocation
    if ( bnR == NULL
            || BN_bin2bn(n->buffer, n->size, bnN) == NULL
            || BN_bin2bn(d->buffer, d->size, bnD) == NULL)
        FAIL(FATAL_ERROR_INTERNAL);

    // Check for divide by zero.
    if(BN_num_bits(bnD) == 0)
        FAIL(FATAL_ERROR_DIVIDE_ZERO);

    // Perform the division
    if (BN_div(bnQ, bnR, bnN, bnD, context) != 1)
        FAIL(FATAL_ERROR_INTERNAL);

    // Convert the BIGNUM result back to our format
    if(q != NULL)        // If the quotient is being returned
    {
        if(!BnTo2B(q, bnQ, q->size))
        {
            retVal = CRYPT_UNDERFLOW;
            goto Done;
        }
    }
    if(r != NULL)        // If the remainder is being returned
    {
        if(!BnTo2B(r, bnR, r->size))
            retVal = CRYPT_UNDERFLOW;
    }

Done:
    BN_CTX_end(context);
    BN_CTX_free(context);

    return retVal;
}
LIB_EXPORT int
_math__uComp(
    const UINT32 aSize,                // IN: size of a
    const BYTE *a,                   // IN: a
    const UINT32 bSize,                                   // IN: size of b
    const BYTE *b                                        // IN: b
)
{
    int borrow = 0;
    int notZero = 0;
    int i;
    // If a has more digits than b, then a is greater than b if
    // any of the more significant bytes is non zero
    if((i = (int)aSize - (int)bSize) > 0)
        for(; i > 0; i--)
            if(*a++)             // means a > b
                return 1;
    // If b has more digits than a, then b is greater if any of the
    // more significant bytes is non zero
    if(i < 0)     // Means that b is longer than a
        for(; i < 0; i++)
            if(*b++)             // means that b > a
                return -1;
    // Either the vales are the same size or the upper bytes of a or b are
    // all zero, so compare the rest
    i = (aSize > bSize) ? bSize : aSize;
    a = &a[i-1];
    b = &b[i-1];
    for(; i > 0; i--)
    {
        borrow = *a-- - *b-- + borrow;
        notZero = notZero || borrow;
        borrow >>= 8;
    }
    // if there is a borrow, then b > a
    if(borrow)
        return -1;
    // either a > b or they are the same
    return notZero;
}
LIB_EXPORT int
_math__Comp(
    const UINT32 aSize,                                   // IN: size of a
    const BYTE *a,                                       // IN: a buffer
    const UINT32 bSize,                                   // IN: size of b
    const BYTE *b                                        // IN: b buffer
)
{
    int signA, signB;                           // sign of a and b

    // For positive or 0, sign_a is 1
    // for negative, sign_a is 0
    signA = ((a[0] & 0x80) == 0) ? 1 : 0;

    // For positive or 0, sign_b is 1
    // for negative, sign_b is 0
    signB = ((b[0] & 0x80) == 0) ? 1 : 0;

    if(signA != signB)
    {
        return signA - signB;
    }

    if(signA == 1)
        // do unsigned compare function
        return _math__uComp(aSize, a, bSize, b);
    else
        // do unsigned compare the other way
        return 0 - _math__uComp(aSize, a, bSize, b);
}
LIB_EXPORT CRYPT_RESULT
_math__ModExp(
    UINT32 cSize,                  // IN: size of the result
    BYTE *c,                     // OUT: results buffer
    const UINT32 mSize,                  // IN: size of number to be exponentiated
    const BYTE *m,                     // IN: number to be exponentiated
    const UINT32 eSize,                  // IN: size of power
    const BYTE *e,                     // IN: power
    const UINT32 nSize,                  // IN: modulus size
    const BYTE *n                      // IN: modulu
)
{
    CRYPT_RESULT retVal = CRYPT_SUCCESS;
    BN_CTX *context;
    BIGNUM *bnC;
    BIGNUM *bnM;
    BIGNUM *bnE;
    BIGNUM *bnN;
    INT32 i;

    context = BN_CTX_new();
    if(context == NULL)
        FAIL(FATAL_ERROR_ALLOCATION);
    BN_CTX_start(context);
    bnC = BN_CTX_get(context);
    bnM = BN_CTX_get(context);
    bnE = BN_CTX_get(context);
    bnN = BN_CTX_get(context);

    // Errors for BN_CTX_get are sticky so only need to check last allocation
    if(bnN == NULL)
        FAIL(FATAL_ERROR_ALLOCATION);

    //convert arguments
    if ( BN_bin2bn(m, mSize, bnM) == NULL
            || BN_bin2bn(e, eSize, bnE) == NULL
            || BN_bin2bn(n, nSize, bnN) == NULL)
        FAIL(FATAL_ERROR_INTERNAL);

    // Don't do exponentiation if the number being exponentiated is
    // larger than the modulus.
    if(BN_ucmp(bnM, bnN) >= 0)
    {
        retVal = CRYPT_PARAMETER;
        goto Cleanup;
    }
    // Perform the exponentiation
    if(!(BN_mod_exp(bnC, bnM, bnE, bnN, context)))
        FAIL(FATAL_ERROR_INTERNAL);

    // Convert the results
    // Make sure that the results will fit in the provided buffer.
    if((unsigned)BN_num_bytes(bnC) > cSize)
    {
        retVal = CRYPT_UNDERFLOW;
        goto Cleanup;
    }
    i = cSize - BN_num_bytes(bnC);
    BN_bn2bin(bnC, &c[i]);
    memset(c, 0, i);

Cleanup:
    // Free up allocated BN values
    BN_CTX_end(context);
    BN_CTX_free(context);
    return retVal;
}
LIB_EXPORT BOOL
_math__IsPrime(
    const UINT32 prime
)
{
    int isPrime;
    BIGNUM *p;

    // Assume the size variables are not overflow, which should not happen in
    // the contexts that this function will be called.
    if((p = BN_new()) == NULL)
        FAIL(FATAL_ERROR_ALLOCATION);
    if(!BN_set_word(p, prime))
        FAIL(FATAL_ERROR_INTERNAL);

    //
    // BN_is_prime returning -1 means that it ran into an error.
    // It should only return 0 or 1
    //
    if((isPrime = BN_is_prime_ex(p, BN_prime_checks, NULL, NULL)) < 0)
        FAIL(FATAL_ERROR_INTERNAL);

    if(p != NULL)
        BN_clear_free(p);
    return (isPrime == 1);
}
