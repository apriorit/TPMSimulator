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

//#define __TPM_RNG_FOR_DEBUG__
#include "OsslCryptoEngine.h"
int s_entropyFailure;
LIB_EXPORT BOOL
_cpri__RngStartup(void)
{
    UINT32 entropySize;
    BYTE entropy[MAX_RNG_ENTROPY_SIZE];
    INT32 returnedSize = 0;

    // Initialize the entropy source
    s_entropyFailure = FALSE;
    _plat__GetEntropy(NULL, 0);

    // Collect entropy until we have enough
    for(entropySize = 0;
            entropySize < MAX_RNG_ENTROPY_SIZE && returnedSize >= 0;
            entropySize += returnedSize)
    {
        returnedSize = _plat__GetEntropy(&entropy[entropySize],
                                         MAX_RNG_ENTROPY_SIZE - entropySize);
    }
    // Got some entropy on the last call and did not get an error
    if(returnedSize > 0)
    {
        // Seed OpenSSL with entropy
        RAND_seed(entropy, entropySize);
    }
    else
    {
        s_entropyFailure = TRUE;
    }
    return s_entropyFailure == FALSE;
}
LIB_EXPORT CRYPT_RESULT
_cpri__DrbgGetPutState(
    GET_PUT direction,
    int bufferSize,
    BYTE *buffer
)
{
    UNREFERENCED_PARAMETER(direction);
    UNREFERENCED_PARAMETER(bufferSize);
    UNREFERENCED_PARAMETER(buffer);

    return CRYPT_SUCCESS;             // Function is not implemented
}
LIB_EXPORT CRYPT_RESULT
_cpri__StirRandom(
    INT32 entropySize,
    BYTE *entropy
)
{
    if (entropySize >= 0)
    {
        RAND_add((const void *)entropy, (int) entropySize, 0.0);

    }
    return CRYPT_SUCCESS;
}
LIB_EXPORT UINT16
_cpri__GenerateRandom(
    INT32 randomSize,
    BYTE *buffer
)
{
    //
    // We don't do negative sizes or ones that are too large
    if (randomSize < 0 || randomSize > UINT16_MAX)
        return 0;
    // RAND_bytes uses 1 for success and we use 0
    if(RAND_bytes(buffer, randomSize) == 1)
        return (UINT16)randomSize;
    else
        return 0;
}
LIB_EXPORT UINT16
_cpri__GenerateSeededRandom(
    INT32 randomSize,        // IN: the size of the request
    BYTE *random,              // OUT: receives the data
    TPM_ALG_ID hashAlg,           // IN: used by KDF version but not here
    TPM2B *seed,                // IN: the seed value
    const char *label,               // IN: a label string (optional)
    TPM2B *partyU,              // IN: other data (oprtional)
    TPM2B *partyV               // IN: still more (optional)
)
{

    return (_cpri__KDFa(hashAlg, seed, label, partyU, partyV,
                        randomSize * 8, random, NULL, FALSE));
}

