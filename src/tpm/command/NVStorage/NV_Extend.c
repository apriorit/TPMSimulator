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
/*     the rights to reproduce, distribute, display, and perform the specification solely for the purpose of      */
/*     developing products based on such documents.                                                               */
/*                                                                                                                */
/*  2.  Source Code Distribution Conditions:                                                                      */
/*     Redistributions of Source Code must retain the above copyright licenses, this list of conditions           */
/*     and the following disclaimers.                                                                             */
/*     Redistributions in binary form must reproduce the above copyright licenses, this list of conditions        */
/*     and the following disclaimers in the documentation and/or other materials provided with the                */
/*     distribution.                                                                                              */
/*                                                                                                                */
/*  3.  Disclaimers:                                                                                              */
/*     THE COPYRIGHT LICENSES SET FORTH ABOVE DO NOT REPRESENT ANY FORM OF                                        */
/*     LICENSE OR WAIVER, EXPRESS OR IMPLIED, BY ESTOPPEL OR OTHERWISE, WITH                                      */
/*     RESPECT TO PATENT RIGHTS HELD BY TCG MEMBERS (OR OTHER THIRD PARTIES)                                      */
/*     THAT MAY BE NECESSARY TO IMPLEMENT THIS SPECIFICATION OR OTHERWISE.                                        */
/*     Contact TCG Administration (admin@trustedcomputinggroup.org) for information on specification              */
/*     licensing rights available through TCG membership agreements.                                              */
/*     THIS SPECIFICATION IS PROVIDED "AS IS" WITH NO EXPRESS OR IMPLIED WARRANTIES                               */
/*     WHATSOEVER, INCLUDING ANY WARRANTY OF MERCHANTABILITY OR FITNESS FOR A                                     */
/*     PARTICULAR PURPOSE, ACCURACY, COMPLETENESS, OR NONINFRINGEMENT OF                                          */
/*     INTELLECTUAL PROPERTY RIGHTS, OR ANY WARRANTY OTHERWISE ARISING OUT OF                                     */
/*     ANY PROPOSAL, SPECIFICATION OR SAMPLE.                                                                     */
/*     Without limitation, TCG and its members and licensors disclaim all liability, including liability for      */
/*     infringement of any proprietary rights, relating to use of information in this specification and to the    */
/*     implementation of this specification, and TCG disclaims all liability for cost of procurement of           */
/*     substitute goods or services, lost profits, loss of use, loss of data or any incidental, consequential,    */
/*     direct, indirect, or special damages, whether under contract, tort, warranty or otherwise, arising in      */
/*     any way out of use or reliance upon this specification or any information herein.                          */
/*     Any marks and brands contained herein are the property of their respective owner.                          */
/*                                                                                                                */
/******************************************************************************************************************/

#include "InternalRoutines.h"
#include "NV_Extend_fp.h"
#ifdef TPM_CC_NV_Extend              // Conditional expansion of this file
#include "NV_spt_fp.h"

// M e
// TPM_RC_ATTRIBUTES the TPMA_NV_EXTEND attribute is not SET in the Index referenced
// by nvIndex
// TPM_RC_NV_AUTHORIZATION the authorization was valid but the authorizing entity (authHandle) is
// not allowed to write to the Index referenced by nvIndex
// TPM_RC_NV_LOCKED the Index referenced by nvIndex is locked for writing

TPM_RC
TPM2_NV_Extend(
    NV_Extend_In *in                     // IN: input parameter list
)
{
    TPM_RC result;
    NV_INDEX nvIndex;

    TPM2B_DIGEST oldDigest;
    TPM2B_DIGEST newDigest;
    HASH_STATE hashState;

// Input Validation

    // Common access checks, NvWriteAccessCheck() may return TPM_RC_NV_AUTHORIZATION
    // or TPM_RC_NV_LOCKED
    result = NvWriteAccessChecks(in->authHandle, in->nvIndex);
    if(result != TPM_RC_SUCCESS)
        return result;

    // Get NV index info
    NvGetIndexInfo(in->nvIndex, &nvIndex);

    // Make sure that this is an extend index
    if(nvIndex.publicArea.attributes.TPMA_NV_EXTEND != SET)
        return TPM_RC_ATTRIBUTES + RC_NV_Extend_nvIndex;

    // If the Index is not-orderly, or if this is the first write, NV will
    // need to be updated.
    if( nvIndex.publicArea.attributes.TPMA_NV_ORDERLY == CLEAR
            || nvIndex.publicArea.attributes.TPMA_NV_WRITTEN == CLEAR)
    {
        // Check if NV is available. NvIsAvailable may return TPM_RC_NV_UNAVAILABLE
        // TPM_RC_NV_RATE or TPM_RC_SUCCESS.
        result = NvIsAvailable();
        if(result != TPM_RC_SUCCESS)
            return result;
    }

// Internal Data Update

    // Perform the write.
    oldDigest.t.size = CryptGetHashDigestSize(nvIndex.publicArea.nameAlg);
    pAssert(oldDigest.t.size <= sizeof(oldDigest.t.buffer));
    if(nvIndex.publicArea.attributes.TPMA_NV_WRITTEN == SET)
    {
        NvGetIndexData(in->nvIndex, &nvIndex, 0,
                       oldDigest.t.size, oldDigest.t.buffer);
    }
    else
    {
        MemorySet(oldDigest.t.buffer, 0, oldDigest.t.size);
    }
    // Start hash
    newDigest.t.size = CryptStartHash(nvIndex.publicArea.nameAlg, &hashState);

    // Adding old digest
    CryptUpdateDigest2B(&hashState, &oldDigest.b);

    // Adding new data
    CryptUpdateDigest2B(&hashState, &in->data.b);

    // Complete hash
    CryptCompleteHash2B(&hashState, &newDigest.b);

    // Write extended hash back.
    // Note, this routine will SET the TPMA_NV_WRITTEN attribute if necessary
    return NvWriteIndexData(in->nvIndex, &nvIndex, 0,
                            newDigest.t.size, newDigest.t.buffer);
}
#endif // CC_NV_Extend
