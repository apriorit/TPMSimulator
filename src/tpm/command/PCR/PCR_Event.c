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
#include "PCR_Event_fp.h"
#ifdef TPM_CC_PCR_Event              // Conditional expansion of this file

// M e
// TPM_RC_LOCALITY current command locality is not allowed to extend the PCR
// referenced by pcrHandle

TPM_RC
TPM2_PCR_Event(
    PCR_Event_In *in,                    // IN: input parameter list
    PCR_Event_Out *out                    // OUT: output parameter list
)
{
    TPM_RC result;
    HASH_STATE hashState;
    UINT32 i;
    UINT16 size;

// Input Validation

    // If a PCR extend is required
    if(in->pcrHandle != TPM_RH_NULL)
    {
        // If the PCR is not allow to extend, return error
        if(!PCRIsExtendAllowed(in->pcrHandle))
            return TPM_RC_LOCALITY;

        // If PCR is state saved and we need to update orderlyState, check NV
        // availability
        if(PCRIsStateSaved(in->pcrHandle) && gp.orderlyState != SHUTDOWN_NONE)
        {
            result = NvIsAvailable();
            if(result != TPM_RC_SUCCESS) return result;
            g_clearOrderly = TRUE;
        }
    }

// Internal Data Update

    out->digests.count = HASH_COUNT;

    // Iterate supported PCR bank algorithms to extend
    for(i = 0; i < HASH_COUNT; i++)
    {
        TPM_ALG_ID hash = CryptGetHashAlgByIndex(i);
        out->digests.digests[i].hashAlg = hash;
        size = CryptStartHash(hash, &hashState);
        CryptUpdateDigest2B(&hashState, &in->eventData.b);
        CryptCompleteHash(&hashState, size,
                          (BYTE *) &out->digests.digests[i].digest);
        if(in->pcrHandle != TPM_RH_NULL)
            PCRExtend(in->pcrHandle, hash, size,
                      (BYTE *) &out->digests.digests[i].digest);
    }

    return TPM_RC_SUCCESS;
}
#endif // CC_PCR_Event
