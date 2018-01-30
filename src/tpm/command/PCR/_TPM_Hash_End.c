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
void
_TPM_Hash_End(
    void
)
{

    UINT32 i;
    TPM2B_DIGEST digest;
    HASH_OBJECT *hashObject;
    TPMI_DH_PCR pcrHandle;

    // If the DRTM handle is not being used, then either _TPM_Hash_Start has not
    // been called, _TPM_Hash_End was previously called, or some other command
    // was executed and the sequence was aborted.
    if(g_DRTMHandle == TPM_RH_UNASSIGNED)
        return;

    // Get DRTM sequence object
    hashObject = (HASH_OBJECT *)ObjectGet(g_DRTMHandle);

    // Is this _TPM_Hash_End after Startup or before
    if(TPMIsStarted())
    {
        // After

        // Reset the DRTM PCR
        PCRResetDynamics();

        // Extend the DRTM_PCR.
        pcrHandle = PCR_FIRST + DRTM_PCR;

        // DRTM sequence increments restartCount
        gr.restartCount++;
    }
    else
    {
        pcrHandle = PCR_FIRST + HCRTM_PCR;
    }

    // Complete hash and extend PCR, or if this is an HCRTM, complete
    // the hash, reset the H-CRTM register (PCR[0]) to 0...04, and then
    // extend the H-CRTM data
    for(i = 0; i < HASH_COUNT; i++)
    {
        TPMI_ALG_HASH hash = CryptGetHashAlgByIndex(i);
        // make sure that the PCR is implemented for this algorithm
        if(PcrIsAllocated(pcrHandle,
                          hashObject->state.hashState[i].state.hashAlg))
        {
            // Complete hash
            digest.t.size = CryptGetHashDigestSize(hash);
            CryptCompleteHash2B(&hashObject->state.hashState[i], &digest.b);

            PcrDrtm(pcrHandle, hash, &digest);
        }
    }

    // Flush sequence object.
    ObjectFlush(g_DRTMHandle);

    g_DRTMHandle = TPM_RH_UNASSIGNED;

    g_DrtmPreStartup = TRUE;

    return;
}
