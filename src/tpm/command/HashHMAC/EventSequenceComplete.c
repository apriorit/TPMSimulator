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
#include "EventSequenceComplete_fp.h"
#ifdef TPM_CC_EventSequenceComplete                        // Conditional expansion of this file

// M e
// TPM_RC_LOCALITY PCR extension is not allowed at the current locality
// TPM_RC_MODE input handle is not a valid event sequence object

TPM_RC
TPM2_EventSequenceComplete(
    EventSequenceComplete_In *in,                       // IN: input parameter list
    EventSequenceComplete_Out *out                       // OUT: output parameter list
)
{
    TPM_RC result;
    HASH_OBJECT *hashObject;
    UINT32 i;
    TPM_ALG_ID hashAlg;

// Input validation

    // get the event sequence object pointer
    hashObject = (HASH_OBJECT *)ObjectGet(in->sequenceHandle);

    // input handle must reference an event sequence object
    if(hashObject->attributes.eventSeq != SET)
        return TPM_RC_MODE + RC_EventSequenceComplete_sequenceHandle;

    // see if a PCR extend is requested in call
    if(in->pcrHandle != TPM_RH_NULL)
    {
        // see if extend of the PCR is allowed at the locality of the command,
        if(!PCRIsExtendAllowed(in->pcrHandle))
            return TPM_RC_LOCALITY;
        // if an extend is going to take place, then check to see if there has
        // been an orderly shutdown. If so, and the selected PCR is one of the
        // state saved PCR, then the orderly state has to change. The orderly state
        // does not change for PCR that are not preserved.
        // NOTE: This doesn't just check for Shutdown(STATE) because the orderly
        // state will have to change if this is a state-saved PCR regardless
        // of the current state. This is because a subsequent Shutdown(STATE) will
        // check to see if there was an orderly shutdown and not do anything if
        // there was. So, this must indicate that a future Shutdown(STATE) has
        // something to do.
        if(gp.orderlyState != SHUTDOWN_NONE && PCRIsStateSaved(in->pcrHandle))
        {
            result = NvIsAvailable();
            if(result != TPM_RC_SUCCESS) return result;
            g_clearOrderly = TRUE;
        }
    }

// Command Output

    out->results.count = 0;

    for(i = 0; i < HASH_COUNT; i++)
    {
        hashAlg = CryptGetHashAlgByIndex(i);
        // Update last piece of data
        CryptUpdateDigest2B(&hashObject->state.hashState[i], &in->buffer.b);
        // Complete hash
        out->results.digests[out->results.count].hashAlg = hashAlg;
        CryptCompleteHash(&hashObject->state.hashState[i],
                          CryptGetHashDigestSize(hashAlg),
                          (BYTE *) &out->results.digests[out->results.count].digest);

        // Extend PCR
        if(in->pcrHandle != TPM_RH_NULL)
            PCRExtend(in->pcrHandle, hashAlg,
                      CryptGetHashDigestSize(hashAlg),
                      (BYTE *) &out->results.digests[out->results.count].digest);
        out->results.count++;
    }

// Internal Data Update

    // mark sequence object as evict so it will be flushed on the way out
    hashObject->attributes.evict = SET;

    return TPM_RC_SUCCESS;
}
#endif // CC_EventSequenceComplete
