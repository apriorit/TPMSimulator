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
#include "PolicyPCR_fp.h"
#ifdef TPM_CC_PolicyPCR              // Conditional expansion of this file

// M e
// TPM_RC_VALUE if provided, pcrDigest does not match the current PCR settings
// TPM_RC_PCR_CHANGED a previous TPM2_PolicyPCR() set pcrCounter and it has changed

TPM_RC
TPM2_PolicyPCR(
    PolicyPCR_In *in                    // IN: input parameter list
)
{
    SESSION *session;
    TPM2B_DIGEST pcrDigest;
    BYTE pcrs[sizeof(TPML_PCR_SELECTION)];
    UINT32 pcrSize;
    BYTE *buffer;
    TPM_CC commandCode = TPM_CC_PolicyPCR;
    HASH_STATE hashState;

// Input Validation

    // Get pointer to the session structure
    session = SessionGet(in->policySession);

    // Do validation for non trial session
    if(session->attributes.isTrialPolicy == CLEAR)
    {
        // Make sure that this is not going to invalidate a previous PCR check
        if(session->pcrCounter != 0 && session->pcrCounter != gr.pcrCounter)
            return TPM_RC_PCR_CHANGED;

        // Compute current PCR digest
        PCRComputeCurrentDigest(session->authHashAlg, &in->pcrs, &pcrDigest);

        // If the caller specified the PCR digest and it does not
        // match the current PCR settings, return an error..
        if(in->pcrDigest.t.size != 0)
        {
            if(!Memory2BEqual(&in->pcrDigest.b, &pcrDigest.b))
                return TPM_RC_VALUE + RC_PolicyPCR_pcrDigest;
        }
    }
    else
    {
        // For trial session, just use the input PCR digest
        pcrDigest = in->pcrDigest;
    }
// Internal Data Update

    // Update policy hash
    // policyDigestnew = hash( policyDigestold || TPM_CC_PolicyPCR
    // || pcrs || pcrDigest)
    // Start hash
    CryptStartHash(session->authHashAlg, &hashState);

    // add old digest
    CryptUpdateDigest2B(&hashState, &session->u2.policyDigest.b);

    // add commandCode
    CryptUpdateDigestInt(&hashState, sizeof(TPM_CC), &commandCode);

    // add PCRS
    buffer = pcrs;
    pcrSize = TPML_PCR_SELECTION_Marshal(&in->pcrs, &buffer, NULL);
    CryptUpdateDigest(&hashState, pcrSize, pcrs);

    // add PCR digest
    CryptUpdateDigest2B(&hashState, &pcrDigest.b);

    // complete the hash and get the results
    CryptCompleteHash2B(&hashState, &session->u2.policyDigest.b);

    // update pcrCounter in session context for non trial session
    if(session->attributes.isTrialPolicy == CLEAR)
    {
        session->pcrCounter = gr.pcrCounter;
    }

    return TPM_RC_SUCCESS;
}
#endif // CC_PolicyPCR
