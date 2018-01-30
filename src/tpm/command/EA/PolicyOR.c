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
#include "PolicyOR_fp.h"
#ifdef TPM_CC_PolicyOR            // Conditional expansion of this file
#include "Policy_spt_fp.h"

// M e
// TPM_RC_VALUE no digest in pHashList matched the current value of policyDigest for
// policySession

TPM_RC
TPM2_PolicyOR(
    PolicyOR_In *in                   // IN: input parameter list
)
{
    SESSION *session;
    UINT32 i;

// Input Validation and Update

    // Get pointer to the session structure
    session = SessionGet(in->policySession);

    // Compare and Update Internal Session policy if match
    for(i = 0; i < in->pHashList.count; i++)
    {
        if( session->attributes.isTrialPolicy == SET
                || (Memory2BEqual(&session->u2.policyDigest.b,
                                  &in->pHashList.digests[i].b))
          )
        {
            // Found a match
            HASH_STATE hashState;
            TPM_CC commandCode = TPM_CC_PolicyOR;

            // Start hash
            session->u2.policyDigest.t.size = CryptStartHash(session->authHashAlg,
                                              &hashState);
            // Set policyDigest to 0 string and add it to hash
            MemorySet(session->u2.policyDigest.t.buffer, 0,
                      session->u2.policyDigest.t.size);
            CryptUpdateDigest2B(&hashState, &session->u2.policyDigest.b);

            // add command code
            CryptUpdateDigestInt(&hashState, sizeof(TPM_CC), &commandCode);

            // Add each of the hashes in the list
            for(i = 0; i < in->pHashList.count; i++)
            {
                // Extend policyDigest
                CryptUpdateDigest2B(&hashState, &in->pHashList.digests[i].b);
            }
            // Complete digest
            CryptCompleteHash2B(&hashState, &session->u2.policyDigest.b);

            return TPM_RC_SUCCESS;
        }
    }
    // None of the values in the list matched the current policyDigest
    return TPM_RC_VALUE + RC_PolicyOR_pHashList;
}
#endif // CC_PolicyOR
