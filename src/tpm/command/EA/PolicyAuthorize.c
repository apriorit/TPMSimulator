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
#include "PolicyAuthorize_fp.h"
#ifdef TPM_CC_PolicyAuthorize                // Conditional expansion of this file
#include "Policy_spt_fp.h"

// M e
// TPM_RC_HASH hash algorithm in keyName is not supported
// TPM_RC_SIZE keyName is not the correct size for its hash algorithm
// TPM_RC_VALUE the current policyDigest of policySession does not match
// approvedPolicy; or checkTicket doesn't match the provided values

TPM_RC
TPM2_PolicyAuthorize(
    PolicyAuthorize_In *in                       // IN: input parameter list
)
{
    SESSION *session;
    TPM2B_DIGEST authHash;
    HASH_STATE hashState;
    TPMT_TK_VERIFIED ticket;
    TPM_ALG_ID hashAlg;
    UINT16 digestSize;

// Input Validation

    // Get pointer to the session structure
    session = SessionGet(in->policySession);

    // Extract from the Name of the key, the algorithm used to compute it's Name
    hashAlg = BYTE_ARRAY_TO_UINT16(in->keySign.t.name);

    // 'keySign' parameter needs to use a supported hash algorithm, otherwise
    // can't tell how large the digest should be
    digestSize = CryptGetHashDigestSize(hashAlg);
    if(digestSize == 0)
        return TPM_RC_HASH + RC_PolicyAuthorize_keySign;

    if(digestSize != (in->keySign.t.size - 2))
        return TPM_RC_SIZE + RC_PolicyAuthorize_keySign;

    //If this is a trial policy, skip all validations
    if(session->attributes.isTrialPolicy == CLEAR)
    {
        // Check that "approvedPolicy" matches the current value of the
        // policyDigest in policy session
        if(!Memory2BEqual(&session->u2.policyDigest.b,
                          &in->approvedPolicy.b))
            return TPM_RC_VALUE + RC_PolicyAuthorize_approvedPolicy;

        // Validate ticket TPMT_TK_VERIFIED
        // Compute aHash. The authorizing object sign a digest
        // aHash := hash(approvedPolicy || policyRef).
        // Start hash
        authHash.t.size = CryptStartHash(hashAlg, &hashState);

        // add approvedPolicy
        CryptUpdateDigest2B(&hashState, &in->approvedPolicy.b);

        // add policyRef
        CryptUpdateDigest2B(&hashState, &in->policyRef.b);

        // complete hash
        CryptCompleteHash2B(&hashState, &authHash.b);

        // re-compute TPMT_TK_VERIFIED
        TicketComputeVerified(in->checkTicket.hierarchy, &authHash,
                              &in->keySign, &ticket);

        // Compare ticket digest. If not match, return error
        if(!Memory2BEqual(&in->checkTicket.digest.b, &ticket.digest.b))
            return TPM_RC_VALUE+ RC_PolicyAuthorize_checkTicket;
    }

// Internal Data Update

    // Set policyDigest to zero digest
    MemorySet(session->u2.policyDigest.t.buffer, 0,
              session->u2.policyDigest.t.size);

    // Update policyDigest
    PolicyContextUpdate(TPM_CC_PolicyAuthorize, &in->keySign, &in->policyRef,
                        NULL, 0, session);

    return TPM_RC_SUCCESS;

}
#endif // CC_PolicyAuthorize
