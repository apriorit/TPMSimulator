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
#include "PolicySecret_fp.h"
#ifdef TPM_CC_PolicySecret              // Conditional expansion of this file
#include "Policy_spt_fp.h"

// M e
// TPM_RC_CPHASH cpHash for policy was previously set to a value that is not the same
// as cpHashA
// TPM_RC_EXPIRED expiration indicates a time in the past
// TPM_RC_NONCE nonceTPM does not match the nonce associated with policySession
// TPM_RC_SIZE cpHashA is not the size of a digest for the hash associated with
// policySession
// TPM_RC_VALUE input policyID or expiration does not match the internal data in policy
// session

TPM_RC
TPM2_PolicySecret(
    PolicySecret_In *in,                 // IN: input parameter list
    PolicySecret_Out *out                 // OUT: output parameter list
)
{
    TPM_RC result;
    SESSION *session;
    TPM2B_NAME entityName;
    UINT32 expiration = (in->expiration < 0)
                        ? -(in->expiration) : in->expiration;
    UINT64 authTimeout = 0;

// Input Validation

    // Get pointer to the session structure
    session = SessionGet(in->policySession);

    //Only do input validation if this is not a trial policy session
    if(session->attributes.isTrialPolicy == CLEAR)
    {

        if(expiration != 0)
            authTimeout = expiration * 1000 + session->startTime;

        result = PolicyParameterChecks(session, authTimeout,
                                       &in->cpHashA, &in->nonceTPM,
                                       RC_PolicySecret_nonceTPM,
                                       RC_PolicySecret_cpHashA,
                                       RC_PolicySecret_expiration);
        if(result != TPM_RC_SUCCESS)
            return result;
    }

// Internal Data Update
    // Need the name of the authorizing entity
    entityName.t.size = EntityGetName(in->authHandle, &entityName.t.name);

    // Update policy context with input policyRef and name of auth key
    // This value is computed even for trial sessions. Possibly update the cpHash
    PolicyContextUpdate(TPM_CC_PolicySecret, &entityName, &in->policyRef,
                        &in->cpHashA, authTimeout, session);

// Command Output

    // Create ticket and timeout buffer if in->expiration < 0 and this is not
    // a trial session.
    // NOTE: PolicyParameterChecks() makes sure that nonceTPM is present
    // when expiration is non-zero.
    if( in->expiration < 0
            && session->attributes.isTrialPolicy == CLEAR
      )
    {
        // Generate timeout buffer. The format of output timeout buffer is
        // TPM-specific.
        // Note: can't do a direct copy because the output buffer is a byte
        // array and it may not be aligned to accept a 64-bit value. The method
        // used has the side-effect of making the returned value a big-endian,
        // 64-bit value that is byte aligned.
        out->timeout.t.size = sizeof(UINT64);
        UINT64_TO_BYTE_ARRAY(authTimeout, out->timeout.t.buffer);

        // Compute policy ticket
        TicketComputeAuth(TPM_ST_AUTH_SECRET, EntityGetHierarchy(in->authHandle),
                          authTimeout, &in->cpHashA, &in->policyRef,
                          &entityName, &out->policyTicket);
    }
    else
    {
        // timeout buffer is null
        out->timeout.t.size = 0;

        // auth ticket is null
        out->policyTicket.tag = TPM_ST_AUTH_SECRET;
        out->policyTicket.hierarchy = TPM_RH_NULL;
        out->policyTicket.digest.t.size = 0;
    }

    return TPM_RC_SUCCESS;
}
#endif // CC_PolicySecret
