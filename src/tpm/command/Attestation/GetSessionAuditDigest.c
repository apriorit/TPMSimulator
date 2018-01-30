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
#include "Attest_spt_fp.h"
#include "GetSessionAuditDigest_fp.h"
#ifdef TPM_CC_GetSessionAuditDigest           // Conditional expansion of this file

// M e
// TPM_RC_KEY key referenced by signHandle is not a signing key
// TPM_RC_SCHEME inScheme is incompatible with signHandle type; or both scheme and
// key's default scheme are empty; or scheme is empty while key's
// default scheme requires explicit input scheme (split signing); or non-
// empty default key scheme differs from scheme
// TPM_RC_TYPE sessionHandle does not reference an audit session
// TPM_RC_VALUE digest generated for the given scheme is greater than the modulus of
// signHandle (for an RSA key); invalid commit status or failed to
// generate r value (for an ECC key)

TPM_RC
TPM2_GetSessionAuditDigest(
    GetSessionAuditDigest_In *in,        // IN: input parameter list
    GetSessionAuditDigest_Out *out        // OUT: output parameter list
)
{
    TPM_RC result;
    SESSION *session;
    TPMS_ATTEST auditInfo;

// Input Validation

    // SessionAuditDigest specific input validation
    // Get session pointer
    session = SessionGet(in->sessionHandle);

    // session must be an audit session
    if(session->attributes.isAudit == CLEAR)
        return TPM_RC_TYPE + RC_GetSessionAuditDigest_sessionHandle;

// Command Output

    // Filling in attest information
    // Common fields
    result = FillInAttestInfo(in->signHandle,
                              &in->inScheme,
                              &in->qualifyingData,
                              &auditInfo);
    if(result != TPM_RC_SUCCESS)
    {
        if(result == TPM_RC_KEY)
            return TPM_RC_KEY + RC_GetSessionAuditDigest_signHandle;
        else
            return RcSafeAddToResult(result, RC_GetSessionAuditDigest_inScheme);
    }

    // SessionAuditDigest specific fields
    // Attestation type
    auditInfo.type = TPM_ST_ATTEST_SESSION_AUDIT;

    // Copy digest
    auditInfo.attested.sessionAudit.sessionDigest = session->u2.auditDigest;

    // Exclusive audit session
    if(g_exclusiveAuditSession == in->sessionHandle)
        auditInfo.attested.sessionAudit.exclusiveSession = TRUE;
    else
        auditInfo.attested.sessionAudit.exclusiveSession = FALSE;

    // Sign attestation structure. A NULL signature will be returned if
    // signHandle is TPM_RH_NULL. A TPM_RC_NV_UNAVAILABLE, TPM_RC_NV_RATE,
    // TPM_RC_VALUE, TPM_RC_SCHEME or TPM_RC_ATTRIBUTES error may be returned at
    // this point
    result = SignAttestInfo(in->signHandle,
                            &in->inScheme,
                            &auditInfo,
                            &in->qualifyingData,
                            &out->auditInfo,
                            &out->signature);
    if(result != TPM_RC_SUCCESS)
        return result;

    // orderly state should be cleared because of the reporting of clock info
    // if signing happens
    if(in->signHandle != TPM_RH_NULL)
        g_clearOrderly = TRUE;

    return TPM_RC_SUCCESS;
}
#endif // CC_GetSessionAuditDigest
