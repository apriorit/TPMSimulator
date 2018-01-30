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
#include "SetPrimaryPolicy_fp.h"
#ifdef TPM_CC_SetPrimaryPolicy               // Conditional expansion of this file

// M e
// TPM_RC_SIZE size of input authPolicy is not consistent with input hash algorithm

TPM_RC
TPM2_SetPrimaryPolicy(
    SetPrimaryPolicy_In *in                  // IN: input parameter list
)
{
    TPM_RC result;

// Input Validation

    // Check the authPolicy consistent with hash algorithm. If the policy size is
    // zero, then the algorithm is required to be TPM_ALG_NULL
    if(in->authPolicy.t.size != CryptGetHashDigestSize(in->hashAlg))
        return TPM_RC_SIZE + RC_SetPrimaryPolicy_authPolicy;

    // The command need NV update for OWNER and ENDORSEMENT hierarchy, and
    // might need orderlyState update for PLATFROM hierarchy.
    // Check if NV is available. A TPM_RC_NV_UNAVAILABLE or TPM_RC_NV_RATE
    // error may be returned at this point
    result = NvIsAvailable();
    if(result != TPM_RC_SUCCESS)
        return result;

// Internal Data Update

    // Set hierarchy policy
    switch(in->authHandle)
    {
    case TPM_RH_OWNER:
        gp.ownerAlg = in->hashAlg;
        gp.ownerPolicy = in->authPolicy;
        NvWriteReserved(NV_OWNER_ALG, &gp.ownerAlg);
        NvWriteReserved(NV_OWNER_POLICY, &gp.ownerPolicy);
        break;
    case TPM_RH_ENDORSEMENT:
        gp.endorsementAlg = in->hashAlg;
        gp.endorsementPolicy = in->authPolicy;
        NvWriteReserved(NV_ENDORSEMENT_ALG, &gp.endorsementAlg);
        NvWriteReserved(NV_ENDORSEMENT_POLICY, &gp.endorsementPolicy);
        break;
    case TPM_RH_PLATFORM:
        gc.platformAlg = in->hashAlg;
        gc.platformPolicy = in->authPolicy;
        // need to update orderly state
        g_clearOrderly = TRUE;
        break;
    case TPM_RH_LOCKOUT:
        gp.lockoutAlg = in->hashAlg;
        gp.lockoutPolicy = in->authPolicy;
        NvWriteReserved(NV_LOCKOUT_ALG, &gp.lockoutAlg);
        NvWriteReserved(NV_LOCKOUT_POLICY, &gp.lockoutPolicy);
        break;

    default:
        pAssert(FALSE);
        break;
    }

    return TPM_RC_SUCCESS;
}
#endif // CC_SetPrimaryPolicy
