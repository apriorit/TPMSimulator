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
#include "VerifySignature_fp.h"
#ifdef TPM_CC_VerifySignature               // Conditional expansion of this file

// M e
// TPM_RC_ATTRIBUTES keyHandle does not reference a signing key
// TPM_RC_SIGNATURE signature is not genuine
// TPM_RC_SCHEME CryptVerifySignature()
// TPM_RC_HANDLE the input handle is references an HMAC key but the private portion is
// not loaded

TPM_RC
TPM2_VerifySignature(
    VerifySignature_In *in,                    // IN: input parameter list
    VerifySignature_Out *out                    // OUT: output parameter list
)
{
    TPM_RC result;
    TPM2B_NAME name;
    OBJECT *signObject;
    TPMI_RH_HIERARCHY hierarchy;

// Input Validation

    // Get sign object pointer
    signObject = ObjectGet(in->keyHandle);

    // The object to validate the signature must be a signing key.
    if(signObject->publicArea.objectAttributes.sign != SET)
        return TPM_RC_ATTRIBUTES + RC_VerifySignature_keyHandle;

    // Validate Signature. TPM_RC_SCHEME, TPM_RC_HANDLE or TPM_RC_SIGNATURE
    // error may be returned by CryptCVerifySignatrue()
    result = CryptVerifySignature(in->keyHandle, &in->digest, &in->signature);
    if(result != TPM_RC_SUCCESS)
        return RcSafeAddToResult(result, RC_VerifySignature_signature);

// Command Output

    hierarchy = ObjectGetHierarchy(in->keyHandle);
    if( hierarchy == TPM_RH_NULL
            || signObject->publicArea.nameAlg == TPM_ALG_NULL)
    {
        // produce empty ticket if hierarchy is TPM_RH_NULL or nameAlg is
        // TPM_ALG_NULL
        out->validation.tag = TPM_ST_VERIFIED;
        out->validation.hierarchy = TPM_RH_NULL;
        out->validation.digest.t.size = 0;
    }
    else
    {
        // Get object name that verifies the signature
        name.t.size = ObjectGetName(in->keyHandle, &name.t.name);
        // Compute ticket
        TicketComputeVerified(hierarchy, &in->digest, &name, &out->validation);
    }

    return TPM_RC_SUCCESS;
}
#endif // CC_VerifySignature
