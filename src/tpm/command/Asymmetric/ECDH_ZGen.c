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
#include "ECDH_ZGen_fp.h"
#ifdef TPM_CC_ECDH_ZGen          // Conditional expansion of this file
#ifdef TPM_ALG_ECC

// M e
// TPM_RC_ATTRIBUTES key referenced by keyA is restricted or not a decrypt key
// TPM_RC_KEY key referenced by keyA is not an ECC key
// TPM_RC_NO_RESULT multiplying inPoint resulted in a point at infinity
// TPM_RC_SCHEME the scheme of the key referenced by keyA is not TPM_ALG_NULL,
// TPM_ALG_ECDH,

TPM_RC
TPM2_ECDH_ZGen(
    ECDH_ZGen_In *in,                   // IN: input parameter list
    ECDH_ZGen_Out *out                   // OUT: output parameter list
)
{
    TPM_RC result;
    OBJECT *eccKey;

// Input Validation

    eccKey = ObjectGet(in->keyHandle);

    // Input key must be a non-restricted, decrypt ECC key
    if( eccKey->publicArea.type != TPM_ALG_ECC)
        return TPM_RCS_KEY + RC_ECDH_ZGen_keyHandle;

    if( eccKey->publicArea.objectAttributes.restricted == SET
            || eccKey->publicArea.objectAttributes.decrypt != SET
      )
        return TPM_RC_KEY + RC_ECDH_ZGen_keyHandle;

    // Make sure the scheme allows this use
    if( eccKey->publicArea.parameters.eccDetail.scheme.scheme != TPM_ALG_ECDH
            && eccKey->publicArea.parameters.eccDetail.scheme.scheme != TPM_ALG_NULL)
        return TPM_RC_SCHEME + RC_ECDH_ZGen_keyHandle;

// Command Output

    // Compute Z. TPM_RC_ECC_POINT or TPM_RC_NO_RESULT may be returned here.
    result = CryptEccPointMultiply(&out->outPoint.t.point,
                                   eccKey->publicArea.parameters.eccDetail.curveID,
                                   &eccKey->sensitive.sensitive.ecc,
                                   &in->inPoint.t.point);
    if(result != TPM_RC_SUCCESS)
        return RcSafeAddToResult(result, RC_ECDH_ZGen_inPoint);

    out->outPoint.t.size = TPMS_ECC_POINT_Marshal(&out->outPoint.t.point,
                           NULL, NULL);

    return TPM_RC_SUCCESS;
}
#endif
#endif // CC_ECDH_ZGen
