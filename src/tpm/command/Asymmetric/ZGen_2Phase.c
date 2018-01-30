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
#include "ZGen_2Phase_fp.h"
#ifdef TPM_CC_ZGen_2Phase           // Conditional expansion of this file

// M e
// TPM_RC_ATTRIBUTES key referenced by keyA is restricted or not a decrypt key
// TPM_RC_ECC_POINT inQsB or inQeB is not on the curve of the key reference by keyA
// TPM_RC_KEY key referenced by keyA is not an ECC key
// TPM_RC_SCHEME the scheme of the key referenced by keyA is not TPM_ALG_NULL,
// TPM_ALG_ECDH, TPM_ALG_ECMQV or TPM_ALG_SM2

TPM_RC
TPM2_ZGen_2Phase(
    ZGen_2Phase_In *in,                    // IN: input parameter list
    ZGen_2Phase_Out *out                    // OUT: output parameter list
)
{
    TPM_RC result;
    OBJECT *eccKey;
    TPM2B_ECC_PARAMETER r;
    TPM_ALG_ID scheme;

// Input Validation

    eccKey = ObjectGet(in->keyA);

    // keyA must be an ECC key
    if(eccKey->publicArea.type != TPM_ALG_ECC)
        return TPM_RC_KEY + RC_ZGen_2Phase_keyA;

    // keyA must not be restricted and must be a decrypt key
    if( eccKey->publicArea.objectAttributes.restricted == SET
            || eccKey->publicArea.objectAttributes.decrypt != SET
      )
        return TPM_RC_ATTRIBUTES + RC_ZGen_2Phase_keyA;

    // if the scheme of keyA is TPM_ALG_NULL, then use the input scheme; otherwise
    // the input scheme must be the same as the scheme of keyA
    scheme = eccKey->publicArea.parameters.asymDetail.scheme.scheme;
    if(scheme != TPM_ALG_NULL)
    {
        if(scheme != in->inScheme)
            return TPM_RC_SCHEME + RC_ZGen_2Phase_inScheme;
    }
    else
        scheme = in->inScheme;
    if(scheme == TPM_ALG_NULL)
        return TPM_RC_SCHEME + RC_ZGen_2Phase_inScheme;

    // Input points must be on the curve of keyA
    if(!CryptEccIsPointOnCurve(eccKey->publicArea.parameters.eccDetail.curveID,
                               &in->inQsB.t.point))
        return TPM_RC_ECC_POINT + RC_ZGen_2Phase_inQsB;

    if(!CryptEccIsPointOnCurve(eccKey->publicArea.parameters.eccDetail.curveID,
                               &in->inQeB.t.point))
        return TPM_RC_ECC_POINT + RC_ZGen_2Phase_inQeB;

    if(!CryptGenerateR(&r, &in->counter,
                       eccKey->publicArea.parameters.eccDetail.curveID,
                       NULL))
        return TPM_RC_VALUE + RC_ZGen_2Phase_counter;

// Command Output

    result = CryptEcc2PhaseKeyExchange(&out->outZ1.t.point,
                                       &out->outZ2.t.point,
                                       eccKey->publicArea.parameters.eccDetail.curveID,
                                       scheme,
                                       &eccKey->sensitive.sensitive.ecc,
                                       &r,
                                       &in->inQsB.t.point,
                                       &in->inQeB.t.point);
    if(result == TPM_RC_SCHEME)
        return TPM_RC_SCHEME + RC_ZGen_2Phase_inScheme;

    if(result == TPM_RC_SUCCESS)
        CryptEndCommit(in->counter);

    return result;
}
#endif
