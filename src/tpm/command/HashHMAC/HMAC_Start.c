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
#include "HMAC_Start_fp.h"
#ifdef TPM_CC_HMAC_Start                  // Conditional expansion of this file

// M e
// TPM_RC_ATTRIBUTES key referenced by handle is not a signing key or is restricted
// TPM_RC_OBJECT_MEMORY no space to create an internal object
// TPM_RC_KEY key referenced by handle is not an HMAC key
// TPM_RC_VALUE hashAlg is not compatible with the hash algorithm of the scheme of
// the object referenced by handle

TPM_RC
TPM2_HMAC_Start(
    HMAC_Start_In *in,                        // IN: input parameter list
    HMAC_Start_Out *out                        // OUT: output parameter list
)
{
    OBJECT *hmacObject;
    TPMT_PUBLIC *publicArea;
    TPM_ALG_ID hashAlg;

// Input Validation

    // Get HMAC key object and public area pointers
    hmacObject = ObjectGet(in->handle);
    publicArea = &hmacObject->publicArea;

    // Make sure that the key is an HMAC key
    if(publicArea->type != TPM_ALG_KEYEDHASH)
        return TPM_RCS_TYPE + RC_HMAC_Start_handle;

    // and that it is unrestricted
    if(publicArea->objectAttributes.restricted == SET)
        return TPM_RCS_ATTRIBUTES + RC_HMAC_Start_handle;

    // and that it is a signing key
    if(publicArea->objectAttributes.sign != SET)
        return TPM_RCS_KEY + RC_HMAC_Start_handle;

    // See if the key has a default
    if(publicArea->parameters.keyedHashDetail.scheme.scheme == TPM_ALG_NULL)
        // it doesn't so use the input value
        hashAlg = in->hashAlg;
    else
    {
        // key has a default so use it
        hashAlg
            = publicArea->parameters.keyedHashDetail.scheme.details.hmac.hashAlg;
        // and verify that the input was either the TPM_ALG_NULL or the default
        if(in->hashAlg != TPM_ALG_NULL && in->hashAlg != hashAlg)
            hashAlg = TPM_ALG_NULL;
    }
    // if we ended up without a hash algorith then return an error
    if(hashAlg == TPM_ALG_NULL)
        return TPM_RCS_VALUE + RC_HMAC_Start_hashAlg;

// Internal Data Update

    // Create a HMAC sequence object. A TPM_RC_OBJECT_MEMORY error may be
    // returned at this point
    return ObjectCreateHMACSequence(hashAlg,
                                    in->handle,
                                    &in->auth,
                                    &out->sequenceHandle);
}
#endif // CC_HMAC_Start
