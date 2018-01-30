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
#include "ActivateCredential_fp.h"
#ifdef TPM_CC_ActivateCredential             // Conditional expansion of this file
#include "Object_spt_fp.h"

// M e
// TPM_RC_ATTRIBUTES keyHandle does not reference a decryption key
// TPM_RC_ECC_POINT secret is invalid (when keyHandle is an ECC key)
// TPM_RC_INSUFFICIENT secret is invalid (when keyHandle is an ECC key)
// TPM_RC_INTEGRITY credentialBlob fails integrity test
// TPM_RC_NO_RESULT secret is invalid (when keyHandle is an ECC key)
// TPM_RC_SIZE secret size is invalid or the credentialBlob does not unmarshal
// correctly
// TPM_RC_TYPE keyHandle does not reference an asymmetric key.
// TPM_RC_VALUE secret is invalid (when keyHandle is an RSA key)

TPM_RC
TPM2_ActivateCredential(
    ActivateCredential_In *in,                     // IN: input parameter list
    ActivateCredential_Out *out                     // OUT: output parameter list
)
{
    TPM_RC result = TPM_RC_SUCCESS;
    OBJECT *object;             // decrypt key
    OBJECT *activateObject;// key associated with
    // credential
    TPM2B_DATA data;                // credential data

// Input Validation

    // Get decrypt key pointer
    object = ObjectGet(in->keyHandle);

    // Get certificated object pointer
    activateObject = ObjectGet(in->activateHandle);

    // input decrypt key must be an asymmetric, restricted decryption key
    if( !CryptIsAsymAlgorithm(object->publicArea.type)
            || object->publicArea.objectAttributes.decrypt == CLEAR
            || object->publicArea.objectAttributes.restricted == CLEAR)
        return TPM_RC_TYPE + RC_ActivateCredential_keyHandle;

// Command output

    // Decrypt input credential data via asymmetric decryption. A
    // TPM_RC_VALUE, TPM_RC_KEY or unmarshal errors may be returned at this
    // point
    result = CryptSecretDecrypt(in->keyHandle, NULL,
                                "IDENTITY", &in->secret, &data);
    if(result != TPM_RC_SUCCESS)
    {
        if(result == TPM_RC_KEY)
            return TPM_RC_FAILURE;
        return RcSafeAddToResult(result, RC_ActivateCredential_secret);
    }

    // Retrieve secret data. A TPM_RC_INTEGRITY error or unmarshal
    // errors may be returned at this point
    result = CredentialToSecret(&in->credentialBlob,
                                &activateObject->name,
                                (TPM2B_SEED *) &data,
                                in->keyHandle,
                                &out->certInfo);
    if(result != TPM_RC_SUCCESS)
        return RcSafeAddToResult(result,RC_ActivateCredential_credentialBlob);

    return TPM_RC_SUCCESS;
}
#endif // CC_ActivateCredential
