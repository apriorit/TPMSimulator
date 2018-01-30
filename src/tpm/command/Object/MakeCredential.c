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
#include "MakeCredential_fp.h"
#ifdef TPM_CC_MakeCredential                // Conditional expansion of this file
#include "Object_spt_fp.h"

// M e
// TPM_RC_KEY handle referenced an ECC key that has a unique field that is not a
// point on the curve of the key
// TPM_RC_SIZE credential is larger than the digest size of Name algorithm of handle
// TPM_RC_TYPE handle does not reference an asymmetric decryption key

TPM_RC
TPM2_MakeCredential(
    MakeCredential_In *in,                // IN: input parameter list
    MakeCredential_Out *out                // OUT: output parameter list
)
{
    TPM_RC result = TPM_RC_SUCCESS;

    OBJECT *object;
    TPM2B_DATA data;

// Input Validation

    // Get object pointer
    object = ObjectGet(in->handle);

    // input key must be an asymmetric, restricted decryption key
    // NOTE: Needs to be restricted to have a symmetric value.
    if( !CryptIsAsymAlgorithm(object->publicArea.type)
            || object->publicArea.objectAttributes.decrypt == CLEAR
            || object->publicArea.objectAttributes.restricted == CLEAR
      )
        return TPM_RC_TYPE + RC_MakeCredential_handle;

    // The credential information may not be larger than the digest size used for
    // the Name of the key associated with handle.
    if(in->credential.t.size > CryptGetHashDigestSize(object->publicArea.nameAlg))
        return TPM_RC_SIZE + RC_MakeCredential_credential;

// Command Output

    // Make encrypt key and its associated secret structure.
    // Even though CrypeSecretEncrypt() may return
    out->secret.t.size = sizeof(out->secret.t.secret);
    result = CryptSecretEncrypt(in->handle, "IDENTITY", &data, &out->secret);
    if(result != TPM_RC_SUCCESS)
        return result;

    // Prepare output credential data from secret
    SecretToCredential(&in->credential, &in->objectName, (TPM2B_SEED *) &data,
                       in->handle, &out->credentialBlob);

    return TPM_RC_SUCCESS;
}
#endif // CC_MakeCredential
