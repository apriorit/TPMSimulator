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
#include "RSA_Encrypt_fp.h"
#ifdef TPM_CC_RSA_Encrypt             // Conditional expansion of this file
#ifdef TPM_ALG_RSA

// M e
// TPM_RC_ATTRIBUTES decrypt attribute is not SET in key referenced by keyHandle
// TPM_RC_KEY keyHandle does not reference an RSA key
// TPM_RC_SCHEME incorrect input scheme, or the chosen scheme is not a valid RSA
// decrypt scheme
// TPM_RC_VALUE the numeric value of message is greater than the public modulus of
// the key referenced by keyHandle, or label is not a null-terminated
// string

TPM_RC
TPM2_RSA_Encrypt(
    RSA_Encrypt_In *in,                       // IN: input parameter list
    RSA_Encrypt_Out *out                       // OUT: output parameter list
)
{
    TPM_RC result;
    OBJECT *rsaKey;
    TPMT_RSA_DECRYPT *scheme;
    char *label = NULL;

// Input Validation

    rsaKey = ObjectGet(in->keyHandle);

    // selected key must be an RSA key
    if(rsaKey->publicArea.type != TPM_ALG_RSA)
        return TPM_RC_KEY + RC_RSA_Encrypt_keyHandle;

    // selected key must have the decryption attribute
    if(rsaKey->publicArea.objectAttributes.decrypt != SET)
        return TPM_RC_ATTRIBUTES + RC_RSA_Encrypt_keyHandle;

    // Is there a label?
    if(in->label.t.size > 0)
    {
        // label is present, so make sure that is it NULL-terminated
        if(in->label.t.buffer[in->label.t.size - 1] != 0)
            return TPM_RC_VALUE + RC_RSA_Encrypt_label;
        label = (char *)in->label.t.buffer;
    }

// Command Output

    // Select a scheme for encryption
    scheme = CryptSelectRSAScheme(in->keyHandle, &in->inScheme);
    if(scheme == NULL)
        return TPM_RC_SCHEME + RC_RSA_Encrypt_inScheme;

    // Encryption. TPM_RC_VALUE, or TPM_RC_SCHEME errors my be returned buy
    // CryptEncyptRSA. Note: It can also return TPM_RC_ATTRIBUTES if the key does
    // not have the decrypt attribute but that was checked above.
    out->outData.t.size = sizeof(out->outData.t.buffer);
    result = CryptEncryptRSA(&out->outData.t.size, out->outData.t.buffer, rsaKey,
                             scheme, in->message.t.size, in->message.t.buffer,
                             label);
    return result;
}
#endif
#endif // CC_RSA_Encrypt
