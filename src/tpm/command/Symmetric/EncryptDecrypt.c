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
#include "EncryptDecrypt_fp.h"
#ifdef TPM_CC_EncryptDecrypt                   // Conditional expansion of this file

// M e
// TPM_RC_KEY is not a symmetric decryption key with both public and private
// portions loaded
// TPM_RC_SIZE IvIn size is incompatible with the block cipher mode; or inData size is
// not an even multiple of the block size for CBC or ECB mode
// TPM_RC_VALUE keyHandle is restricted and the argument mode does not match the
// key's mode

TPM_RC
TPM2_EncryptDecrypt(
    EncryptDecrypt_In *in,                     // IN: input parameter list
    EncryptDecrypt_Out *out                     // OUT: output parameter list
)
{
    OBJECT *symKey;
    UINT16 keySize;
    UINT16 blockSize;
    BYTE *key;
    TPM_ALG_ID alg;

// Input Validation
    symKey = ObjectGet(in->keyHandle);

    // The input key should be a symmetric decrypt key.
    if( symKey->publicArea.type != TPM_ALG_SYMCIPHER
            || symKey->attributes.publicOnly == SET)
        return TPM_RC_KEY + RC_EncryptDecrypt_keyHandle;

    // If the input mode is TPM_ALG_NULL, use the key's mode
    if( in->mode == TPM_ALG_NULL)
        in->mode = symKey->publicArea.parameters.symDetail.sym.mode.sym;

    // If the key is restricted, the input symmetric mode should match the key's
    // symmetric mode
    if( symKey->publicArea.objectAttributes.restricted == SET
            && symKey->publicArea.parameters.symDetail.sym.mode.sym != in->mode)
        return TPM_RC_VALUE + RC_EncryptDecrypt_mode;

    // If the mode is null, then we have a problem.
    // Note: Construction of a TPMT_SYM_DEF does not allow the 'mode' to be
    // TPM_ALG_NULL so setting in->mode to the mode of the key should have
    // produced a valid mode. However, this is suspenders.
    if(in->mode == TPM_ALG_NULL)
        return TPM_RC_VALUE + RC_EncryptDecrypt_mode;

    // The input iv for ECB mode should be null. All the other modes should
    // have an iv size same as encryption block size

    keySize = symKey->publicArea.parameters.symDetail.sym.keyBits.sym;
    alg = symKey->publicArea.parameters.symDetail.sym.algorithm;
    blockSize = CryptGetSymmetricBlockSize(alg, keySize);
    if( (in->mode == TPM_ALG_ECB && in->ivIn.t.size != 0)
            || (in->mode != TPM_ALG_ECB && in->ivIn.t.size != blockSize))
        return TPM_RC_SIZE + RC_EncryptDecrypt_ivIn;

    // The input data size of CBC mode or ECB mode must be an even multiple of
    // the symmetric algorithm's block size
    if( (in->mode == TPM_ALG_CBC || in->mode == TPM_ALG_ECB)
            && (in->inData.t.size % blockSize) != 0)
        return TPM_RC_SIZE + RC_EncryptDecrypt_inData;

    // Copy IV
    // Note: This is copied here so that the calls to the encrypt/decrypt functions
    // will modify the output buffer, not the input buffer
    out->ivOut = in->ivIn;

// Command Output

    key = symKey->sensitive.sensitive.sym.t.buffer;
    // For symmetric encryption, the cipher data size is the same as plain data
    // size.
    out->outData.t.size = in->inData.t.size;
    if(in->decrypt == YES)
    {
        // Decrypt data to output
        CryptSymmetricDecrypt(out->outData.t.buffer,
                              alg,
                              keySize, in->mode, key,
                              &(out->ivOut),
                              in->inData.t.size,
                              in->inData.t.buffer);
    }
    else
    {
        // Encrypt data to output
        CryptSymmetricEncrypt(out->outData.t.buffer,
                              alg,
                              keySize,
                              in->mode, key,
                              &(out->ivOut),
                              in->inData.t.size,
                              in->inData.t.buffer);
    }

    return TPM_RC_SUCCESS;
}
#endif // CC_EncryptDecrypt
