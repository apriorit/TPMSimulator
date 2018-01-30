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
#include "Rewrap_fp.h"
#ifdef TPM_CC_Rewrap        // Conditional expansion of this file
#include "Object_spt_fp.h"

// M e
// TPM_RC_ATTRIBUTES newParent is not a decryption key
// TPM_RC_HANDLE oldParent does not consistent with inSymSeed
// TPM_RC_INTEGRITY the integrity check of inDuplicate failed
// TPM_RC_KEY for an ECC key, the public key is not on the curve of the curve ID
// TPM_RC_KEY_SIZE the decrypted input symmetric key size does not matches the
// symmetric algorithm key size of oldParent
// TPM_RC_TYPE oldParent is not a storage key, or 'newParent is not a storage key
// TPM_RC_VALUE for an 'oldParent; RSA key, the data to be decrypted is greater than
// the public exponent
// Unmarshal errors errors during unmarshaling the input encrypted buffer to a ECC public
// key, or unmarshal the private buffer to sensitive

TPM_RC
TPM2_Rewrap(
    Rewrap_In *in,                    // IN: input parameter list
    Rewrap_Out *out                    // OUT: output parameter list
)
{
    TPM_RC result = TPM_RC_SUCCESS;
    OBJECT *oldParent;
    TPM2B_DATA data;                            // symmetric key
    UINT16 hashSize = 0;
    TPM2B_PRIVATE privateBlob;                     // A temporary private blob
    // to transit between old
    // and new wrappers

// Input Validation

    if((in->inSymSeed.t.size == 0 && in->oldParent != TPM_RH_NULL)
            || (in->inSymSeed.t.size != 0 && in->oldParent == TPM_RH_NULL))
        return TPM_RC_HANDLE + RC_Rewrap_oldParent;

    if(in->oldParent != TPM_RH_NULL)
    {
        // Get old parent pointer
        oldParent = ObjectGet(in->oldParent);

        // old parent key must be a storage object
        if(!ObjectIsStorage(in->oldParent))
            return TPM_RC_TYPE + RC_Rewrap_oldParent;

        // Decrypt input secret data via asymmetric decryption. A
        // TPM_RC_VALUE, TPM_RC_KEY or unmarshal errors may be returned at this
        // point
        result = CryptSecretDecrypt(in->oldParent, NULL,
                                    "DUPLICATE", &in->inSymSeed, &data);
        if(result != TPM_RC_SUCCESS)
            return TPM_RC_VALUE + RC_Rewrap_inSymSeed;

        // Unwrap Outer
        result = UnwrapOuter(in->oldParent, &in->name,
                             oldParent->publicArea.nameAlg, (TPM2B_SEED *) &data,
                             FALSE,
                             in->inDuplicate.t.size, in->inDuplicate.t.buffer);
        if(result != TPM_RC_SUCCESS)
            return RcSafeAddToResult(result, RC_Rewrap_inDuplicate);

        // Copy unwrapped data to temporary variable, remove the integrity field
        hashSize = sizeof(UINT16) +
                   CryptGetHashDigestSize(oldParent->publicArea.nameAlg);
        privateBlob.t.size = in->inDuplicate.t.size - hashSize;
        MemoryCopy(privateBlob.t.buffer, in->inDuplicate.t.buffer + hashSize,
                   privateBlob.t.size, sizeof(privateBlob.t.buffer));
    }
    else
    {
        // No outer wrap from input blob. Direct copy.
        privateBlob = in->inDuplicate;
    }

    if(in->newParent != TPM_RH_NULL)
    {
        OBJECT *newParent;
        newParent = ObjectGet(in->newParent);

        // New parent must be a storage object
        if(!ObjectIsStorage(in->newParent))
            return TPM_RC_TYPE + RC_Rewrap_newParent;

        // Make new encrypt key and its associated secret structure. A
        // TPM_RC_VALUE error may be returned at this point if RSA algorithm is
        // enabled in TPM
        out->outSymSeed.t.size = sizeof(out->outSymSeed.t.secret);
        result = CryptSecretEncrypt(in->newParent,
                                    "DUPLICATE", &data, &out->outSymSeed);
        if(result != TPM_RC_SUCCESS) return result;

// Command output
        // Copy temporary variable to output, reserve the space for integrity
        hashSize = sizeof(UINT16) +
                   CryptGetHashDigestSize(newParent->publicArea.nameAlg);
        out->outDuplicate.t.size = privateBlob.t.size;
        MemoryCopy(out->outDuplicate.t.buffer + hashSize, privateBlob.t.buffer,
                   privateBlob.t.size, sizeof(out->outDuplicate.t.buffer));

        // Produce outer wrapper for output
        out->outDuplicate.t.size = ProduceOuterWrap(in->newParent, &in->name,
                                   newParent->publicArea.nameAlg,
                                   (TPM2B_SEED *) &data,
                                   FALSE,
                                   out->outDuplicate.t.size,
                                   out->outDuplicate.t.buffer);

    }
    else      // New parent is a null key so there is no seed
    {
        out->outSymSeed.t.size = 0;

        // Copy privateBlob directly
        out->outDuplicate = privateBlob;
    }

    return TPM_RC_SUCCESS;
}
#endif // CC_Rewrap
