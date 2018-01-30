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
#include "Import_fp.h"
#ifdef TPM_CC_Import     // Conditional expansion of this file
#include "Object_spt_fp.h"

// M e
// TPM_RC_ASYMMETRIC non-duplicable storage key represented by objectPublic and its
// parent referenced by parentHandle have different public parameters
// TPM_RC_ATTRIBUTES attributes FixedTPM and fixedParent of objectPublic are not both
// CLEAR; or inSymSeed is nonempty and parentHandle does not
// reference a decryption key; or objectPublic and parentHandle have
// incompatible or inconsistent attributes; or encrytpedDuplication is
// SET in objectPublic but the inner or outer wrapper is missing.
// NOTE: if the TPM provides parameter values, the parameter number will indicate symmetricKey
// (missing
// inner wrapper) or inSymSeed (missing outer wrapper).
// TPM_RC_BINDING duplicate and objectPublic are not cryptographically
// bound
// TPM_RC_ECC_POINT inSymSeed is nonempty and ECC point in inSymSeed is not on the
// curve
// TPM_RC_HASH non-duplicable storage key represented by objectPublic and its
// parent referenced by parentHandle have different name algorithm
// TPM_RC_INSUFFICIENT inSymSeed is nonempty and failed to retrieve ECC point from the
// secret; or unmarshaling sensitive value from duplicate failed the
// result of inSymSeed decryption
// TPM_RC_INTEGRITY duplicate integrity is broken
// TPM_RC_KDF objectPublic representing decrypting keyed hash object specifies
// invalid KDF
// TPM_RC_KEY inconsistent parameters of objectPublic; or inSymSeed is nonempty
// and parentHandle does not reference a key of supported type; or
// invalid key size in objectPublic representing an asymmetric key
// TPM_RC_NO_RESULT inSymSeed is nonempty and multiplication resulted in ECC point at
// infinity
// TPM_RC_OBJECT_MEMORY no available object slot
// TPM_RC_SCHEME inconsistent attributes decrypt, sign, restricted and key's scheme ID
// in objectPublic; or hash algorithm is inconsistent with the scheme ID
// for keyed hash object
// TPM_RC_SIZE authPolicy size does not match digest size of the name algorithm in
// objectPublic; or symmetricAlg and encryptionKey have different
// sizes; or inSymSeed is nonempty and it size is not consistent with the
// type of parentHandle; or unmarshaling sensitive value from duplicate
// failed
// TPM_RC_SYMMETRIC objectPublic is either a storage key with no symmetric algorithm or a
// non-storage key with symmetric algorithm different from
// TPM_ALG_NULL
// TPM_RC_TYPE unsupported type of objectPublic; or non-duplicable storage key
// represented by objectPublic and its parent referenced by
// parentHandle are of different types; or parentHandle is not a storage
// key; or only the public portion of parentHandle is loaded; or
// objectPublic and duplicate are of different types
// TPM_RC_VALUE nonempty inSymSeed and its numeric value is greater than the
// modulus of the key referenced by parentHandle or inSymSeed is
// larger than the size of the digest produced by the name algorithm of
// the symmetric key referenced by parentHandle

TPM_RC
TPM2_Import(
    Import_In *in,                    // IN: input parameter list
    Import_Out *out                    // OUT: output parameter list
)
{

    TPM_RC result = TPM_RC_SUCCESS;
    OBJECT *parentObject;
    TPM2B_DATA data;                                     // symmetric key
    TPMT_SENSITIVE sensitive;
    TPM2B_NAME name;

    UINT16 innerKeySize = 0;          // encrypt key size for inner
    // wrapper

// Input Validation

    // FixedTPM and fixedParent must be CLEAR
    if( in->objectPublic.t.publicArea.objectAttributes.fixedTPM == SET
            || in->objectPublic.t.publicArea.objectAttributes.fixedParent == SET)
        return TPM_RC_ATTRIBUTES + RC_Import_objectPublic;

    // Get parent pointer
    parentObject = ObjectGet(in->parentHandle);

    if(!AreAttributesForParent(parentObject))
        return TPM_RC_TYPE + RC_Import_parentHandle;

    if(in->symmetricAlg.algorithm != TPM_ALG_NULL)
    {
        // Get inner wrap key size
        innerKeySize = in->symmetricAlg.keyBits.sym;
        // Input symmetric key must match the size of algorithm.
        if(in->encryptionKey.t.size != (innerKeySize + 7)  / 8)
            return TPM_RC_SIZE + RC_Import_encryptionKey;
    }
    else
    {
        // If input symmetric algorithm is NULL, input symmetric key size must
        // be 0 as well
        if(in->encryptionKey.t.size != 0)
            return TPM_RCS_SIZE + RC_Import_encryptionKey;
        // If encryptedDuplication is SET, then the object must have an inner
        // wrapper
        if(in->objectPublic.t.publicArea.objectAttributes.encryptedDuplication)
            return TPM_RCS_ATTRIBUTES + RC_Import_encryptionKey;
    }

    // See if there is an outer wrapper
    if(in->inSymSeed.t.size != 0)
    {
        // Decrypt input secret data via asymmetric decryption. TPM_RC_ATTRIBUTES,
        // TPM_RC_ECC_POINT, TPM_RC_INSUFFICIENT, TPM_RC_KEY, TPM_RC_NO_RESULT,
        // TPM_RC_SIZE, TPM_RC_VALUE may be returned at this point
        result = CryptSecretDecrypt(in->parentHandle, NULL, "DUPLICATE",
                                    &in->inSymSeed, &data);
        pAssert(result != TPM_RC_BINDING);
        if(result != TPM_RC_SUCCESS)
            return RcSafeAddToResult(result, RC_Import_inSymSeed);
    }
    else
    {
        // If encrytpedDuplication is set, then the object must have an outer
        // wrapper
        if(in->objectPublic.t.publicArea.objectAttributes.encryptedDuplication)
            return TPM_RCS_ATTRIBUTES + RC_Import_inSymSeed;
        data.t.size = 0;
    }

    // Compute name of object
    ObjectComputeName(&(in->objectPublic.t.publicArea), &name);

    // Retrieve sensitive from private.
    // TPM_RC_INSUFFICIENT, TPM_RC_INTEGRITY, TPM_RC_SIZE may be returned here.
    result = DuplicateToSensitive(&in->duplicate, &name, in->parentHandle,
                                  in->objectPublic.t.publicArea.nameAlg,
                                  (TPM2B_SEED *) &data, &in->symmetricAlg,
                                  &in->encryptionKey, &sensitive);
    if(result != TPM_RC_SUCCESS)
        return RcSafeAddToResult(result, RC_Import_duplicate);

    // If the parent of this object has fixedTPM SET, then fully validate this
    // object so that validation can be skipped when it is loaded
    if(parentObject->publicArea.objectAttributes.fixedTPM == SET)
    {
        TPM_HANDLE objectHandle;

        // Perform self check on input public area. A TPM_RC_SIZE, TPM_RC_SCHEME,
        // TPM_RC_VALUE, TPM_RC_SYMMETRIC, TPM_RC_TYPE, TPM_RC_HASH,
        // TPM_RC_ASYMMETRIC, TPM_RC_ATTRIBUTES or TPM_RC_KDF error may be returned
        // at this point
        result = PublicAttributesValidation(TRUE, in->parentHandle,
                                            &in->objectPublic.t.publicArea);
        if(result != TPM_RC_SUCCESS)
            return RcSafeAddToResult(result, RC_Import_objectPublic);

        // Create internal object. A TPM_RC_KEY_SIZE, TPM_RC_KEY or
        // TPM_RC_OBJECT_MEMORY error may be returned at this point
        result = ObjectLoad(TPM_RH_NULL, &in->objectPublic.t.publicArea,
                            &sensitive, NULL, in->parentHandle, FALSE,
                            &objectHandle);
        if(result != TPM_RC_SUCCESS)
            return result;

        // Don't need the object, just needed the checks to be performed so
        // flush the object
        ObjectFlush(objectHandle);
    }

    // Command output

    // Prepare output private data from sensitive
    SensitiveToPrivate(&sensitive, &name, in->parentHandle,
                       in->objectPublic.t.publicArea.nameAlg,
                       &out->outPrivate);

    return TPM_RC_SUCCESS;
}
#endif // CC_Import
