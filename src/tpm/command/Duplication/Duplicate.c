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
#include "Duplicate_fp.h"
#ifdef TPM_CC_Duplicate           // Conditional expansion of this file
#include "Object_spt_fp.h"

// M e
// TPM_RC_ATTRIBUTES key to duplicate has fixedParent SET
// TPM_RC_HIERARCHY encryptedDuplication is SET and newParentHandle specifies Null
// Hierarchy
// TPM_RC_KEY newParentHandle references invalid ECC key (public point not on the
// curve)
// TPM_RC_SIZE input encryption key size does not match the size specified in
// symmetric algorithm
// TPM_RC_SYMMETRIC encryptedDuplication is SET but no symmetric algorithm is provided
// TPM_RC_TYPE newParentHandle is neither a storage key nor TPM_RH_NULL; or
// the object has a NULL nameAlg

TPM_RC
TPM2_Duplicate(
    Duplicate_In *in,                   // IN: input parameter list
    Duplicate_Out *out                   // OUT: output parameter list
)
{
    TPM_RC result = TPM_RC_SUCCESS;
    TPMT_SENSITIVE sensitive;

    UINT16 innerKeySize = 0;   // encrypt key size for inner wrap

    OBJECT *object;
    TPM2B_DATA data;

// Input Validation

    // Get duplicate object pointer
    object = ObjectGet(in->objectHandle);

    // duplicate key must have fixParent bit CLEAR.
    if(object->publicArea.objectAttributes.fixedParent == SET)
        return TPM_RC_ATTRIBUTES + RC_Duplicate_objectHandle;

    // Do not duplicate object with NULL nameAlg
    if(object->publicArea.nameAlg == TPM_ALG_NULL)
        return TPM_RC_TYPE + RC_Duplicate_objectHandle;

    // new parent key must be a storage object or TPM_RH_NULL
    if(in->newParentHandle != TPM_RH_NULL
            && !ObjectIsStorage(in->newParentHandle))
        return TPM_RC_TYPE + RC_Duplicate_newParentHandle;

    // If the duplicates object has encryptedDuplication SET, then there must be
    // an inner wrapper and the new parent may not be TPM_RH_NULL
    if(object->publicArea.objectAttributes.encryptedDuplication == SET)
    {
        if(in->symmetricAlg.algorithm == TPM_ALG_NULL)
            return TPM_RC_SYMMETRIC + RC_Duplicate_symmetricAlg;
        if(in->newParentHandle == TPM_RH_NULL)
            return TPM_RC_HIERARCHY + RC_Duplicate_newParentHandle;
    }

    if(in->symmetricAlg.algorithm == TPM_ALG_NULL)
    {
        // if algorithm is TPM_ALG_NULL, input key size must be 0
        if(in->encryptionKeyIn.t.size != 0)
            return TPM_RC_SIZE + RC_Duplicate_encryptionKeyIn;
    }
    else
    {
        // Get inner wrap key size
        innerKeySize = in->symmetricAlg.keyBits.sym;

        // If provided the input symmetric key must match the size of the algorithm
        if(in->encryptionKeyIn.t.size != 0
                && in->encryptionKeyIn.t.size != (innerKeySize + 7) / 8)
            return TPM_RC_SIZE + RC_Duplicate_encryptionKeyIn;
    }

// Command Output

    if(in->newParentHandle != TPM_RH_NULL)
    {

        // Make encrypt key and its associated secret structure. A TPM_RC_KEY
        // error may be returned at this point
        out->outSymSeed.t.size = sizeof(out->outSymSeed.t.secret);
        result = CryptSecretEncrypt(in->newParentHandle,
                                    "DUPLICATE", &data, &out->outSymSeed);
        pAssert(result != TPM_RC_VALUE);
        if(result != TPM_RC_SUCCESS)
            return result;
    }
    else
    {
        // Do not apply outer wrapper
        data.t.size = 0;
        out->outSymSeed.t.size = 0;
    }

    // Copy sensitive area
    sensitive = object->sensitive;

    // Prepare output private data from sensitive
    SensitiveToDuplicate(&sensitive, &object->name, in->newParentHandle,
                         object->publicArea.nameAlg, (TPM2B_SEED *) &data,
                         &in->symmetricAlg, &in->encryptionKeyIn,
                         &out->duplicate);

    out->encryptionKeyOut = in->encryptionKeyIn;

    return TPM_RC_SUCCESS;
}
#endif // CC_Duplicate
