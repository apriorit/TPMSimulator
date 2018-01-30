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
#include "Load_fp.h"
#ifdef TPM_CC_Load         // Conditional expansion of this file
#include "Object_spt_fp.h"

// M e
// TPM_RC_ASYMMETRIC storage key with different asymmetric type than parent
// TPM_RC_ATTRIBUTES inPulblic attributes are not allowed with selected parent
// TPM_RC_BINDING inPrivate and inPublic are not cryptographically bound
// TPM_RC_HASH incorrect hash selection for signing key
// TPM_RC_INTEGRITY HMAC on inPrivate was not valid
// TPM_RC_KDF KDF selection not allowed
// TPM_RC_KEY the size of the object's unique field is not consistent with the indicated
// size in the object's parameters
// TPM_RC_OBJECT_MEMORY no available object slot
// TPM_RC_SCHEME the signing scheme is not valid for the key
// TPM_RC_SENSITIVE the inPrivate did not unmarshal correctly
// TPM_RC_SIZE inPrivate missing, or authPolicy size for inPublic or is not valid
// TPM_RC_SYMMETRIC symmetric algorithm not provided when required
// TPM_RC_TYPE parentHandle is not a storage key, or the object to load is a storage
// key but its parameters do not match the parameters of the parent.
// TPM_RC_VALUE decryption failure

TPM_RC
TPM2_Load(
    Load_In *in,                 // IN: input parameter list
    Load_Out *out                 // OUT: output parameter list
)
{
    TPM_RC result = TPM_RC_SUCCESS;
    TPMT_SENSITIVE sensitive;
    TPMI_RH_HIERARCHY hierarchy;
    OBJECT *parentObject = NULL;
    BOOL skipChecks = FALSE;

// Input Validation
    if(in->inPrivate.t.size == 0)
        return TPM_RC_SIZE + RC_Load_inPrivate;

    parentObject = ObjectGet(in->parentHandle);
    // Is the object that is being used as the parent actually a parent.
    if(!AreAttributesForParent(parentObject))
        return TPM_RC_TYPE + RC_Load_parentHandle;

    // If the parent is fixedTPM, then the attributes of the object
    // are either "correct by construction" or were validated
    // when the object was imported. If they pass the integrity
    // check, then the values are valid
    if(parentObject->publicArea.objectAttributes.fixedTPM)
        skipChecks = TRUE;
    else
    {
        // If parent doesn't have fixedTPM SET, then this can't have
        // fixedTPM SET.
        if(in->inPublic.t.publicArea.objectAttributes.fixedTPM == SET)
            return TPM_RC_ATTRIBUTES + RC_Load_inPublic;

        // Perform self check on input public area. A TPM_RC_SIZE, TPM_RC_SCHEME,
        // TPM_RC_VALUE, TPM_RC_SYMMETRIC, TPM_RC_TYPE, TPM_RC_HASH,
        // TPM_RC_ASYMMETRIC, TPM_RC_ATTRIBUTES or TPM_RC_KDF error may be returned
        // at this point
        result = PublicAttributesValidation(TRUE, in->parentHandle,
                                            &in->inPublic.t.publicArea);
        if(result != TPM_RC_SUCCESS)
            return RcSafeAddToResult(result, RC_Load_inPublic);
    }

    // Compute the name of object
    ObjectComputeName(&in->inPublic.t.publicArea, &out->name);

    // Retrieve sensitive data. PrivateToSensitive() may return TPM_RC_INTEGRITY or
    // TPM_RC_SENSITIVE
    // errors may be returned at this point
    result = PrivateToSensitive(&in->inPrivate, &out->name, in->parentHandle,
                                in->inPublic.t.publicArea.nameAlg,
                                &sensitive);
    if(result != TPM_RC_SUCCESS)
        return RcSafeAddToResult(result, RC_Load_inPrivate);

// Internal Data Update

    // Get hierarchy of parent
    hierarchy = ObjectGetHierarchy(in->parentHandle);

    // Create internal object. A lot of different errors may be returned by this
    // loading operation as it will do several validations, including the public
    // binding check
    result = ObjectLoad(hierarchy, &in->inPublic.t.publicArea, &sensitive,
                        &out->name, in->parentHandle, skipChecks,
                        &out->objectHandle);

    if(result != TPM_RC_SUCCESS)
        return result;

    return TPM_RC_SUCCESS;
}
#endif // CC_Load
