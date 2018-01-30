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
#include "CreatePrimary_fp.h"
#ifdef TPM_CC_CreatePrimary            // Conditional expansion of this file
#include "Object_spt_fp.h"
#include <Platform.h>

// M e
// TPM_RC_ATTRIBUTES sensitiveDataOrigin is CLEAR when 'sensitive.data' is an Empty
// Buffer, or is SET when 'sensitive.data' is not empty; fixedTPM,
// fixedParent, or encryptedDuplication attributes are inconsistent
// between themselves or with those of the parent object; inconsistent
// restricted, decrypt and sign attributes; attempt to inject sensitive data
// for an asymmetric key; attempt to create a symmetric cipher key that
// is not a decryption key
// TPM_RC_KDF incorrect KDF specified for decrypting keyed hash object
// TPM_RC_OBJECT_MEMORY there is no free slot for the object
// TPM_RC_SCHEME inconsistent attributes decrypt, sign, restricted and key's scheme ID;
// or hash algorithm is inconsistent with the scheme ID for keyed hash
// object
// TPM_RC_SIZE size of public auth policy or sensitive auth value does not match
// digest size of the name algorithm sensitive data size for the keyed
// hash object is larger than is allowed for the scheme
// TPM_RC_SYMMETRIC a storage key with no symmetric algorithm specified; or non-storage
// key with symmetric algorithm different from TPM_ALG_NULL
// TPM_RC_TYPE unknown object type;

TPM_RC
TPM2_CreatePrimary(
    CreatePrimary_In *in,                  // IN: input parameter list
    CreatePrimary_Out *out                  // OUT: output parameter list
)
{
// Local variables
    TPM_RC result = TPM_RC_SUCCESS;
    TPMT_SENSITIVE sensitive;

// Input Validation
    // The sensitiveDataOrigin attribute must be consistent with the setting of
    // the size of the data object in inSensitive.
    if( (in->inPublic.t.publicArea.objectAttributes.sensitiveDataOrigin == SET)
            != (in->inSensitive.t.sensitive.data.t.size == 0 ))
        // Mismatch between the object attributes and the parameter.
        return TPM_RC_ATTRIBUTES + RC_CreatePrimary_inSensitive;

    // Check attributes in input public area. TPM_RC_ATTRIBUTES, TPM_RC_KDF,
    // TPM_RC_SCHEME, TPM_RC_SIZE, TPM_RC_SYMMETRIC, or TPM_RC_TYPE error may
    // be returned at this point.
    result = PublicAttributesValidation(FALSE, in->primaryHandle,
                                        &in->inPublic.t.publicArea);
    if(result != TPM_RC_SUCCESS)
        return RcSafeAddToResult(result, RC_CreatePrimary_inPublic);

    // Validate the sensitive area values
    if( MemoryRemoveTrailingZeros(&in->inSensitive.t.sensitive.userAuth)
            > CryptGetHashDigestSize(in->inPublic.t.publicArea.nameAlg))
        return TPM_RC_SIZE + RC_CreatePrimary_inSensitive;

// Command output

    // Generate Primary Object
    // The primary key generation process uses the Name of the input public
    // template to compute the key. The keys are generated from the template
    // before anything in the template is allowed to be changed.
    // A TPM_RC_KDF, TPM_RC_SIZE error may be returned at this point
    result = CryptCreateObject(in->primaryHandle, &in->inPublic.t.publicArea,
                               &in->inSensitive.t.sensitive,&sensitive);
    if(result != TPM_RC_SUCCESS)
        return result;

    // Fill in creation data
    FillInCreationData(in->primaryHandle, in->inPublic.t.publicArea.nameAlg,
                       &in->creationPCR, &in->outsideInfo, &out->creationData,
                       &out->creationHash);

    // Copy public area
    out->outPublic = in->inPublic;

    // Fill in private area for output
    ObjectComputeName(&(out->outPublic.t.publicArea), &out->name);

    // Compute creation ticket
    TicketComputeCreation(EntityGetHierarchy(in->primaryHandle), &out->name,
                          &out->creationHash, &out->creationTicket);

    // Create a internal object. A TPM_RC_OBJECT_MEMORY error may be returned
    // at this point.
    result = ObjectLoad(in->primaryHandle, &in->inPublic.t.publicArea, &sensitive,
                        &out->name, in->primaryHandle, TRUE, &out->objectHandle);

    return result;
}
#endif // CC_CreatePrimary
