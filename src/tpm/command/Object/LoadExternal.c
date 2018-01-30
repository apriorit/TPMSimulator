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
#include "LoadExternal_fp.h"
#ifdef TPM_CC_LoadExternal             // Conditional expansion of this file
#include "Object_spt_fp.h"

// M e
// TPM_RC_ATTRIBUTES 'fixedParent" and fixedTPM must be CLEAR on on an external key if
// both public and sensitive portions are loaded
// TPM_RC_BINDING the inPublic and inPrivate structures are not cryptographically bound.
// TPM_RC_HASH incorrect hash selection for signing key
// TPM_RC_HIERARCHY hierarchy is turned off, or only NULL hierarchy is allowed when
// loading public and private parts of an object
// TPM_RC_KDF incorrect KDF selection for decrypting keyedHash object
// TPM_RC_KEY the size of the object's unique field is not consistent with the indicated
// size in the object's parameters
// TPM_RC_OBJECT_MEMORY if there is no free slot for an object
// TPM_RC_SCHEME the signing scheme is not valid for the key
// TPM_RC_SIZE authPolicy is not zero and is not the size of a digest produced by the
// object's nameAlg TPM_RH_NULL hierarchy
// TPM_RC_SYMMETRIC symmetric algorithm not provided when required
// TPM_RC_TYPE inPublic and inPrivate are not the same type

TPM_RC
TPM2_LoadExternal(
    LoadExternal_In *in,                   // IN: input parameter list
    LoadExternal_Out *out                   // OUT: output parameter list
)
{
    TPM_RC result;
    TPMT_SENSITIVE *sensitive;
    BOOL skipChecks;

// Input Validation

    // If the target hierarchy is turned off, the object can not be loaded.
    if(!HierarchyIsEnabled(in->hierarchy))
        return TPM_RC_HIERARCHY + RC_LoadExternal_hierarchy;

    // the size of authPolicy is either 0 or the digest size of nameAlg
    if(in->inPublic.t.publicArea.authPolicy.t.size != 0
            && in->inPublic.t.publicArea.authPolicy.t.size !=
            CryptGetHashDigestSize(in->inPublic.t.publicArea.nameAlg))
        return TPM_RC_SIZE + RC_LoadExternal_inPublic;

    // For loading an object with both public and sensitive
    if(in->inPrivate.t.size != 0)
    {
        // An external object can only be loaded at TPM_RH_NULL hierarchy
        if(in->hierarchy != TPM_RH_NULL)
            return TPM_RC_HIERARCHY + RC_LoadExternal_hierarchy;
        // An external object with a sensitive area must have fixedTPM == CLEAR
        // fixedParent == CLEAR, and must have restrict CLEAR so that it does not
        // appear to be a key that was created by this TPM.
        if( in->inPublic.t.publicArea.objectAttributes.fixedTPM != CLEAR
                || in->inPublic.t.publicArea.objectAttributes.fixedParent != CLEAR
                || in->inPublic.t.publicArea.objectAttributes.restricted != CLEAR
          )
            return TPM_RC_ATTRIBUTES + RC_LoadExternal_inPublic;
    }

    // Validate the scheme parameters
    result = SchemeChecks(TRUE, TPM_RH_NULL, &in->inPublic.t.publicArea);
    if(result != TPM_RC_SUCCESS)
        return RcSafeAddToResult(result, RC_LoadExternal_inPublic);

// Internal Data Update
    // Need the name to compute the qualified name
    ObjectComputeName(&in->inPublic.t.publicArea, &out->name);
    skipChecks = (in->inPublic.t.publicArea.nameAlg == TPM_ALG_NULL);

    // If a sensitive area was provided, load it
    if(in->inPrivate.t.size != 0)
        sensitive = &in->inPrivate.t.sensitiveArea;
    else
        sensitive = NULL;

    // Create external object. A TPM_RC_BINDING, TPM_RC_KEY, TPM_RC_OBJECT_MEMORY
    // or TPM_RC_TYPE error may be returned by ObjectLoad()
    result = ObjectLoad(in->hierarchy, &in->inPublic.t.publicArea,
                        sensitive, &out->name, TPM_RH_NULL, skipChecks,
                        &out->objectHandle);
    return result;
}
#endif // CC_LoadExternal
