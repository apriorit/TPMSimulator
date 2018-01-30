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
#include "ObjectChangeAuth_fp.h"
#ifdef TPM_CC_ObjectChangeAuth               // Conditional expansion of this file
#include "Object_spt_fp.h"

// M e
// TPM_RC_SIZE newAuth is larger than the size of the digest of the Name algorithm of
// objectHandle
// TPM_RC_TYPE the key referenced by parentHandle is not the parent of the object
// referenced by objectHandle; or objectHandle is a sequence object.

TPM_RC
TPM2_ObjectChangeAuth(
    ObjectChangeAuth_In *in,                // IN: input parameter list
    ObjectChangeAuth_Out *out                // OUT: output parameter list
)
{
    TPMT_SENSITIVE sensitive;

    OBJECT *object;
    TPM2B_NAME objectQN, QNCompare;
    TPM2B_NAME parentQN;

// Input Validation

    // Get object pointer
    object = ObjectGet(in->objectHandle);

    // Can not change auth on sequence object
    if(ObjectIsSequence(object))
        return TPM_RC_TYPE + RC_ObjectChangeAuth_objectHandle;

    // Make sure that the auth value is consistent with the nameAlg
    if( MemoryRemoveTrailingZeros(&in->newAuth)
            > CryptGetHashDigestSize(object->publicArea.nameAlg))
        return TPM_RC_SIZE + RC_ObjectChangeAuth_newAuth;

    // Check parent for object
    // parent handle must be the parent of object handle. In this
    // implementation we verify this by checking the QN of object. Other
    // implementation may choose different method to verify this attribute.
    ObjectGetQualifiedName(in->parentHandle, &parentQN);
    ObjectComputeQualifiedName(&parentQN, object->publicArea.nameAlg,
                               &object->name, &QNCompare);

    ObjectGetQualifiedName(in->objectHandle, &objectQN);
    if(!Memory2BEqual(&objectQN.b, &QNCompare.b))
        return TPM_RC_TYPE + RC_ObjectChangeAuth_parentHandle;

// Command Output

    // Copy internal sensitive area
    sensitive = object->sensitive;
    // Copy authValue
    sensitive.authValue = in->newAuth;

    // Prepare output private data from sensitive
    SensitiveToPrivate(&sensitive, &object->name, in->parentHandle,
                       object->publicArea.nameAlg,
                       &out->outPrivate);

    return TPM_RC_SUCCESS;
}
#endif // CC_ObjectChangeAuth
