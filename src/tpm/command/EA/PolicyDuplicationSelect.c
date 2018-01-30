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
#include "PolicyDuplicationSelect_fp.h"
#ifdef TPM_CC_PolicyDuplicationSelect              // Conditional expansion of this file

// M e
// TPM_RC_COMMAND_CODE commandCode of 'policySession; is not empty
// TPM_RC_CPHASH cpHash of policySession is not empty

TPM_RC
TPM2_PolicyDuplicationSelect(
    PolicyDuplicationSelect_In *in                    // IN: input parameter list
)
{
    SESSION *session;
    HASH_STATE hashState;
    TPM_CC commandCode = TPM_CC_PolicyDuplicationSelect;

// Input Validation

    // Get pointer to the session structure
    session = SessionGet(in->policySession);

    // cpHash in session context must be empty
    if(session->u1.cpHash.t.size != 0)
        return TPM_RC_CPHASH;

    // commandCode in session context must be empty
    if(session->commandCode != 0)
        return TPM_RC_COMMAND_CODE;

// Internal Data Update

    // Update name hash
    session->u1.cpHash.t.size = CryptStartHash(session->authHashAlg, &hashState);

    // add objectName
    CryptUpdateDigest2B(&hashState, &in->objectName.b);

    // add new parent name
    CryptUpdateDigest2B(&hashState, &in->newParentName.b);

    // complete hash
    CryptCompleteHash2B(&hashState, &session->u1.cpHash.b);

    // update policy hash
    // Old policyDigest size should be the same as the new policyDigest size since
    // they are using the same hash algorithm
    session->u2.policyDigest.t.size
        = CryptStartHash(session->authHashAlg, &hashState);

    // add old policy
    CryptUpdateDigest2B(&hashState, &session->u2.policyDigest.b);

    // add command code
    CryptUpdateDigestInt(&hashState, sizeof(TPM_CC), &commandCode);

    // add objectName
    if(in->includeObject == YES)
        CryptUpdateDigest2B(&hashState, &in->objectName.b);

    // add new parent name
    CryptUpdateDigest2B(&hashState, &in->newParentName.b);

    // add includeObject
    CryptUpdateDigestInt(&hashState, sizeof(TPMI_YES_NO), &in->includeObject);

    // complete digest
    CryptCompleteHash2B(&hashState, &session->u2.policyDigest.b);

    // clear iscpHashDefined bit to indicate now this field contains a nameHash
    session->attributes.iscpHashDefined = CLEAR;

    // set commandCode in session context
    session->commandCode = TPM_CC_Duplicate;

    return TPM_RC_SUCCESS;
}
#endif // CC_PolicyDuplicationSelect
