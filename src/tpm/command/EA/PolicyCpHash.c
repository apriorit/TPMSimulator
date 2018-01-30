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
#include "PolicyCpHash_fp.h"
#ifdef TPM_CC_PolicyCpHash                  // Conditional expansion of this file

// M e
// TPM_RC_CPHASH cpHash of policySession has previously been set to a different value
// TPM_RC_SIZE cpHashA is not the size of a digest produced by the hash algorithm
// associated with policySession

TPM_RC
TPM2_PolicyCpHash(
    PolicyCpHash_In *in                        // IN: input parameter list
)
{
    SESSION *session;
    TPM_CC commandCode = TPM_CC_PolicyCpHash;
    HASH_STATE hashState;

// Input Validation

    // Get pointer to the session structure
    session = SessionGet(in->policySession);

    // A new cpHash is given in input parameter, but cpHash in session context
    // is not empty, or is not the same as the new cpHash
    if( in->cpHashA.t.size != 0
            && session->u1.cpHash.t.size != 0
            && !Memory2BEqual(&in->cpHashA.b, &session->u1.cpHash.b)
      )
        return TPM_RC_CPHASH;

    // A valid cpHash must have the same size as session hash digest
    if(in->cpHashA.t.size != CryptGetHashDigestSize(session->authHashAlg))
        return TPM_RC_SIZE + RC_PolicyCpHash_cpHashA;

// Internal Data Update

    // Update policy hash
    // policyDigestnew = hash(policyDigestold || TPM_CC_PolicyCpHash || cpHashA)
    // Start hash
    CryptStartHash(session->authHashAlg, &hashState);

    // add old digest
    CryptUpdateDigest2B(&hashState, &session->u2.policyDigest.b);

    // add commandCode
    CryptUpdateDigestInt(&hashState, sizeof(TPM_CC), &commandCode);

    // add cpHashA
    CryptUpdateDigest2B(&hashState, &in->cpHashA.b);

    // complete the digest and get the results
    CryptCompleteHash2B(&hashState, &session->u2.policyDigest.b);

    // update cpHash in session context
    session->u1.cpHash = in->cpHashA;
    session->attributes.iscpHashDefined = SET;

    return TPM_RC_SUCCESS;
}
#endif // CC_PolicyCpHash
