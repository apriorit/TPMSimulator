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
#include "PolicyNV_fp.h"
#ifdef TPM_CC_PolicyNV            // Conditional expansion of this file
#include "Policy_spt_fp.h"
#include "NV_spt_fp.h"                      // Include NV support routine for read access check

// M e
// TPM_RC_AUTH_TYPE NV index authorization type is not correct
// TPM_RC_NV_LOCKED NV index read locked
// TPM_RC_NV_UNINITIALIZED the NV index has not been initialized
// TPM_RC_POLICY the comparison to the NV contents failed
// TPM_RC_SIZE the size of nvIndex data starting at offset is less than the size of
// operandB

TPM_RC
TPM2_PolicyNV(
    PolicyNV_In *in                        // IN: input parameter list
)
{
    TPM_RC result;
    SESSION *session;
    NV_INDEX nvIndex;
    BYTE nvBuffer[sizeof(in->operandB.t.buffer)];
    TPM2B_NAME nvName;
    TPM_CC commandCode = TPM_CC_PolicyNV;
    HASH_STATE hashState;
    TPM2B_DIGEST argHash;

// Input Validation

    // Get NV index information
    NvGetIndexInfo(in->nvIndex, &nvIndex);

    // Get pointer to the session structure
    session = SessionGet(in->policySession);

    //If this is a trial policy, skip all validations and the operation
    if(session->attributes.isTrialPolicy == CLEAR)
    {
        // NV Read access check. NV index should be allowed for read. A
        // TPM_RC_AUTH_TYPE or TPM_RC_NV_LOCKED error may be return at this
        // point
        result = NvReadAccessChecks(in->authHandle, in->nvIndex);
        if(result != TPM_RC_SUCCESS) return result;

        // Valid NV data size should not be smaller than input operandB size
        if((nvIndex.publicArea.dataSize - in->offset) < in->operandB.t.size)
            return TPM_RC_SIZE + RC_PolicyNV_operandB;

        // Arithmetic Comparison

        // Get NV data. The size of NV data equals the input operand B size
        NvGetIndexData(in->nvIndex, &nvIndex, in->offset,
                       in->operandB.t.size, nvBuffer);

        switch(in->operation)
        {
        case TPM_EO_EQ:
            // compare A = B
            if(CryptCompare(in->operandB.t.size, nvBuffer,
                            in->operandB.t.size, in->operandB.t.buffer) != 0)
                return TPM_RC_POLICY;
            break;
        case TPM_EO_NEQ:
            // compare A != B
            if(CryptCompare(in->operandB.t.size, nvBuffer,
                            in->operandB.t.size, in->operandB.t.buffer) == 0)
                return TPM_RC_POLICY;
            break;
        case TPM_EO_SIGNED_GT:
            // compare A > B signed
            if(CryptCompareSigned(in->operandB.t.size, nvBuffer,
                                  in->operandB.t.size, in->operandB.t.buffer) <= 0)
                return TPM_RC_POLICY;
            break;
        case TPM_EO_UNSIGNED_GT:
            // compare A > B unsigned
            if(CryptCompare(in->operandB.t.size, nvBuffer,
                            in->operandB.t.size, in->operandB.t.buffer) <= 0)
                return TPM_RC_POLICY;
            break;
        case TPM_EO_SIGNED_LT:
            // compare A < B signed
            if(CryptCompareSigned(in->operandB.t.size, nvBuffer,
                                  in->operandB.t.size, in->operandB.t.buffer) >= 0)
                return TPM_RC_POLICY;
            break;
        case TPM_EO_UNSIGNED_LT:
            // compare A < B unsigned
            if(CryptCompare(in->operandB.t.size, nvBuffer,
                            in->operandB.t.size, in->operandB.t.buffer) >= 0)
                return TPM_RC_POLICY;
            break;
        case TPM_EO_SIGNED_GE:
            // compare A >= B signed
            if(CryptCompareSigned(in->operandB.t.size, nvBuffer,
                                  in->operandB.t.size, in->operandB.t.buffer) < 0)
                return TPM_RC_POLICY;
            break;
        case TPM_EO_UNSIGNED_GE:
            // compare A >= B unsigned
            if(CryptCompare(in->operandB.t.size, nvBuffer,
                            in->operandB.t.size, in->operandB.t.buffer) < 0)
                return TPM_RC_POLICY;
            break;
        case TPM_EO_SIGNED_LE:
            // compare A <= B signed
            if(CryptCompareSigned(in->operandB.t.size, nvBuffer,
                                  in->operandB.t.size, in->operandB.t.buffer) > 0)
                return TPM_RC_POLICY;
            break;
        case TPM_EO_UNSIGNED_LE:
            // compare A <= B unsigned
            if(CryptCompare(in->operandB.t.size, nvBuffer,
                            in->operandB.t.size, in->operandB.t.buffer) > 0)
                return TPM_RC_POLICY;
            break;
        case TPM_EO_BITSET:
            // All bits SET in B are SET in A. ((A&B)=B)
        {
            UINT32 i;
            for (i = 0; i < in->operandB.t.size; i++)
                if((nvBuffer[i] & in->operandB.t.buffer[i])
                        != in->operandB.t.buffer[i])
                    return TPM_RC_POLICY;
        }
        break;
        case TPM_EO_BITCLEAR:
            // All bits SET in B are CLEAR in A. ((A&B)=0)
        {
            UINT32 i;
            for (i = 0; i < in->operandB.t.size; i++)
                if((nvBuffer[i] & in->operandB.t.buffer[i]) != 0)
                    return TPM_RC_POLICY;
        }
        break;
        default:
            pAssert(FALSE);
            break;
        }
    }

// Internal Data Update

    // Start argument hash
    argHash.t.size = CryptStartHash(session->authHashAlg, &hashState);

    // add operandB
    CryptUpdateDigest2B(&hashState, &in->operandB.b);

    // add offset
    CryptUpdateDigestInt(&hashState, sizeof(UINT16), &in->offset);

    // add operation
    CryptUpdateDigestInt(&hashState, sizeof(TPM_EO), &in->operation);

    // complete argument digest
    CryptCompleteHash2B(&hashState, &argHash.b);

    // Update policyDigest
    // Start digest
    CryptStartHash(session->authHashAlg, &hashState);

    // add old digest
    CryptUpdateDigest2B(&hashState, &session->u2.policyDigest.b);

    // add commandCode
    CryptUpdateDigestInt(&hashState, sizeof(TPM_CC), &commandCode);

    // add argument digest
    CryptUpdateDigest2B(&hashState, &argHash.b);

    // Adding nvName
    nvName.t.size = EntityGetName(in->nvIndex, &nvName.t.name);
    CryptUpdateDigest2B(&hashState, &nvName.b);

    // complete the digest
    CryptCompleteHash2B(&hashState, &session->u2.policyDigest.b);

    return TPM_RC_SUCCESS;
}
#endif // CC_PolicyNV
