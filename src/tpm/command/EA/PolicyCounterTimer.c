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
#include "PolicyCounterTimer_fp.h"
#ifdef TPM_CC_PolicyCounterTimer                   // Conditional expansion of this file
#include "Policy_spt_fp.h"

// M e
// TPM_RC_POLICY the comparison of the selected portion of the TPMS_TIME_INFO with
// operandB failed
// TPM_RC_RANGE offset + size exceed size of TPMS_TIME_INFO structure

TPM_RC
TPM2_PolicyCounterTimer(
    PolicyCounterTimer_In *in                        // IN: input parameter list
)
{
    TPM_RC result;
    SESSION *session;
    TIME_INFO infoData;              // data buffer of TPMS_TIME_INFO
    TPM_CC commandCode = TPM_CC_PolicyCounterTimer;
    HASH_STATE hashState;
    TPM2B_DIGEST argHash;

// Input Validation

    // If the command is going to use any part of the counter or timer, need
    // to verify that time is advancing.
    // The time and clock vales are the first two 64-bit values in the clock
    if(in->offset < sizeof(UINT64) + sizeof(UINT64))
    {
        // Using Clock or Time so see if clock is running. Clock doesn't run while
        // NV is unavailable.
        // TPM_RC_NV_UNAVAILABLE or TPM_RC_NV_RATE error may be returned here.
        result = NvIsAvailable();
        if(result != TPM_RC_SUCCESS)
            return result;
    }
    // Get pointer to the session structure
    session = SessionGet(in->policySession);

    //If this is a trial policy, skip all validations and the operation
    if(session->attributes.isTrialPolicy == CLEAR)
    {
        // Get time data info. The size of time info data equals the input
        // operand B size. A TPM_RC_RANGE error may be returned at this point
        result = TimeGetRange(in->offset, in->operandB.t.size, &infoData);
        if(result != TPM_RC_SUCCESS) return result;

        // Arithmetic Comparison
        switch(in->operation)
        {
        case TPM_EO_EQ:
            // compare A = B
            if(CryptCompare(in->operandB.t.size, infoData,
                            in->operandB.t.size, in->operandB.t.buffer) != 0)
                return TPM_RC_POLICY;
            break;
        case TPM_EO_NEQ:
            // compare A != B
            if(CryptCompare(in->operandB.t.size, infoData,
                            in->operandB.t.size, in->operandB.t.buffer) == 0)
                return TPM_RC_POLICY;
            break;
        case TPM_EO_SIGNED_GT:
            // compare A > B signed
            if(CryptCompareSigned(in->operandB.t.size, infoData,
                                  in->operandB.t.size, in->operandB.t.buffer) <= 0)
                return TPM_RC_POLICY;
            break;
        case TPM_EO_UNSIGNED_GT:
            // compare A > B unsigned
            if(CryptCompare(in->operandB.t.size, infoData,
                            in->operandB.t.size, in->operandB.t.buffer) <= 0)
                return TPM_RC_POLICY;
            break;
        case TPM_EO_SIGNED_LT:
            // compare A < B signed
            if(CryptCompareSigned(in->operandB.t.size, infoData,
                                  in->operandB.t.size, in->operandB.t.buffer) >= 0)
                return TPM_RC_POLICY;
            break;
        case TPM_EO_UNSIGNED_LT:
            // compare A < B unsigned
            if(CryptCompare(in->operandB.t.size, infoData,
                            in->operandB.t.size, in->operandB.t.buffer) >= 0)
                return TPM_RC_POLICY;
            break;
        case TPM_EO_SIGNED_GE:
            // compare A >= B signed
            if(CryptCompareSigned(in->operandB.t.size, infoData,
                                  in->operandB.t.size, in->operandB.t.buffer) < 0)
                return TPM_RC_POLICY;
            break;
        case TPM_EO_UNSIGNED_GE:
            // compare A >= B unsigned
            if(CryptCompare(in->operandB.t.size, infoData,
                            in->operandB.t.size, in->operandB.t.buffer) < 0)
                return TPM_RC_POLICY;
            break;
        case TPM_EO_SIGNED_LE:
            // compare A <= B signed
            if(CryptCompareSigned(in->operandB.t.size, infoData,
                                  in->operandB.t.size, in->operandB.t.buffer) > 0)
                return TPM_RC_POLICY;
            break;
        case TPM_EO_UNSIGNED_LE:
            // compare A <= B unsigned
            if(CryptCompare(in->operandB.t.size, infoData,
                            in->operandB.t.size, in->operandB.t.buffer) > 0)
                return TPM_RC_POLICY;
            break;
        case TPM_EO_BITSET:
            // All bits SET in B are SET in A. ((A&B)=B)
        {
            UINT32 i;
            for (i = 0; i < in->operandB.t.size; i++)
                if( (infoData[i] & in->operandB.t.buffer[i])
                        != in->operandB.t.buffer[i])
                    return TPM_RC_POLICY;
        }
        break;
        case TPM_EO_BITCLEAR:
            // All bits SET in B are CLEAR in A. ((A&B)=0)
        {
            UINT32 i;
            for (i = 0; i < in->operandB.t.size; i++)
                if((infoData[i] & in->operandB.t.buffer[i]) != 0)
                    return TPM_RC_POLICY;
        }
        break;
        default:
            pAssert(FALSE);
            break;
        }
    }

// Internal Data Update

    // Start argument list hash
    argHash.t.size = CryptStartHash(session->authHashAlg, &hashState);
    // add operandB
    CryptUpdateDigest2B(&hashState, &in->operandB.b);
    // add offset
    CryptUpdateDigestInt(&hashState, sizeof(UINT16), &in->offset);
    // add operation
    CryptUpdateDigestInt(&hashState, sizeof(TPM_EO), &in->operation);
    // complete argument hash
    CryptCompleteHash2B(&hashState, &argHash.b);

    // update policyDigest
    // start hash
    CryptStartHash(session->authHashAlg, &hashState);

    // add old digest
    CryptUpdateDigest2B(&hashState, &session->u2.policyDigest.b);

    // add commandCode
    CryptUpdateDigestInt(&hashState, sizeof(TPM_CC), &commandCode);

    // add argument digest
    CryptUpdateDigest2B(&hashState, &argHash.b);

    // complete the digest
    CryptCompleteHash2B(&hashState, &session->u2.policyDigest.b);

    return TPM_RC_SUCCESS;
}
#endif // CC_PolicyCounterTimer
