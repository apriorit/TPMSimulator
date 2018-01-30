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
#include "SequenceComplete_fp.h"
#ifdef TPM_CC_SequenceComplete                // Conditional expansion of this file
#include <Platform.h>

// M e
// TPM_RC_TYPE sequenceHandle does not reference a hash or HMAC sequence
// object

TPM_RC
TPM2_SequenceComplete(
    SequenceComplete_In *in,                    // IN: input parameter list
    SequenceComplete_Out *out                    // OUT: output parameter list
)
{
    OBJECT *object;

// Input validation

    // Get hash object pointer
    object = ObjectGet(in->sequenceHandle);

    // input handle must be a hash or HMAC sequence object.
    if( object->attributes.hashSeq == CLEAR
            && object->attributes.hmacSeq == CLEAR)
        return TPM_RC_MODE + RC_SequenceComplete_sequenceHandle;

// Command Output

    if(object->attributes.hashSeq == SET)                                   // sequence object for hash
    {
        // Update last piece of data
        HASH_OBJECT *hashObject = (HASH_OBJECT *)object;

        // Get the hash algorithm before the algorithm is lost in CryptCompleteHash
        TPM_ALG_ID hashAlg = hashObject->state.hashState[0].state.hashAlg;

        CryptUpdateDigest2B(&hashObject->state.hashState[0], &in->buffer.b);

        // Complete hash
        out->result.t.size
            = CryptGetHashDigestSize(
                  CryptGetContextAlg(&hashObject->state.hashState[0]));

        CryptCompleteHash2B(&hashObject->state.hashState[0], &out->result.b);

        // Check if the first block of the sequence has been received
        if(hashObject->attributes.firstBlock == CLEAR)
        {
            // If not, then this is the first block so see if it is 'safe'
            // to sign.
            if(TicketIsSafe(&in->buffer.b))
                hashObject->attributes.ticketSafe = SET;
        }

        // Output ticket
        out->validation.tag = TPM_ST_HASHCHECK;
        out->validation.hierarchy = in->hierarchy;

        if(in->hierarchy == TPM_RH_NULL)
        {
            // Ticket is not required
            out->validation.digest.t.size = 0;
        }
        else if(object->attributes.ticketSafe == CLEAR)
        {
            // Ticket is not safe to generate
            out->validation.hierarchy = TPM_RH_NULL;
            out->validation.digest.t.size = 0;
        }
        else
        {
            // Compute ticket
            TicketComputeHashCheck(out->validation.hierarchy, hashAlg,
                                   &out->result, &out->validation);
        }
    }
    else
    {
        HASH_OBJECT *hashObject = (HASH_OBJECT *)object;

        // Update last piece of data
        CryptUpdateDigest2B(&hashObject->state.hmacState, &in->buffer.b);
        // Complete hash/HMAC
        out->result.t.size =
            CryptGetHashDigestSize(
                CryptGetContextAlg(&hashObject->state.hmacState.hashState));
        CryptCompleteHMAC2B(&(hashObject->state.hmacState), &out->result.b);

        // No ticket is generated for HMAC sequence
        out->validation.tag = TPM_ST_HASHCHECK;
        out->validation.hierarchy = TPM_RH_NULL;
        out->validation.digest.t.size = 0;
    }

// Internal Data Update

    // mark sequence object as evict so it will be flushed on the way out
    object->attributes.evict = SET;

    return TPM_RC_SUCCESS;
}
#endif // CC_SequenceComplete
