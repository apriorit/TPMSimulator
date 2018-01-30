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
#include "SequenceUpdate_fp.h"
#ifdef TPM_CC_SequenceUpdate                // Conditional expansion of this file

// M e
// TPM_RC_MODE sequenceHandle does not reference a hash or HMAC sequence
// object

TPM_RC
TPM2_SequenceUpdate(
    SequenceUpdate_In *in                       // IN: input parameter list
)
{
    OBJECT *object;

// Input Validation

    // Get sequence object pointer
    object = ObjectGet(in->sequenceHandle);

    // Check that referenced object is a sequence object.
    if(!ObjectIsSequence(object))
        return TPM_RC_MODE + RC_SequenceUpdate_sequenceHandle;

// Internal Data Update

    if(object->attributes.eventSeq == SET)
    {
        // Update event sequence object
        UINT32 i;
        HASH_OBJECT *hashObject = (HASH_OBJECT *)object;
        for(i = 0; i < HASH_COUNT; i++)
        {
            // Update sequence object
            CryptUpdateDigest2B(&hashObject->state.hashState[i], &in->buffer.b);
        }
    }
    else
    {
        HASH_OBJECT *hashObject = (HASH_OBJECT *)object;

        // Update hash/HMAC sequence object
        if(hashObject->attributes.hashSeq == SET)
        {
            // Is this the first block of the sequence
            if(hashObject->attributes.firstBlock == CLEAR)
            {
                // If so, indicate that first block was received
                hashObject->attributes.firstBlock = SET;

                // Check the first block to see if the first block can contain
                // the TPM_GENERATED_VALUE. If it does, it is not safe for
                // a ticket.
                if(TicketIsSafe(&in->buffer.b))
                    hashObject->attributes.ticketSafe = SET;
            }
            // Update sequence object hash/HMAC stack
            CryptUpdateDigest2B(&hashObject->state.hashState[0], &in->buffer.b);

        }
        else if(object->attributes.hmacSeq == SET)
        {
            HASH_OBJECT *hashObject = (HASH_OBJECT *)object;

            // Update sequence object hash/HMAC stack
            CryptUpdateDigest2B(&hashObject->state.hmacState, &in->buffer.b);
        }
    }

    return TPM_RC_SUCCESS;
}
#endif // CC_SequenceUpdate
