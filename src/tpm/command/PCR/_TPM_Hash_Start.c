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
void
_TPM_Hash_Start(
    void
)
{
    TPM_RC result;
    TPMI_DH_OBJECT handle;

    // If a DRTM sequence object exists, free it up
    if(g_DRTMHandle != TPM_RH_UNASSIGNED)
    {
        ObjectFlush(g_DRTMHandle);
        g_DRTMHandle = TPM_RH_UNASSIGNED;
    }

    // Create an event sequence object and store the handle in global
    // g_DRTMHandle. A TPM_RC_OBJECT_MEMORY error may be returned at this point
    // The null value for the 'auth' parameter will cause the sequence structure to
    // be allocated without being set as present. This keeps the sequence from
    // being left behind if the sequence is terminated early.
    result = ObjectCreateEventSequence(NULL, &g_DRTMHandle);

    // If a free slot was not available, then free up a slot.
    if(result != TPM_RC_SUCCESS)
    {
        // An implementation does not need to have a fixed relationship between
        // slot numbers and handle numbers. To handle the general case, scan for
        // a handle that is assigned and free it for the DRTM sequence.
        // In the reference implementation, the relationship between handles and
        // slots is fixed. So, if the call to ObjectCreateEvenSequence()
        // failed indicating that all slots are occupied, then the first handle we
        // are going to check (TRANSIENT_FIRST) will be occupied. It will be freed
        // so that it can be assigned for use as the DRTM sequence object.
        for(handle = TRANSIENT_FIRST; handle < TRANSIENT_LAST; handle++)
        {
            // try to flush the first object
            if(ObjectIsPresent(handle))
                break;
        }
        // If the first call to find a slot fails but none of the slots is occupied
        // then there's a big problem
        pAssert(handle < TRANSIENT_LAST);

        // Free the slot
        ObjectFlush(handle);

        // Try to create an event sequence object again. This time, we must
        // succeed.
        result = ObjectCreateEventSequence(NULL, &g_DRTMHandle);
        pAssert(result == TPM_RC_SUCCESS);
    }

    return;
}
