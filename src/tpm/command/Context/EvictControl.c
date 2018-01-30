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
#include "EvictControl_fp.h"
#ifdef TPM_CC_EvictControl              // Conditional expansion of this file

// M e
// TPM_RC_ATTRIBUTES an object with temporary, stClear or publicOnly attribute SET cannot
// be made persistent
// TPM_RC_HIERARCHY auth cannot authorize the operation in the hierarchy of evictObject
// TPM_RC_HANDLE evictHandle of the persistent object to be evicted is not the same as
// the persistentHandle argument
// TPM_RC_NV_HANDLE persistentHandle is unavailable
// TPM_RC_NV_SPACE no space in NV to make evictHandle persistent
// TPM_RC_RANGE persistentHandle is not in the range corresponding to the hierarchy of
// evictObject

TPM_RC
TPM2_EvictControl(
    EvictControl_In *in                        // IN: input parameter list
)
{
    TPM_RC result;
    OBJECT *evictObject;

    // The command needs NV update. Check if NV is available.
    // A TPM_RC_NV_UNAVAILABLE or TPM_RC_NV_RATE error may be returned at
    // this point
    result = NvIsAvailable();
    if(result != TPM_RC_SUCCESS) return result;

// Input Validation

    // Get internal object pointer
    evictObject = ObjectGet(in->objectHandle);

    // Temporary, stClear or public only objects can not be made persistent
    if( evictObject->attributes.temporary == SET
            || evictObject->attributes.stClear == SET
            || evictObject->attributes.publicOnly == SET
      )
        return TPM_RC_ATTRIBUTES + RC_EvictControl_objectHandle;

    // If objectHandle refers to a persistent object, it should be the same as
    // input persistentHandle
    if( evictObject->attributes.evict == SET
            && evictObject->evictHandle != in->persistentHandle
      )
        return TPM_RC_HANDLE + RC_EvictControl_objectHandle;

    // Additional auth validation
    if(in->auth == TPM_RH_PLATFORM)
    {
        // To make persistent
        if(evictObject->attributes.evict == CLEAR)
        {
            // Platform auth can not set evict object in storage or endorsement
            // hierarchy
            if(evictObject->attributes.ppsHierarchy == CLEAR)
                return TPM_RC_HIERARCHY + RC_EvictControl_objectHandle;

            // Platform cannot use a handle outside of platform persistent range.
            if(!NvIsPlatformPersistentHandle(in->persistentHandle))
                return TPM_RC_RANGE + RC_EvictControl_persistentHandle;
        }
        // Platform auth can delete any persistent object
    }
    else if(in->auth == TPM_RH_OWNER)
    {
        // Owner auth can not set or clear evict object in platform hierarchy
        if(evictObject->attributes.ppsHierarchy == SET)
            return TPM_RC_HIERARCHY + RC_EvictControl_objectHandle;

        // Owner cannot use a handle outside of owner persistent range.
        if( evictObject->attributes.evict == CLEAR
                && !NvIsOwnerPersistentHandle(in->persistentHandle)
          )
            return TPM_RC_RANGE + RC_EvictControl_persistentHandle;
    }
    else
    {
        // Other auth is not allowed in this command and should be filtered out
        // at unmarshal process
        pAssert(FALSE);
    }

// Internal Data Update

    // Change evict state
    if(evictObject->attributes.evict == CLEAR)
    {
        // Make object persistent
        // A TPM_RC_NV_HANDLE or TPM_RC_NV_SPACE error may be returned at this
        // point
        result = NvAddEvictObject(in->persistentHandle, evictObject);
        if(result != TPM_RC_SUCCESS) return result;
    }
    else
    {
        // Delete the persistent object in NV
        NvDeleteEntity(evictObject->evictHandle);
    }

    return TPM_RC_SUCCESS;

}
#endif // CC_EvictControl
