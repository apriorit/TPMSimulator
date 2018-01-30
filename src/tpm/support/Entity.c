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
/*     the rights to reproduce, distribute, display, and perform the specification solely for the purpose         */
/*     of developing products based on such documents.                                                            */
/*                                                                                                                */
/*  2.  Source Code Distribution Conditions:                                                                      */
/*     Redistributions of Source Code must retain the above copyright licenses, this list of conditions           */
/*     and the following disclaimers.                                                                             */
/*     Redistributions in binary form must reproduce the above copyright licenses, this list of                   */
/*     conditions and the following disclaimers in the documentation and/or other materials provided              */
/*     with the distribution.                                                                                     */
/*                                                                                                                */
/*  3.  Disclaimers:                                                                                              */
/*     THE COPYRIGHT LICENSES SET FORTH ABOVE DO NOT REPRESENT ANY FORM OF LICENSE OR                             */
/*     WAIVER, EXPRESS OR IMPLIED, BY ESTOPPEL OR OTHERWISE, WITH RESPECT TO PATENT RIGHTS                        */
/*     HELD BY TCG MEMBERS (OR OTHER THIRD PARTIES) THAT MAY BE NECESSARY TO IMPLEMENT                            */
/*     THIS SPECIFICATION OR OTHERWISE. Contact TCG Administration                                                */
/*     (admin@trustedcomputinggroup.org) for information on specification licensing rights available              */
/*     through TCG membership agreements.                                                                         */
/*     THIS SPECIFICATION IS PROVIDED "AS IS" WITH NO EXPRESS OR IMPLIED WARRANTIES                               */
/*     WHATSOEVER, INCLUDING ANY WARRANTY OF MERCHANTABILITY OR FITNESS FOR A                                     */
/*     PARTICULAR PURPOSE, ACCURACY, COMPLETENESS, OR NONINFRINGEMENT OF INTELLECTUAL                             */
/*     PROPERTY RIGHTS, OR ANY WARRANTY OTHERWISE ARISING OUT OF ANY PROPOSAL,                                    */
/*     SPECIFICATION OR SAMPLE.                                                                                   */
/*     Without limitation, TCG and its members and licensors disclaim all liability, including liability for      */
/*     infringement of any proprietary rights, relating to use of information in this specification and to        */
/*     the implementation of this specification, and TCG disclaims all liability for cost of procurement          */
/*     of substitute goods or services, lost profits, loss of use, loss of data or any incidental,                */
/*     consequential, direct, indirect, or special damages, whether under contract, tort, warranty or             */
/*     otherwise, arising in any way out of use or reliance upon this specification or any information            */
/*     herein.                                                                                                    */
/*     Any marks and brands contained herein are the property of their respective owner.                          */
/*                                                                                                                */
/******************************************************************************************************************/

// 9.6.1 Description
// The functions in this file are used for accessing properties for handles of various types. Functions in other
// files require handles of a specific type but the functions in this file allow use of any handle type.
// 9.6.2 Includes
#include "InternalRoutines.h"

// M e
// TPM_RC_HANDLE handle type does not match
// TPM_RC_REFERENCE_H0 entity is not present
// TPM_RC_HIERARCHY entity belongs to a disabled hierarchy
// TPM_RC_OBJECT_MEMORY handle is an evict object but there is no space to load it to RAM

TPM_RC
EntityGetLoadStatus(
    TPM_HANDLE *handle,                  // IN/OUT: handle of the entity
    TPM_CC commandCode               // IN: the commmandCode
)
{
    TPM_RC result = TPM_RC_SUCCESS;

    switch(HandleGetType(*handle))
    {
    // For handles associated with hierarchies, the entity is present
    // only if the associated enable is SET.
    case TPM_HT_PERMANENT:
        switch(*handle)
        {
        case TPM_RH_OWNER:
            if(!gc.shEnable)
                result = TPM_RC_HIERARCHY;
            break;

#ifdef VENDOR_PERMANENT
        case VENDOR_PERMANENT:
#endif
        case TPM_RH_ENDORSEMENT:
            if(!gc.ehEnable)
                result = TPM_RC_HIERARCHY;
            break;
        case TPM_RH_PLATFORM:
            if(!g_phEnable)
                result = TPM_RC_HIERARCHY;
            break;
        // null handle, PW session handle and lockout
        // handle are always available
        case TPM_RH_NULL:
        case TPM_RS_PW:
        case TPM_RH_LOCKOUT:
            break;
        default:
            // handling of the manufacture_specific handles
            if( ((TPM_RH)*handle >= TPM_RH_AUTH_00)
                    && ((TPM_RH)*handle <= TPM_RH_AUTH_FF))
                // use the value that would have been returned from
                // unmarshaling if it did the handle filtering
                result = TPM_RC_VALUE;
            else
                pAssert(FALSE);
            break;
        }
        break;
    case TPM_HT_TRANSIENT:
        // For a transient object, check if the handle is associated
        // with a loaded object.
        if(!ObjectIsPresent(*handle))
            result = TPM_RC_REFERENCE_H0;
        break;
    case TPM_HT_PERSISTENT:
        // Persistent object
        // Copy the persistent object to RAM and replace the handle with the
        // handle of the assigned slot. A TPM_RC_OBJECT_MEMORY,
        // TPM_RC_HIERARCHY or TPM_RC_REFERENCE_H0 error may be returned by
        // ObjectLoadEvict()
        result = ObjectLoadEvict(handle, commandCode);
        break;
    case TPM_HT_HMAC_SESSION:
        // For an HMAC session, see if the session is loaded
        // and if the session in the session slot is actually
        // an HMAC session.
        if(SessionIsLoaded(*handle))
        {
            SESSION *session;
            session = SessionGet(*handle);
            // Check if the session is a HMAC session
            if(session->attributes.isPolicy == SET)
                result = TPM_RC_HANDLE;
        }
        else
            result = TPM_RC_REFERENCE_H0;
        break;
    case TPM_HT_POLICY_SESSION:
        // For a policy session, see if the session is loaded
        // and if the session in the session slot is actually
        // a policy session.
        if(SessionIsLoaded(*handle))
        {
            SESSION *session;
            session = SessionGet(*handle);
            // Check if the session is a policy session
            if(session->attributes.isPolicy == CLEAR)
                result = TPM_RC_HANDLE;
        }
        else
            result = TPM_RC_REFERENCE_H0;
        break;
    case TPM_HT_NV_INDEX:
        // For an NV Index, use the platform-specific routine
        // to search the IN Index space.
        result = NvIndexIsAccessible(*handle, commandCode);
        break;
    case TPM_HT_PCR:
        // Any PCR handle that is unmarshaled successfully referenced
        // a PCR that is defined.
        break;
    default:
        // Any other handle type is a defect in the unmarshaling code.
        pAssert(FALSE);
        break;
    }
    return result;
}
UINT16
EntityGetAuthValue(
    TPMI_DH_ENTITY handle,                   // IN: handle of entity
    AUTH_VALUE *auth                     // OUT: authValue of the entity
)
{
    TPM2B_AUTH authValue = {0};

    switch(HandleGetType(handle))
    {
    case TPM_HT_PERMANENT:
        switch(handle)
        {
        case TPM_RH_OWNER:
            // ownerAuth for TPM_RH_OWNER
            authValue = gp.ownerAuth;
            break;
        case TPM_RH_ENDORSEMENT:
            // endorsementAuth for TPM_RH_ENDORSEMENT
            authValue = gp.endorsementAuth;
            break;
        case TPM_RH_PLATFORM:
            // platformAuth for TPM_RH_PLATFORM
            authValue = gc.platformAuth;
            break;
        case TPM_RH_LOCKOUT:
            // lockoutAuth for TPM_RH_LOCKOUT
            authValue = gp.lockoutAuth;
            break;
        case TPM_RH_NULL:
            // nullAuth for TPM_RH_NULL. Return 0 directly here
            return 0;
            break;
#ifdef VENDOR_PERMANENT
        case VENDOR_PERMANENT:
            // vendor auth value
            authValue = g_platformUniqueDetails;
#endif
        default:
            // If any other permanent handle is present it is
            // a code defect.
            pAssert(FALSE);
            break;
        }
        break;
    case TPM_HT_TRANSIENT:
        // authValue for an object
        // A persistent object would have been copied into RAM
        // and would have an transient object handle here.
    {
        OBJECT *object;
        object = ObjectGet(handle);
        // special handling if this is a sequence object
        if(ObjectIsSequence(object))
        {
            authValue = ((HASH_OBJECT *)object)->auth;
        }
        else
        {
            // Auth value is available only when the private portion of
            // the object is loaded. The check should be made before
            // this function is called
            pAssert(object->attributes.publicOnly == CLEAR);
            authValue = object->sensitive.authValue;
        }
    }
    break;
    case TPM_HT_NV_INDEX:
        // authValue for an NV index
    {
        NV_INDEX nvIndex;
        NvGetIndexInfo(handle, &nvIndex);
        authValue = nvIndex.authValue;
    }
    break;
    case TPM_HT_PCR:
        // authValue for PCR
        PCRGetAuthValue(handle, &authValue);
        break;
    default:
        // If any other handle type is present here, then there is a defect
        // in the unmarshaling code.
        pAssert(FALSE);
        break;
    }

    // Copy the authValue
    pAssert(authValue.t.size <= sizeof(authValue.t.buffer));
    MemoryCopy(auth, authValue.t.buffer, authValue.t.size, sizeof(TPMU_HA));

    return authValue.t.size;
}
TPMI_ALG_HASH
EntityGetAuthPolicy(
    TPMI_DH_ENTITY handle,               // IN: handle of entity
    TPM2B_DIGEST *authPolicy              // OUT: authPolicy of the entity
)
{
    TPMI_ALG_HASH hashAlg = TPM_ALG_NULL;

    switch(HandleGetType(handle))
    {
    case TPM_HT_PERMANENT:
        switch(handle)
        {
        case TPM_RH_OWNER:
            // ownerPolicy for TPM_RH_OWNER
            *authPolicy = gp.ownerPolicy;
            hashAlg = gp.ownerAlg;
            break;
        case TPM_RH_ENDORSEMENT:
            // endorsementPolicy for TPM_RH_ENDORSEMENT
            *authPolicy = gp.endorsementPolicy;
            hashAlg = gp.endorsementAlg;
            break;
        case TPM_RH_PLATFORM:
            // platformPolicy for TPM_RH_PLATFORM
            *authPolicy = gc.platformPolicy;
            hashAlg = gc.platformAlg;
            break;
        case TPM_RH_LOCKOUT:
            // lockoutPolicy for TPM_RH_LOCKOUT
            *authPolicy = gp.lockoutPolicy;
            hashAlg = gp.lockoutAlg;
            break;
        default:
            // If any other permanent handle is present it is
            // a code defect.
            pAssert(FALSE);
            break;
        }
        break;
    case TPM_HT_TRANSIENT:
        // authPolicy for an object
    {
        OBJECT *object = ObjectGet(handle);
        *authPolicy = object->publicArea.authPolicy;
        hashAlg = object->publicArea.nameAlg;
    }
    break;
    case TPM_HT_NV_INDEX:
        // authPolicy for a NV index
    {
        NV_INDEX nvIndex;
        NvGetIndexInfo(handle, &nvIndex);
        *authPolicy = nvIndex.publicArea.authPolicy;
        hashAlg = nvIndex.publicArea.nameAlg;
    }
    break;
    case TPM_HT_PCR:
        // authPolicy for a PCR
        hashAlg = PCRGetAuthPolicy(handle, authPolicy);
        break;
    default:
        // If any other handle type is present it is a code defect.
        pAssert(FALSE);
        break;
    }
    return hashAlg;
}
UINT16
EntityGetName(
    TPMI_DH_ENTITY handle,                 // IN: handle of entity
    NAME *name                      // OUT: name of entity
)
{
    UINT16 nameSize;

    switch(HandleGetType(handle))
    {
    case TPM_HT_TRANSIENT:
        // Name for an object
        nameSize = ObjectGetName(handle, name);
        break;
    case TPM_HT_NV_INDEX:
        // Name for a NV index
        nameSize = NvGetName(handle, name);
        break;
    default:
        // For all other types, the handle is the Name
        nameSize = TPM_HANDLE_Marshal(&handle, (BYTE **)&name, NULL);
        break;
    }
    return nameSize;
}
TPMI_RH_HIERARCHY
EntityGetHierarchy(
    TPMI_DH_ENTITY handle                 // IN :handle of entity
)
{
    TPMI_RH_HIERARCHY hierarcy = TPM_RH_NULL;

    switch(HandleGetType(handle))
    {
    case TPM_HT_PERMANENT:
        // hierarchy for a permanent handle
        switch(handle)
        {
        case TPM_RH_PLATFORM:
        case TPM_RH_ENDORSEMENT:
        case TPM_RH_NULL:
            hierarcy = handle;
            break;
        // all other permanent handles are associated with the owner
        // hierarchy. (should only be TPM_RH_OWNER and TPM_RH_LOCKOUT)
        default:
            hierarcy = TPM_RH_OWNER;
            break;
        }
        break;
    case TPM_HT_NV_INDEX:
        // hierarchy for NV index
    {
        NV_INDEX nvIndex;
        NvGetIndexInfo(handle, &nvIndex);
        // If only the platform can delete the index, then it is
        // considered to be in the platform hierarchy, otherwise it
        // is in the owner hierarchy.
        if(nvIndex.publicArea.attributes.TPMA_NV_PLATFORMCREATE == SET)
            hierarcy = TPM_RH_PLATFORM;
        else
            hierarcy = TPM_RH_OWNER;
    }
    break;
    case TPM_HT_TRANSIENT:
        // hierarchy for an object
    {
        OBJECT *object;
        object = ObjectGet(handle);
        if(object->attributes.ppsHierarchy)
        {
            hierarcy = TPM_RH_PLATFORM;
        }
        else if(object->attributes.epsHierarchy)
        {
            hierarcy = TPM_RH_ENDORSEMENT;
        }
        else if(object->attributes.spsHierarchy)
        {
            hierarcy = TPM_RH_OWNER;
        }

    }
    break;
    case TPM_HT_PCR:
        hierarcy = TPM_RH_OWNER;
        break;
    default:
        pAssert(0);
        break;
    }
    // this is unreachable but it provides a return value for the default
    // case which makes the complier happy
    return hierarcy;
}
