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

// 6.4.1 Introduction
// This file contains the subsystem that process the authorization sessions including implementation of the
// Dictionary Attack logic. ExecCommand() uses ParseSessionBuffer() to process the authorization session
// area of a command and BuildResponseSession() to create the authorization session area of a response.
// 6.4.2 Includes and Data Definitions
#define SESSION_PROCESS_C
#include "InternalRoutines.h"
#include "SessionProcess_fp.h"
#include "Platform.h"
BOOL
IsDAExempted(
    TPM_HANDLE handle            // IN: entity handle
)
{
    BOOL result = FALSE;

    switch(HandleGetType(handle))
    {
    case TPM_HT_PERMANENT:
        // All permanent handles, other than TPM_RH_LOCKOUT, are exempt from
        // DA protection.
        result = (handle != TPM_RH_LOCKOUT);
        break;

    // When this function is called, a persistent object will have been loaded
    // into an object slot and assigned a transient handle.
    case TPM_HT_TRANSIENT:
    {
        OBJECT *object;
        object = ObjectGet(handle);
        result = (object->publicArea.objectAttributes.noDA == SET);
        break;
    }
    case TPM_HT_NV_INDEX:
    {
        NV_INDEX nvIndex;
        NvGetIndexInfo(handle, &nvIndex);
        result = (nvIndex.publicArea.attributes.TPMA_NV_NO_DA == SET);
        break;
    }
    case TPM_HT_PCR:
        // PCRs are always exempted from DA.
        result = TRUE;
        break;
    default:
        break;
    }
    return result;
}

// M e
// TPM_RC_AUTH_FAIL authorization failure that caused DA lockout to increment
// TPM_RC_BAD_AUTH authorization failure did not cause DA lockout to increment

static TPM_RC
IncrementLockout(
    UINT32 sessionIndex
)
{
    TPM_HANDLE handle = s_associatedHandles[sessionIndex];
    TPM_HANDLE sessionHandle = s_sessionHandles[sessionIndex];
    TPM_RC result;
    SESSION *session = NULL;

    // Don't increment lockout unless the handle associated with the session
    // is DA protected or the session is bound to a DA protected entity.
    if(sessionHandle == TPM_RS_PW)
    {
        if(IsDAExempted(handle))
            return TPM_RC_BAD_AUTH;

    }
    else
    {
        session = SessionGet(sessionHandle);
        // If the session is bound to lockout, then use that as the relevant
        // handle. This means that an auth failure with a bound session
        // bound to lockoutAuth will take precedence over any other
        // lockout check
        if(session->attributes.isLockoutBound == SET)
            handle = TPM_RH_LOCKOUT;

        if( session->attributes.isDaBound == CLEAR
                && IsDAExempted(handle)
          )
            // If the handle was changed to TPM_RH_LOCKOUT, this will not return
            // TPM_RC_BAD_AUTH
            return TPM_RC_BAD_AUTH;

    }

    if(handle == TPM_RH_LOCKOUT)
    {
        pAssert(gp.lockOutAuthEnabled);
        gp.lockOutAuthEnabled = FALSE;
        // For TPM_RH_LOCKOUT, if lockoutRecovery is 0, no need to update NV since
        // the lockout auth will be reset at startup.
        if(gp.lockoutRecovery != 0)
        {
            result = NvIsAvailable();
            if(result != TPM_RC_SUCCESS)
            {
                // No NV access for now. Put the TPM in pending mode.
                s_DAPendingOnNV = TRUE;
            }
            else
            {
                // Update NV.
                NvWriteReserved(NV_LOCKOUT_AUTH_ENABLED, &gp.lockOutAuthEnabled);
                g_updateNV = TRUE;
            }
        }
    }
    else
    {
        if(gp.recoveryTime != 0)
        {
            gp.failedTries++;
            result = NvIsAvailable();
            if(result != TPM_RC_SUCCESS)
            {
                // No NV access for now. Put the TPM in pending mode.
                s_DAPendingOnNV = TRUE;
            }
            else
            {
                // Record changes to NV.
                NvWriteReserved(NV_FAILED_TRIES, &gp.failedTries);
                g_updateNV = TRUE;
            }
        }
    }

    // Register a DA failure and reset the timers.
    DARegisterFailure(handle);

    return TPM_RC_AUTH_FAIL;
}
static BOOL
IsSessionBindEntity(
    TPM_HANDLE associatedHandle,             // IN: handle to be authorized
    SESSION *session                      // IN: associated session
)
{
    TPM2B_NAME entity;                         // The bind value for the entity

    // If the session is not bound, return FALSE.
    if(!session->attributes.isBound)
        return FALSE;

    // Compute the bind value for the entity.
    SessionComputeBoundEntity(associatedHandle, &entity);

    // Compare to the bind value in the session.
    session->attributes.requestWasBound =
        Memory2BEqual(&entity.b, &session->u1.boundEntity.b);
    return session->attributes.requestWasBound;
}
static BOOL
IsPolicySessionRequired(
    TPM_CC commandCode,          // IN: command code
    UINT32 sessionIndex          // IN: session index
)
{
    AUTH_ROLE role = CommandAuthRole(commandCode, sessionIndex);
    TPM_HT type = HandleGetType(s_associatedHandles[sessionIndex]);

    if(role == AUTH_DUP)
        return TRUE;

    if(role == AUTH_ADMIN)
    {
        if(type == TPM_HT_TRANSIENT)
        {
            OBJECT *object = ObjectGet(s_associatedHandles[sessionIndex]);

            if(object->publicArea.objectAttributes.adminWithPolicy == CLEAR)
                return FALSE;
        }
        return TRUE;
    }

    if(type == TPM_HT_PCR)
    {
        if(PCRPolicyIsAvailable(s_associatedHandles[sessionIndex]))
        {
            TPM2B_DIGEST policy;
            TPMI_ALG_HASH policyAlg;
            policyAlg = PCRGetAuthPolicy(s_associatedHandles[sessionIndex],
                                         &policy);
            if(policyAlg != TPM_ALG_NULL)
                return TRUE;
        }
    }
    return FALSE;
}
static BOOL
IsAuthValueAvailable(
    TPM_HANDLE handle,                    // IN: handle of entity
    TPM_CC commandCode,               // IN: commandCode
    UINT32 sessionIndex               // IN: session index
)
{
    BOOL result = FALSE;
    // If a policy session is required, the entity can not be authorized by
    // authValue. However, at this point, the policy session requirement should
    // already have been checked.
    pAssert(!IsPolicySessionRequired(commandCode, sessionIndex));

    switch(HandleGetType(handle))
    {
    case TPM_HT_PERMANENT:
        switch(handle)
        {
        // At this point hierarchy availability has already been
        // checked so primary seed handles are always available here
        case TPM_RH_OWNER:
        case TPM_RH_ENDORSEMENT:
        case TPM_RH_PLATFORM:
#ifdef VENDOR_PERMANENT
        // This vendor defined handle associated with the
        // manufacturer's shared secret
        case VENDOR_PERMANENT:
#endif
        // NullAuth is always available.
        case TPM_RH_NULL:
        // At the point when authValue availability is checked, control
        // path has already passed the DA check so LockOut auth is
        // always available here
        case TPM_RH_LOCKOUT:

            result = TRUE;
            break;
        default:
            // Otherwise authValue is not available.
            break;
        }
        break;
    case TPM_HT_TRANSIENT:
        // A persistent object has already been loaded and the internal
        // handle changed.
    {
        OBJECT *object;
        object = ObjectGet(handle);

        // authValue is always available for a sequence object.
        if(ObjectIsSequence(object))
        {
            result = TRUE;
            break;
        }
        // authValue is available for an object if it has its sensitive
        // portion loaded and
        // 1. userWithAuth bit is SET, or
        // 2. ADMIN role is required
        if( object->attributes.publicOnly == CLEAR
                && (object->publicArea.objectAttributes.userWithAuth == SET
                    || (CommandAuthRole(commandCode, sessionIndex) == AUTH_ADMIN
                        && object->publicArea.objectAttributes.adminWithPolicy
                        == CLEAR)))
            result = TRUE;
    }
    break;
    case TPM_HT_NV_INDEX:
        // NV Index.
    {
        NV_INDEX nvIndex;
        NvGetIndexInfo(handle, &nvIndex);
        if(IsWriteOperation(commandCode))
        {
            if (nvIndex.publicArea.attributes.TPMA_NV_AUTHWRITE == SET)
                result = TRUE;

        }
        else
        {
            if (nvIndex.publicArea.attributes.TPMA_NV_AUTHREAD == SET)
                result = TRUE;
        }
    }
    break;
    case TPM_HT_PCR:
        // PCR handle.
        // authValue is always allowed for PCR
        result = TRUE;
        break;
    default:
        // Otherwise, authValue is not available
        break;
    }
    return result;
}
static BOOL
IsAuthPolicyAvailable(
    TPM_HANDLE handle,             // IN: handle of entity
    TPM_CC commandCode,        // IN: commandCode
    UINT32 sessionIndex        // IN: session index
)
{
    BOOL result = FALSE;
    switch(HandleGetType(handle))
    {
    case TPM_HT_PERMANENT:
        switch(handle)
        {
        // At this point hierarchy availability has already been checked.
        case TPM_RH_OWNER:
            if (gp.ownerPolicy.t.size != 0)
                result = TRUE;
            break;

        case TPM_RH_ENDORSEMENT:
            if (gp.endorsementPolicy.t.size != 0)
                result = TRUE;
            break;

        case TPM_RH_PLATFORM:
            if (gc.platformPolicy.t.size != 0)
                result = TRUE;
            break;
        case TPM_RH_LOCKOUT:
            if(gp.lockoutPolicy.t.size != 0)
                result = TRUE;
            break;
        default:
            break;
        }
        break;
    case TPM_HT_TRANSIENT:
    {
        // Object handle.
        // An evict object would already have been loaded and given a
        // transient object handle by this point.
        OBJECT *object = ObjectGet(handle);
        // Policy authorization is not available for an object with only
        // public portion loaded.
        if(object->attributes.publicOnly == CLEAR)
        {
            // Policy authorization is always available for an object but
            // is never available for a sequence.
            if(!ObjectIsSequence(object))
                result = TRUE;
        }
        break;
    }
    case TPM_HT_NV_INDEX:
        // An NV Index.
    {
        NV_INDEX nvIndex;
        NvGetIndexInfo(handle, &nvIndex);
        // If the policy size is not zero, check if policy can be used.
        if(nvIndex.publicArea.authPolicy.t.size != 0)
        {
            // If policy session is required for this handle, always
            // uses policy regardless of the attributes bit setting
            if(IsPolicySessionRequired(commandCode, sessionIndex))
                result = TRUE;
            // Otherwise, the presence of the policy depends on the NV
            // attributes.
            else if(IsWriteOperation(commandCode))
            {
                if ( nvIndex.publicArea.attributes.TPMA_NV_POLICYWRITE
                        == SET)
                    result = TRUE;
            }
            else
            {
                if ( nvIndex.publicArea.attributes.TPMA_NV_POLICYREAD
                        == SET)
                    result = TRUE;
            }
        }
    }
    break;
    case TPM_HT_PCR:
        // PCR handle.
        if(PCRPolicyIsAvailable(handle))
            result = TRUE;
        break;
    default:
        break;
    }
    return result;
}
static void
ComputeCpHash(
    TPMI_ALG_HASH hashAlg,                        // IN: hash algorithm
    TPM_CC commandCode,                    // IN: command code
    UINT32 handleNum,                      // IN: number of handle
    TPM_HANDLE handles[],                      // IN: array of handle
    UINT32 parmBufferSize,                 // IN: size of input parameter area
    BYTE *parmBuffer,                       // IN: input parameter area
    TPM2B_DIGEST *cpHash,                           // OUT: cpHash
    TPM2B_DIGEST *nameHash                          // OUT: name hash of command
)
{
    UINT32 i;
    HASH_STATE hashState;
    TPM2B_NAME name;

    // cpHash = hash(commandCode [ || authName1
    // [ || authName2
    // [ || authName 3 ]]]
    // [ || parameters])
    // A cpHash can contain just a commandCode only if the lone session is
    // an audit session.

    // Start cpHash.
    cpHash->t.size = CryptStartHash(hashAlg, &hashState);

    // Add commandCode.
    CryptUpdateDigestInt(&hashState, sizeof(TPM_CC), &commandCode);

    // Add authNames for each of the handles.
    for(i = 0; i < handleNum; i++)
    {
        name.t.size = EntityGetName(handles[i], &name.t.name);
        CryptUpdateDigest2B(&hashState, &name.b);
    }

    // Add the parameters.
    CryptUpdateDigest(&hashState, parmBufferSize, parmBuffer);

    // Complete the hash.
    CryptCompleteHash2B(&hashState, &cpHash->b);

    // If the nameHash is needed, compute it here.
    if(nameHash != NULL)
    {
        // Start name hash. hashState may be reused.
        nameHash->t.size = CryptStartHash(hashAlg, &hashState);

        // Adding names.
        for(i = 0; i < handleNum; i++)
        {
            name.t.size = EntityGetName(handles[i], &name.t.name);
            CryptUpdateDigest2B(&hashState, &name.b);
        }
        // Complete hash.
        CryptCompleteHash2B(&hashState, &nameHash->b);
    }
    return;
}

// E r
// M e
// TPM_RC_AUTH_FAIL
// TPM_RC_BAD_AUTH

static TPM_RC
CheckPWAuthSession(
    UINT32 sessionIndex            // IN: index of session to be processed
)
{
    TPM2B_AUTH authValue;
    TPM_HANDLE associatedHandle = s_associatedHandles[sessionIndex];

    // Strip trailing zeros from the password.
    MemoryRemoveTrailingZeros(&s_inputAuthValues[sessionIndex]);

    // Get the auth value and size.
    authValue.t.size = EntityGetAuthValue(associatedHandle, &authValue.t.buffer);

    // Success if the digests are identical.
    if(Memory2BEqual(&s_inputAuthValues[sessionIndex].b, &authValue.b))
    {
        return TPM_RC_SUCCESS;
    }
    else                                         // if the digests are not identical
    {
        // Invoke DA protection if applicable.
        return IncrementLockout(sessionIndex);
    }
}
static void
ComputeCommandHMAC(
    UINT32 sessionIndex,                 // IN: index of session to be processed
    TPM2B_DIGEST *cpHash,                       // IN: cpHash
    TPM2B_DIGEST *hmac                          // OUT: authorization HMAC
)
{
    TPM2B_TYPE(KEY, (sizeof(AUTH_VALUE) * 2));
    TPM2B_KEY key;
    BYTE marshalBuffer[sizeof(TPMA_SESSION)];
    BYTE *buffer;
    UINT32 marshalSize;
    HMAC_STATE hmacState;
    TPM2B_NONCE *nonceDecrypt;
    TPM2B_NONCE *nonceEncrypt;
    SESSION *session;
    TPM_HT sessionHandleType =
        HandleGetType(s_sessionHandles[sessionIndex]);

    nonceDecrypt = NULL;
    nonceEncrypt = NULL;

    // Determine if extra nonceTPM values are going to be required.
    // If this is the first session (sessionIndex = 0) and it is an authorization
    // session that uses an HMAC, then check if additional session nonces are to be
    // included.
    if( sessionIndex == 0
            && s_associatedHandles[sessionIndex] != TPM_RH_UNASSIGNED)
    {
        // If there is a decrypt session and if this is not the decrypt session,
        // then an extra nonce may be needed.
        if( s_decryptSessionIndex != UNDEFINED_INDEX
                && s_decryptSessionIndex != sessionIndex)
        {
            // Will add the nonce for the decrypt session.
            SESSION *decryptSession
                = SessionGet(s_sessionHandles[s_decryptSessionIndex]);
            nonceDecrypt = &decryptSession->nonceTPM;
        }
        // Now repeat for the encrypt session.
        if( s_encryptSessionIndex != UNDEFINED_INDEX
                && s_encryptSessionIndex != sessionIndex
                && s_encryptSessionIndex != s_decryptSessionIndex)
        {
            // Have to have the nonce for the encrypt session.
            SESSION *encryptSession
                = SessionGet(s_sessionHandles[s_encryptSessionIndex]);
            nonceEncrypt = &encryptSession->nonceTPM;
        }
    }

    // Continue with the HMAC processing.
    session = SessionGet(s_sessionHandles[sessionIndex]);

    // Generate HMAC key.
    MemoryCopy2B(&key.b, &session->sessionKey.b, sizeof(key.t.buffer));

    // Check if the session has an associated handle and if the associated entity
    // is the one to which the session is bound. If not, add the authValue of
    // this entity to the HMAC key.
    // If the session is bound to the object or the session is a policy session
    // with no authValue required, do not include the authValue in the HMAC key.
    // Note: For a policy session, its isBound attribute is CLEARED.

    // If the session isn't used for authorization, then there is no auth value
    // to add
    if(s_associatedHandles[sessionIndex] != TPM_RH_UNASSIGNED)
    {
        // used for auth so see if this is a policy session with authValue needed
        // or an hmac session that is not bound
        if( sessionHandleType == TPM_HT_POLICY_SESSION
                && session->attributes.isAuthValueNeeded == SET
                || sessionHandleType == TPM_HT_HMAC_SESSION
                && !IsSessionBindEntity(s_associatedHandles[sessionIndex], session)
          )
        {
            // add the authValue to the HMAC key
            pAssert((sizeof(AUTH_VALUE) + key.t.size) <= sizeof(key.t.buffer));
            key.t.size = key.t.size
                         + EntityGetAuthValue(s_associatedHandles[sessionIndex],
                                              (AUTH_VALUE *)&(key.t.buffer[key.t.size]));
        }
    }

    // if the HMAC key size is 0, a NULL string HMAC is allowed
    if( key.t.size == 0
            && s_inputAuthValues[sessionIndex].t.size == 0)
    {
        hmac->t.size = 0;
        return;
    }

    // Start HMAC
    hmac->t.size = CryptStartHMAC2B(session->authHashAlg, &key.b, &hmacState);

    // Add cpHash
    CryptUpdateDigest2B(&hmacState, &cpHash->b);

    // Add nonceCaller
    CryptUpdateDigest2B(&hmacState, &s_nonceCaller[sessionIndex].b);

    // Add nonceTPM
    CryptUpdateDigest2B(&hmacState, &session->nonceTPM.b);

    // If needed, add nonceTPM for decrypt session
    if(nonceDecrypt != NULL)
        CryptUpdateDigest2B(&hmacState, &nonceDecrypt->b);

    // If needed, add nonceTPM for encrypt session
    if(nonceEncrypt != NULL)
        CryptUpdateDigest2B(&hmacState, &nonceEncrypt->b);

    // Add sessionAttributes
    buffer = marshalBuffer;
    marshalSize = TPMA_SESSION_Marshal(&(s_attributes[sessionIndex]),
                                       &buffer, NULL);
    CryptUpdateDigest(&hmacState, marshalSize, marshalBuffer);

    // Complete the HMAC computation
    CryptCompleteHMAC2B(&hmacState, &hmac->b);

    return;
}

// E r
// M e
// TPM_RC_AUTH_FAIL
// TPM_RC_BAD_AUTH

static TPM_RC
CheckSessionHMAC(
    UINT32 sessionIndex,        // IN: index of session to be processed
    TPM2B_DIGEST *cpHash                  // IN: cpHash of the command
)
{
    TPM2B_DIGEST hmac;                   // authHMAC for comparing

    // Compute authHMAC
    ComputeCommandHMAC(sessionIndex, cpHash, &hmac);

    // Compare the input HMAC with the authHMAC computed above.
    if(!Memory2BEqual(&s_inputAuthValues[sessionIndex].b, &hmac.b))
    {
        // If an HMAC session has a failure, invoke the anti-hammering
        // if it applies to the authorized entity or the session.
        // Otherwise, just indicate that the authorization is bad.
        return IncrementLockout(sessionIndex);
    }
    return TPM_RC_SUCCESS;
}

// E r
// M e
// TPM_RC_PCR_CHANGED
// TPM_RC_POLICY_FAIL
// TPM_RC_LOCALITY
// TPM_RC_POLICY_CC
// TPM_RC_EXPIRED
// TPM_RC_PP
// TPM_RC_NV_UNAVAILABLE
// TPM_RC_NV_RATE

static TPM_RC
CheckPolicyAuthSession(
    UINT32 sessionIndex,              // IN: index of session to be processed
    TPM_CC commandCode,               // IN: command code
    TPM2B_DIGEST *cpHash,                     // IN: cpHash using the algorithm of this
    // session
    TPM2B_DIGEST *nameHash                    // IN: nameHash using the session algorithm
)
{
    TPM_RC result = TPM_RC_SUCCESS;
    SESSION *session;
    TPM2B_DIGEST authPolicy;
    TPMI_ALG_HASH policyAlg;
    UINT8 locality;

    // Initialize pointer to the auth session.
    session = SessionGet(s_sessionHandles[sessionIndex]);

    // If the command is TPM_RC_PolicySecret(), make sure that
    // either password or authValue is required
    if( commandCode == TPM_CC_PolicySecret
            && session->attributes.isPasswordNeeded == CLEAR
            && session->attributes.isAuthValueNeeded == CLEAR)
        return TPM_RC_MODE;

    // See if the PCR counter for the session is still valid.
    if( !SessionPCRValueIsCurrent(s_sessionHandles[sessionIndex]) )
        return TPM_RC_PCR_CHANGED;

    // Get authPolicy.
    policyAlg = EntityGetAuthPolicy(s_associatedHandles[sessionIndex],
                                    &authPolicy);
    // Compare authPolicy.
    if(!Memory2BEqual(&session->u2.policyDigest.b, &authPolicy.b))
        return TPM_RC_POLICY_FAIL;

    // Policy is OK so check if the other factors are correct

    // Compare policy hash algorithm.
    if(policyAlg != session->authHashAlg)
        return TPM_RC_POLICY_FAIL;

    // Compare timeout.
    if(session->timeOut != 0)
    {
        // Cannot compare time if clock stop advancing. An TPM_RC_NV_UNAVAILABLE
        // or TPM_RC_NV_RATE error may be returned here.
        result = NvIsAvailable();
        if(result != TPM_RC_SUCCESS)
            return result;

        if(session->timeOut < go.clock)
            return TPM_RC_EXPIRED;
    }

    // If command code is provided it must match
    if(session->commandCode != 0)
    {
        if(session->commandCode != commandCode)
            return TPM_RC_POLICY_CC;
    }
    else
    {
        // If command requires a DUP or ADMIN authorization, the session must have
        // command code set.
        AUTH_ROLE role = CommandAuthRole(commandCode, sessionIndex);
        if(role == AUTH_ADMIN || role == AUTH_DUP)
            return TPM_RC_POLICY_FAIL;
    }
    // Check command locality.
    {
        BYTE sessionLocality[sizeof(TPMA_LOCALITY)];
        BYTE *buffer = sessionLocality;

        // Get existing locality setting in canonical form
        TPMA_LOCALITY_Marshal(&session->commandLocality, &buffer, NULL);

        // See if the locality has been set
        if(sessionLocality[0] != 0)
        {
            // If so, get the current locality
            locality = _plat__LocalityGet();
            if (locality < 5)
            {
                if( ((sessionLocality[0] & (1 << locality)) == 0)
                        || sessionLocality[0] > 31)
                    return TPM_RC_LOCALITY;
            }
            else if (locality > 31)
            {
                if(sessionLocality[0] != locality)
                    return TPM_RC_LOCALITY;
            }
            else
            {
                // Could throw an assert here but a locality error is just
                // as good. It just means that, whatever the locality is, it isn't
                // the locality requested so...
                return TPM_RC_LOCALITY;
            }
        }
    }   // end of locality check

    // Check physical presence.
    if( session->attributes.isPPRequired == SET
            && !_plat__PhysicalPresenceAsserted())
        return TPM_RC_PP;

    // Compare cpHash/nameHash if defined, or if the command requires an ADMIN or
    // DUP role for this handle.
    if(session->u1.cpHash.b.size != 0)
    {
        if(session->attributes.iscpHashDefined)
        {
            // Compare cpHash.
            if(!Memory2BEqual(&session->u1.cpHash.b, &cpHash->b))
                return TPM_RC_POLICY_FAIL;
        }
        else
        {
            // Compare nameHash.
            // When cpHash is not defined, nameHash is placed in its space.
            if(!Memory2BEqual(&session->u1.cpHash.b, &nameHash->b))
                return TPM_RC_POLICY_FAIL;
        }
    }
    if(session->attributes.checkNvWritten)
    {
        NV_INDEX nvIndex;

        // If this is not an NV index, the policy makes no sense so fail it.
        if(HandleGetType(s_associatedHandles[sessionIndex])!= TPM_HT_NV_INDEX)
            return TPM_RC_POLICY_FAIL;

        // Get the index data
        NvGetIndexInfo(s_associatedHandles[sessionIndex], &nvIndex);

        // Make sure that the TPMA_WRITTEN_ATTRIBUTE has the desired state
        if( (nvIndex.publicArea.attributes.TPMA_NV_WRITTEN == SET)
                != (session->attributes.nvWrittenState == SET))
            return TPM_RC_POLICY_FAIL;
    }

    return TPM_RC_SUCCESS;
}

// E r
// M e
// TPM_RC_SUCCSS
// TPM_RC_SIZE


static TPM_RC
RetrieveSessionData (
    TPM_CC commandCode,          // IN: command code
    UINT32 *sessionCount,            // OUT: number of sessions found
    BYTE *sessionBuffer,           // IN: pointer to the session buffer
    INT32 bufferSize            // IN: size of the session buffer
)
{
    int sessionIndex;
    int i;
    TPM_RC result;
    SESSION *session;
    TPM_HT sessionType;

    s_decryptSessionIndex = UNDEFINED_INDEX;
    s_encryptSessionIndex = UNDEFINED_INDEX;
    s_auditSessionIndex = UNDEFINED_INDEX;

    for(sessionIndex = 0; bufferSize > 0; sessionIndex++)
    {
        // If maximum allowed number of sessions has been parsed, return a size
        // error with a session number that is larger than the number of allowed
        // sessions
        if(sessionIndex == MAX_SESSION_NUM)
            return TPM_RC_SIZE + TPM_RC_S + g_rcIndex[sessionIndex+1];

        // make sure that the associated handle for each session starts out
        // unassigned
        s_associatedHandles[sessionIndex] = TPM_RH_UNASSIGNED;

        // First parameter: Session handle.
        result = TPMI_SH_AUTH_SESSION_Unmarshal(&s_sessionHandles[sessionIndex],
                                                &sessionBuffer, &bufferSize, TRUE);
        if(result != TPM_RC_SUCCESS)
            return result + TPM_RC_S + g_rcIndex[sessionIndex];

        // Second parameter: Nonce.
        result = TPM2B_NONCE_Unmarshal(&s_nonceCaller[sessionIndex],
                                       &sessionBuffer, &bufferSize);
        if(result != TPM_RC_SUCCESS)
            return result + TPM_RC_S + g_rcIndex[sessionIndex];

        // Third parameter: sessionAttributes.
        result = TPMA_SESSION_Unmarshal(&s_attributes[sessionIndex],
                                        &sessionBuffer, &bufferSize);
        if(result != TPM_RC_SUCCESS)
            return result + TPM_RC_S + g_rcIndex[sessionIndex];

        // Fourth parameter: authValue (PW or HMAC).
        result = TPM2B_AUTH_Unmarshal(&s_inputAuthValues[sessionIndex],
                                      &sessionBuffer, &bufferSize);
        if(result != TPM_RC_SUCCESS)
            return result + TPM_RC_S + g_rcIndex[sessionIndex];

        if(s_sessionHandles[sessionIndex] == TPM_RS_PW)
        {
            // A PWAP session needs additional processing.
            // Can't have any attributes set other than continueSession bit
            if( s_attributes[sessionIndex].encrypt
                    || s_attributes[sessionIndex].decrypt
                    || s_attributes[sessionIndex].audit
                    || s_attributes[sessionIndex].auditExclusive
                    || s_attributes[sessionIndex].auditReset
              )
                return TPM_RC_ATTRIBUTES + TPM_RC_S + g_rcIndex[sessionIndex];

            // The nonce size must be zero.
            if(s_nonceCaller[sessionIndex].t.size != 0)
                return TPM_RC_NONCE + TPM_RC_S + g_rcIndex[sessionIndex];

            continue;
        }
        // For not password sessions...

        // Find out if the session is loaded.
        if(!SessionIsLoaded(s_sessionHandles[sessionIndex]))
            return TPM_RC_REFERENCE_S0 + sessionIndex;

        sessionType = HandleGetType(s_sessionHandles[sessionIndex]);
        session = SessionGet(s_sessionHandles[sessionIndex]);
        // Check if the session is an HMAC/policy session.
        if( ( session->attributes.isPolicy == SET
                && sessionType == TPM_HT_HMAC_SESSION
            )
                || ( session->attributes.isPolicy == CLEAR
                     && sessionType == TPM_HT_POLICY_SESSION
                   )
          )
            return TPM_RC_HANDLE + TPM_RC_S + g_rcIndex[sessionIndex];

        // Check that this handle has not previously been used.
        for(i = 0; i < sessionIndex; i++)
        {
            if(s_sessionHandles[i] == s_sessionHandles[sessionIndex])
                return TPM_RC_HANDLE + TPM_RC_S + g_rcIndex[sessionIndex];
        }

        // If the session is used for parameter encryption or audit as well, set
        // the corresponding indices.

        // First process decrypt.
        if(s_attributes[sessionIndex].decrypt)
        {
            // Check if the commandCode allows command parameter encryption.
            if(DecryptSize(commandCode) == 0)
                return TPM_RC_ATTRIBUTES + TPM_RC_S + g_rcIndex[sessionIndex];

            // Encrypt attribute can only appear in one session
            if(s_decryptSessionIndex != UNDEFINED_INDEX)
                return TPM_RC_ATTRIBUTES + TPM_RC_S + g_rcIndex[sessionIndex];

            // Can't decrypt if the session's symmetric algorithm is TPM_ALG_NULL
            if(session->symmetric.algorithm == TPM_ALG_NULL)
                return TPM_RC_SYMMETRIC + TPM_RC_S + g_rcIndex[sessionIndex];

            // All checks passed, so set the index for the session used to decrypt
            // a command parameter.
            s_decryptSessionIndex = sessionIndex;
        }

        // Now process encrypt.
        if(s_attributes[sessionIndex].encrypt)
        {
            // Check if the commandCode allows response parameter encryption.
            if(EncryptSize(commandCode) == 0)
                return TPM_RC_ATTRIBUTES + TPM_RC_S + g_rcIndex[sessionIndex];

            // Encrypt attribute can only appear in one session.
            if(s_encryptSessionIndex != UNDEFINED_INDEX)
                return TPM_RC_ATTRIBUTES + TPM_RC_S + g_rcIndex[sessionIndex];

            // Can't encrypt if the session's symmetric algorithm is TPM_ALG_NULL
            if(session->symmetric.algorithm == TPM_ALG_NULL)
                return TPM_RC_SYMMETRIC + TPM_RC_S + g_rcIndex[sessionIndex];

            // All checks passed, so set the index for the session used to encrypt
            // a response parameter.
            s_encryptSessionIndex = sessionIndex;
        }

        // At last process audit.
        if(s_attributes[sessionIndex].audit)
        {
            // Audit attribute can only appear in one session.
            if(s_auditSessionIndex != UNDEFINED_INDEX)
                return TPM_RC_ATTRIBUTES + TPM_RC_S + g_rcIndex[sessionIndex];

            // An audit session can not be policy session.
            if( HandleGetType(s_sessionHandles[sessionIndex])
                    == TPM_HT_POLICY_SESSION)
                return TPM_RC_ATTRIBUTES + TPM_RC_S + g_rcIndex[sessionIndex];

            // If this is a reset of the audit session, or the first use
            // of the session as an audit session, it doesn't matter what
            // the exclusive state is. The session will become exclusive.
            if( s_attributes[sessionIndex].auditReset == CLEAR
                    && session->attributes.isAudit == SET)
            {
                // Not first use or reset. If auditExlusive is SET, then this
                // session must be the current exclusive session.
                if( s_attributes[sessionIndex].auditExclusive == SET
                        && g_exclusiveAuditSession != s_sessionHandles[sessionIndex])
                    return TPM_RC_EXCLUSIVE;
            }

            s_auditSessionIndex = sessionIndex;
        }

        // Initialize associated handle as undefined. This will be changed when
        // the handles are processed.
        s_associatedHandles[sessionIndex] = TPM_RH_UNASSIGNED;

    }

    // Set the number of sessions found.
    *sessionCount = sessionIndex;
    return TPM_RC_SUCCESS;
}

// E r
// M e
// TPM_RC_NV_RATE
// TPM_RC_NV_UNAVAILABLE
// TPM_RC_LOCKOUT

static TPM_RC
CheckLockedOut(
    BOOL lockoutAuthCheck                // IN: TRUE if checking is for lockoutAuth
)
{
    TPM_RC result;

    // If NV is unavailable, and current cycle state recorded in NV is not
    // SHUTDOWN_NONE, refuse to check any authorization because we would
    // not be able to handle a DA failure.
    result = NvIsAvailable();
    if(result != TPM_RC_SUCCESS && gp.orderlyState != SHUTDOWN_NONE)
        return result;

    // Check if DA info needs to be updated in NV.
    if(s_DAPendingOnNV)
    {
        // If NV is accessible, ...
        if(result == TPM_RC_SUCCESS)
        {
            // ... write the pending DA data and proceed.
            NvWriteReserved(NV_LOCKOUT_AUTH_ENABLED,
                            &gp.lockOutAuthEnabled);
            NvWriteReserved(NV_FAILED_TRIES, &gp.failedTries);
            g_updateNV = TRUE;
            s_DAPendingOnNV = FALSE;
        }
        else
        {
            // Otherwise no authorization can be checked.
            return result;
        }
    }

    // Lockout is in effect if checking for lockoutAuth and use of lockoutAuth
    // is disabled...
    if(lockoutAuthCheck)
    {
        if(gp.lockOutAuthEnabled == FALSE)
            return TPM_RC_LOCKOUT;
    }
    else
    {
        // ... or if the number of failed tries has been maxed out.
        if(gp.failedTries >= gp.maxTries)
            return TPM_RC_LOCKOUT;
    }
    return TPM_RC_SUCCESS;
}

// E r
// M e
// TPM_RC_LOCKOUT

// TPM_RC_PP
// TPM_RC_AUTH_FAIL

// TPM_RC_BAD_AUTH

// TPM_RC_POLICY_FAIL
// TPM_RC_POLICY_CC
// TPM_RC_EXPIRED
// TPM_RC_PCR
// TPM_RC_AUTH_UNAVAILABLE

static TPM_RC
CheckAuthSession(
    TPM_CC commandCode,            // IN: commandCode
    UINT32 sessionIndex,           // IN: index of session to be processed
    TPM2B_DIGEST *cpHash,                // IN: cpHash
    TPM2B_DIGEST *nameHash               // IN: nameHash
)
{
    TPM_RC result;
    SESSION *session = NULL;
    TPM_HANDLE sessionHandle = s_sessionHandles[sessionIndex];
    TPM_HANDLE associatedHandle = s_associatedHandles[sessionIndex];
    TPM_HT sessionHandleType = HandleGetType(sessionHandle);

    pAssert(sessionHandle != TPM_RH_UNASSIGNED);

    if(sessionHandle != TPM_RS_PW)
        session = SessionGet(sessionHandle);

    pAssert(sessionHandleType != TPM_HT_POLICY_SESSION || session != NULL);

    // If the authorization session is not a policy session, or if the policy
    // session requires authorization, then check lockout.
    if( sessionHandleType != TPM_HT_POLICY_SESSION
            || session->attributes.isAuthValueNeeded
            || session->attributes.isPasswordNeeded)
    {
        // See if entity is subject to lockout.
        if(!IsDAExempted(associatedHandle))
        {
            // If NV is unavailable, and current cycle state recorded in NV is not
            // SHUTDOWN_NONE, refuse to check any authorization because we would
            // not be able to handle a DA failure.
            result = CheckLockedOut(associatedHandle == TPM_RH_LOCKOUT);
            if(result != TPM_RC_SUCCESS)
                return result;
        }
    }

    if(associatedHandle == TPM_RH_PLATFORM)
    {
        // If the physical presence is required for this command, check for PP
        // assertion. If it isn't asserted, no point going any further.
        if( PhysicalPresenceIsRequired(commandCode)
                && !_plat__PhysicalPresenceAsserted()
          )
            return TPM_RC_PP;
    }
    // If a policy session is required, make sure that it is being used.
    if( IsPolicySessionRequired(commandCode, sessionIndex)
            && sessionHandleType != TPM_HT_POLICY_SESSION)
        return TPM_RC_AUTH_TYPE;

    // If this is a PW authorization, check it and return.
    if(sessionHandle == TPM_RS_PW)
    {
        if(IsAuthValueAvailable(associatedHandle, commandCode, sessionIndex))
            return CheckPWAuthSession(sessionIndex);
        else
            return TPM_RC_AUTH_UNAVAILABLE;
    }
    // If this is a policy session, ...
    if(sessionHandleType == TPM_HT_POLICY_SESSION)
    {
        // ... see if the entity has a policy, ...
        if( !IsAuthPolicyAvailable(associatedHandle, commandCode, sessionIndex))
            return TPM_RC_AUTH_UNAVAILABLE;
        // ... and check the policy session.
        result = CheckPolicyAuthSession(sessionIndex, commandCode,
                                        cpHash, nameHash);
        if (result != TPM_RC_SUCCESS)
            return result;
    }
    else
    {
        // For non policy, the entity being accessed must allow authorization
        // with an auth value. This is required even if the auth value is not
        // going to be used in an HMAC because it is bound.
        if(!IsAuthValueAvailable(associatedHandle, commandCode, sessionIndex))
            return TPM_RC_AUTH_UNAVAILABLE;
    }
    // At this point, the session must be either a policy or an HMAC session.
    session = SessionGet(s_sessionHandles[sessionIndex]);

    if( sessionHandleType == TPM_HT_POLICY_SESSION
            && session->attributes.isPasswordNeeded == SET)
    {
        // For policy session that requires a password, check it as PWAP session.
        return CheckPWAuthSession(sessionIndex);
    }
    else
    {
        // For other policy or HMAC sessions, have its HMAC checked.
        return CheckSessionHMAC(sessionIndex, cpHash);
    }
}
#ifdef TPM_CC_GetCommandAuditDigest

// E r
// M e
// TPM_RC_NV_UNAVAILABLE
// TPM_RC_NV_RATE

static TPM_RC
CheckCommandAudit(
    TPM_CC commandCode,                      // IN: Command code
    UINT32 handleNum,                        // IN: number of element in handle array
    TPM_HANDLE handles[],                        // IN: array of handle
    BYTE *parmBufferStart,                 // IN: start of parameter buffer
    UINT32 parmBufferSize                    // IN: size of parameter buffer
)
{
    TPM_RC result = TPM_RC_SUCCESS;

    // If audit is implemented, need to check to see if auditing is being done
    // for this command.
    if(CommandAuditIsRequired(commandCode))
    {
        // If the audit digest is clear and command audit is required, NV must be
        // available so that TPM2_GetCommandAuditDigest() is able to increment
        // audit counter. If NV is not available, the function bails out to prevent
        // the TPM from attempting an operation that would fail anyway.
        if( gr.commandAuditDigest.t.size == 0
                || commandCode == TPM_CC_GetCommandAuditDigest)
        {
            result = NvIsAvailable();
            if(result != TPM_RC_SUCCESS)
                return result;
        }
        ComputeCpHash(gp.auditHashAlg, commandCode, handleNum,
                      handles, parmBufferSize, parmBufferStart,
                      &s_cpHashForCommandAudit, NULL);
    }

    return TPM_RC_SUCCESS;
}
#endif

// E r
// M e
// various

TPM_RC
ParseSessionBuffer(
    TPM_CC commandCode,                     // IN: Command code
    UINT32 handleNum,                       // IN: number of element in handle array
    TPM_HANDLE handles[],                       // IN: array of handle
    BYTE *sessionBufferStart,                 // IN: start of session buffer
    UINT32 sessionBufferSize,               // IN: size of session buffer
    BYTE *parmBufferStart,                    // IN: start of parameter buffer
    UINT32 parmBufferSize                   // IN: size of parameter buffer
)
{
    TPM_RC result;
    UINT32 i;
    INT32 size = 0;
    TPM2B_AUTH extraKey;
    UINT32 sessionIndex;
    SESSION *session;
    TPM2B_DIGEST cpHash;
    TPM2B_DIGEST nameHash;
    TPM_ALG_ID cpHashAlg = TPM_ALG_NULL;         // algID for the last computed
    // cpHash

    // Check if a command allows any session in its session area.
    if(!IsSessionAllowed(commandCode))
        return TPM_RC_AUTH_CONTEXT;

    // Default-initialization.
    s_sessionNum = 0;
    cpHash.t.size = 0;

    result = RetrieveSessionData(commandCode, &s_sessionNum,
                                 sessionBufferStart, sessionBufferSize);
    if(result != TPM_RC_SUCCESS)
        return result;

    // There is no command in the TPM spec that has more handles than
    // MAX_SESSION_NUM.
    pAssert(handleNum <= MAX_SESSION_NUM);

    // Associate the session with an authorization handle.
    for(i = 0; i < handleNum; i++)
    {
        if(CommandAuthRole(commandCode, i) != AUTH_NONE)
        {
            // If the received session number is less than the number of handle
            // that requires authorization, an error should be returned.
            // Note: for all the TPM 2.0 commands, handles requiring
            // authorization come first in a command input.
            if(i > (s_sessionNum - 1))
                return TPM_RC_AUTH_MISSING;

            // Record the handle associated with the authorization session
            s_associatedHandles[i] = handles[i];
        }
    }

    // Consistency checks are done first to avoid auth failure when the command
    // will not be executed anyway.
    for(sessionIndex = 0; sessionIndex < s_sessionNum; sessionIndex++)
    {
        // PW session must be an authorization session
        if(s_sessionHandles[sessionIndex] == TPM_RS_PW )
        {
            if(s_associatedHandles[sessionIndex] == TPM_RH_UNASSIGNED)
                return TPM_RC_HANDLE + g_rcIndex[sessionIndex];
        }
        else
        {
            session = SessionGet(s_sessionHandles[sessionIndex]);

            // A trial session can not appear in session area, because it cannot
            // be used for authorization, audit or encrypt/decrypt.
            if(session->attributes.isTrialPolicy == SET)
                return TPM_RC_ATTRIBUTES + TPM_RC_S + g_rcIndex[sessionIndex];

            // See if the session is bound to a DA protected entity
            // NOTE: Since a policy session is never bound, a policy is still
            // usable even if the object is DA protected and the TPM is in
            // lockout.
            if(session->attributes.isDaBound == SET)
            {
                result = CheckLockedOut(session->attributes.isLockoutBound == SET);
                if(result != TPM_RC_SUCCESS)
                    return result;
            }
            // If the current cpHash is the right one, don't re-compute.
            if(cpHashAlg != session->authHashAlg)                        // different so compute
            {
                cpHashAlg = session->authHashAlg;                        // save this new algID
                ComputeCpHash(session->authHashAlg, commandCode, handleNum,
                              handles, parmBufferSize, parmBufferStart,
                              &cpHash, &nameHash);
            }
            // If this session is for auditing, save the cpHash.
            if(s_attributes[sessionIndex].audit)
                s_cpHashForAudit = cpHash;
        }

        // if the session has an associated handle, check the auth
        if(s_associatedHandles[sessionIndex] != TPM_RH_UNASSIGNED)
        {
            result = CheckAuthSession(commandCode, sessionIndex,
                                      &cpHash, &nameHash);
            if(result != TPM_RC_SUCCESS)
                return RcSafeAddToResult(result,
                                         TPM_RC_S + g_rcIndex[sessionIndex]);
        }
        else
        {
            // a session that is not for authorization must either be encrypt,
            // decrypt, or audit
            if( s_attributes[sessionIndex].audit == CLEAR
                    && s_attributes[sessionIndex].encrypt == CLEAR
                    && s_attributes[sessionIndex].decrypt == CLEAR)
                return TPM_RC_ATTRIBUTES + TPM_RC_S + g_rcIndex[sessionIndex];

            // check HMAC for encrypt/decrypt/audit only sessions
            result = CheckSessionHMAC(sessionIndex, &cpHash);
            if(result != TPM_RC_SUCCESS)
                return RcSafeAddToResult(result,
                                         TPM_RC_S + g_rcIndex[sessionIndex]);
        }
    }

#ifdef TPM_CC_GetCommandAuditDigest
    // Check if the command should be audited.
    result = CheckCommandAudit(commandCode, handleNum, handles,
                               parmBufferStart, parmBufferSize);
    if(result != TPM_RC_SUCCESS)
        return result;                            // No session number to reference
#endif

    // Decrypt the first parameter if applicable. This should be the last operation
    // in session processing.
    // If the encrypt session is associated with a handle and the handle's
    // authValue is available, then authValue is concatenated with sessionAuth to
    // generate encryption key, no matter if the handle is the session bound entity
    // or not.
    if(s_decryptSessionIndex != UNDEFINED_INDEX)
    {
        // Get size of the leading size field in decrypt parameter
        if( s_associatedHandles[s_decryptSessionIndex] != TPM_RH_UNASSIGNED
                && IsAuthValueAvailable(s_associatedHandles[s_decryptSessionIndex],
                                        commandCode,
                                        s_decryptSessionIndex)
          )
        {
            extraKey.b.size=
                EntityGetAuthValue(s_associatedHandles[s_decryptSessionIndex],
                                   &extraKey.t.buffer);
        }
        else
        {
            extraKey.b.size = 0;
        }
        size = DecryptSize(commandCode);
        result = CryptParameterDecryption(
                     s_sessionHandles[s_decryptSessionIndex],
                     &s_nonceCaller[s_decryptSessionIndex].b,
                     parmBufferSize, (UINT16)size,
                     &extraKey,
                     parmBufferStart);
        if(result != TPM_RC_SUCCESS)
            return RcSafeAddToResult(result,
                                     TPM_RC_S + g_rcIndex[s_decryptSessionIndex]);
    }

    return TPM_RC_SUCCESS;
}

// E r
// M e
// TPM_RC_AUTH_MISSING

TPM_RC
CheckAuthNoSession(
    TPM_CC commandCode,                // IN: Command Code
    UINT32 handleNum,                  // IN: number of handles in command
    TPM_HANDLE handles[],                  // IN: array of handle
    BYTE *parmBufferStart,               // IN: start of parameter buffer
    UINT32 parmBufferSize              // IN: size of parameter buffer
)
{
    UINT32 i;
    TPM_RC result = TPM_RC_SUCCESS;

    // Check if the commandCode requires authorization
    for(i = 0; i < handleNum; i++)
    {
        if(CommandAuthRole(commandCode, i) != AUTH_NONE)
            return TPM_RC_AUTH_MISSING;
    }

#ifdef TPM_CC_GetCommandAuditDigest
    // Check if the command should be audited.
    result = CheckCommandAudit(commandCode, handleNum, handles,
                               parmBufferStart, parmBufferSize);
    if(result != TPM_RC_SUCCESS) return result;
#endif

    // Initialize number of sessions to be 0
    s_sessionNum = 0;

    return TPM_RC_SUCCESS;
}
static void
ComputeRpHash(
    TPM_ALG_ID hashAlg,                    // IN: hash algorithm to compute rpHash
    TPM_CC commandCode,                // IN: commandCode
    UINT32 resParmBufferSize,          // IN: size of response parameter buffer
    BYTE *resParmBuffer,                 // IN: response parameter buffer
    TPM2B_DIGEST *rpHash                         // OUT: rpHash
)
{
    // The command result in rpHash is always TPM_RC_SUCCESS.
    TPM_RC responseCode = TPM_RC_SUCCESS;
    HASH_STATE hashState;

    // rpHash := hash(responseCode || commandCode || parameters)

    // Initiate hash creation.
    rpHash->t.size = CryptStartHash(hashAlg, &hashState);

    // Add hash constituents.
    CryptUpdateDigestInt(&hashState, sizeof(TPM_RC), &responseCode);
    CryptUpdateDigestInt(&hashState, sizeof(TPM_CC), &commandCode);
    CryptUpdateDigest(&hashState, resParmBufferSize, resParmBuffer);

    // Complete hash computation.
    CryptCompleteHash2B(&hashState, &rpHash->b);

    return;
}
static void
InitAuditSession(
    SESSION *session                 // session to be initialized
)
{
    // Mark session as an audit session.
    session->attributes.isAudit = SET;

    // Audit session can not be bound.
    session->attributes.isBound = CLEAR;

    // Size of the audit log is the size of session hash algorithm digest.
    session->u2.auditDigest.t.size = CryptGetHashDigestSize(session->authHashAlg);

    // Set the original digest value to be 0.
    MemorySet(&session->u2.auditDigest.t.buffer,
              0,
              session->u2.auditDigest.t.size);

    return;
}
static void
Audit(
    SESSION *auditSession,                 // IN: loaded audit session
    TPM_CC commandCode,                   // IN: commandCode
    UINT32 resParmBufferSize,             // IN: size of response parameter buffer
    BYTE *resParmBuffer                 // IN: response parameter buffer
)
{
    TPM2B_DIGEST rpHash;                        // rpHash for response
    HASH_STATE hashState;

    // Compute rpHash
    ComputeRpHash(auditSession->authHashAlg,
                  commandCode,
                  resParmBufferSize,
                  resParmBuffer,
                  &rpHash);

    // auditDigestnew := hash (auditDigestold || cpHash || rpHash)

    // Start hash computation.
    CryptStartHash(auditSession->authHashAlg, &hashState);

    // Add old digest.
    CryptUpdateDigest2B(&hashState, &auditSession->u2.auditDigest.b);

    // Add cpHash and rpHash.
    CryptUpdateDigest2B(&hashState, &s_cpHashForAudit.b);
    CryptUpdateDigest2B(&hashState, &rpHash.b);

    // Finalize the hash.
    CryptCompleteHash2B(&hashState, &auditSession->u2.auditDigest.b);

    return;
}
#ifdef TPM_CC_GetCommandAuditDigest
static void
CommandAudit(
    TPM_CC commandCode,                    // IN: commandCode
    UINT32 resParmBufferSize,              // IN: size of response parameter buffer
    BYTE *resParmBuffer                    // IN: response parameter buffer
)
{
    if(CommandAuditIsRequired(commandCode))
    {
        TPM2B_DIGEST rpHash;                 // rpHash for response
        HASH_STATE hashState;

        // Compute rpHash.
        ComputeRpHash(gp.auditHashAlg, commandCode, resParmBufferSize,
                      resParmBuffer, &rpHash);

        // If the digest.size is one, it indicates the special case of changing
        // the audit hash algorithm. For this case, no audit is done on exit.
        // NOTE: When the hash algorithm is changed, g_updateNV is set in order to
        // force an update to the NV on exit so that the change in digest will
        // be recorded. So, it is safe to exit here without setting any flags
        // because the digest change will be written to NV when this code exits.
        if(gr.commandAuditDigest.t.size == 1)
        {
            gr.commandAuditDigest.t.size = 0;
            return;
        }

        // If the digest size is zero, need to start a new digest and increment
        // the audit counter.
        if(gr.commandAuditDigest.t.size == 0)
        {
            gr.commandAuditDigest.t.size = CryptGetHashDigestSize(gp.auditHashAlg);
            MemorySet(gr.commandAuditDigest.t.buffer,
                      0,
                      gr.commandAuditDigest.t.size);

            // Bump the counter and save its value to NV.
            gp.auditCounter++;
            NvWriteReserved(NV_AUDIT_COUNTER, &gp.auditCounter);
            g_updateNV = TRUE;
        }

        // auditDigestnew := hash (auditDigestold || cpHash || rpHash)

        // Start hash computation.
        CryptStartHash(gp.auditHashAlg, &hashState);

        // Add old digest.
        CryptUpdateDigest2B(&hashState, &gr.commandAuditDigest.b);

        // Add cpHash
        CryptUpdateDigest2B(&hashState, &s_cpHashForCommandAudit.b);

        // Add rpHash
        CryptUpdateDigest2B(&hashState, &rpHash.b);

        // Finalize the hash.
        CryptCompleteHash2B(&hashState, &gr.commandAuditDigest.b);
    }
    return;
}
#endif
static void
UpdateAuditSessionStatus(
    TPM_CC commandCode,                   // IN: commandCode
    UINT32 resParmBufferSize,             // IN: size of response parameter buffer
    BYTE *resParmBuffer                   // IN: response parameter buffer
)
{
    UINT32 i;
    TPM_HANDLE auditSession = TPM_RH_UNASSIGNED;

    // Iterate through sessions
    for (i = 0; i < s_sessionNum; i++)
    {
        SESSION *session;

        // PW session do not have a loaded session and can not be an audit
        // session either. Skip it.
        if(s_sessionHandles[i] == TPM_RS_PW) continue;

        session = SessionGet(s_sessionHandles[i]);

        // If a session is used for audit
        if(s_attributes[i].audit == SET)
        {
            // An audit session has been found
            auditSession = s_sessionHandles[i];

            // If the session has not been an audit session yet, or
            // the auditSetting bits indicate a reset, initialize it and set
            // it to be the exclusive session
            if( session->attributes.isAudit == CLEAR
                    || s_attributes[i].auditReset == SET
              )
            {
                InitAuditSession(session);
                g_exclusiveAuditSession = auditSession;
            }
            else
            {
                // Check if the audit session is the current exclusive audit
                // session and, if not, clear previous exclusive audit session.
                if(g_exclusiveAuditSession != auditSession)
                    g_exclusiveAuditSession = TPM_RH_UNASSIGNED;
            }

            // Report audit session exclusivity.
            if(g_exclusiveAuditSession == auditSession)
            {
                s_attributes[i].auditExclusive = SET;
            }
            else
            {
                s_attributes[i].auditExclusive = CLEAR;
            }

            // Extend audit log.
            Audit(session, commandCode, resParmBufferSize, resParmBuffer);
        }
    }

    // If no audit session is found in the command, and the command allows
    // a session then, clear the current exclusive
    // audit session.
    if(auditSession == TPM_RH_UNASSIGNED && IsSessionAllowed(commandCode))
    {
        g_exclusiveAuditSession = TPM_RH_UNASSIGNED;
    }

    return;
}
static void
ComputeResponseHMAC(
    UINT32 sessionIndex,                   // IN: session index to be processed
    SESSION *session,                       // IN: loaded session
    TPM_CC commandCode,                    // IN: commandCode
    TPM2B_NONCE *nonceTPM,                      // IN: nonceTPM
    UINT32 resParmBufferSize,              // IN: size of response parameter buffer
    BYTE *resParmBuffer,                 // IN: response parameter buffer
    TPM2B_DIGEST *hmac                           // OUT: authHMAC
)
{
    TPM2B_TYPE(KEY, (sizeof(AUTH_VALUE) * 2));
    TPM2B_KEY key;                // HMAC key
    BYTE marshalBuffer[sizeof(TPMA_SESSION)];
    BYTE *buffer;
    UINT32 marshalSize;
    HMAC_STATE hmacState;
    TPM2B_DIGEST rp_hash;

    // Compute rpHash.
    ComputeRpHash(session->authHashAlg, commandCode, resParmBufferSize,
                  resParmBuffer, &rp_hash);

    // Generate HMAC key
    MemoryCopy2B(&key.b, &session->sessionKey.b, sizeof(key.t.buffer));

    // Check if the session has an associated handle and the associated entity is
    // the one that the session is bound to.
    // If not bound, add the authValue of this entity to the HMAC key.
    if( s_associatedHandles[sessionIndex] != TPM_RH_UNASSIGNED
            && !( HandleGetType(s_sessionHandles[sessionIndex])
                  == TPM_HT_POLICY_SESSION
                  && session->attributes.isAuthValueNeeded == CLEAR)
            && !session->attributes.requestWasBound)
    {
        pAssert((sizeof(AUTH_VALUE) + key.t.size) <= sizeof(key.t.buffer));
        key.t.size = key.t.size +
                     EntityGetAuthValue(s_associatedHandles[sessionIndex],
                                        (AUTH_VALUE *)&key.t.buffer[key.t.size]);
    }

    // if the HMAC key size for a policy session is 0, the response HMAC is
    // computed according to the input HMAC
    if(HandleGetType(s_sessionHandles[sessionIndex]) == TPM_HT_POLICY_SESSION
            && key.t.size == 0
            && s_inputAuthValues[sessionIndex].t.size == 0)
    {
        hmac->t.size = 0;
        return;
    }

    // Start HMAC computation.
    hmac->t.size = CryptStartHMAC2B(session->authHashAlg, &key.b, &hmacState);

    // Add hash components.
    CryptUpdateDigest2B(&hmacState, &rp_hash.b);
    CryptUpdateDigest2B(&hmacState, &nonceTPM->b);
    CryptUpdateDigest2B(&hmacState, &s_nonceCaller[sessionIndex].b);

    // Add session attributes.
    buffer = marshalBuffer;
    marshalSize = TPMA_SESSION_Marshal(&s_attributes[sessionIndex], &buffer, NULL);
    CryptUpdateDigest(&hmacState, marshalSize, marshalBuffer);

    // Finalize HMAC.
    CryptCompleteHMAC2B(&hmacState, &hmac->b);

    return;
}
static void
BuildSingleResponseAuth(
    UINT32 sessionIndex,                    // IN: session index to be processed
    TPM_CC commandCode,                     // IN: commandCode
    UINT32 resParmBufferSize,               // IN: size of response parameter buffer
    BYTE *resParmBuffer,                  // IN: response parameter buffer
    TPM2B_AUTH *auth                            // OUT: authHMAC
)
{
    // For password authorization, field is empty.
    if(s_sessionHandles[sessionIndex] == TPM_RS_PW)
    {
        auth->t.size = 0;
    }
    else
    {
        // Fill in policy/HMAC based session response.
        SESSION *session = SessionGet(s_sessionHandles[sessionIndex]);

        // If the session is a policy session with isPasswordNeeded SET, the auth
        // field is empty.
        if(HandleGetType(s_sessionHandles[sessionIndex]) == TPM_HT_POLICY_SESSION
                && session->attributes.isPasswordNeeded == SET)
            auth->t.size = 0;
        else
            // Compute response HMAC.
            ComputeResponseHMAC(sessionIndex,
                                session,
                                commandCode,
                                &session->nonceTPM,
                                resParmBufferSize,
                                resParmBuffer,
                                auth);
    }

    return;
}
static void
UpdateTPMNonce(
    UINT16 noncesSize,              // IN: number of elements in 'nonces' array
    TPM2B_NONCE nonces[]                 // OUT: nonceTPM
)
{
    UINT32 i;
    pAssert(noncesSize >= s_sessionNum);
    for(i = 0; i < s_sessionNum; i++)
    {
        SESSION *session;
        // For PW session, nonce is 0.
        if(s_sessionHandles[i] == TPM_RS_PW)
        {
            nonces[i].t.size = 0;
            continue;
        }
        session = SessionGet(s_sessionHandles[i]);
        // Update nonceTPM in both internal session and response.
        CryptGenerateRandom(session->nonceTPM.t.size, session->nonceTPM.t.buffer);
        nonces[i] = session->nonceTPM;
    }
    return;
}
static void
UpdateInternalSession(
    void
)
{
    UINT32 i;
    for(i = 0; i < s_sessionNum; i++)
    {
        // For PW session, no update.
        if(s_sessionHandles[i] == TPM_RS_PW) continue;

        if(s_attributes[i].continueSession == CLEAR)
        {
            // Close internal session.
            SessionFlush(s_sessionHandles[i]);
        }
        else
        {
            // If nonce is rolling in a policy session, the policy related data
            // will be re-initialized.
            if(HandleGetType(s_sessionHandles[i]) == TPM_HT_POLICY_SESSION)
            {
                SESSION *session = SessionGet(s_sessionHandles[i]);

                // When the nonce rolls it starts a new timing interval for the
                // policy session.
                SessionResetPolicyData(session);
                session->startTime = go.clock;
            }
        }
    }
    return;
}
void
BuildResponseSession(
    TPM_ST tag,                      // IN: tag
    TPM_CC commandCode,              // IN: commandCode
    UINT32 resHandleSize,            // IN: size of response handle buffer
    UINT32 resParmSize,              // IN: size of response parameter buffer
    UINT32 *resSessionSize           // OUT: response session area
)
{
    BYTE *resParmBuffer;
    TPM2B_NONCE responseNonces[MAX_SESSION_NUM];

    // Compute response parameter buffer start.
    resParmBuffer = MemoryGetResponseBuffer(commandCode) + sizeof(TPM_ST) +
                    sizeof(UINT32) + sizeof(TPM_RC) + resHandleSize;

    // For TPM_ST_SESSIONS, there is parameterSize field.
    if(tag == TPM_ST_SESSIONS)
        resParmBuffer += sizeof(UINT32);

    // Session nonce should be updated before parameter encryption
    if(tag == TPM_ST_SESSIONS)
    {
        UpdateTPMNonce(MAX_SESSION_NUM, responseNonces);

        // Encrypt first parameter if applicable. Parameter encryption should
        // happen after nonce update and before any rpHash is computed.
        // If the encrypt session is associated with a handle, the authValue of
        // this handle will be concatenated with sessionAuth to generate
        // encryption key, no matter if the handle is the session bound entity
        // or not. The authValue is added to sessionAuth only when the authValue
        // is available.
        if(s_encryptSessionIndex != UNDEFINED_INDEX)
        {
            UINT32 size;
            TPM2B_AUTH extraKey;

            // Get size of the leading size field
            if( s_associatedHandles[s_encryptSessionIndex] != TPM_RH_UNASSIGNED
                    && IsAuthValueAvailable(s_associatedHandles[s_encryptSessionIndex],
                                            commandCode, s_encryptSessionIndex)
              )
            {
                extraKey.b.size =
                    EntityGetAuthValue(s_associatedHandles[s_encryptSessionIndex],
                                       &extraKey.t.buffer);
            }
            else
            {
                extraKey.b.size = 0;
            }
            size = EncryptSize(commandCode);
            CryptParameterEncryption(s_sessionHandles[s_encryptSessionIndex],
                                     &s_nonceCaller[s_encryptSessionIndex].b,
                                     (UINT16)size,
                                     &extraKey,
                                     resParmBuffer);

        }

    }
    // Audit session should be updated first regardless of the tag.
    // A command with no session may trigger a change of the exclusivity state.
    UpdateAuditSessionStatus(commandCode, resParmSize, resParmBuffer);

    // Audit command.
    CommandAudit(commandCode, resParmSize, resParmBuffer);

    // Process command with sessions.
    if(tag == TPM_ST_SESSIONS)
    {
        UINT32 i;
        BYTE *buffer;
        TPM2B_DIGEST responseAuths[MAX_SESSION_NUM];

        pAssert(s_sessionNum > 0);

        // Iterate over each session in the command session area, and create
        // corresponding sessions for response.
        for(i = 0; i < s_sessionNum; i++)
        {
            BuildSingleResponseAuth(
                i,
                commandCode,
                resParmSize,
                resParmBuffer,
                &responseAuths[i]);
            // Make sure that continueSession is SET on any Password session.
            // This makes it marginally easier for the management software
            // to keep track of the closed sessions.
            if( s_attributes[i].continueSession == CLEAR
                    && s_sessionHandles[i] == TPM_RS_PW)
            {
                s_attributes[i].continueSession = SET;
            }
        }

        // Assemble Response Sessions.
        *resSessionSize = 0;
        buffer = resParmBuffer + resParmSize;
        for(i = 0; i < s_sessionNum; i++)
        {
            *resSessionSize += TPM2B_NONCE_Marshal(&responseNonces[i],
                                                   &buffer, NULL);
            *resSessionSize += TPMA_SESSION_Marshal(&s_attributes[i],
                                                    &buffer, NULL);
            *resSessionSize += TPM2B_DIGEST_Marshal(&responseAuths[i],
                                                    &buffer, NULL);
        }

        // Update internal sessions after completing response buffer computation.
        UpdateInternalSession();
    }
    else
    {
        // Process command with no session.
        *resSessionSize = 0;
    }

    return;
}
void
SessionRemoveAssociationToHandle(
    TPM_HANDLE           handle
    )
{
    UINT32               i;
    for(i = 0; i < MAX_SESSION_NUM; i++)
    {
        if(s_associatedHandles[i] == handle)
        {
            s_associatedHandles[i] = TPM_RH_NULL;
        }
    }
}
