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

// 8.8.1 Introduction
// The code in this file is used to manage the session context counter. The scheme implemented here is a
// "truncated counter". This scheme allows the TPM to not need TPM_SU_CLEAR for a very long period of
// time and still not have the context count for a session repeated.
// The counter (contextCounter)in this implementation is a UINT64 but can be smaller. The
// "tracking array"
// (contextArray) only has 16-bits per context. The tracking array is the data that needs to be saved and
// restored across TPM_SU_STATE so that sessions are not lost when the system enters the sleep state.
// Also, when the TPM is active, the tracking array is kept in RAM making it important that the number of
// bytes for each entry be kept as small as possible.
// The TPM prevents collisions of these truncated values by not allowing a contextID to be assigned if it
// would be the same as an existing value. Since the array holds 16 bits, after a context has been
// saved,
// an additional 2^16-1 contexts may be saved before the count would again match.
// The normal
// expectation is that the context will be flushed before its count value is needed again but it is always
// possible to have long-lived sessions.
// The contextID is assigned when the context is saved (TPM2_ContextSave()). At that time, the TPM will
// compare the low-order 16 bits of contextCounter to the existing values in contextArray
// and if one
// matches, the TPM will return TPM_RC_CONTEXT_GAP (by construction, the entry that contains the
// matching value is the oldest context).
// The expected remediation by the TRM is to load the oldest saved session context (the one found by the
// TPM), and save it. Since loading the oldest session also eliminates its contextID value from
// contextArray,
// there TPM will always be able to load and save the oldest existing context.
// In the worst case, software may have to load and save several contexts in order to save an additional
// one. This should happen very infrequently.
// When the TPM searches contextArray and finds that none of the contextIDs match the low-order 16-bits
// of contextCount, the TPM can copy the low bits to the contextArray associated with the session, and
// increment contextCount.
// There is one entry in contextArray for each of the active sessions allowed by the TPM implementation.
// This array contains either a context count, an index, or a value indicating the slot is available (0).
// The index into the contextArray is the handle for the session with the region selector byte of the session
// set to zero. If an entry in contextArray contains 0, then the corresponding handle may be assigned to a
// session. If the entry contains a value that is less than or equal to the number of loaded sessions for the
// TPM, then the array entry is the slot in which the context is loaded.
// EXAMPLE: If the TPM allows 8 loaded sessions, then the slot numbers would be 1-8 and a contextArrary value
// in that
// range would represent the loaded session.
// NOTE: When the TPM firmware determines that the array entry is for a loaded session, it will subtract 1
// to create the
// zero-based slot number.
// There is one significant corner case in this scheme. When the contextCount is equal to a value in the
// contextArray, the oldest session needs to be recycled or flushed. In order to recycle the session, it must
// be loaded. To be loaded, there must be an available slot. Rather than require that a spare slot
// be
// available all the time, the TPM will check to see if the contextCount is equal to some value
// in the
// contextArray when a session is created. This prevents the last session slot from being used when it is
// likely that a session will need to be recycled.
// If a TPM with both 1.2 and 2.0 functionality uses this scheme for both 1.2 and 2.0 sessions, and the list of
// active contexts is read with TPM_GetCapabiltiy(), the TPM will create 32-bit representations of the list that
// contains 16-bit values (the TPM2_GetCapability() returns a list of handles for active sessions rather than
// a list of contextID). The full contextID has high-order bits that are either the same as the
// current
// contextCount or one less. It is one less if the 16-bits of the contextArray has a value that is larger than
// the low-order 16 bits of contextCount.
// 8.8.2 Includes, Defines, and Local Variables
#define SESSION_C
#include "InternalRoutines.h"
#include "Platform.h"
#include "SessionProcess_fp.h"
static void
ContextIdSetOldest(
    void
)
{
    CONTEXT_SLOT lowBits;
    CONTEXT_SLOT entry;
    CONTEXT_SLOT smallest = ((CONTEXT_SLOT) ~0);
    UINT32 i;

    // Set oldestSaveContext to a value indicating none assigned
    s_oldestSavedSession = MAX_ACTIVE_SESSIONS + 1;

    lowBits = (CONTEXT_SLOT)gr.contextCounter;
    for(i = 0; i < MAX_ACTIVE_SESSIONS; i++)
    {
        entry = gr.contextArray[i];

        // only look at entries that are saved contexts
        if(entry > MAX_LOADED_SESSIONS)
        {
            // Use a less than or equal in case the oldest
            // is brand new (= lowBits-1) and equal to our initial
            // value for smallest.
            if(((CONTEXT_SLOT) (entry - lowBits)) <= smallest)
            {
                smallest = (entry - lowBits);
                s_oldestSavedSession = i;
            }
        }
    }
    // When we finish, either the s_oldestSavedSession still has its initial
    // value, or it has the index of the oldest saved context.
}
void
SessionStartup(
    STARTUP_TYPE type
)
{
    UINT32 i;

    // Initialize session slots. At startup, all the in-memory session slots
    // are cleared and marked as not occupied
    for(i = 0; i < MAX_LOADED_SESSIONS; i++)
        s_sessions[i].occupied = FALSE;               // session slot is not occupied

    // The free session slots the number of maximum allowed loaded sessions
    s_freeSessionSlots = MAX_LOADED_SESSIONS;

    // Initialize context ID data. On a ST_SAVE or hibernate sequence, it will
    // scan the saved array of session context counts, and clear any entry that
    // references a session that was in memory during the state save since that
    // memory was not preserved over the ST_SAVE.
    if(type == SU_RESUME || type == SU_RESTART)
    {
        // On ST_SAVE we preserve the contexts that were saved but not the ones
        // in memory
        for (i = 0; i < MAX_ACTIVE_SESSIONS; i++)
        {
            // If the array value is unused or references a loaded session then
            // that loaded session context is lost and the array entry is
            // reclaimed.
            if (gr.contextArray[i] <= MAX_LOADED_SESSIONS)
                gr.contextArray[i] = 0;
        }
        // Find the oldest session in context ID data and set it in
        // s_oldestSavedSession
        ContextIdSetOldest();
    }
    else
    {
        // For STARTUP_CLEAR, clear out the contextArray
        for (i = 0; i < MAX_ACTIVE_SESSIONS; i++)
            gr.contextArray[i] = 0;

        // reset the context counter
        gr.contextCounter = MAX_LOADED_SESSIONS + 1;

        // Initialize oldest saved session
        s_oldestSavedSession = MAX_ACTIVE_SESSIONS + 1;
    }
    return;
}
BOOL
SessionIsLoaded(
    TPM_HANDLE handle               // IN: session handle
)
{
    pAssert( HandleGetType(handle) == TPM_HT_POLICY_SESSION
             || HandleGetType(handle) == TPM_HT_HMAC_SESSION);

    handle = handle & HR_HANDLE_MASK;

    // if out of range of possible active session, or not assigned to a loaded
    // session return false
    if( handle >= MAX_ACTIVE_SESSIONS
            || gr.contextArray[handle] == 0
            || gr.contextArray[handle] > MAX_LOADED_SESSIONS
      )
        return FALSE;

    return TRUE;
}
BOOL
SessionIsSaved(
    TPM_HANDLE handle             // IN: session handle
)
{
    pAssert( HandleGetType(handle) == TPM_HT_POLICY_SESSION
             || HandleGetType(handle) == TPM_HT_HMAC_SESSION);

    handle = handle & HR_HANDLE_MASK;
    // if out of range of possible active session, or not assigned, or
    // assigned to a loaded session, return false
    if( handle >= MAX_ACTIVE_SESSIONS
            || gr.contextArray[handle] == 0
            || gr.contextArray[handle] <= MAX_LOADED_SESSIONS
      )
        return FALSE;

    return TRUE;
}
BOOL
SessionPCRValueIsCurrent(
    TPMI_SH_POLICY handle             // IN: session handle
)
{
    SESSION *session;

    pAssert(SessionIsLoaded(handle));

    session = SessionGet(handle);
    if( session->pcrCounter != 0
            && session->pcrCounter != gr.pcrCounter
      )
        return FALSE;
    else
        return TRUE;
}
SESSION *
SessionGet(
    TPM_HANDLE handle                       // IN: session handle
)
{
    CONTEXT_SLOT sessionIndex;

    pAssert( HandleGetType(handle) == TPM_HT_POLICY_SESSION
             || HandleGetType(handle) == TPM_HT_HMAC_SESSION
           );

    pAssert((handle & HR_HANDLE_MASK) < MAX_ACTIVE_SESSIONS);

    // get the contents of the session array. Because session is loaded, we
    // should always get a valid sessionIndex
    sessionIndex = gr.contextArray[handle & HR_HANDLE_MASK] - 1;

    pAssert(sessionIndex < MAX_LOADED_SESSIONS);

    return &s_sessions[sessionIndex].session;
}
static TPM_RC
ContextIdSessionCreate (
    TPM_HANDLE *handle,                          // OUT: receives the assigned handle. This will
    // be an index that must be adjusted by the
    // caller according to the type of the
    // session created
    UINT32 sessionIndex                 // IN: The session context array entry that will
    // be occupied by the created session
)
{

    pAssert(sessionIndex < MAX_LOADED_SESSIONS);

    // check to see if creating the context is safe
    // Is this going to be an assignment for the last session context
    // array entry? If so, then there will be no room to recycle the
    // oldest context if needed. If the gap is not at maximum, then
    // it will be possible to save a context if it becomes necessary.
    if( s_oldestSavedSession < MAX_ACTIVE_SESSIONS
            && s_freeSessionSlots == 1)
    {
        // See if the gap is at maximum
        if( (CONTEXT_SLOT)gr.contextCounter
                == gr.contextArray[s_oldestSavedSession])

            // Note: if this is being used on a TPM.combined, this return
            // code should be transformed to an appropriate 1.2 error
            // code for this case.
            return TPM_RC_CONTEXT_GAP;
    }

    // Find an unoccupied entry in the contextArray
    for(*handle = 0; *handle < MAX_ACTIVE_SESSIONS; (*handle)++)
    {
        if(gr.contextArray[*handle] == 0)
        {
            // indicate that the session associated with this handle
            // references a loaded session
            gr.contextArray[*handle] = (CONTEXT_SLOT)(sessionIndex+1);
            return TPM_RC_SUCCESS;
        }
    }
    return TPM_RC_SESSION_HANDLES;
}

// E r
// M e
// TPM_RC_CONTEXT_GAP
// TPM_RC_SESSION_HANDLE
// TPM_RC_SESSION_MEMORY

TPM_RC
SessionCreate(
    TPM_SE sessionType,                  // IN: the session type
    TPMI_ALG_HASH authHash,                     // IN: the hash algorithm
    TPM2B_NONCE *nonceCaller,                 // IN: initial nonceCaller
    TPMT_SYM_DEF *symmetric,                   // IN: the symmetric algorithm
    TPMI_DH_ENTITY bind,                         // IN: the bind object
    TPM2B_DATA *seed,                        // IN: seed data
    TPM_HANDLE *sessionHandle                // OUT: the session handle
)
{
    TPM_RC result = TPM_RC_SUCCESS;
    CONTEXT_SLOT slotIndex;
    SESSION *session = NULL;

    pAssert( sessionType == TPM_SE_HMAC
             || sessionType == TPM_SE_POLICY
             || sessionType == TPM_SE_TRIAL);

    // If there are no open spots in the session array, then no point in searching
    if(s_freeSessionSlots == 0)
        return TPM_RC_SESSION_MEMORY;

    // Find a space for loading a session
    for(slotIndex = 0; slotIndex < MAX_LOADED_SESSIONS; slotIndex++)
    {
        // Is this available?
        if(s_sessions[slotIndex].occupied == FALSE)
        {
            session = &s_sessions[slotIndex].session;
            break;
        }
    }
    // if no spot found, then this is an internal error
    pAssert (slotIndex < MAX_LOADED_SESSIONS);

    // Call context ID function to get a handle. TPM_RC_SESSION_HANDLE may be
    // returned from ContextIdHandelAssign()
    result = ContextIdSessionCreate(sessionHandle, slotIndex);
    if(result != TPM_RC_SUCCESS)
        return result;

    //*** Only return from this point on is TPM_RC_SUCCESS

    // Can now indicate that the session array entry is occupied.
    s_freeSessionSlots--;
    s_sessions[slotIndex].occupied = TRUE;

    // Initialize the session data
    MemorySet(session, 0, sizeof(SESSION));

    // Initialize internal session data
    session->authHashAlg = authHash;
    // Initialize session type
    if(sessionType == TPM_SE_HMAC)
    {
        *sessionHandle += HMAC_SESSION_FIRST;

    }
    else
    {
        *sessionHandle += POLICY_SESSION_FIRST;

        // For TPM_SE_POLICY or TPM_SE_TRIAL
        session->attributes.isPolicy = SET;
        if(sessionType == TPM_SE_TRIAL)
            session->attributes.isTrialPolicy = SET;

        // Initialize policy session data
        SessionInitPolicyData(session);
    }
    // Create initial session nonce
    session->nonceTPM.t.size = nonceCaller->t.size;
    CryptGenerateRandom(session->nonceTPM.t.size, session->nonceTPM.t.buffer);

    // Set up session parameter encryption algorithm
    session->symmetric = *symmetric;

    // If there is a bind object or a session secret, then need to compute
    // a sessionKey.
    if(bind != TPM_RH_NULL || seed->t.size != 0)
    {
        // sessionKey = KDFa(hash, (authValue || seed), "ATH", nonceTPM,
        // nonceCaller, bits)
        // The HMAC key for generating the sessionSecret can be the concatenation
        // of an authorization value and a seed value
        TPM2B_TYPE(KEY, (sizeof(TPMT_HA) + sizeof(seed->t.buffer)));
        TPM2B_KEY key;

        UINT16 hashSize;                     // The size of the hash used by the
        // session crated by this command
        TPM2B_AUTH entityAuth;                                      // The authValue of the entity
        // associated with HMAC session

        // Get hash size, which is also the length of sessionKey
        hashSize = CryptGetHashDigestSize(session->authHashAlg);

        // Get authValue of associated entity
        entityAuth.t.size = EntityGetAuthValue(bind, &entityAuth.t.buffer);

        // Concatenate authValue and seed
        pAssert(entityAuth.t.size + seed->t.size <= sizeof(key.t.buffer));
        MemoryCopy2B(&key.b, &entityAuth.b, sizeof(key.t.buffer));
        MemoryConcat2B(&key.b, &seed->b, sizeof(key.t.buffer));

        session->sessionKey.t.size = hashSize;

        // Compute the session key
        KDFa(session->authHashAlg, &key.b, "ATH", &session->nonceTPM.b,
             &nonceCaller->b, hashSize * 8, session->sessionKey.t.buffer, NULL);
    }

    // Copy the name of the entity that the HMAC session is bound to
    // Policy session is not bound to an entity
    if(bind != TPM_RH_NULL && sessionType == TPM_SE_HMAC)
    {
        session->attributes.isBound = SET;
        SessionComputeBoundEntity(bind, &session->u1.boundEntity);
    }
    // If there is a bind object and it is subject to DA, then use of this session
    // is subject to DA regardless of how it is used.
    session->attributes.isDaBound = (bind != TPM_RH_NULL)
                                    && (IsDAExempted(bind) == FALSE);

    // If the session is bound, then check to see if it is bound to lockoutAuth
    session->attributes.isLockoutBound = (session->attributes.isDaBound == SET)
                                         && (bind == TPM_RH_LOCKOUT);
    return TPM_RC_SUCCESS;

}

// E r
// M e
// TPM_RC_CONTEXT_GAP
// TPM_RC_TOO_MANY_CONTEXTS

TPM_RC
SessionContextSave (
    TPM_HANDLE handle,                        // IN: session handle
    CONTEXT_COUNTER *contextID                       // OUT: assigned contextID
)
{
    UINT32 contextIndex;
    CONTEXT_SLOT slotIndex;

    pAssert(SessionIsLoaded(handle));

    // check to see if the gap is already maxed out
    // Need to have a saved session
    if( s_oldestSavedSession < MAX_ACTIVE_SESSIONS
            // if the oldest saved session has the same value as the low bits
            // of the contextCounter, then the GAP is maxed out.
            && gr.contextArray[s_oldestSavedSession] == (CONTEXT_SLOT)gr.contextCounter)
        return TPM_RC_CONTEXT_GAP;

    // if the caller wants the context counter, set it
    if(contextID != NULL)
        *contextID = gr.contextCounter;

    pAssert((handle & HR_HANDLE_MASK) < MAX_ACTIVE_SESSIONS);

    contextIndex = handle & HR_HANDLE_MASK;

    // Extract the session slot number referenced by the contextArray
    // because we are going to overwrite this with the low order
    // contextID value.
    slotIndex = gr.contextArray[contextIndex] - 1;

    // Set the contextID for the contextArray
    gr.contextArray[contextIndex] = (CONTEXT_SLOT)gr.contextCounter;

    // Increment the counter
    gr.contextCounter++;

    // In the unlikely event that the 64-bit context counter rolls over...
    if(gr.contextCounter == 0)
    {
        // back it up
        gr.contextCounter--;
        // return an error
        return TPM_RC_TOO_MANY_CONTEXTS;
    }
    // if the low-order bits wrapped, need to advance the value to skip over
    // the values used to indicate that a session is loaded
    if(((CONTEXT_SLOT)gr.contextCounter) == 0)
        gr.contextCounter += MAX_LOADED_SESSIONS + 1;

    // If no other sessions are saved, this is now the oldest.
    if(s_oldestSavedSession >= MAX_ACTIVE_SESSIONS)
        s_oldestSavedSession = contextIndex;

    // Mark the session slot as unoccupied
    s_sessions[slotIndex].occupied = FALSE;

    // and indicate that there is an additional open slot
    s_freeSessionSlots++;

    return TPM_RC_SUCCESS;
}

// E r
// M e
// TPM_RC_SESSION_MEMORY
// TPM_RC_CONTEXT_GAP

TPM_RC
SessionContextLoad(
    SESSION *session,                           // IN: session structure from saved context
    TPM_HANDLE *handle                             // IN/OUT: session handle
)
{
    UINT32 contextIndex;
    CONTEXT_SLOT slotIndex;

    pAssert( HandleGetType(*handle) == TPM_HT_POLICY_SESSION
             || HandleGetType(*handle) == TPM_HT_HMAC_SESSION);

    // Don't bother looking if no openings
    if(s_freeSessionSlots == 0)
        return TPM_RC_SESSION_MEMORY;

    // Find a free session slot to load the session
    for(slotIndex = 0; slotIndex < MAX_LOADED_SESSIONS; slotIndex++)
        if(s_sessions[slotIndex].occupied == FALSE) break;

    // if no spot found, then this is an internal error
    pAssert (slotIndex < MAX_LOADED_SESSIONS);

    contextIndex = *handle & HR_HANDLE_MASK;                         // extract the index

    // If there is only one slot left, and the gap is at maximum, the only session
    // context that we can safely load is the oldest one.
    if( s_oldestSavedSession < MAX_ACTIVE_SESSIONS
            && s_freeSessionSlots == 1
            && (CONTEXT_SLOT)gr.contextCounter == gr.contextArray[s_oldestSavedSession]
            && contextIndex != s_oldestSavedSession
      )
        return TPM_RC_CONTEXT_GAP;

    pAssert(contextIndex < MAX_ACTIVE_SESSIONS);

    // set the contextArray value to point to the session slot where
    // the context is loaded
    gr.contextArray[contextIndex] = slotIndex + 1;

    // if this was the oldest context, find the new oldest
    if(contextIndex == s_oldestSavedSession)
        ContextIdSetOldest();

    // Copy session data to session slot
    s_sessions[slotIndex].session = *session;

    // Set session slot as occupied
    s_sessions[slotIndex].occupied = TRUE;

    // Reduce the number of open spots
    s_freeSessionSlots--;

    return TPM_RC_SUCCESS;
}
void
SessionFlush(
    TPM_HANDLE handle                     // IN: loaded or saved session handle
)
{
    CONTEXT_SLOT slotIndex;
    UINT32 contextIndex;                 // Index into contextArray

    pAssert( ( HandleGetType(handle) == TPM_HT_POLICY_SESSION
               || HandleGetType(handle) == TPM_HT_HMAC_SESSION
             )
             && (SessionIsLoaded(handle) || SessionIsSaved(handle))
           );

    // Flush context ID of this session
    // Convert handle to an index into the contextArray
    contextIndex = handle & HR_HANDLE_MASK;

    pAssert(contextIndex < sizeof(gr.contextArray)/sizeof(gr.contextArray[0]));

    // Get the current contents of the array
    slotIndex = gr.contextArray[contextIndex];

    // Mark context array entry as available
    gr.contextArray[contextIndex] = 0;

    // Is this a saved session being flushed
    if(slotIndex > MAX_LOADED_SESSIONS)
    {
        // Flushing the oldest session?
        if(contextIndex == s_oldestSavedSession)
            // If so, find a new value for oldest.
            ContextIdSetOldest();
    }
    else
    {
        // Adjust slot index to point to session array index
        slotIndex -= 1;

        // Free session array index
        s_sessions[slotIndex].occupied = FALSE;
        s_freeSessionSlots++;
    }

    return;
}
void
SessionComputeBoundEntity(
    TPMI_DH_ENTITY entityHandle,                // IN: handle of entity
    TPM2B_NAME *bind                        // OUT: binding value
)
{
    TPM2B_AUTH auth;
    INT16 overlap;

    // Get name
    bind->t.size = EntityGetName(entityHandle, &bind->t.name);

//        // The bound value of a reserved handle is the handle itself
// if(bind->t.size == sizeof(TPM_HANDLE)) return;

    // For all the other entities, concatenate the auth value to the name.
    // Get a local copy of the auth value because some overlapping
    // may be necessary.
    auth.t.size = EntityGetAuthValue(entityHandle, &auth.t.buffer);
    pAssert(auth.t.size <= sizeof(TPMU_HA));

    // Figure out if there will be any overlap
    overlap = bind->t.size + auth.t.size - sizeof(bind->t.name);

    // There is overlap if the combined sizes are greater than will fit
    if(overlap > 0)
    {
        // The overlap area is at the end of the Name
        BYTE *result = &bind->t.name[bind->t.size - overlap];
        int i;

        // XOR the auth value into the Name for the overlap area
        for(i = 0; i < overlap; i++)
            result[i] ^= auth.t.buffer[i];
    }
    else
    {
        // There is no overlap
        overlap = 0;
    }
    //copy the remainder of the authData to the end of the name
    MemoryCopy(&bind->t.name[bind->t.size], &auth.t.buffer[overlap],
               auth.t.size - overlap, sizeof(bind->t.name) - bind->t.size);

    // Increase the size of the bind data by the size of the auth - the overlap
    bind->t.size += auth.t.size-overlap;

    return;
}
void
SessionInitPolicyData(
    SESSION *session                     // IN: session handle
)
{
    // Initialize start time
    session->startTime = go.clock;

    // Initialize policyDigest. policyDigest is initialized with a string of 0 of
    // session algorithm digest size. Since the policy already contains all zeros
    // it is only necessary to set the size
    session->u2.policyDigest.t.size = CryptGetHashDigestSize(session->authHashAlg);
    return;
}
void
SessionResetPolicyData(
    SESSION *session                       // IN: the session to reset
)
{
    session->commandCode = 0;           // No command

    // No locality selected
    MemorySet(&session->commandLocality, 0, sizeof(session->commandLocality));

    // The cpHash size to zero
    session->u1.cpHash.b.size = 0;

    // No timeout
    session->timeOut = 0;

    // Reset the pcrCounter
    session->pcrCounter = 0;

    // Reset the policy hash
    MemorySet(&session->u2.policyDigest.t.buffer, 0,
              session->u2.policyDigest.t.size);

    // Reset the session attributes
    MemorySet(&session->attributes, 0, sizeof(SESSION_ATTRIBUTES));

    // set the policy attribute
    session->attributes.isPolicy = SET;
}
TPMI_YES_NO
SessionCapGetLoaded(
    TPMI_SH_POLICY handle,                     // IN: start handle
    UINT32 count,                      // IN: count of returned handle
    TPML_HANDLE *handleList                    // OUT: list of handle
)
{
    TPMI_YES_NO more = NO;
    UINT32 i;

    pAssert(HandleGetType(handle) == TPM_HT_LOADED_SESSION);

    // Initialize output handle list
    handleList->count = 0;

    // The maximum count of handles we may return is MAX_CAP_HANDLES
    if(count > MAX_CAP_HANDLES) count = MAX_CAP_HANDLES;

    // Iterate session context ID slots to get loaded session handles
    for(i = handle & HR_HANDLE_MASK; i < MAX_ACTIVE_SESSIONS; i++)
    {
        // If session is active
        if(gr.contextArray[i] != 0)
        {
            // If session is loaded
            if (gr.contextArray[i] <= MAX_LOADED_SESSIONS)
            {
                if(handleList->count < count)
                {
                    SESSION *session;

                    // If we have not filled up the return list, add this
                    // session handle to it
                    // assume that this is going to be an HMAC session
                    handle = i + HMAC_SESSION_FIRST;
                    session = SessionGet(handle);
                    if(session->attributes.isPolicy)
                        handle = i + POLICY_SESSION_FIRST;
                    handleList->handle[handleList->count] = handle;
                    handleList->count++;
                }
                else
                {
                    // If the return list is full but we still have loaded object
                    // available, report this and stop iterating
                    more = YES;
                    break;
                }
            }
        }
    }

    return more;

}
TPMI_YES_NO
SessionCapGetSaved(
    TPMI_SH_HMAC handle,                          // IN: start handle
    UINT32 count,                           // IN: count of returned handle
    TPML_HANDLE *handleList                        // OUT: list of handle
)
{
    TPMI_YES_NO more = NO;
    UINT32 i;

    pAssert(HandleGetType(handle) == TPM_HT_ACTIVE_SESSION);

    // Initialize output handle list
    handleList->count = 0;

    // The maximum count of handles we may return is MAX_CAP_HANDLES
    if(count > MAX_CAP_HANDLES) count = MAX_CAP_HANDLES;

    // Iterate session context ID slots to get loaded session handles
    for(i = handle & HR_HANDLE_MASK; i < MAX_ACTIVE_SESSIONS; i++)
    {
        // If session is active
        if(gr.contextArray[i] != 0)
        {
            // If session is saved
            if (gr.contextArray[i] > MAX_LOADED_SESSIONS)
            {
                if(handleList->count < count)
                {
                    // If we have not filled up the return list, add this
                    // session handle to it
                    handleList->handle[handleList->count] = i + HMAC_SESSION_FIRST;
                    handleList->count++;
                }
                else
                {
                    // If the return list is full but we still have loaded object
                    // available, report this and stop iterating
                    more = YES;
                    break;
                }
            }
        }
    }

    return more;

}
UINT32
SessionCapGetLoadedNumber(
    void
)
{
    return MAX_LOADED_SESSIONS - s_freeSessionSlots;
}
UINT32
SessionCapGetLoadedAvail(
    void
)
{
    return s_freeSessionSlots;
}
UINT32
SessionCapGetActiveNumber(
    void
)
{
    UINT32 i;
    UINT32 num = 0;

    // Iterate the context array to find the number of non-zero slots
    for(i = 0; i < MAX_ACTIVE_SESSIONS; i++)
    {
        if(gr.contextArray[i] != 0) num++;
    }

    return num;
}
UINT32
SessionCapGetActiveAvail(
    void
)
{
    UINT32 i;
    UINT32 num = 0;

    // Iterate the context array to find the number of zero slots
    for(i = 0; i < MAX_ACTIVE_SESSIONS; i++)
    {
        if(gr.contextArray[i] == 0) num++;
    }

    return num;
}
