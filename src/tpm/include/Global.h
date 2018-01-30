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

#ifndef GLOBAL_H
#define GLOBAL_H
//#define SELF_TEST
#include "TpmBuildSwitches.h"
#include "Tpm.h"
#include "TPMB.h"
#include "CryptoEngine.h"
#include <setjmp.h>
#ifndef UNREFERENCED_PARAMETER
# define UNREFERENCED_PARAMETER(a) (a)
#endif
#include "bits.h"
#ifndef SELF_TEST
extern ALGORITHM_VECTOR g_implementedAlgorithms;
extern ALGORITHM_VECTOR g_toTest;
#else
LIB_IMPORT extern ALGORITHM_VECTOR g_implementedAlgorithms;
LIB_IMPORT extern ALGORITHM_VECTOR g_toTest;
#endif
#define TEST(alg) if(TEST_BIT(alg, g_toTest)) CryptTestAlgorithm(alg, NULL)
#define TEST_HASH(alg) \
 if( TEST_BIT(alg, g_toTest) \
 && (alg != ALG_NULL_VALUE)) \
 CryptTestAlgorithm(alg, NULL)
typedef BYTE HASH_STATE_TYPE;
#define HASH_STATE_EMPTY ((HASH_STATE_TYPE) 0)
#define HASH_STATE_HASH ((HASH_STATE_TYPE) 1)
#define HASH_STATE_HMAC ((HASH_STATE_TYPE) 2)
typedef struct
{
    CPRI_HASH_STATE state;                // hash state
    HASH_STATE_TYPE type;                 // type of the context
} HASH_STATE;
typedef struct
{
    HASH_STATE hashState;                 // the hash state
    TPM2B_HASH_BLOCK hmacKey;                   // the HMAC key
} HMAC_STATE;
typedef BYTE AUTH_VALUE[sizeof(TPMU_HA)];
typedef BYTE TIME_INFO[sizeof(TPMS_TIME_INFO)];
typedef BYTE NAME[sizeof(TPMU_NAME)];
typedef struct
{
    unsigned publicOnly : 1;  //0) SET if only the public portion of
    // an object is loaded
    unsigned epsHierarchy : 1;  //1) SET if the object belongs to EPS
    // Hierarchy
    unsigned ppsHierarchy : 1;  //2) SET if the object belongs to PPS
    // Hierarchy
    unsigned spsHierarchy : 1;  //3) SET f the object belongs to SPS
    // Hierarchy
    unsigned evict : 1;  //4) SET if the object is a platform or
    // owner evict object. Platform-
    // evict object belongs to PPS
    // hierarchy, owner-evict object
    // belongs to SPS or EPS hierarchy.
    // This bit is also used to mark a
    // completed sequence object so it
    // will be flush when the
    // SequenceComplete command succeeds.
    unsigned primary : 1;  //5) SET for a primary object
    unsigned temporary : 1;      //6) SET for a temporary object
    unsigned stClear : 1;      //7) SET for an stClear object
    unsigned hmacSeq : 1;      //8) SET for an HMAC sequence object
    unsigned hashSeq : 1;      //9) SET for a hash sequence object
    unsigned eventSeq : 1;      //10) SET for an event sequence object
    unsigned ticketSafe : 1;      //11) SET if a ticket is safe to create
    // for hash sequence object
    unsigned firstBlock : 1;      //12) SET if the first block of hash
    // data has been received. It
    // works with ticketSafe bit
    unsigned isParent : 1;      //13) SET if the key has the proper
    // attributes to be a parent key
    unsigned privateExp : 1;      //14) SET when the private exponent
    // of an RSA key has been validated.
    unsigned reserved : 1;         //15) reserved bits. unused.
} OBJECT_ATTRIBUTES;
typedef struct
{
    // The attributes field is required to be first followed by the publicArea.
    // This allows the overlay of the object structure and a sequence structure
    OBJECT_ATTRIBUTES attributes;                 // object attributes
    TPMT_PUBLIC publicArea;                 // public area of an object
    TPMT_SENSITIVE sensitive;                  // sensitive area of an object

#ifdef TPM_ALG_RSA
    TPM2B_PUBLIC_KEY_RSA privateExponent;            // Additional field for the private
    // exponent of an RSA key.
#endif
    TPM2B_NAME qualifiedName;              // object qualified name
    TPMI_DH_OBJECT evictHandle;                // if the object is an evict object,
    // the original handle is kept here.
    // The 'working' handle will be the
    // handle of an object slot.

    TPM2B_NAME name;                       // Name of the object name. Kept here
    // to avoid repeatedly computing it.
} OBJECT;
typedef struct
{
    OBJECT_ATTRIBUTES attributes;                 // The attributes of the HASH object
    TPMI_ALG_PUBLIC type;                       // algorithm
    TPMI_ALG_HASH nameAlg;                    // name algorithm
    TPMA_OBJECT objectAttributes;           // object attributes

    // The data below is unique to a sequence object
    TPM2B_AUTH auth;                     // auth for use of sequence
    union
    {
        HASH_STATE hashState[HASH_COUNT];
        HMAC_STATE hmacState;
    } state;
} HASH_OBJECT;
typedef union
{
    OBJECT entity;
    HASH_OBJECT hash;
} ANY_OBJECT;
typedef UINT32 AUTH_ROLE;
#define AUTH_NONE ((AUTH_ROLE)(0))
#define AUTH_USER ((AUTH_ROLE)(1))
#define AUTH_ADMIN ((AUTH_ROLE)(2))
#define AUTH_DUP ((AUTH_ROLE)(3))
typedef struct
{
    unsigned isPolicy : 1;        //1) SET if the session may only
    // be used for policy
    unsigned isAudit : 1;        //2) SET if the session is used
    // for audit
    unsigned isBound : 1;        //3) SET if the session is bound to
    // with an entity.
    // This attribute will be CLEAR if
    // either isPolicy or isAudit is SET.
    unsigned iscpHashDefined : 1;//4) SET if the cpHash has been defined
    // This attribute is not SET unless
    // 'isPolicy' is SET.
    unsigned isAuthValueNeeded : 1;
    //5) SET if the authValue is required
    // for computing the session HMAC.
    // This attribute is not SET unless
    // isPolicy is SET.
    unsigned isPasswordNeeded : 1;
    //6) SET if a password authValue is
    // required for authorization
    // This attribute is not SET unless
    // isPolicy is SET.
    unsigned isPPRequired : 1;            //7) SET if physical presence is
    // required to be asserted when the
    // authorization is checked.
    // This attribute is not SET unless
    // isPolicy is SET.
    unsigned isTrialPolicy : 1;     //8) SET if the policy session is
    // created for trial of the policy's
    // policyHash generation.
    // This attribute is not SET unless
    // isPolicy is SET.
    unsigned isDaBound : 1;                        //9) SET if the bind entity had noDA
    // CLEAR. If this is SET, then an
    // auth failure using this session
    // will count against lockout even
    // if the object being authorized is
    // exempt from DA.
    unsigned isLockoutBound : 1;  //10)SET if the session is bound to
    // lockoutAuth.
    unsigned requestWasBound : 1;//11) SET if the session is being used
    // with the bind entity. If SET
    // the authValue will not be use
    // in the response HMAC computation.
    unsigned checkNvWritten : 1;  //12) SET if the TPMA_NV_WRITTEN
    // attribute needs to be checked
    // when the policy is used for
    // authorization for NV access.
    // If this is SET for any other
    // type, the policy will fail.
    unsigned nvWrittenState : 1;  //13) SET if TPMA_NV_WRITTEN is
    // required to be SET.
} SESSION_ATTRIBUTES;
typedef struct
{
    TPM_ALG_ID authHashAlg;                             // session hash algorithm
    TPM2B_NONCE nonceTPM;                                // last TPM-generated nonce for
    // this session

    TPMT_SYM_DEF symmetric;                               // session symmetric algorithm (if any)
    TPM2B_AUTH sessionKey;                              // session secret value used for
    // generating HMAC and encryption keys

    SESSION_ATTRIBUTES attributes;                              // session attributes
    TPM_CC commandCode;                             // command code (policy session)
    TPMA_LOCALITY commandLocality;                         // command locality (policy session)
    UINT32 pcrCounter;                              // PCR counter value when PCR is
    // included (policy session)
    // If no PCR is included, this
    // value is 0.

    UINT64 startTime;                               // value of TPMS_CLOCK_INFO.clock when
    // the session was started (policy
    // session)

    UINT64 timeOut;                // timeout relative to
    // TPMS_CLOCK_INFO.clock
    // There is no timeout if this value
    // is 0.
    union
    {
        TPM2B_NAME boundEntity;            // value used to track the entity to
        // which the session is bound

        TPM2B_DIGEST cpHash;                 // the required cpHash value for the
        // command being authorized

    } u1;                                          // 'boundEntity' and 'cpHash' may
    // share the same space to save memory

    union
    {
        TPM2B_DIGEST auditDigest;            // audit session digest
        TPM2B_DIGEST policyDigest;               // policyHash

    } u2;                                          // audit log and policyHash may
    // share space to save memory
} SESSION;
typedef struct
{
#ifdef TPM_ALG_SHA1
    BYTE sha1[NUM_STATIC_PCR][SHA1_DIGEST_SIZE];
#endif
#ifdef TPM_ALG_SHA256
    BYTE sha256[NUM_STATIC_PCR][SHA256_DIGEST_SIZE];
#endif
#ifdef TPM_ALG_SHA384
    BYTE sha384[NUM_STATIC_PCR][SHA384_DIGEST_SIZE];
#endif
#ifdef TPM_ALG_SHA512
    BYTE sha512[NUM_STATIC_PCR][SHA512_DIGEST_SIZE];
#endif
#ifdef TPM_ALG_SM3_256
    BYTE sm3_256[NUM_STATIC_PCR][SM3_256_DIGEST_SIZE];
#endif

    // This counter increments whenever the PCR are updated.
    // NOTE: A platform-specific specification may designate
    // certain PCR changes as not causing this counter
    // to increment.
    UINT32 pcrCounter;

} PCR_SAVE;
typedef struct
{
    TPMI_ALG_HASH hashAlg[NUM_POLICY_PCR_GROUP];
    TPM2B_DIGEST a;
    TPM2B_DIGEST policy[NUM_POLICY_PCR_GROUP];
} PCR_POLICY;
typedef struct
{
    TPM2B_DIGEST auth[NUM_AUTHVALUE_PCR_GROUP];
} PCR_AUTHVALUE;
#define SHUTDOWN_NONE (TPM_SU)(0xFFFF)
typedef enum
{
    SU_RESET,
    SU_RESTART,
    SU_RESUME
} STARTUP_TYPE;
typedef enum
{
// Entries below mirror the PERSISTENT_DATA structure. These values are written
// to NV as individual items.
    // hierarchy
    NV_DISABLE_CLEAR,
    NV_OWNER_ALG,
    NV_ENDORSEMENT_ALG,
    NV_LOCKOUT_ALG,
    NV_OWNER_POLICY,
    NV_ENDORSEMENT_POLICY,
    NV_LOCKOUT_POLICY,
    NV_OWNER_AUTH,
    NV_ENDORSEMENT_AUTH,
    NV_LOCKOUT_AUTH,

    NV_EP_SEED,
    NV_SP_SEED,
    NV_PP_SEED,

    NV_PH_PROOF,
    NV_SH_PROOF,
    NV_EH_PROOF,

    // Time
    NV_TOTAL_RESET_COUNT,
    NV_RESET_COUNT,

    // PCR
    NV_PCR_POLICIES,
    NV_PCR_ALLOCATED,

    // Physical Presence
    NV_PP_LIST,

    // Dictionary Attack
    NV_FAILED_TRIES,
    NV_MAX_TRIES,
    NV_RECOVERY_TIME,
    NV_LOCKOUT_RECOVERY,
    NV_LOCKOUT_AUTH_ENABLED,

    // Orderly State flag
    NV_ORDERLY,

    // Command Audit
    NV_AUDIT_COMMANDS,
    NV_AUDIT_HASH_ALG,
    NV_AUDIT_COUNTER,

    // Algorithm Set
    NV_ALGORITHM_SET,

    NV_FIRMWARE_V1,
    NV_FIRMWARE_V2,

// The entries above are in PERSISTENT_DATA. The entries below represent
// structures that are read and written as a unit.

// ORDERLY_DATA data structure written on each orderly shutdown
    NV_ORDERLY_DATA,

// STATE_CLEAR_DATA structure written on each Shutdown(STATE)
    NV_STATE_CLEAR,

// STATE_RESET_DATA structure written on each Shutdown(STATE)
    NV_STATE_RESET,

    NV_RESERVE_LAST                      // end of NV reserved data list
} NV_RESERVE;
typedef struct
{
    TPMS_NV_PUBLIC publicArea;
    TPM2B_AUTH authValue;
} NV_INDEX;
#ifdef TPM_ALG_ECC
#define COMMIT_INDEX_MASK ((UINT16)((sizeof(gr.commitArray)*8)-1))
#endif
extern const UINT16 g_rcIndex[15];
extern TPM_HANDLE g_exclusiveAuditSession;
extern UINT64 g_time;
extern BOOL g_phEnable;
extern BOOL g_pcrReConfig;
extern TPMI_DH_OBJECT g_DRTMHandle;
extern BOOL g_DrtmPreStartup;
#define PRE_STARTUP_FLAG 0x8000
extern BOOL g_StartupLocality3;
#define STARTUP_LOCALITY_3 0x4000
extern BOOL g_updateNV;
extern BOOL g_clearOrderly;
extern TPM_SU g_prevOrderlyState;
extern BOOL g_nvOk;
extern TPM2B_AUTH g_platformUniqueAuthorities;               // Reserved for RNG
extern TPM2B_AUTH g_platformUniqueDetails;               // referenced by VENDOR_PERMANENT
typedef struct
{
//*********************************************************************************
// Hierarchy
//*********************************************************************************
// The values in this section are related to the hierarchies.

    BOOL disableClear;                // TRUE if TPM2_Clear() using
    // lockoutAuth is disabled

    // Hierarchy authPolicies
    TPMI_ALG_HASH ownerAlg;
    TPMI_ALG_HASH endorsementAlg;
    TPMI_ALG_HASH lockoutAlg;
    TPM2B_DIGEST ownerPolicy;
    TPM2B_DIGEST endorsementPolicy;
    TPM2B_DIGEST lockoutPolicy;

    // Hierarchy authValues
    TPM2B_AUTH ownerAuth;
    TPM2B_AUTH endorsementAuth;
    TPM2B_AUTH lockoutAuth;

    // Primary Seeds
    TPM2B_SEED EPSeed;
    TPM2B_SEED SPSeed;
    TPM2B_SEED PPSeed;
    // Note there is a nullSeed in the state_reset memory.

    // Hierarchy proofs
    TPM2B_AUTH phProof;
    TPM2B_AUTH shProof;
    TPM2B_AUTH ehProof;
    // Note there is a nullProof in the state_reset memory.

//*********************************************************************************
// Reset Events
//*********************************************************************************
// A count that increments at each TPM reset and never get reset during the life
// time of TPM. The value of this counter is initialized to 1 during TPM
// manufacture process.
    UINT64 totalResetCount;

// This counter increments on each TPM Reset. The counter is reset by
// TPM2_Clear().
    UINT32 resetCount;

//*********************************************************************************
// PCR
//*********************************************************************************
// This structure hold the policies for those PCR that have an update policy.
// This implementation only supports a single group of PCR controlled by
// policy. If more are required, then this structure would be changed to
// an array.
    PCR_POLICY pcrPolicies;

// This structure indicates the allocation of PCR. The structure contains a
// list of PCR allocations for each implemented algorithm. If no PCR are
// allocated for an algorithm, a list entry still exists but the bit map
// will contain no SET bits.
    TPML_PCR_SELECTION pcrAllocated;

//*********************************************************************************
// Physical Presence
//*********************************************************************************
// The PP_LIST type contains a bit map of the commands that require physical
// to be asserted when the authorization is evaluated. Physical presence will be
// checked if the corresponding bit in the array is SET and if the authorization
// handle is TPM_RH_PLATFORM.
//
// These bits may be changed with TPM2_PP_Commands().
    BYTE ppList[((TPM_CC_PP_LAST - TPM_CC_PP_FIRST + 1) + 7)/8];

//*********************************************************************************
// Dictionary attack values
//*********************************************************************************
// These values are used for dictionary attack tracking and control.
    UINT32 failedTries;                   // the current count of unexpired
    // authorization failures

    UINT32 maxTries;                      // number of unexpired authorization
    // failures before the TPM is in
    // lockout

    UINT32 recoveryTime;                 // time between authorization failures
    // before failedTries is decremented

    UINT32 lockoutRecovery;              // time that must expire between
    // authorization failures associated
    // with lockoutAuth

    BOOL lockOutAuthEnabled;           // TRUE if use of lockoutAuth is
    // allowed

//*****************************************************************************
// Orderly State
//*****************************************************************************
// The orderly state for current cycle
    TPM_SU orderlyState;

//*****************************************************************************
// Command audit values.
//*****************************************************************************
    BYTE auditComands[((TPM_CC_LAST - TPM_CC_FIRST + 1) + 7)  / 8];
    TPMI_ALG_HASH auditHashAlg;
    UINT64 auditCounter;

//*****************************************************************************
// Algorithm selection
//*****************************************************************************
//
// The 'algorithmSet' value indicates the collection of algorithms that are
// currently in used on the TPM. The interpretation of value is vendor dependent.
    UINT32 algorithmSet;

//*****************************************************************************
// Firmware version
//*****************************************************************************
// The firmwareV1 and firmwareV2 values are instanced in TimeStamp.c. This is
// a scheme used in development to allow determination of the linker build time
// of the TPM. An actual implementation would implement these values in a way that
// is consistent with vendor needs. The values are maintained in RAM for simplified
// access with a master version in NV. These values are modified in a
// vendor-specific way.

// g_firmwareV1 contains the more significant 32-bits of the vendor version number.
// In the reference implementation, if this value is printed as a hex
// value, it will have the format of yyyymmdd
    UINT32 firmwareV1;

// g_firmwareV1 contains the less significant 32-bits of the vendor version number.
// In the reference implementation, if this value is printed as a hex
// value, it will have the format of 00 hh mm ss
    UINT32 firmwareV2;

} PERSISTENT_DATA;
extern PERSISTENT_DATA gp;
typedef struct orderly_data
{

//*****************************************************************************
// TIME
//*****************************************************************************

// Clock has two parts. One is the state save part and one is the NV part. The
// state save version is updated on each command. When the clock rolls over, the
// NV version is updated. When the TPM starts up, if the TPM was shutdown in and
// orderly way, then the sClock value is used to initialize the clock. If the
// TPM shutdown was not orderly, then the persistent value is used and the safe
// attribute is clear.

    UINT64 clock;                           // The orderly version of clock
    TPMI_YES_NO clockSafe;                       // Indicates if the clock value is
    // safe.
//*********************************************************************************
// DRBG
//*********************************************************************************
#ifdef _DRBG_STATE_SAVE
    // This is DRBG state data. This is saved each time the value of clock is
    // updated.
    DRBG_STATE drbgState;
#endif

} ORDERLY_DATA;
extern ORDERLY_DATA go;
typedef struct state_clear_data
{
//*****************************************************************************
// Hierarchy Control
//*****************************************************************************
    BOOL shEnable;                        // default reset is SET
    BOOL ehEnable;                        // default reset is SET
    BOOL phEnableNV;                      // default reset is SET
    TPMI_ALG_HASH platformAlg;                     // default reset is TPM_ALG_NULL
    TPM2B_DIGEST platformPolicy;                  // default reset is an Empty Buffer
    TPM2B_AUTH platformAuth;                    // default reset is an Empty Buffer

//*****************************************************************************
// PCR
//*****************************************************************************
// The set of PCR to be saved on Shutdown(STATE)
    PCR_SAVE pcrSave;                         // default reset is 0...0

// This structure hold the authorization values for those PCR that have an
// update authorization.
// This implementation only supports a single group of PCR controlled by
// authorization. If more are required, then this structure would be changed to
// an array.
    PCR_AUTHVALUE pcrAuthValues;

} STATE_CLEAR_DATA;
extern STATE_CLEAR_DATA gc;
typedef struct state_reset_data
{
//*****************************************************************************
// Hierarchy Control
//*****************************************************************************
    TPM2B_AUTH nullProof;                        // The proof value associated with
    // the TPM_RH_NULL hierarchy. The
    // default reset value is from the RNG.

    TPM2B_SEED nullSeed;                         // The seed value for the TPM_RN_NULL
    // hierarchy. The default reset value
    // is from the RNG.

//*****************************************************************************
// Context
//*****************************************************************************
// The 'clearCount' counter is incremented each time the TPM successfully executes
// a TPM Resume. The counter is included in each saved context that has 'stClear'
// SET (including descendants of keys that have 'stClear' SET). This prevents these
// objects from being loaded after a TPM Resume.
// If 'clearCount' at its maximum value when the TPM receives a Shutdown(STATE),
// the TPM will return TPM_RC_RANGE and the TPM will only accept Shutdown(CLEAR).
    UINT32 clearCount;                       // The default reset value is 0.

    UINT64 objectContextID;                  // This is the context ID for a saved
    // object context. The default reset
    // value is 0.

    CONTEXT_SLOT contextArray[MAX_ACTIVE_SESSIONS];
    // This is the value from which the
    // 'contextID' is derived. The
    // default reset value is {0}.

    CONTEXT_COUNTER contextCounter;                   // This array contains contains the
    // values used to track the version
    // numbers of saved contexts (see
    // Session.c in for details). The
    // default reset value is 0.

//*****************************************************************************
// Command Audit
//*****************************************************************************
// When an audited command completes, ExecuteCommand() checks the return
// value. If it is TPM_RC_SUCCESS, and the command is an audited command, the
// TPM will extend the cpHash and rpHash for the command to this value. If this
// digest was the Zero Digest before the cpHash was extended, the audit counter
// is incremented.

    TPM2B_DIGEST commandAuditDigest;               // This value is set to an Empty Digest
    // by TPM2_GetCommandAuditDigest() or a
    // TPM Reset.

//*****************************************************************************
// Boot counter
//*****************************************************************************

    UINT32 restartCount;                     // This counter counts TPM Restarts.
    // The default reset value is 0.

//*********************************************************************************
// PCR
//*********************************************************************************
// This counter increments whenever the PCR are updated. This counter is preserved
// across TPM Resume even though the PCR are not preserved. This is because
// sessions remain active across TPM Restart and the count value in the session
// is compared to this counter so this counter must have values that are unique
// as long as the sessions are active.
// NOTE: A platform-specific specification may designate that certain PCR changes
// do not increment this counter to increment.
    UINT32 pcrCounter;                           // The default reset value is 0.

#ifdef TPM_ALG_ECC

//*****************************************************************************
// ECDAA
//*****************************************************************************
    UINT64 commitCounter;                        // This counter increments each time
    // TPM2_Commit() returns
    // TPM_RC_SUCCESS. The default reset
    // value is 0.

    TPM2B_NONCE commitNonce;                          // This random value is used to compute
    // the commit values. The default reset
    // value is from the RNG.

// This implementation relies on the number of bits in g_commitArray being a
// power of 2 (8, 16, 32, 64, etc.) and no greater than 64K.
    BYTE commitArray[16];                 // The default reset value is {0}.

#endif     //TPM_ALG_ECC

} STATE_RESET_DATA;
extern STATE_RESET_DATA gr;
#define RcSafeAddToResult(r, v) \
 ((r) + (((r) & RC_FMT1) ? (v) : 0))
#define UNREFERENCED(a) ((void)(a))
#if defined SESSION_PROCESS_C || defined GLOBAL_C || defined MANUFACTURE_C
extern TPM_HANDLE s_sessionHandles[MAX_SESSION_NUM];
extern TPMA_SESSION s_attributes[MAX_SESSION_NUM];
extern TPM_HANDLE s_associatedHandles[MAX_SESSION_NUM];
extern TPM2B_NONCE s_nonceCaller[MAX_SESSION_NUM];
extern TPM2B_AUTH s_inputAuthValues[MAX_SESSION_NUM];
#define UNDEFINED_INDEX (0xFFFF)
extern UINT32 s_encryptSessionIndex;
extern UINT32 s_decryptSessionIndex;
extern UINT32 s_auditSessionIndex;
extern TPM2B_DIGEST s_cpHashForAudit;
#ifdef TPM_CC_GetCommandAuditDigest
extern TPM2B_DIGEST s_cpHashForCommandAudit;
#endif
extern UINT32 s_sessionNum;
extern BOOL s_DAPendingOnNV;
#endif   // SESSION_PROCESS_C
#if defined DA_C || defined GLOBAL_C || defined MANUFACTURE_C
extern UINT64 s_selfHealTimer;
extern UINT64 s_lockoutTimer;
#endif  // DA_C
#if defined NV_C || defined GLOBAL_C
extern UINT32 s_reservedAddr[NV_RESERVE_LAST];
extern UINT32 s_reservedSize[NV_RESERVE_LAST];
extern UINT32 s_ramIndexSize;
extern BYTE s_ramIndex[RAM_INDEX_SPACE];
extern UINT32 s_ramIndexSizeAddr;
extern UINT32 s_ramIndexAddr;
extern UINT32 s_maxCountAddr;
extern UINT32 s_evictNvStart;
extern UINT32 s_evictNvEnd;
extern TPM_RC s_NvStatus;
#endif
#if defined OBJECT_C || defined GLOBAL_C
typedef struct
{
    BOOL occupied;
    ANY_OBJECT object;
} OBJECT_SLOT;
extern OBJECT_SLOT s_objects[MAX_LOADED_OBJECTS];
#endif   // OBJECT_C
#if defined PCR_C || defined GLOBAL_C
typedef struct
{
#ifdef TPM_ALG_SHA1
    // SHA1 PCR
    BYTE sha1Pcr[SHA1_DIGEST_SIZE];
#endif
#ifdef TPM_ALG_SHA256
    // SHA256 PCR
    BYTE sha256Pcr[SHA256_DIGEST_SIZE];
#endif
#ifdef TPM_ALG_SHA384
    // SHA384 PCR
    BYTE sha384Pcr[SHA384_DIGEST_SIZE];
#endif
#ifdef TPM_ALG_SHA512
    // SHA512 PCR
    BYTE sha512Pcr[SHA512_DIGEST_SIZE];
#endif
#ifdef TPM_ALG_SM3_256
    // SHA256 PCR
    BYTE sm3_256Pcr[SM3_256_DIGEST_SIZE];
#endif
} PCR;
typedef struct
{
    unsigned int stateSave : 1;                // if the PCR value should be
    // saved in state save
    unsigned int resetLocality : 5;      // The locality that the PCR
    // can be reset
    unsigned int extendLocality : 5;      // The locality that the PCR
    // can be extend
} PCR_Attributes;
extern PCR s_pcrs[IMPLEMENTATION_PCR];
#endif   // PCR_C
#if defined SESSION_C || defined GLOBAL_C
typedef struct
{
    BOOL occupied;
    SESSION session;                 // session structure
} SESSION_SLOT;
extern SESSION_SLOT s_sessions[MAX_LOADED_SESSIONS];
extern UINT32 s_oldestSavedSession;
extern int s_freeSessionSlots;
#endif    // SESSION_C
extern BOOL g_manufactured;
#if defined POWER_C || defined GLOBAL_C
extern BOOL s_initialized;
#endif    // POWER_C
#if defined MEMORY_LIB_C || defined GLOBAL_C
extern UINT32 s_actionInputBuffer[1024];                             // action input buffer
extern UINT32 s_actionOutputBuffer[1024];                            // action output buffer
extern BYTE s_responseBuffer[MAX_RESPONSE_SIZE];// response buffer
#endif    // MEMORY_LIB_C
extern jmp_buf g_jumpBuffer;                 // the jump buffer
extern BOOL g_inFailureMode;              // Indicates that the TPM is in failure mode
extern BOOL g_forceFailureMode;           // flag to force failure mode during test
#if defined TPM_FAIL_C || defined GLOBAL_C || 1
extern UINT32 s_failFunction;
extern UINT32 s_failLine;                   // the line in the file at which
// the error was signaled
extern UINT32 s_failCode;                   // the error code used
#endif    // TPM_FAIL_C
#endif    // GLOBAL_H
