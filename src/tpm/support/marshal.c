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
/*     Any marks and brands contained herein are the property of their respective owners.                         */
/*                                                                                                                */
/******************************************************************************************************************/

#include "InternalRoutines.h"


// Table 2:3 - Definition of Base Types (TypedefTable)
TPM_RC
UINT8_Unmarshal(
    UINT8 *target, BYTE **buffer, INT32 *size)
{
    if((*size) < sizeof(UINT8)) // if buffer size not sufficient
        return TPM_RC_INSUFFICIENT;  // return corresponding error code

    *target = BYTE_ARRAY_TO_UINT8(*buffer);
    *buffer += sizeof(UINT8);
    *size -= sizeof(UINT8);

    return TPM_RC_SUCCESS;
}

UINT16
UINT8_Marshal(
    UINT8 *source, BYTE **buffer, INT32 *size)
{
    if (buffer != NULL)  // if buffer pointer is not a null pointer
    {
        pAssert ((size == NULL) || (((UINT32)*size) >= sizeof(UINT8))); // assert size of buffer is large enough

        UINT8_TO_BYTE_ARRAY(*source, *buffer);
        *buffer += sizeof(UINT8); // adjust size of empty buffer
        if (size != NULL)
        {
            *size -= sizeof(UINT8);
        }

    }
    return sizeof(UINT8);
}


// UINT8 definition used from Table 2:3
// BYTE_Unmarshal changed to #define
// BYTE_Marshal changed to #define

// UINT8 definition used from Table 2:3
// INT8_Unmarshal changed to #define
// INT8_Marshal changed to #define

TPM_RC
UINT16_Unmarshal(
    UINT16 *target, BYTE **buffer, INT32 *size)
{
    if((*size) < sizeof(UINT16)) // if buffer size not sufficient
        return TPM_RC_INSUFFICIENT;  // return corresponding error code

    *target = BYTE_ARRAY_TO_UINT16(*buffer);
    *buffer += sizeof(UINT16);
    *size -= sizeof(UINT16);

    return TPM_RC_SUCCESS;
}

UINT16
UINT16_Marshal(
    UINT16 *source, BYTE **buffer, INT32 *size)
{
    if (buffer != NULL)  // if buffer pointer is not a null pointer
    {
        pAssert ((size == NULL) || (((UINT32)*size) >= sizeof(UINT16))); // assert size of buffer is large enough

        UINT16_TO_BYTE_ARRAY(*source, *buffer);
        *buffer += sizeof(UINT16); // adjust size of empty buffer
        if (size != NULL)
        {
            *size -= sizeof(UINT16);
        }

    }
    return sizeof(UINT16);
}


// UINT16 definition used from Table 2:3
// INT16_Unmarshal changed to #define
// INT16_Marshal changed to #define

TPM_RC
UINT32_Unmarshal(
    UINT32 *target, BYTE **buffer, INT32 *size)
{
    if((*size) < sizeof(UINT32)) // if buffer size not sufficient
        return TPM_RC_INSUFFICIENT;  // return corresponding error code

    *target = BYTE_ARRAY_TO_UINT32(*buffer);
    *buffer += sizeof(UINT32);
    *size -= sizeof(UINT32);

    return TPM_RC_SUCCESS;
}

UINT16
UINT32_Marshal(
    UINT32 *source, BYTE **buffer, INT32 *size)
{
    if (buffer != NULL)  // if buffer pointer is not a null pointer
    {
        pAssert ((size == NULL) || (((UINT32)*size) >= sizeof(UINT32))); // assert size of buffer is large enough

        UINT32_TO_BYTE_ARRAY(*source, *buffer);
        *buffer += sizeof(UINT32); // adjust size of empty buffer
        if (size != NULL)
        {
            *size -= sizeof(UINT32);
        }

    }
    return sizeof(UINT32);
}


// UINT32 definition used from Table 2:3
// INT32_Unmarshal changed to #define
// INT32_Marshal changed to #define

TPM_RC
UINT64_Unmarshal(
    UINT64 *target, BYTE **buffer, INT32 *size)
{
    if((*size) < sizeof(UINT64)) // if buffer size not sufficient
        return TPM_RC_INSUFFICIENT;  // return corresponding error code

    *target = BYTE_ARRAY_TO_UINT64(*buffer);
    *buffer += sizeof(UINT64);
    *size -= sizeof(UINT64);

    return TPM_RC_SUCCESS;
}

UINT16
UINT64_Marshal(
    UINT64 *source, BYTE **buffer, INT32 *size)
{
    if (buffer != NULL)  // if buffer pointer is not a null pointer
    {
        pAssert ((size == NULL) || (((UINT32)*size) >= sizeof(UINT64))); // assert size of buffer is large enough

        UINT64_TO_BYTE_ARRAY(*source, *buffer);
        *buffer += sizeof(UINT64); // adjust size of empty buffer
        if (size != NULL)
        {
            *size -= sizeof(UINT64);
        }

    }
    return sizeof(UINT64);
}


// UINT64 definition used from Table 2:3
// INT64_Unmarshal changed to #define
// INT64_Marshal changed to #define


// Table 2:5 - Definition of Types for Documentation Clarity (TypedefTable)
// UINT32 definition used from Table 2:3
// TPM_ALGORITHM_ID_Unmarshal changed to #define
// TPM_ALGORITHM_ID_Marshal changed to #define

// UINT32 definition used from Table 2:3
// TPM_MODIFIER_INDICATOR_Unmarshal changed to #define
// TPM_MODIFIER_INDICATOR_Marshal changed to #define

// UINT32 definition used from Table 2:3
// TPM_AUTHORIZATION_SIZE_Unmarshal changed to #define
// TPM_AUTHORIZATION_SIZE_Marshal changed to #define

// UINT32 definition used from Table 2:3
// TPM_PARAMETER_SIZE_Unmarshal changed to #define
// TPM_PARAMETER_SIZE_Marshal changed to #define

// UINT16 definition used from Table 2:3
// TPM_KEY_SIZE_Unmarshal changed to #define
// TPM_KEY_SIZE_Marshal changed to #define

// UINT16 definition used from Table 2:3
// TPM_KEY_BITS_Unmarshal changed to #define
// TPM_KEY_BITS_Marshal changed to #define


// Table 2:6 - Definition of (UINT32) TPM_SPEC Constants (EnumTable)
// TPM_SPEC_Unmarshal not required
// TPM_SPEC_Marshal not required

// Table 2:7 - Definition of (UINT32) TPM_GENERATED Constants (EnumTable)
// TPM_GENERATED_Unmarshal not required
// TPM_GENERATED_Marshal changed to #define

// Table 2:9 - Definition of (UINT16) TPM_ALG_ID Constants (EnumTable)
// TPM_ALG_ID_Unmarshal changed to #define
// TPM_ALG_ID_Marshal changed to #define

// Table 2:10 - Definition of (UINT16) {ECC} TPM_ECC_CURVE Constants (EnumTable)
#ifdef TPM_ALG_ECC
// TPM_ECC_CURVE_Unmarshal changed to #define
// TPM_ECC_CURVE_Marshal changed to #define
#endif // TPM_ALG_ECC


// Table 2:13 - Definition of (UINT32) TPM_CC Constants (EnumTable)
// TPM_CC_Unmarshal changed to #define
// TPM_CC_Marshal changed to #define

// Table 2:17 - Definition of (UINT32) TPM_RC Constants (EnumTable)
// TPM_RC_Unmarshal not required
// TPM_RC_Marshal changed to #define

// Table 2:18 - Definition of (INT8) TPM_CLOCK_ADJUST Constants (EnumTable)
TPM_RC
TPM_CLOCK_ADJUST_Unmarshal(
    TPM_CLOCK_ADJUST *target, BYTE **buffer, INT32 *size)
{
    TPM_RC rc;
    rc = INT8_Unmarshal((INT8 *)target, buffer, size); // perform unmarshal

    if(rc == TPM_RC_SUCCESS) // if unmarshalling succeeds
    {
        switch(*target)
        {
        case TPM_CLOCK_COARSE_SLOWER :
        case TPM_CLOCK_MEDIUM_SLOWER :
        case TPM_CLOCK_FINE_SLOWER :
        case TPM_CLOCK_NO_CHANGE :
        case TPM_CLOCK_FINE_FASTER :
        case TPM_CLOCK_MEDIUM_FASTER :
        case TPM_CLOCK_COARSE_FASTER :
            break;
        default :           // if target does not contain valid value
            rc = TPM_RC_VALUE;  // return fail
        }
    }
    return rc;
}

// TPM_CLOCK_ADJUST_Marshal not required

// Table 2:19 - Definition of (UINT16) TPM_EO Constants (EnumTable)
TPM_RC
TPM_EO_Unmarshal(
    TPM_EO *target, BYTE **buffer, INT32 *size)
{
    TPM_RC rc;
    rc = UINT16_Unmarshal((UINT16 *)target, buffer, size); // perform unmarshal

    if(rc == TPM_RC_SUCCESS) // if unmarshalling succeeds
    {
        switch(*target)
        {
        case TPM_EO_EQ :
        case TPM_EO_NEQ :
        case TPM_EO_SIGNED_GT :
        case TPM_EO_UNSIGNED_GT :
        case TPM_EO_SIGNED_LT :
        case TPM_EO_UNSIGNED_LT :
        case TPM_EO_SIGNED_GE :
        case TPM_EO_UNSIGNED_GE :
        case TPM_EO_SIGNED_LE :
        case TPM_EO_UNSIGNED_LE :
        case TPM_EO_BITSET :
        case TPM_EO_BITCLEAR :
            break;
        default :           // if target does not contain valid value
            rc = TPM_RC_VALUE;  // return fail
        }
    }
    return rc;
}

// TPM_EO_Marshal changed to #define

// Table 2:20 - Definition of (UINT16) TPM_ST Constants (EnumTable)
// TPM_ST_Unmarshal changed to #define
// TPM_ST_Marshal changed to #define

// Table 2:21 - Definition of (UINT16) TPM_SU Constants (EnumTable)
TPM_RC
TPM_SU_Unmarshal(
    TPM_SU *target, BYTE **buffer, INT32 *size)
{
    TPM_RC rc;
    rc = UINT16_Unmarshal((UINT16 *)target, buffer, size); // perform unmarshal

    if(rc == TPM_RC_SUCCESS) // if unmarshalling succeeds
    {
        switch(*target)
        {
        case TPM_SU_CLEAR :
        case TPM_SU_STATE :
            break;
        default :           // if target does not contain valid value
            rc = TPM_RC_VALUE;  // return fail
        }
    }
    return rc;
}

// TPM_SU_Marshal not required

// Table 2:22 - Definition of (UINT8) TPM_SE Constants (EnumTable)
TPM_RC
TPM_SE_Unmarshal(
    TPM_SE *target, BYTE **buffer, INT32 *size)
{
    TPM_RC rc;
    rc = UINT8_Unmarshal((UINT8 *)target, buffer, size); // perform unmarshal

    if(rc == TPM_RC_SUCCESS) // if unmarshalling succeeds
    {
        switch(*target)
        {
        case TPM_SE_HMAC :
        case TPM_SE_POLICY :
        case TPM_SE_TRIAL :
            break;
        default :           // if target does not contain valid value
            rc = TPM_RC_VALUE;  // return fail
        }
    }
    return rc;
}

// TPM_SE_Marshal not required

// Table 2:23 - Definition of (UINT32) TPM_CAP Constants (EnumTable)
TPM_RC
TPM_CAP_Unmarshal(
    TPM_CAP *target, BYTE **buffer, INT32 *size)
{
    TPM_RC rc;
    rc = UINT32_Unmarshal((UINT32 *)target, buffer, size); // perform unmarshal

    if(rc == TPM_RC_SUCCESS) // if unmarshalling succeeds
    {
        switch(*target)
        {
        case TPM_CAP_ALGS :
        case TPM_CAP_HANDLES :
        case TPM_CAP_COMMANDS :
        case TPM_CAP_PP_COMMANDS :
        case TPM_CAP_AUDIT_COMMANDS :
        case TPM_CAP_PCRS :
        case TPM_CAP_TPM_PROPERTIES :
        case TPM_CAP_PCR_PROPERTIES :
        case TPM_CAP_ECC_CURVES :
        case TPM_CAP_VENDOR_PROPERTY :
            break;
        default :           // if target does not contain valid value
            rc = TPM_RC_VALUE;  // return fail
        }
    }
    return rc;
}

// TPM_CAP_Marshal changed to #define

// Table 2:24 - Definition of (UINT32) TPM_PT Constants (EnumTable)
// TPM_PT_Unmarshal changed to #define
// TPM_PT_Marshal changed to #define

// Table 2:25 - Definition of (UINT32) TPM_PT_PCR Constants (EnumTable)
// TPM_PT_PCR_Unmarshal changed to #define
// TPM_PT_PCR_Marshal changed to #define

// Table 2:26 - Definition of (UINT32) TPM_PS Constants (EnumTable)
// TPM_PS_Unmarshal not required
// TPM_PS_Marshal changed to #define

// Table 2:27 - Definition of Types for Handles (TypedefTable)
// UINT32 definition used from Table 2:3
// TPM_HANDLE_Unmarshal changed to #define
// TPM_HANDLE_Marshal changed to #define


// Table 2:28 - Definition of (UINT8) TPM_HT Constants (EnumTable)
// TPM_HT_Unmarshal not required
// TPM_HT_Marshal not required

// Table 2:29 - Definition of (TPM_HANDLE) TPM_RH Constants (EnumTable)

// Table 2:30 - Definition of (TPM_HANDLE) TPM_HC Constants (EnumTable)

// Table 2:31 - Definition of (UINT32) TPMA_ALGORITHM Bits (BitsTable)
TPM_RC
TPMA_ALGORITHM_Unmarshal(
    TPMA_ALGORITHM *target, BYTE **buffer, INT32 *size)
{
    TPM_RC rc;
    rc = UINT32_Unmarshal(&target->val, buffer, size);

    if(rc == TPM_RC_SUCCESS)
        if(target->val & (UINT32)0xfffff8f0)
            rc = TPM_RC_RESERVED_BITS;

    return rc;
}

// TPMA_ALGORITHM_Marshal changed to #define

// Table 2:32 - Definition of (UINT32) TPMA_OBJECT Bits (BitsTable)
TPM_RC
TPMA_OBJECT_Unmarshal(
    TPMA_OBJECT *target, BYTE **buffer, INT32 *size)
{
    TPM_RC rc;
    rc = UINT32_Unmarshal(&target->val, buffer, size);

    if(rc == TPM_RC_SUCCESS)
        if(target->val & (UINT32)0xfff8f309)
            rc = TPM_RC_RESERVED_BITS;

    return rc;
}

// TPMA_OBJECT_Marshal changed to #define

// Table 2:33 - Definition of (UINT8) TPMA_SESSION Bits (BitsTable)
TPM_RC
TPMA_SESSION_Unmarshal(
    TPMA_SESSION *target, BYTE **buffer, INT32 *size)
{
    TPM_RC rc;
    rc = UINT8_Unmarshal(&target->val, buffer, size);

    if(rc == TPM_RC_SUCCESS)
        if(target->val & (UINT8)0x18)
            rc = TPM_RC_RESERVED_BITS;

    return rc;
}

// TPMA_SESSION_Marshal changed to #define

// Table 2:34 - Definition of (UINT8) TPMA_LOCALITY Bits (BitsTable)
// TPMA_LOCALITY_Unmarshal changed to #define
// TPMA_LOCALITY_Marshal changed to #define

// Table 2:35 - Definition of (UINT32) TPMA_PERMANENT Bits (BitsTable)
TPM_RC
TPMA_PERMANENT_Unmarshal(
    TPMA_PERMANENT *target, BYTE **buffer, INT32 *size)
{
    TPM_RC rc;
    rc = UINT32_Unmarshal(&target->val, buffer, size);

    if(rc == TPM_RC_SUCCESS)
        if(target->val & (UINT32)0xfffff8f8)
            rc = TPM_RC_RESERVED_BITS;

    return rc;
}

// TPMA_PERMANENT_Marshal changed to #define

// Table 2:36 - Definition of (UINT32) TPMA_STARTUP_CLEAR Bits (BitsTable)
TPM_RC
TPMA_STARTUP_CLEAR_Unmarshal(
    TPMA_STARTUP_CLEAR *target, BYTE **buffer, INT32 *size)
{
    TPM_RC rc;
    rc = UINT32_Unmarshal(&target->val, buffer, size);

    if(rc == TPM_RC_SUCCESS)
        if(target->val & (UINT32)0x7ffffff0)
            rc = TPM_RC_RESERVED_BITS;

    return rc;
}

// TPMA_STARTUP_CLEAR_Marshal changed to #define

// Table 2:37 - Definition of (UINT32) TPMA_MEMORY Bits (BitsTable)
TPM_RC
TPMA_MEMORY_Unmarshal(
    TPMA_MEMORY *target, BYTE **buffer, INT32 *size)
{
    TPM_RC rc;
    rc = UINT32_Unmarshal(&target->val, buffer, size);

    if(rc == TPM_RC_SUCCESS)
        if(target->val & (UINT32)0xfffffff8)
            rc = TPM_RC_RESERVED_BITS;

    return rc;
}

// TPMA_MEMORY_Marshal changed to #define

// Table 2:38 - Definition of (TPM_CC) TPMA_CC Bits (BitsTable)
TPM_RC
TPMA_CC_Unmarshal(
    TPMA_CC *target, BYTE **buffer, INT32 *size)
{
    TPM_RC rc;
    rc = TPM_CC_Unmarshal(&target->val, buffer, size);

    if(rc == TPM_RC_SUCCESS)
        if(target->val & (TPM_CC)0x3f0000)
            rc = TPM_RC_RESERVED_BITS;

    return rc;
}

// TPMA_CC_Marshal changed to #define

// Table 2:39 - Definition of (BYTE) TPMI_YES_NO Type (InterfaceTable)
TPM_RC
TPMI_YES_NO_Unmarshal(
    TPMI_YES_NO *target, BYTE **buffer, INT32 *size)
{
    TPM_RC rc;
    rc = BYTE_Unmarshal((BYTE *)target, buffer, size);

    if (rc == TPM_RC_SUCCESS) // if unmarshalling succeeds
    {
        switch (*target)
        {
        case NO:
        case YES:

            break;

        default:
            rc = TPM_RC_VALUE;
        }
    }
    return rc;
}

// TPMI_YES_NO_Marshal changed to #define

// Table 2:40 - Definition of (TPM_HANDLE) TPMI_DH_OBJECT Type (InterfaceTable)
TPM_RC
TPMI_DH_OBJECT_Unmarshal(
    TPMI_DH_OBJECT *target, BYTE **buffer, INT32 *size, BOOL allowNull)
{
    TPM_RC rc;
    rc = TPM_HANDLE_Unmarshal((TPM_HANDLE *)target, buffer, size);

    if (rc == TPM_RC_SUCCESS) // if unmarshalling succeeds
    {
        if (*target == TPM_RH_NULL)
        {
            if (!allowNull)
                rc = TPM_RC_VALUE;
        }
        else if(((*target < TRANSIENT_FIRST) || (*target > TRANSIENT_LAST))
                && ((*target < PERSISTENT_FIRST) || (*target > PERSISTENT_LAST)))
            rc = TPM_RC_VALUE;
    }
    return rc;
}

// TPMI_DH_OBJECT_Marshal changed to #define

// Table 2:41 - Definition of (TPM_HANDLE) TPMI_DH_PERSISTENT Type (InterfaceTable)
TPM_RC
TPMI_DH_PERSISTENT_Unmarshal(
    TPMI_DH_PERSISTENT *target, BYTE **buffer, INT32 *size)
{
    TPM_RC rc;
    rc = TPM_HANDLE_Unmarshal((TPM_HANDLE *)target, buffer, size);

    if (rc == TPM_RC_SUCCESS) // if unmarshalling succeeds
    {

        if(((*target < PERSISTENT_FIRST) || (*target > PERSISTENT_LAST)))
            rc = TPM_RC_VALUE;
    }
    return rc;
}

// TPMI_DH_PERSISTENT_Marshal changed to #define

// Table 2:42 - Definition of (TPM_HANDLE) TPMI_DH_ENTITY Type (InterfaceTable)
TPM_RC
TPMI_DH_ENTITY_Unmarshal(
    TPMI_DH_ENTITY *target, BYTE **buffer, INT32 *size, BOOL allowNull)
{
    TPM_RC rc;
    rc = TPM_HANDLE_Unmarshal((TPM_HANDLE *)target, buffer, size);

    if (rc == TPM_RC_SUCCESS) // if unmarshalling succeeds
    {
        switch (*target)
        {
        case TPM_RH_OWNER:
        case TPM_RH_ENDORSEMENT:
        case TPM_RH_PLATFORM:
        case TPM_RH_LOCKOUT:

            break;
        case TPM_RH_NULL:
            if (!allowNull)
                rc = TPM_RC_VALUE;
            break;
        default:
            if(((*target < TRANSIENT_FIRST) || (*target > TRANSIENT_LAST))
                    && ((*target < PERSISTENT_FIRST) || (*target > PERSISTENT_LAST))
                    && ((*target < NV_INDEX_FIRST) || (*target > NV_INDEX_LAST))
                    && ((*target < PCR_FIRST) || (*target > PCR_LAST))
                    && ((*target < TPM_RH_AUTH_00) || (*target > TPM_RH_AUTH_FF)))
                rc = TPM_RC_VALUE;
        }
    }
    return rc;
}


// Table 2:43 - Definition of (TPM_HANDLE) TPMI_DH_PCR Type (InterfaceTable)
TPM_RC
TPMI_DH_PCR_Unmarshal(
    TPMI_DH_PCR *target, BYTE **buffer, INT32 *size, BOOL allowNull)
{
    TPM_RC rc;
    rc = TPM_HANDLE_Unmarshal((TPM_HANDLE *)target, buffer, size);

    if (rc == TPM_RC_SUCCESS) // if unmarshalling succeeds
    {
        if (*target == TPM_RH_NULL)
        {
            if (!allowNull)
                rc = TPM_RC_VALUE;
        }
        else if(((*target < PCR_FIRST) || (*target > PCR_LAST)))
            rc = TPM_RC_VALUE;
    }
    return rc;
}


// Table 2:44 - Definition of (TPM_HANDLE) TPMI_SH_AUTH_SESSION Type (InterfaceTable)
TPM_RC
TPMI_SH_AUTH_SESSION_Unmarshal(
    TPMI_SH_AUTH_SESSION *target, BYTE **buffer, INT32 *size, BOOL allowNull)
{
    TPM_RC rc;
    rc = TPM_HANDLE_Unmarshal((TPM_HANDLE *)target, buffer, size);

    if (rc == TPM_RC_SUCCESS) // if unmarshalling succeeds
    {
        if (*target == TPM_RS_PW)
        {
            if (!allowNull)
                rc = TPM_RC_VALUE;
        }
        else if(((*target < HMAC_SESSION_FIRST) || (*target > HMAC_SESSION_LAST))
                && ((*target < POLICY_SESSION_FIRST) || (*target > POLICY_SESSION_LAST)))
            rc = TPM_RC_VALUE;
    }
    return rc;
}

// TPMI_SH_AUTH_SESSION_Marshal changed to #define

// Table 2:45 - Definition of (TPM_HANDLE) TPMI_SH_HMAC Type (InterfaceTable)
TPM_RC
TPMI_SH_HMAC_Unmarshal(
    TPMI_SH_HMAC *target, BYTE **buffer, INT32 *size)
{
    TPM_RC rc;
    rc = TPM_HANDLE_Unmarshal((TPM_HANDLE *)target, buffer, size);

    if (rc == TPM_RC_SUCCESS) // if unmarshalling succeeds
    {

        if(((*target < HMAC_SESSION_FIRST) || (*target > HMAC_SESSION_LAST)))
            rc = TPM_RC_VALUE;
    }
    return rc;
}

// TPMI_SH_HMAC_Marshal changed to #define

// Table 2:46 - Definition of (TPM_HANDLE) TPMI_SH_POLICY Type (InterfaceTable)
TPM_RC
TPMI_SH_POLICY_Unmarshal(
    TPMI_SH_POLICY *target, BYTE **buffer, INT32 *size)
{
    TPM_RC rc;
    rc = TPM_HANDLE_Unmarshal((TPM_HANDLE *)target, buffer, size);

    if (rc == TPM_RC_SUCCESS) // if unmarshalling succeeds
    {

        if(((*target < POLICY_SESSION_FIRST) || (*target > POLICY_SESSION_LAST)))
            rc = TPM_RC_VALUE;
    }
    return rc;
}

// TPMI_SH_POLICY_Marshal changed to #define

// Table 2:47 - Definition of (TPM_HANDLE) TPMI_DH_CONTEXT Type (InterfaceTable)
TPM_RC
TPMI_DH_CONTEXT_Unmarshal(
    TPMI_DH_CONTEXT *target, BYTE **buffer, INT32 *size)
{
    TPM_RC rc;
    rc = TPM_HANDLE_Unmarshal((TPM_HANDLE *)target, buffer, size);

    if (rc == TPM_RC_SUCCESS) // if unmarshalling succeeds
    {

        if(((*target < HMAC_SESSION_FIRST) || (*target > HMAC_SESSION_LAST))
                && ((*target < POLICY_SESSION_FIRST) || (*target > POLICY_SESSION_LAST))
                && ((*target < TRANSIENT_FIRST) || (*target > TRANSIENT_LAST)))
            rc = TPM_RC_VALUE;
    }
    return rc;
}

// TPMI_DH_CONTEXT_Marshal changed to #define

// Table 2:48 - Definition of (TPM_HANDLE) TPMI_RH_HIERARCHY Type (InterfaceTable)
TPM_RC
TPMI_RH_HIERARCHY_Unmarshal(
    TPMI_RH_HIERARCHY *target, BYTE **buffer, INT32 *size, BOOL allowNull)
{
    TPM_RC rc;
    rc = TPM_HANDLE_Unmarshal((TPM_HANDLE *)target, buffer, size);

    if (rc == TPM_RC_SUCCESS) // if unmarshalling succeeds
    {
        switch (*target)
        {
        case TPM_RH_OWNER:
        case TPM_RH_PLATFORM:
        case TPM_RH_ENDORSEMENT:

            break;
        case TPM_RH_NULL:
            if (allowNull)
                break;
        default:
            rc = TPM_RC_VALUE;
        }
    }
    return rc;
}

// TPMI_RH_HIERARCHY_Marshal changed to #define

// Table 2:49 - Definition of (TPM_HANDLE) TPMI_RH_ENABLES Type (InterfaceTable)
TPM_RC
TPMI_RH_ENABLES_Unmarshal(
    TPMI_RH_ENABLES *target, BYTE **buffer, INT32 *size, BOOL allowNull)
{
    TPM_RC rc;
    rc = TPM_HANDLE_Unmarshal((TPM_HANDLE *)target, buffer, size);

    if (rc == TPM_RC_SUCCESS) // if unmarshalling succeeds
    {
        switch (*target)
        {
        case TPM_RH_OWNER:
        case TPM_RH_PLATFORM:
        case TPM_RH_ENDORSEMENT:
        case TPM_RH_PLATFORM_NV:

            break;
        case TPM_RH_NULL:
            if (allowNull)
                break;
        default:
            rc = TPM_RC_VALUE;
        }
    }
    return rc;
}

// TPMI_RH_ENABLES_Marshal changed to #define

// Table 2:50 - Definition of (TPM_HANDLE) TPMI_RH_HIERARCHY_AUTH Type (InterfaceTable)
TPM_RC
TPMI_RH_HIERARCHY_AUTH_Unmarshal(
    TPMI_RH_HIERARCHY_AUTH *target, BYTE **buffer, INT32 *size)
{
    TPM_RC rc;
    rc = TPM_HANDLE_Unmarshal((TPM_HANDLE *)target, buffer, size);

    if (rc == TPM_RC_SUCCESS) // if unmarshalling succeeds
    {
        switch (*target)
        {
        case TPM_RH_OWNER:
        case TPM_RH_PLATFORM:
        case TPM_RH_ENDORSEMENT:
        case TPM_RH_LOCKOUT:

            break;

        default:
            rc = TPM_RC_VALUE;
        }
    }
    return rc;
}


// Table 2:51 - Definition of (TPM_HANDLE) TPMI_RH_PLATFORM Type (InterfaceTable)
TPM_RC
TPMI_RH_PLATFORM_Unmarshal(
    TPMI_RH_PLATFORM *target, BYTE **buffer, INT32 *size)
{
    TPM_RC rc;
    rc = TPM_HANDLE_Unmarshal((TPM_HANDLE *)target, buffer, size);

    if (rc == TPM_RC_SUCCESS) // if unmarshalling succeeds
    {
        switch (*target)
        {
        case TPM_RH_PLATFORM:

            break;

        default:
            rc = TPM_RC_VALUE;
        }
    }
    return rc;
}


// Table 2:52 - Definition of (TPM_HANDLE) TPMI_RH_OWNER Type (InterfaceTable)
TPM_RC
TPMI_RH_OWNER_Unmarshal(
    TPMI_RH_OWNER *target, BYTE **buffer, INT32 *size, BOOL allowNull)
{
    TPM_RC rc;
    rc = TPM_HANDLE_Unmarshal((TPM_HANDLE *)target, buffer, size);

    if (rc == TPM_RC_SUCCESS) // if unmarshalling succeeds
    {
        switch (*target)
        {
        case TPM_RH_OWNER:

            break;
        case TPM_RH_NULL:
            if (allowNull)
                break;
        default:
            rc = TPM_RC_VALUE;
        }
    }
    return rc;
}


// Table 2:53 - Definition of (TPM_HANDLE) TPMI_RH_ENDORSEMENT Type (InterfaceTable)
TPM_RC
TPMI_RH_ENDORSEMENT_Unmarshal(
    TPMI_RH_ENDORSEMENT *target, BYTE **buffer, INT32 *size, BOOL allowNull)
{
    TPM_RC rc;
    rc = TPM_HANDLE_Unmarshal((TPM_HANDLE *)target, buffer, size);

    if (rc == TPM_RC_SUCCESS) // if unmarshalling succeeds
    {
        switch (*target)
        {
        case TPM_RH_ENDORSEMENT:

            break;
        case TPM_RH_NULL:
            if (allowNull)
                break;
        default:
            rc = TPM_RC_VALUE;
        }
    }
    return rc;
}


// Table 2:54 - Definition of (TPM_HANDLE) TPMI_RH_PROVISION Type (InterfaceTable)
TPM_RC
TPMI_RH_PROVISION_Unmarshal(
    TPMI_RH_PROVISION *target, BYTE **buffer, INT32 *size)
{
    TPM_RC rc;
    rc = TPM_HANDLE_Unmarshal((TPM_HANDLE *)target, buffer, size);

    if (rc == TPM_RC_SUCCESS) // if unmarshalling succeeds
    {
        switch (*target)
        {
        case TPM_RH_OWNER:
        case TPM_RH_PLATFORM:

            break;

        default:
            rc = TPM_RC_VALUE;
        }
    }
    return rc;
}


// Table 2:55 - Definition of (TPM_HANDLE) TPMI_RH_CLEAR Type (InterfaceTable)
TPM_RC
TPMI_RH_CLEAR_Unmarshal(
    TPMI_RH_CLEAR *target, BYTE **buffer, INT32 *size)
{
    TPM_RC rc;
    rc = TPM_HANDLE_Unmarshal((TPM_HANDLE *)target, buffer, size);

    if (rc == TPM_RC_SUCCESS) // if unmarshalling succeeds
    {
        switch (*target)
        {
        case TPM_RH_LOCKOUT:
        case TPM_RH_PLATFORM:

            break;

        default:
            rc = TPM_RC_VALUE;
        }
    }
    return rc;
}


// Table 2:56 - Definition of (TPM_HANDLE) TPMI_RH_NV_AUTH Type (InterfaceTable)
TPM_RC
TPMI_RH_NV_AUTH_Unmarshal(
    TPMI_RH_NV_AUTH *target, BYTE **buffer, INT32 *size)
{
    TPM_RC rc;
    rc = TPM_HANDLE_Unmarshal((TPM_HANDLE *)target, buffer, size);

    if (rc == TPM_RC_SUCCESS) // if unmarshalling succeeds
    {
        switch (*target)
        {
        case TPM_RH_PLATFORM:
        case TPM_RH_OWNER:

            break;

        default:
            if(((*target < NV_INDEX_FIRST) || (*target > NV_INDEX_LAST)))
                rc = TPM_RC_VALUE;
        }
    }
    return rc;
}


// Table 2:57 - Definition of (TPM_HANDLE) TPMI_RH_LOCKOUT Type (InterfaceTable)
TPM_RC
TPMI_RH_LOCKOUT_Unmarshal(
    TPMI_RH_LOCKOUT *target, BYTE **buffer, INT32 *size)
{
    TPM_RC rc;
    rc = TPM_HANDLE_Unmarshal((TPM_HANDLE *)target, buffer, size);

    if (rc == TPM_RC_SUCCESS) // if unmarshalling succeeds
    {
        switch (*target)
        {
        case TPM_RH_LOCKOUT:

            break;

        default:
            rc = TPM_RC_VALUE;
        }
    }
    return rc;
}


// Table 2:58 - Definition of (TPM_HANDLE) TPMI_RH_NV_INDEX Type (InterfaceTable)
TPM_RC
TPMI_RH_NV_INDEX_Unmarshal(
    TPMI_RH_NV_INDEX *target, BYTE **buffer, INT32 *size)
{
    TPM_RC rc;
    rc = TPM_HANDLE_Unmarshal((TPM_HANDLE *)target, buffer, size);

    if (rc == TPM_RC_SUCCESS) // if unmarshalling succeeds
    {

        if(((*target < NV_INDEX_FIRST) || (*target > NV_INDEX_LAST)))
            rc = TPM_RC_VALUE;
    }
    return rc;
}

// TPMI_RH_NV_INDEX_Marshal changed to #define

// Table 2:59 - Definition of (TPM_ALG_ID) TPMI_ALG_HASH Type (InterfaceTable)
TPM_RC
TPMI_ALG_HASH_Unmarshal(
    TPMI_ALG_HASH *target, BYTE **buffer, INT32 *size, BOOL allowNull)
{
    TPM_RC rc;
    rc = TPM_ALG_ID_Unmarshal((TPM_ALG_ID *)target, buffer, size);

    if (rc == TPM_RC_SUCCESS) // if unmarshalling succeeds
    {
        switch (*target)
        {
#ifdef TPM_ALG_SHA1
        case TPM_ALG_SHA1:
#endif // TPM_ALG_SHA1
#ifdef TPM_ALG_SHA256
        case TPM_ALG_SHA256:
#endif // TPM_ALG_SHA256
#ifdef TPM_ALG_SHA384
        case TPM_ALG_SHA384:
#endif // TPM_ALG_SHA384
#ifdef TPM_ALG_SHA512
        case TPM_ALG_SHA512:
#endif // TPM_ALG_SHA512
#ifdef TPM_ALG_SM3_256
        case TPM_ALG_SM3_256:
#endif // TPM_ALG_SM3_256
            break;
        case TPM_ALG_NULL:
            if (!allowNull)
                rc = TPM_RC_HASH;
            break;
        default:
            rc = TPM_RC_HASH;
        }
    }
    return rc;
}

// TPMI_ALG_HASH_Marshal changed to #define

// Table 2:60 - Definition of (TPM_ALG_ID) TPMI_ALG_ASYM Type (InterfaceTable)
TPM_RC
TPMI_ALG_ASYM_Unmarshal(
    TPMI_ALG_ASYM *target, BYTE **buffer, INT32 *size, BOOL allowNull)
{
    TPM_RC rc;
    rc = TPM_ALG_ID_Unmarshal((TPM_ALG_ID *)target, buffer, size);

    if (rc == TPM_RC_SUCCESS) // if unmarshalling succeeds
    {
        switch (*target)
        {
#ifdef TPM_ALG_RSA
        case TPM_ALG_RSA:
#endif // TPM_ALG_RSA
#ifdef TPM_ALG_ECC
        case TPM_ALG_ECC:
#endif // TPM_ALG_ECC
            break;
        case TPM_ALG_NULL:
            if (!allowNull)
                rc = TPM_RC_ASYMMETRIC;
            break;
        default:
            rc = TPM_RC_ASYMMETRIC;
        }
    }
    return rc;
}

// TPMI_ALG_ASYM_Marshal changed to #define

// Table 2:61 - Definition of (TPM_ALG_ID) TPMI_ALG_SYM Type (InterfaceTable)
TPM_RC
TPMI_ALG_SYM_Unmarshal(
    TPMI_ALG_SYM *target, BYTE **buffer, INT32 *size, BOOL allowNull)
{
    TPM_RC rc;
    rc = TPM_ALG_ID_Unmarshal((TPM_ALG_ID *)target, buffer, size);

    if (rc == TPM_RC_SUCCESS) // if unmarshalling succeeds
    {
        switch (*target)
        {
#ifdef TPM_ALG_AES
        case TPM_ALG_AES:
#endif // TPM_ALG_AES
#ifdef TPM_ALG_SM4
        case TPM_ALG_SM4:
#endif // TPM_ALG_SM4
#ifdef TPM_ALG_CAMELLIA
        case TPM_ALG_CAMELLIA:
#endif // TPM_ALG_CAMELLIA
#ifdef TPM_ALG_XOR
        case TPM_ALG_XOR:
#endif // TPM_ALG_XOR
            break;
        case TPM_ALG_NULL:
            if (allowNull)
                break;
        default:
            rc = TPM_RC_SYMMETRIC;
        }
    }
    return rc;
}

// TPMI_ALG_SYM_Marshal changed to #define

// Table 2:62 - Definition of (TPM_ALG_ID) TPMI_ALG_SYM_OBJECT Type (InterfaceTable)
TPM_RC
TPMI_ALG_SYM_OBJECT_Unmarshal(
    TPMI_ALG_SYM_OBJECT *target, BYTE **buffer, INT32 *size, BOOL allowNull)
{
    TPM_RC rc;
    rc = TPM_ALG_ID_Unmarshal((TPM_ALG_ID *)target, buffer, size);

    if (rc == TPM_RC_SUCCESS) // if unmarshalling succeeds
    {
        switch (*target)
        {
#ifdef TPM_ALG_AES
        case TPM_ALG_AES:
#endif // TPM_ALG_AES
#ifdef TPM_ALG_SM4
        case TPM_ALG_SM4:
#endif // TPM_ALG_SM4
#ifdef TPM_ALG_CAMELLIA
        case TPM_ALG_CAMELLIA:
#endif // TPM_ALG_CAMELLIA
            break;
        case TPM_ALG_NULL:
            if (!allowNull)
                rc = TPM_RC_SYMMETRIC;
            break;
        default:
            rc = TPM_RC_SYMMETRIC;
        }
    }
    return rc;
}

// TPMI_ALG_SYM_OBJECT_Marshal changed to #define

// Table 2:63 - Definition of (TPM_ALG_ID) TPMI_ALG_SYM_MODE Type (InterfaceTable)
TPM_RC
TPMI_ALG_SYM_MODE_Unmarshal(
    TPMI_ALG_SYM_MODE *target, BYTE **buffer, INT32 *size, BOOL allowNull)
{
    TPM_RC rc;
    rc = TPM_ALG_ID_Unmarshal((TPM_ALG_ID *)target, buffer, size);

    if (rc == TPM_RC_SUCCESS) // if unmarshalling succeeds
    {
        switch (*target)
        {
#ifdef TPM_ALG_CTR
        case TPM_ALG_CTR:
#endif // TPM_ALG_CTR
#ifdef TPM_ALG_OFB
        case TPM_ALG_OFB:
#endif // TPM_ALG_OFB
#ifdef TPM_ALG_CBC
        case TPM_ALG_CBC:
#endif // TPM_ALG_CBC
#ifdef TPM_ALG_CFB
        case TPM_ALG_CFB:
#endif // TPM_ALG_CFB
#ifdef TPM_ALG_ECB
        case TPM_ALG_ECB:
#endif // TPM_ALG_ECB
            break;
        case TPM_ALG_NULL:
            if (!allowNull)
                rc = TPM_RC_MODE;
            break;
        default:
            rc = TPM_RC_MODE;
        }
    }
    return rc;
}

// TPMI_ALG_SYM_MODE_Marshal changed to #define

// Table 2:64 - Definition of (TPM_ALG_ID) TPMI_ALG_KDF Type (InterfaceTable)
TPM_RC
TPMI_ALG_KDF_Unmarshal(
    TPMI_ALG_KDF *target, BYTE **buffer, INT32 *size, BOOL allowNull)
{
    TPM_RC rc;
    rc = TPM_ALG_ID_Unmarshal((TPM_ALG_ID *)target, buffer, size);

    if (rc == TPM_RC_SUCCESS) // if unmarshalling succeeds
    {
        switch (*target)
        {
#ifdef TPM_ALG_MGF1
        case TPM_ALG_MGF1:
#endif // TPM_ALG_MGF1
#ifdef TPM_ALG_KDF1_SP800_56A
        case TPM_ALG_KDF1_SP800_56A:
#endif // TPM_ALG_KDF1_SP800_56A
#ifdef TPM_ALG_KDF2
        case TPM_ALG_KDF2:
#endif // TPM_ALG_KDF2
#ifdef TPM_ALG_KDF1_SP800_108
        case TPM_ALG_KDF1_SP800_108:
#endif // TPM_ALG_KDF1_SP800_108
            break;
        case TPM_ALG_NULL:
            if (!allowNull)
                rc = TPM_RC_KDF;
            break;
        default:
            rc = TPM_RC_KDF;
        }
    }
    return rc;
}

// TPMI_ALG_KDF_Marshal changed to #define

// Table 2:65 - Definition of (TPM_ALG_ID) TPMI_ALG_SIG_SCHEME Type (InterfaceTable)
TPM_RC
TPMI_ALG_SIG_SCHEME_Unmarshal(
    TPMI_ALG_SIG_SCHEME *target, BYTE **buffer, INT32 *size, BOOL allowNull)
{
    TPM_RC rc;
    rc = TPM_ALG_ID_Unmarshal((TPM_ALG_ID *)target, buffer, size);

    if (rc == TPM_RC_SUCCESS) // if unmarshalling succeeds
    {
        switch (*target)
        {
#ifdef TPM_ALG_RSASSA
        case TPM_ALG_RSASSA:
#endif // TPM_ALG_RSASSA
#ifdef TPM_ALG_RSAPSS
        case TPM_ALG_RSAPSS:
#endif // TPM_ALG_RSAPSS
#ifdef TPM_ALG_ECDSA
        case TPM_ALG_ECDSA:
#endif // TPM_ALG_ECDSA
#ifdef TPM_ALG_SM2
        case TPM_ALG_SM2:
#endif // TPM_ALG_SM2
#ifdef TPM_ALG_ECSCHNORR
        case TPM_ALG_ECSCHNORR:
#endif // TPM_ALG_ECSCHNORR
#ifdef TPM_ALG_ECDAA
        case TPM_ALG_ECDAA:
#endif // TPM_ALG_ECDAA
#ifdef TPM_ALG_HMAC
        case TPM_ALG_HMAC:
#endif // TPM_ALG_HMAC
            break;
        case TPM_ALG_NULL:
            if (allowNull)
                break;
        default:
            rc = TPM_RC_SCHEME;
        }
    }
    return rc;
}

// TPMI_ALG_SIG_SCHEME_Marshal changed to #define

// Table 2:66 - Definition of (TPM_ALG_ID){ECC} TPMI_ECC_KEY_EXCHANGE Type (InterfaceTable)
#ifdef TPM_ALG_ECC
TPM_RC
TPMI_ECC_KEY_EXCHANGE_Unmarshal(
    TPMI_ECC_KEY_EXCHANGE *target, BYTE **buffer, INT32 *size, BOOL allowNull)
{
    TPM_RC rc;
    rc = TPM_ALG_ID_Unmarshal((TPM_ALG_ID *)target, buffer, size);

    if (rc == TPM_RC_SUCCESS) // if unmarshalling succeeds
    {
        switch (*target)
        {
#ifdef TPM_ALG_ECDH
        case TPM_ALG_ECDH:
#endif // TPM_ALG_ECDH
#ifdef TPM_ALG_ECMQV
        case TPM_ALG_ECMQV:
#endif // TPM_ALG_ECMQV
#ifdef TPM_ALG_SM2
        case TPM_ALG_SM2:
#endif // TPM_ALG_SM2
            break;
        case TPM_ALG_NULL:
            if (allowNull)
                break;
        default:
            rc = TPM_RC_SCHEME;
        }
    }
    return rc;
}

// TPMI_ECC_KEY_EXCHANGE_Marshal changed to #define
#endif // TPM_ALG_ECC


// Table 2:67 - Definition of (TPM_ST) TPMI_ST_COMMAND_TAG Type (InterfaceTable)
TPM_RC
TPMI_ST_COMMAND_TAG_Unmarshal(
    TPMI_ST_COMMAND_TAG *target, BYTE **buffer, INT32 *size)
{
    TPM_RC rc;
    rc = TPM_ST_Unmarshal((TPM_ST *)target, buffer, size);

    if (rc == TPM_RC_SUCCESS) // if unmarshalling succeeds
    {
        switch (*target)
        {
        case TPM_ST_NO_SESSIONS:
        case TPM_ST_SESSIONS:

            break;

        default:
            rc = TPM_RC_BAD_TAG;
        }
    }
    return rc;
}

// TPMI_ST_COMMAND_TAG_Marshal changed to #define
TPM_RC
TPMS_EMPTY_Unmarshal(
    TPMS_EMPTY *target, BYTE **buffer, INT32 *size)
{
    // unreferenced parameters (see Part 4: Unreferenced Parameter)
    UNREFERENCED(target);
    UNREFERENCED(buffer);
    UNREFERENCED(size);
    return TPM_RC_SUCCESS;      // return success
}

UINT16
TPMS_EMPTY_Marshal(
    TPMS_EMPTY *source, BYTE **buffer, INT32 *size)
{
    // unreferenced parameters (see Part 4: Unreferenced Parameter)
    UNREFERENCED(source);
    UNREFERENCED(buffer);
    UNREFERENCED(size);
    return 0;                   // return zero
}


// Table 2:69 - Definition of TPMS_ALGORITHM_DESCRIPTION Structure (StructureTable)
// TPMS_ALGORITHM_DESCRIPTION_Unmarshal not required
UINT16
TPMS_ALGORITHM_DESCRIPTION_Marshal(
    TPMS_ALGORITHM_DESCRIPTION *source, BYTE **buffer, INT32 *size)
{
    UINT16 written = 0;
    written += TPM_ALG_ID_Marshal((TPM_ALG_ID*)&(source->alg), buffer, size );
    written += TPMA_ALGORITHM_Marshal((TPMA_ALGORITHM*)&(source->attributes), buffer, size );
    return written;
}


// Table 2:70 - Definition of TPMU_HA Union (UnionTable)
TPM_RC
TPMU_HA_Unmarshal(
    TPMU_HA *target, BYTE **buffer, INT32 *size, UINT32 selector)
{
    switch (selector)
    {
#ifdef TPM_ALG_SHA1
    case TPM_ALG_SHA1:
        return BYTE_Array_Unmarshal((BYTE*)(target->sha1), buffer, size , (INT32)SHA1_DIGEST_SIZE);
#endif // TPM_ALG_SHA1
#ifdef TPM_ALG_SHA256
    case TPM_ALG_SHA256:
        return BYTE_Array_Unmarshal((BYTE*)(target->sha256), buffer, size , (INT32)SHA256_DIGEST_SIZE);
#endif // TPM_ALG_SHA256
#ifdef TPM_ALG_SHA384
    case TPM_ALG_SHA384:
        return BYTE_Array_Unmarshal((BYTE*)(target->sha384), buffer, size , (INT32)SHA384_DIGEST_SIZE);
#endif // TPM_ALG_SHA384
#ifdef TPM_ALG_SHA512
    case TPM_ALG_SHA512:
        return BYTE_Array_Unmarshal((BYTE*)(target->sha512), buffer, size , (INT32)SHA512_DIGEST_SIZE);
#endif // TPM_ALG_SHA512
#ifdef TPM_ALG_SM3_256
    case TPM_ALG_SM3_256:
        return BYTE_Array_Unmarshal((BYTE*)(target->sm3_256), buffer, size , (INT32)SM3_256_DIGEST_SIZE);
#endif // TPM_ALG_SM3_256

    case TPM_ALG_NULL:
        return TPM_RC_SUCCESS;
    }
    return TPM_RC_SELECTOR;
}

UINT16
TPMU_HA_Marshal(
    TPMU_HA *source, BYTE **buffer, INT32 *size, UINT32 selector
)
{
    switch (selector)
    {
#ifdef TPM_ALG_SHA1
    case TPM_ALG_SHA1:
        return BYTE_Array_Marshal((BYTE*)(source->sha1), buffer, size , (INT32)SHA1_DIGEST_SIZE);
#endif // TPM_ALG_SHA1
#ifdef TPM_ALG_SHA256
    case TPM_ALG_SHA256:
        return BYTE_Array_Marshal((BYTE*)(source->sha256), buffer, size , (INT32)SHA256_DIGEST_SIZE);
#endif // TPM_ALG_SHA256
#ifdef TPM_ALG_SHA384
    case TPM_ALG_SHA384:
        return BYTE_Array_Marshal((BYTE*)(source->sha384), buffer, size , (INT32)SHA384_DIGEST_SIZE);
#endif // TPM_ALG_SHA384
#ifdef TPM_ALG_SHA512
    case TPM_ALG_SHA512:
        return BYTE_Array_Marshal((BYTE*)(source->sha512), buffer, size , (INT32)SHA512_DIGEST_SIZE);
#endif // TPM_ALG_SHA512
#ifdef TPM_ALG_SM3_256
    case TPM_ALG_SM3_256:
        return BYTE_Array_Marshal((BYTE*)(source->sm3_256), buffer, size , (INT32)SM3_256_DIGEST_SIZE);
#endif // TPM_ALG_SM3_256

    case TPM_ALG_NULL:
        return 0;
    }
    return 0;
}


// Table 2:71 - Definition of TPMT_HA Structure (StructureTable)
TPM_RC
TPMT_HA_Unmarshal(
    TPMT_HA *target, BYTE **buffer, INT32 *size, BOOL allowNull)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    if (rc == TPM_RC_SUCCESS)
    {
        rc = TPMI_ALG_HASH_Unmarshal((TPMI_ALG_HASH*)&target->hashAlg, buffer, size , allowNull);
    }
    if (rc == TPM_RC_SUCCESS)
    {
        rc = TPMU_HA_Unmarshal((TPMU_HA*)&target->digest, buffer, size , (UINT32)(target->hashAlg));
    }
    return rc;
}

UINT16
TPMT_HA_Marshal(
    TPMT_HA *source, BYTE **buffer, INT32 *size)
{
    UINT16 written = 0;
    written += TPMI_ALG_HASH_Marshal((TPMI_ALG_HASH*)&(source->hashAlg), buffer, size );
    written += TPMU_HA_Marshal((TPMU_HA*)&(source->digest), buffer, size , (UINT32)(source->hashAlg));
    return written;
}


// Table 2:72 - Definition of TPM2B_DIGEST Structure (StructureTable)
TPM_RC
TPM2B_DIGEST_Unmarshal(
    TPM2B_DIGEST *target, BYTE **buffer, INT32 *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    if (rc == TPM_RC_SUCCESS)
    {
        rc = UINT16_Unmarshal((UINT16*)&target->t.size, buffer, size );
    }
// if size is zero, then the structure is a zero buffer
    if(target->t.size == 0)
        return TPM_RC_SUCCESS;
    if((target->t.size) > sizeof(TPMU_HA))
        return TPM_RC_SIZE;
    if (rc == TPM_RC_SUCCESS)
    {
        rc = BYTE_Array_Unmarshal((BYTE*)target->t.buffer, buffer, size , (INT32)(target->t.size));
    }
    return rc;
}

UINT16
TPM2B_DIGEST_Marshal(
    TPM2B_DIGEST *source, BYTE **buffer, INT32 *size)
{
    UINT16 written = 0;
    written += UINT16_Marshal((UINT16*)&(source->t.size), buffer, size );
    if(source->t.size == 0)
        return written;

    written += BYTE_Array_Marshal((BYTE*)(source->t.buffer), buffer, size , (INT32)(source->t.size));
    return written;
}


// Table 2:73 - Definition of TPM2B_DATA Structure (StructureTable)
TPM_RC
TPM2B_DATA_Unmarshal(
    TPM2B_DATA *target, BYTE **buffer, INT32 *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    if (rc == TPM_RC_SUCCESS)
    {
        rc = UINT16_Unmarshal((UINT16*)&target->t.size, buffer, size );
    }
// if size is zero, then the structure is a zero buffer
    if(target->t.size == 0)
        return TPM_RC_SUCCESS;
    if((target->t.size) > sizeof(TPMT_HA))
        return TPM_RC_SIZE;
    if (rc == TPM_RC_SUCCESS)
    {
        rc = BYTE_Array_Unmarshal((BYTE*)target->t.buffer, buffer, size , (INT32)(target->t.size));
    }
    return rc;
}

UINT16
TPM2B_DATA_Marshal(
    TPM2B_DATA *source, BYTE **buffer, INT32 *size)
{
    UINT16 written = 0;
    written += UINT16_Marshal((UINT16*)&(source->t.size), buffer, size );
    if(source->t.size == 0)
        return written;

    written += BYTE_Array_Marshal((BYTE*)(source->t.buffer), buffer, size , (INT32)(source->t.size));
    return written;
}


// Table 2:74 - Definition of Types for TPM2B_NONCE (TypedefTable)
// TPM2B_DIGEST definition used from Table 2:72
// TPM2B_NONCE_Unmarshal changed to #define
// TPM2B_NONCE_Marshal changed to #define


// Table 2:75 - Definition of Types for TPM2B_AUTH (TypedefTable)
// TPM2B_DIGEST definition used from Table 2:72
// TPM2B_AUTH_Unmarshal changed to #define
// TPM2B_AUTH_Marshal changed to #define


// Table 2:76 - Definition of Types for TPM2B_OPERAND (TypedefTable)
// TPM2B_DIGEST definition used from Table 2:72
// TPM2B_OPERAND_Unmarshal changed to #define
// TPM2B_OPERAND_Marshal changed to #define


// Table 2:77 - Definition of TPM2B_EVENT Structure (StructureTable)
TPM_RC
TPM2B_EVENT_Unmarshal(
    TPM2B_EVENT *target, BYTE **buffer, INT32 *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    if (rc == TPM_RC_SUCCESS)
    {
        rc = UINT16_Unmarshal((UINT16*)&target->t.size, buffer, size );
    }
// if size is zero, then the structure is a zero buffer
    if(target->t.size == 0)
        return TPM_RC_SUCCESS;
    if((target->t.size) > 1024)
        return TPM_RC_SIZE;
    if (rc == TPM_RC_SUCCESS)
    {
        rc = BYTE_Array_Unmarshal((BYTE*)target->t.buffer, buffer, size , (INT32)(target->t.size));
    }
    return rc;
}

UINT16
TPM2B_EVENT_Marshal(
    TPM2B_EVENT *source, BYTE **buffer, INT32 *size)
{
    UINT16 written = 0;
    written += UINT16_Marshal((UINT16*)&(source->t.size), buffer, size );
    if(source->t.size == 0)
        return written;

    written += BYTE_Array_Marshal((BYTE*)(source->t.buffer), buffer, size , (INT32)(source->t.size));
    return written;
}


// Table 2:78 - Definition of TPM2B_MAX_BUFFER Structure (StructureTable)
TPM_RC
TPM2B_MAX_BUFFER_Unmarshal(
    TPM2B_MAX_BUFFER *target, BYTE **buffer, INT32 *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    if (rc == TPM_RC_SUCCESS)
    {
        rc = UINT16_Unmarshal((UINT16*)&target->t.size, buffer, size );
    }
// if size is zero, then the structure is a zero buffer
    if(target->t.size == 0)
        return TPM_RC_SUCCESS;
    if((target->t.size) > MAX_DIGEST_BUFFER)
        return TPM_RC_SIZE;
    if (rc == TPM_RC_SUCCESS)
    {
        rc = BYTE_Array_Unmarshal((BYTE*)target->t.buffer, buffer, size , (INT32)(target->t.size));
    }
    return rc;
}

UINT16
TPM2B_MAX_BUFFER_Marshal(
    TPM2B_MAX_BUFFER *source, BYTE **buffer, INT32 *size)
{
    UINT16 written = 0;
    written += UINT16_Marshal((UINT16*)&(source->t.size), buffer, size );
    if(source->t.size == 0)
        return written;

    written += BYTE_Array_Marshal((BYTE*)(source->t.buffer), buffer, size , (INT32)(source->t.size));
    return written;
}


// Table 2:79 - Definition of TPM2B_MAX_NV_BUFFER Structure (StructureTable)
TPM_RC
TPM2B_MAX_NV_BUFFER_Unmarshal(
    TPM2B_MAX_NV_BUFFER *target, BYTE **buffer, INT32 *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    if (rc == TPM_RC_SUCCESS)
    {
        rc = UINT16_Unmarshal((UINT16*)&target->t.size, buffer, size );
    }
// if size is zero, then the structure is a zero buffer
    if(target->t.size == 0)
        return TPM_RC_SUCCESS;
    if((target->t.size) > MAX_NV_BUFFER_SIZE)
        return TPM_RC_SIZE;
    if (rc == TPM_RC_SUCCESS)
    {
        rc = BYTE_Array_Unmarshal((BYTE*)target->t.buffer, buffer, size , (INT32)(target->t.size));
    }
    return rc;
}

UINT16
TPM2B_MAX_NV_BUFFER_Marshal(
    TPM2B_MAX_NV_BUFFER *source, BYTE **buffer, INT32 *size)
{
    UINT16 written = 0;
    written += UINT16_Marshal((UINT16*)&(source->t.size), buffer, size );
    if(source->t.size == 0)
        return written;

    written += BYTE_Array_Marshal((BYTE*)(source->t.buffer), buffer, size , (INT32)(source->t.size));
    return written;
}


// Table 2:80 - Definition of TPM2B_TIMEOUT Structure (StructureTable)
TPM_RC
TPM2B_TIMEOUT_Unmarshal(
    TPM2B_TIMEOUT *target, BYTE **buffer, INT32 *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    if (rc == TPM_RC_SUCCESS)
    {
        rc = UINT16_Unmarshal((UINT16*)&target->t.size, buffer, size );
    }
// if size is zero, then the structure is a zero buffer
    if(target->t.size == 0)
        return TPM_RC_SUCCESS;
    if((target->t.size) > sizeof(UINT64))
        return TPM_RC_SIZE;
    if (rc == TPM_RC_SUCCESS)
    {
        rc = BYTE_Array_Unmarshal((BYTE*)target->t.buffer, buffer, size , (INT32)(target->t.size));
    }
    return rc;
}

UINT16
TPM2B_TIMEOUT_Marshal(
    TPM2B_TIMEOUT *source, BYTE **buffer, INT32 *size)
{
    UINT16 written = 0;
    written += UINT16_Marshal((UINT16*)&(source->t.size), buffer, size );
    if(source->t.size == 0)
        return written;

    written += BYTE_Array_Marshal((BYTE*)(source->t.buffer), buffer, size , (INT32)(source->t.size));
    return written;
}


// Table 2:81 - Definition of TPM2B_IV Structure (StructureTable)
TPM_RC
TPM2B_IV_Unmarshal(
    TPM2B_IV *target, BYTE **buffer, INT32 *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    if (rc == TPM_RC_SUCCESS)
    {
        rc = UINT16_Unmarshal((UINT16*)&target->t.size, buffer, size );
    }
// if size is zero, then the structure is a zero buffer
    if(target->t.size == 0)
        return TPM_RC_SUCCESS;
    if((target->t.size) > MAX_SYM_BLOCK_SIZE)
        return TPM_RC_SIZE;
    if (rc == TPM_RC_SUCCESS)
    {
        rc = BYTE_Array_Unmarshal((BYTE*)target->t.buffer, buffer, size , (INT32)(target->t.size));
    }
    return rc;
}

UINT16
TPM2B_IV_Marshal(
    TPM2B_IV *source, BYTE **buffer, INT32 *size)
{
    UINT16 written = 0;
    written += UINT16_Marshal((UINT16*)&(source->t.size), buffer, size );
    if(source->t.size == 0)
        return written;

    written += BYTE_Array_Marshal((BYTE*)(source->t.buffer), buffer, size , (INT32)(source->t.size));
    return written;
}


// Table 2:82 - Definition of TPMU_NAME Union (UnionTable)
// TPMU_NAME_Unmarshal not required
// TPMU_NAME_Marshal not required

// Table 2:83 - Definition of TPM2B_NAME Structure (StructureTable)
TPM_RC
TPM2B_NAME_Unmarshal(
    TPM2B_NAME *target, BYTE **buffer, INT32 *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    if (rc == TPM_RC_SUCCESS)
    {
        rc = UINT16_Unmarshal((UINT16*)&target->t.size, buffer, size );
    }
// if size is zero, then the structure is a zero buffer
    if(target->t.size == 0)
        return TPM_RC_SUCCESS;
    if((target->t.size) > sizeof(TPMU_NAME))
        return TPM_RC_SIZE;
    if (rc == TPM_RC_SUCCESS)
    {
        rc = BYTE_Array_Unmarshal((BYTE*)target->t.name, buffer, size , (INT32)(target->t.size));
    }
    return rc;
}

UINT16
TPM2B_NAME_Marshal(
    TPM2B_NAME *source, BYTE **buffer, INT32 *size)
{
    UINT16 written = 0;
    written += UINT16_Marshal((UINT16*)&(source->t.size), buffer, size );
    if(source->t.size == 0)
        return written;

    written += BYTE_Array_Marshal((BYTE*)(source->t.name), buffer, size , (INT32)(source->t.size));
    return written;
}


// Table 2:84 - Definition of TPMS_PCR_SELECT Structure (StructureTable)
TPM_RC
TPMS_PCR_SELECT_Unmarshal(
    TPMS_PCR_SELECT *target, BYTE **buffer, INT32 *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    if (rc == TPM_RC_SUCCESS)
    {
        rc = UINT8_Unmarshal((UINT8*)&target->sizeofSelect, buffer, size );
    }
    if((target->sizeofSelect) < PCR_SELECT_MIN)
        return TPM_RC_VALUE;
    if((target->sizeofSelect) > PCR_SELECT_MAX)
        return TPM_RC_VALUE;
    if (rc == TPM_RC_SUCCESS)
    {
        rc = BYTE_Array_Unmarshal((BYTE*)target->pcrSelect, buffer, size , (INT32)(target->sizeofSelect));
    }
    return rc;
}

UINT16
TPMS_PCR_SELECT_Marshal(
    TPMS_PCR_SELECT *source, BYTE **buffer, INT32 *size)
{
    UINT16 written = 0;
    written += UINT8_Marshal((UINT8*)&(source->sizeofSelect), buffer, size );
    written += BYTE_Array_Marshal((BYTE*)(source->pcrSelect), buffer, size , (INT32)(source->sizeofSelect));
    return written;
}


// Table 2:85 - Definition of TPMS_PCR_SELECTION Structure (StructureTable)
TPM_RC
TPMS_PCR_SELECTION_Unmarshal(
    TPMS_PCR_SELECTION *target, BYTE **buffer, INT32 *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    if (rc == TPM_RC_SUCCESS)
    {
        rc = TPMI_ALG_HASH_Unmarshal((TPMI_ALG_HASH*)&target->hash, buffer, size , 0);
    }
    if (rc == TPM_RC_SUCCESS)
    {
        rc = UINT8_Unmarshal((UINT8*)&target->sizeofSelect, buffer, size );
    }
    if((target->sizeofSelect) < PCR_SELECT_MIN)
        return TPM_RC_VALUE;
    if((target->sizeofSelect) > PCR_SELECT_MAX)
        return TPM_RC_VALUE;
    if (rc == TPM_RC_SUCCESS)
    {
        rc = BYTE_Array_Unmarshal((BYTE*)target->pcrSelect, buffer, size , (INT32)(target->sizeofSelect));
    }
    return rc;
}

UINT16
TPMS_PCR_SELECTION_Marshal(
    TPMS_PCR_SELECTION *source, BYTE **buffer, INT32 *size)
{
    UINT16 written = 0;
    written += TPMI_ALG_HASH_Marshal((TPMI_ALG_HASH*)&(source->hash), buffer, size );
    written += UINT8_Marshal((UINT8*)&(source->sizeofSelect), buffer, size );
    written += BYTE_Array_Marshal((BYTE*)(source->pcrSelect), buffer, size , (INT32)(source->sizeofSelect));
    return written;
}


// Table 2:88 - Definition of TPMT_TK_CREATION Structure (StructureTable)
TPM_RC
TPMT_TK_CREATION_Unmarshal(
    TPMT_TK_CREATION *target, BYTE **buffer, INT32 *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    if (rc == TPM_RC_SUCCESS)
    {
        rc = TPM_ST_Unmarshal((TPM_ST*)&target->tag, buffer, size );
    }
    if( ((target->tag) != TPM_ST_CREATION))
        return TPM_RC_TAG;
    if (rc == TPM_RC_SUCCESS)
    {
        rc = TPMI_RH_HIERARCHY_Unmarshal((TPMI_RH_HIERARCHY*)&target->hierarchy, buffer, size , 1);
    }
    if (rc == TPM_RC_SUCCESS)
    {
        rc = TPM2B_DIGEST_Unmarshal((TPM2B_DIGEST*)&target->digest, buffer, size );
    }
    return rc;
}

UINT16
TPMT_TK_CREATION_Marshal(
    TPMT_TK_CREATION *source, BYTE **buffer, INT32 *size)
{
    UINT16 written = 0;
    written += TPM_ST_Marshal((TPM_ST*)&(source->tag), buffer, size );
    written += TPMI_RH_HIERARCHY_Marshal((TPMI_RH_HIERARCHY*)&(source->hierarchy), buffer, size );
    written += TPM2B_DIGEST_Marshal((TPM2B_DIGEST*)&(source->digest), buffer, size );
    return written;
}


// Table 2:89 - Definition of TPMT_TK_VERIFIED Structure (StructureTable)
TPM_RC
TPMT_TK_VERIFIED_Unmarshal(
    TPMT_TK_VERIFIED *target, BYTE **buffer, INT32 *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    if (rc == TPM_RC_SUCCESS)
    {
        rc = TPM_ST_Unmarshal((TPM_ST*)&target->tag, buffer, size );
    }
    if( ((target->tag) != TPM_ST_VERIFIED))
        return TPM_RC_TAG;
    if (rc == TPM_RC_SUCCESS)
    {
        rc = TPMI_RH_HIERARCHY_Unmarshal((TPMI_RH_HIERARCHY*)&target->hierarchy, buffer, size , 1);
    }
    if (rc == TPM_RC_SUCCESS)
    {
        rc = TPM2B_DIGEST_Unmarshal((TPM2B_DIGEST*)&target->digest, buffer, size );
    }
    return rc;
}

UINT16
TPMT_TK_VERIFIED_Marshal(
    TPMT_TK_VERIFIED *source, BYTE **buffer, INT32 *size)
{
    UINT16 written = 0;
    written += TPM_ST_Marshal((TPM_ST*)&(source->tag), buffer, size );
    written += TPMI_RH_HIERARCHY_Marshal((TPMI_RH_HIERARCHY*)&(source->hierarchy), buffer, size );
    written += TPM2B_DIGEST_Marshal((TPM2B_DIGEST*)&(source->digest), buffer, size );
    return written;
}


// Table 2:90 - Definition of TPMT_TK_AUTH Structure (StructureTable)
TPM_RC
TPMT_TK_AUTH_Unmarshal(
    TPMT_TK_AUTH *target, BYTE **buffer, INT32 *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    if (rc == TPM_RC_SUCCESS)
    {
        rc = TPM_ST_Unmarshal((TPM_ST*)&target->tag, buffer, size );
    }
    if( ((target->tag) != TPM_ST_AUTH_SIGNED)
            && ((target->tag) != TPM_ST_AUTH_SECRET))
        return TPM_RC_TAG;
    if (rc == TPM_RC_SUCCESS)
    {
        rc = TPMI_RH_HIERARCHY_Unmarshal((TPMI_RH_HIERARCHY*)&target->hierarchy, buffer, size , 1);
    }
    if (rc == TPM_RC_SUCCESS)
    {
        rc = TPM2B_DIGEST_Unmarshal((TPM2B_DIGEST*)&target->digest, buffer, size );
    }
    return rc;
}

UINT16
TPMT_TK_AUTH_Marshal(
    TPMT_TK_AUTH *source, BYTE **buffer, INT32 *size)
{
    UINT16 written = 0;
    written += TPM_ST_Marshal((TPM_ST*)&(source->tag), buffer, size );
    written += TPMI_RH_HIERARCHY_Marshal((TPMI_RH_HIERARCHY*)&(source->hierarchy), buffer, size );
    written += TPM2B_DIGEST_Marshal((TPM2B_DIGEST*)&(source->digest), buffer, size );
    return written;
}


// Table 2:91 - Definition of TPMT_TK_HASHCHECK Structure (StructureTable)
TPM_RC
TPMT_TK_HASHCHECK_Unmarshal(
    TPMT_TK_HASHCHECK *target, BYTE **buffer, INT32 *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    if (rc == TPM_RC_SUCCESS)
    {
        rc = TPM_ST_Unmarshal((TPM_ST*)&target->tag, buffer, size );
    }
    if( ((target->tag) != TPM_ST_HASHCHECK))
        return TPM_RC_TAG;
    if (rc == TPM_RC_SUCCESS)
    {
        rc = TPMI_RH_HIERARCHY_Unmarshal((TPMI_RH_HIERARCHY*)&target->hierarchy, buffer, size , 1);
    }
    if (rc == TPM_RC_SUCCESS)
    {
        rc = TPM2B_DIGEST_Unmarshal((TPM2B_DIGEST*)&target->digest, buffer, size );
    }
    return rc;
}

UINT16
TPMT_TK_HASHCHECK_Marshal(
    TPMT_TK_HASHCHECK *source, BYTE **buffer, INT32 *size)
{
    UINT16 written = 0;
    written += TPM_ST_Marshal((TPM_ST*)&(source->tag), buffer, size );
    written += TPMI_RH_HIERARCHY_Marshal((TPMI_RH_HIERARCHY*)&(source->hierarchy), buffer, size );
    written += TPM2B_DIGEST_Marshal((TPM2B_DIGEST*)&(source->digest), buffer, size );
    return written;
}


// Table 2:92 - Definition of TPMS_ALG_PROPERTY Structure (StructureTable)
// TPMS_ALG_PROPERTY_Unmarshal not required
UINT16
TPMS_ALG_PROPERTY_Marshal(
    TPMS_ALG_PROPERTY *source, BYTE **buffer, INT32 *size)
{
    UINT16 written = 0;
    written += TPM_ALG_ID_Marshal((TPM_ALG_ID*)&(source->alg), buffer, size );
    written += TPMA_ALGORITHM_Marshal((TPMA_ALGORITHM*)&(source->algProperties), buffer, size );
    return written;
}


// Table 2:93 - Definition of TPMS_TAGGED_PROPERTY Structure (StructureTable)
// TPMS_TAGGED_PROPERTY_Unmarshal not required
UINT16
TPMS_TAGGED_PROPERTY_Marshal(
    TPMS_TAGGED_PROPERTY *source, BYTE **buffer, INT32 *size)
{
    UINT16 written = 0;
    written += TPM_PT_Marshal((TPM_PT*)&(source->property), buffer, size );
    written += UINT32_Marshal((UINT32*)&(source->value), buffer, size );
    return written;
}


// Table 2:94 - Definition of TPMS_TAGGED_PCR_SELECT Structure (StructureTable)
// TPMS_TAGGED_PCR_SELECT_Unmarshal not required
UINT16
TPMS_TAGGED_PCR_SELECT_Marshal(
    TPMS_TAGGED_PCR_SELECT *source, BYTE **buffer, INT32 *size)
{
    UINT16 written = 0;
    written += TPM_PT_Marshal((TPM_PT*)&(source->tag), buffer, size );
    written += UINT8_Marshal((UINT8*)&(source->sizeofSelect), buffer, size );
    written += BYTE_Array_Marshal((BYTE*)(source->pcrSelect), buffer, size , (INT32)(source->sizeofSelect));
    return written;
}


// Table 2:95 - Definition of TPML_CC Structure (StructureTable)
TPM_RC
TPML_CC_Unmarshal(
    TPML_CC *target, BYTE **buffer, INT32 *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    if (rc == TPM_RC_SUCCESS)
    {
        rc = UINT32_Unmarshal((UINT32*)&target->count, buffer, size );
    }
    if((target->count) > MAX_CAP_CC)
        return TPM_RC_SIZE;
    if (rc == TPM_RC_SUCCESS)
    {
        rc = TPM_CC_Array_Unmarshal((TPM_CC*)target->commandCodes, buffer, size , (INT32)(target->count));
    }
    return rc;
}

UINT16
TPML_CC_Marshal(
    TPML_CC *source, BYTE **buffer, INT32 *size)
{
    UINT16 written = 0;
    written += UINT32_Marshal((UINT32*)&(source->count), buffer, size );
    written += TPM_CC_Array_Marshal((TPM_CC*)(source->commandCodes), buffer, size , (INT32)(source->count));
    return written;
}


// Table 2:96 - Definition of TPML_CCA Structure (StructureTable)
// TPML_CCA_Unmarshal not required
UINT16
TPML_CCA_Marshal(
    TPML_CCA *source, BYTE **buffer, INT32 *size)
{
    UINT16 written = 0;
    written += UINT32_Marshal((UINT32*)&(source->count), buffer, size );
    written += TPMA_CC_Array_Marshal((TPMA_CC*)(source->commandAttributes), buffer, size , (INT32)(source->count));
    return written;
}


// Table 2:97 - Definition of TPML_ALG Structure (StructureTable)
TPM_RC
TPML_ALG_Unmarshal(
    TPML_ALG *target, BYTE **buffer, INT32 *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    if (rc == TPM_RC_SUCCESS)
    {
        rc = UINT32_Unmarshal((UINT32*)&target->count, buffer, size );
    }
    if((target->count) > MAX_ALG_LIST_SIZE)
        return TPM_RC_SIZE;
    if (rc == TPM_RC_SUCCESS)
    {
        rc = TPM_ALG_ID_Array_Unmarshal((TPM_ALG_ID*)target->algorithms, buffer, size , (INT32)(target->count));
    }
    return rc;
}

UINT16
TPML_ALG_Marshal(
    TPML_ALG *source, BYTE **buffer, INT32 *size)
{
    UINT16 written = 0;
    written += UINT32_Marshal((UINT32*)&(source->count), buffer, size );
    written += TPM_ALG_ID_Array_Marshal((TPM_ALG_ID*)(source->algorithms), buffer, size , (INT32)(source->count));
    return written;
}


// Table 2:98 - Definition of TPML_HANDLE Structure (StructureTable)
// TPML_HANDLE_Unmarshal not required
UINT16
TPML_HANDLE_Marshal(
    TPML_HANDLE *source, BYTE **buffer, INT32 *size)
{
    UINT16 written = 0;
    written += UINT32_Marshal((UINT32*)&(source->count), buffer, size );
    written += TPM_HANDLE_Array_Marshal((TPM_HANDLE*)(source->handle), buffer, size , (INT32)(source->count));
    return written;
}


// Table 2:99 - Definition of TPML_DIGEST Structure (StructureTable)
TPM_RC
TPML_DIGEST_Unmarshal(
    TPML_DIGEST *target, BYTE **buffer, INT32 *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    if (rc == TPM_RC_SUCCESS)
    {
        rc = UINT32_Unmarshal((UINT32*)&target->count, buffer, size );
    }
    if((target->count) < 2)
        return TPM_RC_SIZE;
    if((target->count) > 8)
        return TPM_RC_SIZE;
    if (rc == TPM_RC_SUCCESS)
    {
        rc = TPM2B_DIGEST_Array_Unmarshal((TPM2B_DIGEST*)target->digests, buffer, size , (INT32)(target->count));
    }
    return rc;
}

UINT16
TPML_DIGEST_Marshal(
    TPML_DIGEST *source, BYTE **buffer, INT32 *size)
{
    UINT16 written = 0;
    written += UINT32_Marshal((UINT32*)&(source->count), buffer, size );
    written += TPM2B_DIGEST_Array_Marshal((TPM2B_DIGEST*)(source->digests), buffer, size , (INT32)(source->count));
    return written;
}


// Table 2:100 - Definition of TPML_DIGEST_VALUES Structure (StructureTable)
TPM_RC
TPML_DIGEST_VALUES_Unmarshal(
    TPML_DIGEST_VALUES *target, BYTE **buffer, INT32 *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    if (rc == TPM_RC_SUCCESS)
    {
        rc = UINT32_Unmarshal((UINT32*)&target->count, buffer, size );
    }
    if((target->count) > HASH_COUNT)
        return TPM_RC_SIZE;
    if (rc == TPM_RC_SUCCESS)
    {
        rc = TPMT_HA_Array_Unmarshal((TPMT_HA*)target->digests, buffer, size , 0, (INT32)(target->count));
    }
    return rc;
}

UINT16
TPML_DIGEST_VALUES_Marshal(
    TPML_DIGEST_VALUES *source, BYTE **buffer, INT32 *size)
{
    UINT16 written = 0;
    written += UINT32_Marshal((UINT32*)&(source->count), buffer, size );
    written += TPMT_HA_Array_Marshal((TPMT_HA*)(source->digests), buffer, size , (INT32)(source->count));
    return written;
}


// Table 2:101 - Definition of TPM2B_DIGEST_VALUES Structure (StructureTable)
TPM_RC
TPM2B_DIGEST_VALUES_Unmarshal(
    TPM2B_DIGEST_VALUES *target, BYTE **buffer, INT32 *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    if (rc == TPM_RC_SUCCESS)
    {
        rc = UINT16_Unmarshal((UINT16*)&target->t.size, buffer, size );
    }
// if size is zero, then the structure is a zero buffer
    if(target->t.size == 0)
        return TPM_RC_SUCCESS;
    if((target->t.size) > sizeof(TPML_DIGEST_VALUES))
        return TPM_RC_SIZE;
    if (rc == TPM_RC_SUCCESS)
    {
        rc = BYTE_Array_Unmarshal((BYTE*)target->t.buffer, buffer, size , (INT32)(target->t.size));
    }
    return rc;
}

UINT16
TPM2B_DIGEST_VALUES_Marshal(
    TPM2B_DIGEST_VALUES *source, BYTE **buffer, INT32 *size)
{
    UINT16 written = 0;
    written += UINT16_Marshal((UINT16*)&(source->t.size), buffer, size );
    if(source->t.size == 0)
        return written;

    written += BYTE_Array_Marshal((BYTE*)(source->t.buffer), buffer, size , (INT32)(source->t.size));
    return written;
}


// Table 2:102 - Definition of TPML_PCR_SELECTION Structure (StructureTable)
TPM_RC
TPML_PCR_SELECTION_Unmarshal(
    TPML_PCR_SELECTION *target, BYTE **buffer, INT32 *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    if (rc == TPM_RC_SUCCESS)
    {
        rc = UINT32_Unmarshal((UINT32*)&target->count, buffer, size );
    }
    if((target->count) > HASH_COUNT)
        return TPM_RC_SIZE;
    if (rc == TPM_RC_SUCCESS)
    {
        rc = TPMS_PCR_SELECTION_Array_Unmarshal((TPMS_PCR_SELECTION*)target->pcrSelections, buffer, size , (INT32)(target->count));
    }
    return rc;
}

UINT16
TPML_PCR_SELECTION_Marshal(
    TPML_PCR_SELECTION *source, BYTE **buffer, INT32 *size)
{
    UINT16 written = 0;
    written += UINT32_Marshal((UINT32*)&(source->count), buffer, size );
    written += TPMS_PCR_SELECTION_Array_Marshal((TPMS_PCR_SELECTION*)(source->pcrSelections), buffer, size , (INT32)(source->count));
    return written;
}


// Table 2:103 - Definition of TPML_ALG_PROPERTY Structure (StructureTable)
// TPML_ALG_PROPERTY_Unmarshal not required
UINT16
TPML_ALG_PROPERTY_Marshal(
    TPML_ALG_PROPERTY *source, BYTE **buffer, INT32 *size)
{
    UINT16 written = 0;
    written += UINT32_Marshal((UINT32*)&(source->count), buffer, size );
    written += TPMS_ALG_PROPERTY_Array_Marshal((TPMS_ALG_PROPERTY*)(source->algProperties), buffer, size , (INT32)(source->count));
    return written;
}


// Table 2:104 - Definition of TPML_TAGGED_TPM_PROPERTY Structure (StructureTable)
// TPML_TAGGED_TPM_PROPERTY_Unmarshal not required
UINT16
TPML_TAGGED_TPM_PROPERTY_Marshal(
    TPML_TAGGED_TPM_PROPERTY *source, BYTE **buffer, INT32 *size)
{
    UINT16 written = 0;
    written += UINT32_Marshal((UINT32*)&(source->count), buffer, size );
    written += TPMS_TAGGED_PROPERTY_Array_Marshal((TPMS_TAGGED_PROPERTY*)(source->tpmProperty), buffer, size , (INT32)(source->count));
    return written;
}


// Table 2:105 - Definition of TPML_TAGGED_PCR_PROPERTY Structure (StructureTable)
// TPML_TAGGED_PCR_PROPERTY_Unmarshal not required
UINT16
TPML_TAGGED_PCR_PROPERTY_Marshal(
    TPML_TAGGED_PCR_PROPERTY *source, BYTE **buffer, INT32 *size)
{
    UINT16 written = 0;
    written += UINT32_Marshal((UINT32*)&(source->count), buffer, size );
    written += TPMS_TAGGED_PCR_SELECT_Array_Marshal((TPMS_TAGGED_PCR_SELECT*)(source->pcrProperty), buffer, size , (INT32)(source->count));
    return written;
}


// Table 2:106 - Definition of {ECC} TPML_ECC_CURVE Structure (StructureTable)
#ifdef TPM_ALG_ECC
// TPML_ECC_CURVE_Unmarshal not required
UINT16
TPML_ECC_CURVE_Marshal(
    TPML_ECC_CURVE *source, BYTE **buffer, INT32 *size)
{
    UINT16 written = 0;
    written += UINT32_Marshal((UINT32*)&(source->count), buffer, size );
    written += TPM_ECC_CURVE_Array_Marshal((TPM_ECC_CURVE*)(source->eccCurves), buffer, size , (INT32)(source->count));
    return written;
}

#endif // TPM_ALG_ECC


// Table 2:107 - Definition of TPMU_CAPABILITIES Union (UnionTable)
// TPMU_CAPABILITIES_Unmarshal not required
UINT16
TPMU_CAPABILITIES_Marshal(
    TPMU_CAPABILITIES *source, BYTE **buffer, INT32 *size, UINT32 selector
)
{
    switch (selector)
    {

    case TPM_CAP_ALGS:
        return TPML_ALG_PROPERTY_Marshal((TPML_ALG_PROPERTY*)&(source->algorithms), buffer, size );
    case TPM_CAP_HANDLES:
        return TPML_HANDLE_Marshal((TPML_HANDLE*)&(source->handles), buffer, size );
    case TPM_CAP_COMMANDS:
        return TPML_CCA_Marshal((TPML_CCA*)&(source->command), buffer, size );
    case TPM_CAP_PP_COMMANDS:
        return TPML_CC_Marshal((TPML_CC*)&(source->ppCommands), buffer, size );
    case TPM_CAP_AUDIT_COMMANDS:
        return TPML_CC_Marshal((TPML_CC*)&(source->auditCommands), buffer, size );
    case TPM_CAP_PCRS:
        return TPML_PCR_SELECTION_Marshal((TPML_PCR_SELECTION*)&(source->assignedPCR), buffer, size );
    case TPM_CAP_TPM_PROPERTIES:
        return TPML_TAGGED_TPM_PROPERTY_Marshal((TPML_TAGGED_TPM_PROPERTY*)&(source->tpmProperties), buffer, size );
    case TPM_CAP_PCR_PROPERTIES:
        return TPML_TAGGED_PCR_PROPERTY_Marshal((TPML_TAGGED_PCR_PROPERTY*)&(source->pcrProperties), buffer, size );
#ifdef TPM_ALG_ECC
    case TPM_CAP_ECC_CURVES:
        return TPML_ECC_CURVE_Marshal((TPML_ECC_CURVE*)&(source->eccCurves), buffer, size );
#endif // TPM_ALG_ECC
    }
    return 0;
}


// Table 2:108 - Definition of TPMS_CAPABILITY_DATA Structure (StructureTable)
// TPMS_CAPABILITY_DATA_Unmarshal not required
UINT16
TPMS_CAPABILITY_DATA_Marshal(
    TPMS_CAPABILITY_DATA *source, BYTE **buffer, INT32 *size)
{
    UINT16 written = 0;
    written += TPM_CAP_Marshal((TPM_CAP*)&(source->capability), buffer, size );
    written += TPMU_CAPABILITIES_Marshal((TPMU_CAPABILITIES*)&(source->data), buffer, size , (UINT32)(source->capability));
    return written;
}


// Table 2:109 - Definition of TPMS_CLOCK_INFO Structure (StructureTable)
TPM_RC
TPMS_CLOCK_INFO_Unmarshal(
    TPMS_CLOCK_INFO *target, BYTE **buffer, INT32 *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    if (rc == TPM_RC_SUCCESS)
    {
        rc = UINT64_Unmarshal((UINT64*)&target->clock, buffer, size );
    }
    if (rc == TPM_RC_SUCCESS)
    {
        rc = UINT32_Unmarshal((UINT32*)&target->resetCount, buffer, size );
    }
    if (rc == TPM_RC_SUCCESS)
    {
        rc = UINT32_Unmarshal((UINT32*)&target->restartCount, buffer, size );
    }
    if (rc == TPM_RC_SUCCESS)
    {
        rc = TPMI_YES_NO_Unmarshal((TPMI_YES_NO*)&target->safe, buffer, size );
    }
    return rc;
}

UINT16
TPMS_CLOCK_INFO_Marshal(
    TPMS_CLOCK_INFO *source, BYTE **buffer, INT32 *size)
{
    UINT16 written = 0;
    written += UINT64_Marshal((UINT64*)&(source->clock), buffer, size );
    written += UINT32_Marshal((UINT32*)&(source->resetCount), buffer, size );
    written += UINT32_Marshal((UINT32*)&(source->restartCount), buffer, size );
    written += TPMI_YES_NO_Marshal((TPMI_YES_NO*)&(source->safe), buffer, size );
    return written;
}


// Table 2:110 - Definition of TPMS_TIME_INFO Structure (StructureTable)
TPM_RC
TPMS_TIME_INFO_Unmarshal(
    TPMS_TIME_INFO *target, BYTE **buffer, INT32 *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    if (rc == TPM_RC_SUCCESS)
    {
        rc = UINT64_Unmarshal((UINT64*)&target->time, buffer, size );
    }
    if (rc == TPM_RC_SUCCESS)
    {
        rc = TPMS_CLOCK_INFO_Unmarshal((TPMS_CLOCK_INFO*)&target->clockInfo, buffer, size );
    }
    return rc;
}

UINT16
TPMS_TIME_INFO_Marshal(
    TPMS_TIME_INFO *source, BYTE **buffer, INT32 *size)
{
    UINT16 written = 0;
    written += UINT64_Marshal((UINT64*)&(source->time), buffer, size );
    written += TPMS_CLOCK_INFO_Marshal((TPMS_CLOCK_INFO*)&(source->clockInfo), buffer, size );
    return written;
}


// Table 2:111 - Definition of TPMS_TIME_ATTEST_INFO Structure (StructureTable)
// TPMS_TIME_ATTEST_INFO_Unmarshal not required
UINT16
TPMS_TIME_ATTEST_INFO_Marshal(
    TPMS_TIME_ATTEST_INFO *source, BYTE **buffer, INT32 *size)
{
    UINT16 written = 0;
    written += TPMS_TIME_INFO_Marshal((TPMS_TIME_INFO*)&(source->time), buffer, size );
    written += UINT64_Marshal((UINT64*)&(source->firmwareVersion), buffer, size );
    return written;
}


// Table 2:112 - Definition of TPMS_CERTIFY_INFO Structure (StructureTable)
// TPMS_CERTIFY_INFO_Unmarshal not required
UINT16
TPMS_CERTIFY_INFO_Marshal(
    TPMS_CERTIFY_INFO *source, BYTE **buffer, INT32 *size)
{
    UINT16 written = 0;
    written += TPM2B_NAME_Marshal((TPM2B_NAME*)&(source->name), buffer, size );
    written += TPM2B_NAME_Marshal((TPM2B_NAME*)&(source->qualifiedName), buffer, size );
    return written;
}


// Table 2:113 - Definition of TPMS_QUOTE_INFO Structure (StructureTable)
// TPMS_QUOTE_INFO_Unmarshal not required
UINT16
TPMS_QUOTE_INFO_Marshal(
    TPMS_QUOTE_INFO *source, BYTE **buffer, INT32 *size)
{
    UINT16 written = 0;
    written += TPML_PCR_SELECTION_Marshal((TPML_PCR_SELECTION*)&(source->pcrSelect), buffer, size );
    written += TPM2B_DIGEST_Marshal((TPM2B_DIGEST*)&(source->pcrDigest), buffer, size );
    return written;
}


// Table 2:114 - Definition of TPMS_COMMAND_AUDIT_INFO Structure (StructureTable)
// TPMS_COMMAND_AUDIT_INFO_Unmarshal not required
UINT16
TPMS_COMMAND_AUDIT_INFO_Marshal(
    TPMS_COMMAND_AUDIT_INFO *source, BYTE **buffer, INT32 *size)
{
    UINT16 written = 0;
    written += UINT64_Marshal((UINT64*)&(source->auditCounter), buffer, size );
    written += TPM_ALG_ID_Marshal((TPM_ALG_ID*)&(source->digestAlg), buffer, size );
    written += TPM2B_DIGEST_Marshal((TPM2B_DIGEST*)&(source->auditDigest), buffer, size );
    written += TPM2B_DIGEST_Marshal((TPM2B_DIGEST*)&(source->commandDigest), buffer, size );
    return written;
}


// Table 2:115 - Definition of TPMS_SESSION_AUDIT_INFO Structure (StructureTable)
// TPMS_SESSION_AUDIT_INFO_Unmarshal not required
UINT16
TPMS_SESSION_AUDIT_INFO_Marshal(
    TPMS_SESSION_AUDIT_INFO *source, BYTE **buffer, INT32 *size)
{
    UINT16 written = 0;
    written += TPMI_YES_NO_Marshal((TPMI_YES_NO*)&(source->exclusiveSession), buffer, size );
    written += TPM2B_DIGEST_Marshal((TPM2B_DIGEST*)&(source->sessionDigest), buffer, size );
    return written;
}


// Table 2:116 - Definition of TPMS_CREATION_INFO Structure (StructureTable)
// TPMS_CREATION_INFO_Unmarshal not required
UINT16
TPMS_CREATION_INFO_Marshal(
    TPMS_CREATION_INFO *source, BYTE **buffer, INT32 *size)
{
    UINT16 written = 0;
    written += TPM2B_NAME_Marshal((TPM2B_NAME*)&(source->objectName), buffer, size );
    written += TPM2B_DIGEST_Marshal((TPM2B_DIGEST*)&(source->creationHash), buffer, size );
    return written;
}


// Table 2:117 - Definition of TPMS_NV_CERTIFY_INFO Structure (StructureTable)
// TPMS_NV_CERTIFY_INFO_Unmarshal not required
UINT16
TPMS_NV_CERTIFY_INFO_Marshal(
    TPMS_NV_CERTIFY_INFO *source, BYTE **buffer, INT32 *size)
{
    UINT16 written = 0;
    written += TPM2B_NAME_Marshal((TPM2B_NAME*)&(source->indexName), buffer, size );
    written += UINT16_Marshal((UINT16*)&(source->offset), buffer, size );
    written += TPM2B_MAX_NV_BUFFER_Marshal((TPM2B_MAX_NV_BUFFER*)&(source->nvContents), buffer, size );
    return written;
}


// Table 2:118 - Definition of (TPM_ST) TPMI_ST_ATTEST Type (InterfaceTable)
// TPMI_ST_ATTEST_Marshal changed to #define

// Table 2:119 - Definition of TPMU_ATTEST Union (UnionTable)
// TPMU_ATTEST_Unmarshal not required
UINT16
TPMU_ATTEST_Marshal(
    TPMU_ATTEST *source, BYTE **buffer, INT32 *size, UINT32 selector
)
{
    switch (selector)
    {

    case TPM_ST_ATTEST_CERTIFY:
        return TPMS_CERTIFY_INFO_Marshal((TPMS_CERTIFY_INFO*)&(source->certify), buffer, size );
    case TPM_ST_ATTEST_CREATION:
        return TPMS_CREATION_INFO_Marshal((TPMS_CREATION_INFO*)&(source->creation), buffer, size );
    case TPM_ST_ATTEST_QUOTE:
        return TPMS_QUOTE_INFO_Marshal((TPMS_QUOTE_INFO*)&(source->quote), buffer, size );
    case TPM_ST_ATTEST_COMMAND_AUDIT:
        return TPMS_COMMAND_AUDIT_INFO_Marshal((TPMS_COMMAND_AUDIT_INFO*)&(source->commandAudit), buffer, size );
    case TPM_ST_ATTEST_SESSION_AUDIT:
        return TPMS_SESSION_AUDIT_INFO_Marshal((TPMS_SESSION_AUDIT_INFO*)&(source->sessionAudit), buffer, size );
    case TPM_ST_ATTEST_TIME:
        return TPMS_TIME_ATTEST_INFO_Marshal((TPMS_TIME_ATTEST_INFO*)&(source->time), buffer, size );
    case TPM_ST_ATTEST_NV:
        return TPMS_NV_CERTIFY_INFO_Marshal((TPMS_NV_CERTIFY_INFO*)&(source->nv), buffer, size );
    }
    return 0;
}


// Table 2:120 - Definition of TPMS_ATTEST Structure (StructureTable)
// TPMS_ATTEST_Unmarshal not required
UINT16
TPMS_ATTEST_Marshal(
    TPMS_ATTEST *source, BYTE **buffer, INT32 *size)
{
    UINT16 written = 0;
    written += TPM_GENERATED_Marshal((TPM_GENERATED*)&(source->magic), buffer, size );
    written += TPMI_ST_ATTEST_Marshal((TPMI_ST_ATTEST*)&(source->type), buffer, size );
    written += TPM2B_NAME_Marshal((TPM2B_NAME*)&(source->qualifiedSigner), buffer, size );
    written += TPM2B_DATA_Marshal((TPM2B_DATA*)&(source->extraData), buffer, size );
    written += TPMS_CLOCK_INFO_Marshal((TPMS_CLOCK_INFO*)&(source->clockInfo), buffer, size );
    written += UINT64_Marshal((UINT64*)&(source->firmwareVersion), buffer, size );
    written += TPMU_ATTEST_Marshal((TPMU_ATTEST*)&(source->attested), buffer, size , (UINT32)(source->type));
    return written;
}


// Table 2:121 - Definition of TPM2B_ATTEST Structure (StructureTable)
// TPM2B_ATTEST_Unmarshal not required
UINT16
TPM2B_ATTEST_Marshal(
    TPM2B_ATTEST *source, BYTE **buffer, INT32 *size)
{
    UINT16 written = 0;
    written += UINT16_Marshal((UINT16*)&(source->t.size), buffer, size );
    if(source->t.size == 0)
        return written;

    written += BYTE_Array_Marshal((BYTE*)(source->t.attestationData), buffer, size , (INT32)(source->t.size));
    return written;
}


// Table 2:122 - Definition of TPMS_AUTH_COMMAND Structure (StructureTable)
TPM_RC
TPMS_AUTH_COMMAND_Unmarshal(
    TPMS_AUTH_COMMAND *target, BYTE **buffer, INT32 *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    if (rc == TPM_RC_SUCCESS)
    {
        rc = TPMI_SH_AUTH_SESSION_Unmarshal((TPMI_SH_AUTH_SESSION*)&target->sessionHandle, buffer, size , 1);
    }
    if (rc == TPM_RC_SUCCESS)
    {
        rc = TPM2B_NONCE_Unmarshal((TPM2B_NONCE*)&target->nonce, buffer, size );
    }
    if (rc == TPM_RC_SUCCESS)
    {
        rc = TPMA_SESSION_Unmarshal((TPMA_SESSION*)&target->sessionAttributes, buffer, size );
    }
    if (rc == TPM_RC_SUCCESS)
    {
        rc = TPM2B_AUTH_Unmarshal((TPM2B_AUTH*)&target->hmac, buffer, size );
    }
    return rc;
}

// TPMS_AUTH_COMMAND_Marshal not required

// Table 2:123 - Definition of TPMS_AUTH_RESPONSE Structure (StructureTable)
// TPMS_AUTH_RESPONSE_Unmarshal not required
UINT16
TPMS_AUTH_RESPONSE_Marshal(
    TPMS_AUTH_RESPONSE *source, BYTE **buffer, INT32 *size)
{
    UINT16 written = 0;
    written += TPM2B_NONCE_Marshal((TPM2B_NONCE*)&(source->nonce), buffer, size );
    written += TPMA_SESSION_Marshal((TPMA_SESSION*)&(source->sessionAttributes), buffer, size );
    written += TPM2B_AUTH_Marshal((TPM2B_AUTH*)&(source->hmac), buffer, size );
    return written;
}


// Table 2:124 - Definition of {!ALG.S} (TPM_KEY_BITS) TPMI_!ALG.S_KEY_BITS Type (InterfaceTable)
// Table 2:124 - Definition of TPMI_AES_KEY_BITS Type (InterfaceTable)
#ifdef TPM_ALG_AES
TPM_RC
TPMI_AES_KEY_BITS_Unmarshal(
    TPMI_AES_KEY_BITS *target, BYTE **buffer, INT32 *size)
{
    TPM_RC rc;
    rc = TPM_KEY_BITS_Unmarshal((TPM_KEY_BITS *)target, buffer, size);

    if (rc == TPM_RC_SUCCESS) // if unmarshalling succeeds
    {
        switch (*target)
        {
        case 128:
        case 256:

            break;

        default:
            rc = TPM_RC_VALUE;
        }
    }
    return rc;
}

// TPMI_AES_KEY_BITS_Marshal changed to #define
#endif // TPM_ALG_AES

// Table 2:124 - Definition of TPMI_SM4_KEY_BITS Type (InterfaceTable)
#ifdef TPM_ALG_SM4
TPM_RC
TPMI_SM4_KEY_BITS_Unmarshal(
    TPMI_SM4_KEY_BITS *target, BYTE **buffer, INT32 *size)
{
    TPM_RC rc;
    rc = TPM_KEY_BITS_Unmarshal((TPM_KEY_BITS *)target, buffer, size);

    if (rc == TPM_RC_SUCCESS) // if unmarshalling succeeds
    {
        switch (*target)
        {
        case 128:

            break;

        default:
            rc = TPM_RC_VALUE;
        }
    }
    return rc;
}

// TPMI_SM4_KEY_BITS_Marshal changed to #define
#endif // TPM_ALG_SM4

// Table 2:124 - Definition of TPMI_CAMELLIA_KEY_BITS Type (InterfaceTable)
#ifdef TPM_ALG_CAMELLIA
TPM_RC
TPMI_CAMELLIA_KEY_BITS_Unmarshal(
    TPMI_CAMELLIA_KEY_BITS *target, BYTE **buffer, INT32 *size)
{
    TPM_RC rc;
    rc = TPM_KEY_BITS_Unmarshal((TPM_KEY_BITS *)target, buffer, size);

    if (rc == TPM_RC_SUCCESS) // if unmarshalling succeeds
    {
        switch (*target)
        {
        case 128:

            break;

        default:
            rc = TPM_RC_VALUE;
        }
    }
    return rc;
}

// TPMI_CAMELLIA_KEY_BITS_Marshal changed to #define
#endif // TPM_ALG_CAMELLIA


// Table 2:125 - Definition of TPMU_SYM_KEY_BITS Union (UnionTable)
TPM_RC
TPMU_SYM_KEY_BITS_Unmarshal(
    TPMU_SYM_KEY_BITS *target, BYTE **buffer, INT32 *size, UINT32 selector)
{
    switch (selector)
    {
#ifdef TPM_ALG_AES
    case TPM_ALG_AES:
        return TPMI_AES_KEY_BITS_Unmarshal((TPMI_AES_KEY_BITS*)&(target->aes), buffer, size );
#endif // TPM_ALG_AES
#ifdef TPM_ALG_SM4
    case TPM_ALG_SM4:
        return TPMI_SM4_KEY_BITS_Unmarshal((TPMI_SM4_KEY_BITS*)&(target->sm4), buffer, size );
#endif // TPM_ALG_SM4
#ifdef TPM_ALG_CAMELLIA
    case TPM_ALG_CAMELLIA:
        return TPMI_CAMELLIA_KEY_BITS_Unmarshal((TPMI_CAMELLIA_KEY_BITS*)&(target->camellia), buffer, size );
#endif // TPM_ALG_CAMELLIA
#ifdef TPM_ALG_XOR
    case TPM_ALG_XOR:
        return TPMI_ALG_HASH_Unmarshal((TPMI_ALG_HASH*)&(target->xor), buffer, size , 0);
#endif // TPM_ALG_XOR

    case TPM_ALG_NULL:
        return TPM_RC_SUCCESS;
    }
    return TPM_RC_SELECTOR;
}

UINT16
TPMU_SYM_KEY_BITS_Marshal(
    TPMU_SYM_KEY_BITS *source, BYTE **buffer, INT32 *size, UINT32 selector
)
{
    switch (selector)
    {
#ifdef TPM_ALG_AES
    case TPM_ALG_AES:
        return TPMI_AES_KEY_BITS_Marshal((TPMI_AES_KEY_BITS*)&(source->aes), buffer, size );
#endif // TPM_ALG_AES
#ifdef TPM_ALG_SM4
    case TPM_ALG_SM4:
        return TPMI_SM4_KEY_BITS_Marshal((TPMI_SM4_KEY_BITS*)&(source->sm4), buffer, size );
#endif // TPM_ALG_SM4
#ifdef TPM_ALG_CAMELLIA
    case TPM_ALG_CAMELLIA:
        return TPMI_CAMELLIA_KEY_BITS_Marshal((TPMI_CAMELLIA_KEY_BITS*)&(source->camellia), buffer, size );
#endif // TPM_ALG_CAMELLIA
#ifdef TPM_ALG_XOR
    case TPM_ALG_XOR:
        return TPMI_ALG_HASH_Marshal((TPMI_ALG_HASH*)&(source->xor), buffer, size );
#endif // TPM_ALG_XOR

    case TPM_ALG_NULL:
        return 0;
    }
    return 0;
}


// Table 2:126 - Definition of TPMU_SYM_MODE Union (UnionTable)
TPM_RC
TPMU_SYM_MODE_Unmarshal(
    TPMU_SYM_MODE *target, BYTE **buffer, INT32 *size, UINT32 selector)
{
    switch (selector)
    {
#ifdef TPM_ALG_AES
    case TPM_ALG_AES:
        return TPMI_ALG_SYM_MODE_Unmarshal((TPMI_ALG_SYM_MODE*)&(target->aes), buffer, size , 0);
#endif // TPM_ALG_AES
#ifdef TPM_ALG_SM4
    case TPM_ALG_SM4:
        return TPMI_ALG_SYM_MODE_Unmarshal((TPMI_ALG_SYM_MODE*)&(target->sm4), buffer, size , 0);
#endif // TPM_ALG_SM4
#ifdef TPM_ALG_CAMELLIA
    case TPM_ALG_CAMELLIA:
        return TPMI_ALG_SYM_MODE_Unmarshal((TPMI_ALG_SYM_MODE*)&(target->camellia), buffer, size , 0);
#endif // TPM_ALG_CAMELLIA
#ifdef TPM_ALG_XOR
    case TPM_ALG_XOR:
        return TPM_RC_SUCCESS;
#endif // TPM_ALG_XOR

    case TPM_ALG_NULL:
        return TPM_RC_SUCCESS;
    }
    return TPM_RC_SELECTOR;
}

UINT16
TPMU_SYM_MODE_Marshal(
    TPMU_SYM_MODE *source, BYTE **buffer, INT32 *size, UINT32 selector
)
{
    switch (selector)
    {
#ifdef TPM_ALG_AES
    case TPM_ALG_AES:
        return TPMI_ALG_SYM_MODE_Marshal((TPMI_ALG_SYM_MODE*)&(source->aes), buffer, size );
#endif // TPM_ALG_AES
#ifdef TPM_ALG_SM4
    case TPM_ALG_SM4:
        return TPMI_ALG_SYM_MODE_Marshal((TPMI_ALG_SYM_MODE*)&(source->sm4), buffer, size );
#endif // TPM_ALG_SM4
#ifdef TPM_ALG_CAMELLIA
    case TPM_ALG_CAMELLIA:
        return TPMI_ALG_SYM_MODE_Marshal((TPMI_ALG_SYM_MODE*)&(source->camellia), buffer, size );
#endif // TPM_ALG_CAMELLIA
#ifdef TPM_ALG_XOR
    case TPM_ALG_XOR:
        return 0;
#endif // TPM_ALG_XOR

    case TPM_ALG_NULL:
        return 0;
    }
    return 0;
}


// Table 2:128 - Definition of TPMT_SYM_DEF Structure (StructureTable)
TPM_RC
TPMT_SYM_DEF_Unmarshal(
    TPMT_SYM_DEF *target, BYTE **buffer, INT32 *size, BOOL allowNull)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    if (rc == TPM_RC_SUCCESS)
    {
        rc = TPMI_ALG_SYM_Unmarshal((TPMI_ALG_SYM*)&target->algorithm, buffer, size , allowNull);
    }
    if (rc == TPM_RC_SUCCESS)
    {
        rc = TPMU_SYM_KEY_BITS_Unmarshal((TPMU_SYM_KEY_BITS*)&target->keyBits, buffer, size , (UINT32)(target->algorithm));
    }
    if (rc == TPM_RC_SUCCESS)
    {
        rc = TPMU_SYM_MODE_Unmarshal((TPMU_SYM_MODE*)&target->mode, buffer, size , (UINT32)(target->algorithm));
    }
    return rc;
}

UINT16
TPMT_SYM_DEF_Marshal(
    TPMT_SYM_DEF *source, BYTE **buffer, INT32 *size)
{
    UINT16 written = 0;
    written += TPMI_ALG_SYM_Marshal((TPMI_ALG_SYM*)&(source->algorithm), buffer, size );
    written += TPMU_SYM_KEY_BITS_Marshal((TPMU_SYM_KEY_BITS*)&(source->keyBits), buffer, size , (UINT32)(source->algorithm));
    written += TPMU_SYM_MODE_Marshal((TPMU_SYM_MODE*)&(source->mode), buffer, size , (UINT32)(source->algorithm));
    return written;
}


// Table 2:129 - Definition of TPMT_SYM_DEF_OBJECT Structure (StructureTable)
TPM_RC
TPMT_SYM_DEF_OBJECT_Unmarshal(
    TPMT_SYM_DEF_OBJECT *target, BYTE **buffer, INT32 *size, BOOL allowNull)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    if (rc == TPM_RC_SUCCESS)
    {
        rc = TPMI_ALG_SYM_OBJECT_Unmarshal((TPMI_ALG_SYM_OBJECT*)&target->algorithm, buffer, size , allowNull);
    }
    if (rc == TPM_RC_SUCCESS)
    {
        rc = TPMU_SYM_KEY_BITS_Unmarshal((TPMU_SYM_KEY_BITS*)&target->keyBits, buffer, size , (UINT32)(target->algorithm));
    }
    if (rc == TPM_RC_SUCCESS)
    {
        rc = TPMU_SYM_MODE_Unmarshal((TPMU_SYM_MODE*)&target->mode, buffer, size , (UINT32)(target->algorithm));
    }
    return rc;
}

UINT16
TPMT_SYM_DEF_OBJECT_Marshal(
    TPMT_SYM_DEF_OBJECT *source, BYTE **buffer, INT32 *size)
{
    UINT16 written = 0;
    written += TPMI_ALG_SYM_OBJECT_Marshal((TPMI_ALG_SYM_OBJECT*)&(source->algorithm), buffer, size );
    written += TPMU_SYM_KEY_BITS_Marshal((TPMU_SYM_KEY_BITS*)&(source->keyBits), buffer, size , (UINT32)(source->algorithm));
    written += TPMU_SYM_MODE_Marshal((TPMU_SYM_MODE*)&(source->mode), buffer, size , (UINT32)(source->algorithm));
    return written;
}


// Table 2:130 - Definition of TPM2B_SYM_KEY Structure (StructureTable)
TPM_RC
TPM2B_SYM_KEY_Unmarshal(
    TPM2B_SYM_KEY *target, BYTE **buffer, INT32 *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    if (rc == TPM_RC_SUCCESS)
    {
        rc = UINT16_Unmarshal((UINT16*)&target->t.size, buffer, size );
    }
// if size is zero, then the structure is a zero buffer
    if(target->t.size == 0)
        return TPM_RC_SUCCESS;
    if((target->t.size) > MAX_SYM_KEY_BYTES)
        return TPM_RC_SIZE;
    if (rc == TPM_RC_SUCCESS)
    {
        rc = BYTE_Array_Unmarshal((BYTE*)target->t.buffer, buffer, size , (INT32)(target->t.size));
    }
    return rc;
}

UINT16
TPM2B_SYM_KEY_Marshal(
    TPM2B_SYM_KEY *source, BYTE **buffer, INT32 *size)
{
    UINT16 written = 0;
    written += UINT16_Marshal((UINT16*)&(source->t.size), buffer, size );
    if(source->t.size == 0)
        return written;

    written += BYTE_Array_Marshal((BYTE*)(source->t.buffer), buffer, size , (INT32)(source->t.size));
    return written;
}


// Table 2:131 - Definition of TPMS_SYMCIPHER_PARMS Structure (StructureTable)
// TPMS_SYMCIPHER_PARMS_Unmarshal changed to #define
// TPMS_SYMCIPHER_PARMS_Marshal changed to #define

// Table 2:132 - Definition of TPM2B_SENSITIVE_DATA Structure (StructureTable)
TPM_RC
TPM2B_SENSITIVE_DATA_Unmarshal(
    TPM2B_SENSITIVE_DATA *target, BYTE **buffer, INT32 *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    if (rc == TPM_RC_SUCCESS)
    {
        rc = UINT16_Unmarshal((UINT16*)&target->t.size, buffer, size );
    }
// if size is zero, then the structure is a zero buffer
    if(target->t.size == 0)
        return TPM_RC_SUCCESS;
    if((target->t.size) > MAX_SYM_DATA)
        return TPM_RC_SIZE;
    if (rc == TPM_RC_SUCCESS)
    {
        rc = BYTE_Array_Unmarshal((BYTE*)target->t.buffer, buffer, size , (INT32)(target->t.size));
    }
    return rc;
}

UINT16
TPM2B_SENSITIVE_DATA_Marshal(
    TPM2B_SENSITIVE_DATA *source, BYTE **buffer, INT32 *size)
{
    UINT16 written = 0;
    written += UINT16_Marshal((UINT16*)&(source->t.size), buffer, size );
    if(source->t.size == 0)
        return written;

    written += BYTE_Array_Marshal((BYTE*)(source->t.buffer), buffer, size , (INT32)(source->t.size));
    return written;
}


// Table 2:133 - Definition of TPMS_SENSITIVE_CREATE Structure (StructureTable)
TPM_RC
TPMS_SENSITIVE_CREATE_Unmarshal(
    TPMS_SENSITIVE_CREATE *target, BYTE **buffer, INT32 *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    if (rc == TPM_RC_SUCCESS)
    {
        rc = TPM2B_AUTH_Unmarshal((TPM2B_AUTH*)&target->userAuth, buffer, size );
    }
    if (rc == TPM_RC_SUCCESS)
    {
        rc = TPM2B_SENSITIVE_DATA_Unmarshal((TPM2B_SENSITIVE_DATA*)&target->data, buffer, size );
    }
    return rc;
}

// TPMS_SENSITIVE_CREATE_Marshal not required

// Table 2:134 - Definition of TPM2B_SENSITIVE_CREATE Structure (StructureTable)
TPM_RC
TPM2B_SENSITIVE_CREATE_Unmarshal(
    TPM2B_SENSITIVE_CREATE *target, BYTE **buffer, INT32 *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    INT32 startSize;
    if (rc == TPM_RC_SUCCESS)
    {
        rc = UINT16_Unmarshal((UINT16*)&target->t.size, buffer, size );
    }
// if size is zero, then the structure is a zero buffer
    if(target->t.size == 0)
        return TPM_RC_SIZE;
    startSize = *size;
    if (rc == TPM_RC_SUCCESS)
    {
        rc = TPMS_SENSITIVE_CREATE_Unmarshal((TPMS_SENSITIVE_CREATE*)&target->t.sensitive, buffer, size );
    }

    if (rc == TPM_RC_SUCCESS)
    {
        if(target->t.size != (startSize - *size)) return TPM_RC_SIZE;
    }
    return TPM_RC_SUCCESS;
}

// TPM2B_SENSITIVE_CREATE_Marshal not required

// Table 2:135 - Definition of TPMS_SCHEME_HASH Structure (StructureTable)
// TPMS_SCHEME_HASH_Unmarshal changed to #define
// TPMS_SCHEME_HASH_Marshal changed to #define

// Table 2:136 - Definition of {ECC} TPMS_SCHEME_ECDAA Structure (StructureTable)
#ifdef TPM_ALG_ECC
TPM_RC
TPMS_SCHEME_ECDAA_Unmarshal(
    TPMS_SCHEME_ECDAA *target, BYTE **buffer, INT32 *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    if (rc == TPM_RC_SUCCESS)
    {
        rc = TPMI_ALG_HASH_Unmarshal((TPMI_ALG_HASH*)&target->hashAlg, buffer, size , 0);
    }
    if (rc == TPM_RC_SUCCESS)
    {
        rc = UINT16_Unmarshal((UINT16*)&target->count, buffer, size );
    }
    return rc;
}

UINT16
TPMS_SCHEME_ECDAA_Marshal(
    TPMS_SCHEME_ECDAA *source, BYTE **buffer, INT32 *size)
{
    UINT16 written = 0;
    written += TPMI_ALG_HASH_Marshal((TPMI_ALG_HASH*)&(source->hashAlg), buffer, size );
    written += UINT16_Marshal((UINT16*)&(source->count), buffer, size );
    return written;
}

#endif // TPM_ALG_ECC


// Table 2:137 - Definition of (TPM_ALG_ID) TPMI_ALG_KEYEDHASH_SCHEME Type (InterfaceTable)
TPM_RC
TPMI_ALG_KEYEDHASH_SCHEME_Unmarshal(
    TPMI_ALG_KEYEDHASH_SCHEME *target, BYTE **buffer, INT32 *size, BOOL allowNull)
{
    TPM_RC rc;
    rc = TPM_ALG_ID_Unmarshal((TPM_ALG_ID *)target, buffer, size);

    if (rc == TPM_RC_SUCCESS) // if unmarshalling succeeds
    {
        switch (*target)
        {
#ifdef TPM_ALG_HMAC
        case TPM_ALG_HMAC:
#endif // TPM_ALG_HMAC
#ifdef TPM_ALG_XOR
        case TPM_ALG_XOR:
#endif // TPM_ALG_XOR
            break;
        case TPM_ALG_NULL:
            if (allowNull)
                break;
        default:
            rc = TPM_RC_VALUE;
        }
    }
    return rc;
}

// TPMI_ALG_KEYEDHASH_SCHEME_Marshal changed to #define

// Table 2:138 - Definition of Types for HMAC_SIG_SCHEME (TypedefTable)
// TPMS_SCHEME_HASH definition used from Table 2:135
// TPMS_SCHEME_HMAC_Unmarshal changed to #define
// TPMS_SCHEME_HMAC_Marshal changed to #define


// Table 2:139 - Definition of TPMS_SCHEME_XOR Structure (StructureTable)
TPM_RC
TPMS_SCHEME_XOR_Unmarshal(
    TPMS_SCHEME_XOR *target, BYTE **buffer, INT32 *size, BOOL allowNull)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    if (rc == TPM_RC_SUCCESS)
    {
        rc = TPMI_ALG_HASH_Unmarshal((TPMI_ALG_HASH*)&target->hashAlg, buffer, size , allowNull);
    }
    if (rc == TPM_RC_SUCCESS)
    {
        rc = TPMI_ALG_KDF_Unmarshal((TPMI_ALG_KDF*)&target->kdf, buffer, size , 0);
    }
    return rc;
}

UINT16
TPMS_SCHEME_XOR_Marshal(
    TPMS_SCHEME_XOR *source, BYTE **buffer, INT32 *size)
{
    UINT16 written = 0;
    written += TPMI_ALG_HASH_Marshal((TPMI_ALG_HASH*)&(source->hashAlg), buffer, size );
    written += TPMI_ALG_KDF_Marshal((TPMI_ALG_KDF*)&(source->kdf), buffer, size );
    return written;
}


// Table 2:140 - Definition of TPMU_SCHEME_KEYEDHASH Union (UnionTable)
TPM_RC
TPMU_SCHEME_KEYEDHASH_Unmarshal(
    TPMU_SCHEME_KEYEDHASH *target, BYTE **buffer, INT32 *size, UINT32 selector)
{
    switch (selector)
    {
#ifdef TPM_ALG_HMAC
    case TPM_ALG_HMAC:
        return TPMS_SCHEME_HMAC_Unmarshal((TPMS_SCHEME_HMAC*)&(target->hmac), buffer, size );
#endif // TPM_ALG_HMAC
#ifdef TPM_ALG_XOR
    case TPM_ALG_XOR:
        return TPMS_SCHEME_XOR_Unmarshal((TPMS_SCHEME_XOR*)&(target->xor), buffer, size , 0);
#endif // TPM_ALG_XOR

    case TPM_ALG_NULL:
        return TPM_RC_SUCCESS;
    }
    return TPM_RC_SELECTOR;
}

UINT16
TPMU_SCHEME_KEYEDHASH_Marshal(
    TPMU_SCHEME_KEYEDHASH *source, BYTE **buffer, INT32 *size, UINT32 selector
)
{
    switch (selector)
    {
#ifdef TPM_ALG_HMAC
    case TPM_ALG_HMAC:
        return TPMS_SCHEME_HMAC_Marshal((TPMS_SCHEME_HMAC*)&(source->hmac), buffer, size );
#endif // TPM_ALG_HMAC
#ifdef TPM_ALG_XOR
    case TPM_ALG_XOR:
        return TPMS_SCHEME_XOR_Marshal((TPMS_SCHEME_XOR*)&(source->xor), buffer, size );
#endif // TPM_ALG_XOR

    case TPM_ALG_NULL:
        return 0;
    }
    return 0;
}


// Table 2:141 - Definition of TPMT_KEYEDHASH_SCHEME Structure (StructureTable)
TPM_RC
TPMT_KEYEDHASH_SCHEME_Unmarshal(
    TPMT_KEYEDHASH_SCHEME *target, BYTE **buffer, INT32 *size, BOOL allowNull)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    if (rc == TPM_RC_SUCCESS)
    {
        rc = TPMI_ALG_KEYEDHASH_SCHEME_Unmarshal((TPMI_ALG_KEYEDHASH_SCHEME*)&target->scheme, buffer, size , allowNull);
    }
    if (rc == TPM_RC_SUCCESS)
    {
        rc = TPMU_SCHEME_KEYEDHASH_Unmarshal((TPMU_SCHEME_KEYEDHASH*)&target->details, buffer, size , (UINT32)(target->scheme));
    }
    return rc;
}

UINT16
TPMT_KEYEDHASH_SCHEME_Marshal(
    TPMT_KEYEDHASH_SCHEME *source, BYTE **buffer, INT32 *size)
{
    UINT16 written = 0;
    written += TPMI_ALG_KEYEDHASH_SCHEME_Marshal((TPMI_ALG_KEYEDHASH_SCHEME*)&(source->scheme), buffer, size );
    written += TPMU_SCHEME_KEYEDHASH_Marshal((TPMU_SCHEME_KEYEDHASH*)&(source->details), buffer, size , (UINT32)(source->scheme));
    return written;
}


// Table 2:142 - Definition of {RSA} Types for RSA Signature Schemes (TypedefTable)
#ifdef TPM_ALG_RSA
// TPMS_SCHEME_HASH definition used from Table 2:135
// TPMS_SIG_SCHEME_RSASSA_Unmarshal changed to #define
// TPMS_SIG_SCHEME_RSASSA_Marshal changed to #define
#endif // TPM_ALG_RSA


#ifdef TPM_ALG_RSA
// TPMS_SCHEME_HASH definition used from Table 2:135
// TPMS_SIG_SCHEME_RSAPSS_Unmarshal changed to #define
// TPMS_SIG_SCHEME_RSAPSS_Marshal changed to #define
#endif // TPM_ALG_RSA



// Table 2:143 - Definition of {ECC} Types for ECC Signature Schemes (TypedefTable)
#ifdef TPM_ALG_ECC
// TPMS_SCHEME_HASH definition used from Table 2:135
// TPMS_SIG_SCHEME_ECDSA_Unmarshal changed to #define
// TPMS_SIG_SCHEME_ECDSA_Marshal changed to #define
#endif // TPM_ALG_ECC


#ifdef TPM_ALG_ECC
// TPMS_SCHEME_HASH definition used from Table 2:135
// TPMS_SIG_SCHEME_SM2_Unmarshal changed to #define
// TPMS_SIG_SCHEME_SM2_Marshal changed to #define
#endif // TPM_ALG_ECC


#ifdef TPM_ALG_ECC
// TPMS_SCHEME_HASH definition used from Table 2:135
// TPMS_SIG_SCHEME_ECSCHNORR_Unmarshal changed to #define
// TPMS_SIG_SCHEME_ECSCHNORR_Marshal changed to #define
#endif // TPM_ALG_ECC


#ifdef TPM_ALG_ECC
// TPMS_SCHEME_ECDAA definition used from Table 2:136
// TPMS_SIG_SCHEME_ECDAA_Unmarshal changed to #define
// TPMS_SIG_SCHEME_ECDAA_Marshal changed to #define
#endif // TPM_ALG_ECC



// Table 2:144 - Definition of TPMU_SIG_SCHEME Union (UnionTable)
TPM_RC
TPMU_SIG_SCHEME_Unmarshal(
    TPMU_SIG_SCHEME *target, BYTE **buffer, INT32 *size, UINT32 selector)
{
    switch (selector)
    {
#ifdef TPM_ALG_RSASSA
    case TPM_ALG_RSASSA:
        return TPMS_SIG_SCHEME_RSASSA_Unmarshal((TPMS_SIG_SCHEME_RSASSA*)&(target->rsassa), buffer, size );
#endif // TPM_ALG_RSASSA
#ifdef TPM_ALG_RSAPSS
    case TPM_ALG_RSAPSS:
        return TPMS_SIG_SCHEME_RSAPSS_Unmarshal((TPMS_SIG_SCHEME_RSAPSS*)&(target->rsapss), buffer, size );
#endif // TPM_ALG_RSAPSS
#ifdef TPM_ALG_ECDSA
    case TPM_ALG_ECDSA:
        return TPMS_SIG_SCHEME_ECDSA_Unmarshal((TPMS_SIG_SCHEME_ECDSA*)&(target->ecdsa), buffer, size );
#endif // TPM_ALG_ECDSA
#ifdef TPM_ALG_SM2
    case TPM_ALG_SM2:
        return TPMS_SIG_SCHEME_SM2_Unmarshal((TPMS_SIG_SCHEME_SM2*)&(target->sm2), buffer, size );
#endif // TPM_ALG_SM2
#ifdef TPM_ALG_ECSCHNORR
    case TPM_ALG_ECSCHNORR:
        return TPMS_SIG_SCHEME_ECSCHNORR_Unmarshal((TPMS_SIG_SCHEME_ECSCHNORR*)&(target->ecschnorr), buffer, size );
#endif // TPM_ALG_ECSCHNORR
#ifdef TPM_ALG_ECDAA
    case TPM_ALG_ECDAA:
        return TPMS_SIG_SCHEME_ECDAA_Unmarshal((TPMS_SIG_SCHEME_ECDAA*)&(target->ecdaa), buffer, size );
#endif // TPM_ALG_ECDAA
#ifdef TPM_ALG_HMAC
    case TPM_ALG_HMAC:
        return TPMS_SCHEME_HMAC_Unmarshal((TPMS_SCHEME_HMAC*)&(target->hmac), buffer, size );
#endif // TPM_ALG_HMAC

    case TPM_ALG_NULL:
        return TPM_RC_SUCCESS;
    }
    return TPM_RC_SELECTOR;
}

UINT16
TPMU_SIG_SCHEME_Marshal(
    TPMU_SIG_SCHEME *source, BYTE **buffer, INT32 *size, UINT32 selector
)
{
    switch (selector)
    {
#ifdef TPM_ALG_RSASSA
    case TPM_ALG_RSASSA:
        return TPMS_SIG_SCHEME_RSASSA_Marshal((TPMS_SIG_SCHEME_RSASSA*)&(source->rsassa), buffer, size );
#endif // TPM_ALG_RSASSA
#ifdef TPM_ALG_RSAPSS
    case TPM_ALG_RSAPSS:
        return TPMS_SIG_SCHEME_RSAPSS_Marshal((TPMS_SIG_SCHEME_RSAPSS*)&(source->rsapss), buffer, size );
#endif // TPM_ALG_RSAPSS
#ifdef TPM_ALG_ECDSA
    case TPM_ALG_ECDSA:
        return TPMS_SIG_SCHEME_ECDSA_Marshal((TPMS_SIG_SCHEME_ECDSA*)&(source->ecdsa), buffer, size );
#endif // TPM_ALG_ECDSA
#ifdef TPM_ALG_SM2
    case TPM_ALG_SM2:
        return TPMS_SIG_SCHEME_SM2_Marshal((TPMS_SIG_SCHEME_SM2*)&(source->sm2), buffer, size );
#endif // TPM_ALG_SM2
#ifdef TPM_ALG_ECSCHNORR
    case TPM_ALG_ECSCHNORR:
        return TPMS_SIG_SCHEME_ECSCHNORR_Marshal((TPMS_SIG_SCHEME_ECSCHNORR*)&(source->ecschnorr), buffer, size );
#endif // TPM_ALG_ECSCHNORR
#ifdef TPM_ALG_ECDAA
    case TPM_ALG_ECDAA:
        return TPMS_SIG_SCHEME_ECDAA_Marshal((TPMS_SIG_SCHEME_ECDAA*)&(source->ecdaa), buffer, size );
#endif // TPM_ALG_ECDAA
#ifdef TPM_ALG_HMAC
    case TPM_ALG_HMAC:
        return TPMS_SCHEME_HMAC_Marshal((TPMS_SCHEME_HMAC*)&(source->hmac), buffer, size );
#endif // TPM_ALG_HMAC

    case TPM_ALG_NULL:
        return 0;
    }
    return 0;
}


// Table 2:145 - Definition of TPMT_SIG_SCHEME Structure (StructureTable)
TPM_RC
TPMT_SIG_SCHEME_Unmarshal(
    TPMT_SIG_SCHEME *target, BYTE **buffer, INT32 *size, BOOL allowNull)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    if (rc == TPM_RC_SUCCESS)
    {
        rc = TPMI_ALG_SIG_SCHEME_Unmarshal((TPMI_ALG_SIG_SCHEME*)&target->scheme, buffer, size , allowNull);
    }
    if (rc == TPM_RC_SUCCESS)
    {
        rc = TPMU_SIG_SCHEME_Unmarshal((TPMU_SIG_SCHEME*)&target->details, buffer, size , (UINT32)(target->scheme));
    }
    return rc;
}

UINT16
TPMT_SIG_SCHEME_Marshal(
    TPMT_SIG_SCHEME *source, BYTE **buffer, INT32 *size)
{
    UINT16 written = 0;
    written += TPMI_ALG_SIG_SCHEME_Marshal((TPMI_ALG_SIG_SCHEME*)&(source->scheme), buffer, size );
    written += TPMU_SIG_SCHEME_Marshal((TPMU_SIG_SCHEME*)&(source->details), buffer, size , (UINT32)(source->scheme));
    return written;
}


// Table 2:146 - Definition of Types for {RSA} Encryption Schemes (TypedefTable)
#ifdef TPM_ALG_RSA
// TPMS_SCHEME_HASH definition used from Table 2:135
// TPMS_ENC_SCHEME_OAEP_Unmarshal changed to #define
// TPMS_ENC_SCHEME_OAEP_Marshal changed to #define
#endif // TPM_ALG_RSA


#ifdef TPM_ALG_RSA
// TPMS_EMPTY definition used from Table 2:68
// TPMS_ENC_SCHEME_RSAES_Unmarshal changed to #define
// TPMS_ENC_SCHEME_RSAES_Marshal changed to #define
#endif // TPM_ALG_RSA



// Table 2:147 - Definition of Types for {ECC} ECC Key Exchange (TypedefTable)
#ifdef TPM_ALG_ECC
// TPMS_SCHEME_HASH definition used from Table 2:135
// TPMS_KEY_SCHEME_ECDH_Unmarshal changed to #define
// TPMS_KEY_SCHEME_ECDH_Marshal changed to #define
#endif // TPM_ALG_ECC


#ifdef TPM_ALG_ECC
// TPMS_SCHEME_HASH definition used from Table 2:135
// TPMS_KEY_SCHEME_ECMQV_Unmarshal changed to #define
// TPMS_KEY_SCHEME_ECMQV_Marshal changed to #define
#endif // TPM_ALG_ECC



// Table 2:148 - Definition of Types for KDF Schemes (TypedefTable)
// TPMS_SCHEME_HASH definition used from Table 2:135
// TPMS_SCHEME_MGF1_Unmarshal changed to #define
// TPMS_SCHEME_MGF1_Marshal changed to #define

// TPMS_SCHEME_HASH definition used from Table 2:135
// TPMS_SCHEME_KDF1_SP800_56A_Unmarshal changed to #define
// TPMS_SCHEME_KDF1_SP800_56A_Marshal changed to #define

// TPMS_SCHEME_HASH definition used from Table 2:135
// TPMS_SCHEME_KDF2_Unmarshal changed to #define
// TPMS_SCHEME_KDF2_Marshal changed to #define

// TPMS_SCHEME_HASH definition used from Table 2:135
// TPMS_SCHEME_KDF1_SP800_108_Unmarshal changed to #define
// TPMS_SCHEME_KDF1_SP800_108_Marshal changed to #define


// Table 2:149 - Definition of TPMU_KDF_SCHEME Union (UnionTable)
TPM_RC
TPMU_KDF_SCHEME_Unmarshal(
    TPMU_KDF_SCHEME *target, BYTE **buffer, INT32 *size, UINT32 selector)
{
    switch (selector)
    {
#ifdef TPM_ALG_MGF1
    case TPM_ALG_MGF1:
        return TPMS_SCHEME_MGF1_Unmarshal((TPMS_SCHEME_MGF1*)&(target->mgf1), buffer, size );
#endif // TPM_ALG_MGF1
#ifdef TPM_ALG_KDF1_SP800_56A
    case TPM_ALG_KDF1_SP800_56A:
        return TPMS_SCHEME_KDF1_SP800_56A_Unmarshal((TPMS_SCHEME_KDF1_SP800_56A*)&(target->kdf1_sp800_56a), buffer, size );
#endif // TPM_ALG_KDF1_SP800_56A
#ifdef TPM_ALG_KDF2
    case TPM_ALG_KDF2:
        return TPMS_SCHEME_KDF2_Unmarshal((TPMS_SCHEME_KDF2*)&(target->kdf2), buffer, size );
#endif // TPM_ALG_KDF2
#ifdef TPM_ALG_KDF1_SP800_108
    case TPM_ALG_KDF1_SP800_108:
        return TPMS_SCHEME_KDF1_SP800_108_Unmarshal((TPMS_SCHEME_KDF1_SP800_108*)&(target->kdf1_sp800_108), buffer, size );
#endif // TPM_ALG_KDF1_SP800_108

    case TPM_ALG_NULL:
        return TPM_RC_SUCCESS;
    }
    return TPM_RC_SELECTOR;
}

UINT16
TPMU_KDF_SCHEME_Marshal(
    TPMU_KDF_SCHEME *source, BYTE **buffer, INT32 *size, UINT32 selector
)
{
    switch (selector)
    {
#ifdef TPM_ALG_MGF1
    case TPM_ALG_MGF1:
        return TPMS_SCHEME_MGF1_Marshal((TPMS_SCHEME_MGF1*)&(source->mgf1), buffer, size );
#endif // TPM_ALG_MGF1
#ifdef TPM_ALG_KDF1_SP800_56A
    case TPM_ALG_KDF1_SP800_56A:
        return TPMS_SCHEME_KDF1_SP800_56A_Marshal((TPMS_SCHEME_KDF1_SP800_56A*)&(source->kdf1_sp800_56a), buffer, size );
#endif // TPM_ALG_KDF1_SP800_56A
#ifdef TPM_ALG_KDF2
    case TPM_ALG_KDF2:
        return TPMS_SCHEME_KDF2_Marshal((TPMS_SCHEME_KDF2*)&(source->kdf2), buffer, size );
#endif // TPM_ALG_KDF2
#ifdef TPM_ALG_KDF1_SP800_108
    case TPM_ALG_KDF1_SP800_108:
        return TPMS_SCHEME_KDF1_SP800_108_Marshal((TPMS_SCHEME_KDF1_SP800_108*)&(source->kdf1_sp800_108), buffer, size );
#endif // TPM_ALG_KDF1_SP800_108

    case TPM_ALG_NULL:
        return 0;
    }
    return 0;
}


// Table 2:150 - Definition of TPMT_KDF_SCHEME Structure (StructureTable)
TPM_RC
TPMT_KDF_SCHEME_Unmarshal(
    TPMT_KDF_SCHEME *target, BYTE **buffer, INT32 *size, BOOL allowNull)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    if (rc == TPM_RC_SUCCESS)
    {
        rc = TPMI_ALG_KDF_Unmarshal((TPMI_ALG_KDF*)&target->scheme, buffer, size , allowNull);
    }
    if (rc == TPM_RC_SUCCESS)
    {
        rc = TPMU_KDF_SCHEME_Unmarshal((TPMU_KDF_SCHEME*)&target->details, buffer, size , (UINT32)(target->scheme));
    }
    return rc;
}

UINT16
TPMT_KDF_SCHEME_Marshal(
    TPMT_KDF_SCHEME *source, BYTE **buffer, INT32 *size)
{
    UINT16 written = 0;
    written += TPMI_ALG_KDF_Marshal((TPMI_ALG_KDF*)&(source->scheme), buffer, size );
    written += TPMU_KDF_SCHEME_Marshal((TPMU_KDF_SCHEME*)&(source->details), buffer, size , (UINT32)(source->scheme));
    return written;
}


// Table 2:151 - Definition of (TPM_ALG_ID) TPMI_ALG_ASYM_SCHEME Type (InterfaceTable)

// Table 2:152 - Definition of TPMU_ASYM_SCHEME Union (UnionTable)
TPM_RC
TPMU_ASYM_SCHEME_Unmarshal(
    TPMU_ASYM_SCHEME *target, BYTE **buffer, INT32 *size, UINT32 selector)
{
    switch (selector)
    {
#ifdef TPM_ALG_ECDH
    case TPM_ALG_ECDH:
        return TPMS_KEY_SCHEME_ECDH_Unmarshal((TPMS_KEY_SCHEME_ECDH*)&(target->ecdh), buffer, size );
#endif // TPM_ALG_ECDH
#ifdef TPM_ALG_ECMQV
    case TPM_ALG_ECMQV:
        return TPMS_KEY_SCHEME_ECMQV_Unmarshal((TPMS_KEY_SCHEME_ECMQV*)&(target->ecmqv), buffer, size );
#endif // TPM_ALG_ECMQV
#ifdef TPM_ALG_RSASSA
    case TPM_ALG_RSASSA:
        return TPMS_SIG_SCHEME_RSASSA_Unmarshal((TPMS_SIG_SCHEME_RSASSA*)&(target->rsassa), buffer, size );
#endif // TPM_ALG_RSASSA
#ifdef TPM_ALG_RSAPSS
    case TPM_ALG_RSAPSS:
        return TPMS_SIG_SCHEME_RSAPSS_Unmarshal((TPMS_SIG_SCHEME_RSAPSS*)&(target->rsapss), buffer, size );
#endif // TPM_ALG_RSAPSS
#ifdef TPM_ALG_ECDSA
    case TPM_ALG_ECDSA:
        return TPMS_SIG_SCHEME_ECDSA_Unmarshal((TPMS_SIG_SCHEME_ECDSA*)&(target->ecdsa), buffer, size );
#endif // TPM_ALG_ECDSA
#ifdef TPM_ALG_SM2
    case TPM_ALG_SM2:
        return TPMS_SIG_SCHEME_SM2_Unmarshal((TPMS_SIG_SCHEME_SM2*)&(target->sm2), buffer, size );
#endif // TPM_ALG_SM2
#ifdef TPM_ALG_ECSCHNORR
    case TPM_ALG_ECSCHNORR:
        return TPMS_SIG_SCHEME_ECSCHNORR_Unmarshal((TPMS_SIG_SCHEME_ECSCHNORR*)&(target->ecschnorr), buffer, size );
#endif // TPM_ALG_ECSCHNORR
#ifdef TPM_ALG_ECDAA
    case TPM_ALG_ECDAA:
        return TPMS_SIG_SCHEME_ECDAA_Unmarshal((TPMS_SIG_SCHEME_ECDAA*)&(target->ecdaa), buffer, size );
#endif // TPM_ALG_ECDAA
#ifdef TPM_ALG_RSAES
    case TPM_ALG_RSAES:
        return TPMS_ENC_SCHEME_RSAES_Unmarshal((TPMS_ENC_SCHEME_RSAES*)&(target->rsaes), buffer, size );
#endif // TPM_ALG_RSAES
#ifdef TPM_ALG_OAEP
    case TPM_ALG_OAEP:
        return TPMS_ENC_SCHEME_OAEP_Unmarshal((TPMS_ENC_SCHEME_OAEP*)&(target->oaep), buffer, size );
#endif // TPM_ALG_OAEP

    case TPM_ALG_NULL:
        return TPM_RC_SUCCESS;
    }
    return TPM_RC_SELECTOR;
}

UINT16
TPMU_ASYM_SCHEME_Marshal(
    TPMU_ASYM_SCHEME *source, BYTE **buffer, INT32 *size, UINT32 selector
)
{
    switch (selector)
    {
#ifdef TPM_ALG_ECDH
    case TPM_ALG_ECDH:
        return TPMS_KEY_SCHEME_ECDH_Marshal((TPMS_KEY_SCHEME_ECDH*)&(source->ecdh), buffer, size );
#endif // TPM_ALG_ECDH
#ifdef TPM_ALG_ECMQV
    case TPM_ALG_ECMQV:
        return TPMS_KEY_SCHEME_ECMQV_Marshal((TPMS_KEY_SCHEME_ECMQV*)&(source->ecmqv), buffer, size );
#endif // TPM_ALG_ECMQV
#ifdef TPM_ALG_RSASSA
    case TPM_ALG_RSASSA:
        return TPMS_SIG_SCHEME_RSASSA_Marshal((TPMS_SIG_SCHEME_RSASSA*)&(source->rsassa), buffer, size );
#endif // TPM_ALG_RSASSA
#ifdef TPM_ALG_RSAPSS
    case TPM_ALG_RSAPSS:
        return TPMS_SIG_SCHEME_RSAPSS_Marshal((TPMS_SIG_SCHEME_RSAPSS*)&(source->rsapss), buffer, size );
#endif // TPM_ALG_RSAPSS
#ifdef TPM_ALG_ECDSA
    case TPM_ALG_ECDSA:
        return TPMS_SIG_SCHEME_ECDSA_Marshal((TPMS_SIG_SCHEME_ECDSA*)&(source->ecdsa), buffer, size );
#endif // TPM_ALG_ECDSA
#ifdef TPM_ALG_SM2
    case TPM_ALG_SM2:
        return TPMS_SIG_SCHEME_SM2_Marshal((TPMS_SIG_SCHEME_SM2*)&(source->sm2), buffer, size );
#endif // TPM_ALG_SM2
#ifdef TPM_ALG_ECSCHNORR
    case TPM_ALG_ECSCHNORR:
        return TPMS_SIG_SCHEME_ECSCHNORR_Marshal((TPMS_SIG_SCHEME_ECSCHNORR*)&(source->ecschnorr), buffer, size );
#endif // TPM_ALG_ECSCHNORR
#ifdef TPM_ALG_ECDAA
    case TPM_ALG_ECDAA:
        return TPMS_SIG_SCHEME_ECDAA_Marshal((TPMS_SIG_SCHEME_ECDAA*)&(source->ecdaa), buffer, size );
#endif // TPM_ALG_ECDAA
#ifdef TPM_ALG_RSAES
    case TPM_ALG_RSAES:
        return TPMS_ENC_SCHEME_RSAES_Marshal((TPMS_ENC_SCHEME_RSAES*)&(source->rsaes), buffer, size );
#endif // TPM_ALG_RSAES
#ifdef TPM_ALG_OAEP
    case TPM_ALG_OAEP:
        return TPMS_ENC_SCHEME_OAEP_Marshal((TPMS_ENC_SCHEME_OAEP*)&(source->oaep), buffer, size );
#endif // TPM_ALG_OAEP

    case TPM_ALG_NULL:
        return 0;
    }
    return 0;
}


// Table 2:153 - Definition of TPMT_ASYM_SCHEME Structure (StructureTable)
// TPMT_ASYM_SCHEME_Unmarshal not required
// TPMT_ASYM_SCHEME_Marshal not required

// Table 2:154 - Definition of (TPM_ALG_ID) {RSA} TPMI_ALG_RSA_SCHEME Type (InterfaceTable)
#ifdef TPM_ALG_RSA
TPM_RC
TPMI_ALG_RSA_SCHEME_Unmarshal(
    TPMI_ALG_RSA_SCHEME *target, BYTE **buffer, INT32 *size, BOOL allowNull)
{
    TPM_RC rc;
    rc = TPM_ALG_ID_Unmarshal((TPM_ALG_ID *)target, buffer, size);

    if (rc == TPM_RC_SUCCESS) // if unmarshalling succeeds
    {
        switch (*target)
        {
#ifdef TPM_ALG_RSAES
        case TPM_ALG_RSAES:
#endif // TPM_ALG_RSAES
#ifdef TPM_ALG_OAEP
        case TPM_ALG_OAEP:
#endif // TPM_ALG_OAEP
#ifdef TPM_ALG_RSASSA
        case TPM_ALG_RSASSA:
#endif // TPM_ALG_RSASSA
#ifdef TPM_ALG_RSAPSS
        case TPM_ALG_RSAPSS:
#endif // TPM_ALG_RSAPSS
            break;
        case TPM_ALG_NULL:
            if (!allowNull)
                rc = TPM_RC_VALUE;
            break;
        default:
            rc = TPM_RC_VALUE;
        }
    }
    return rc;
}

// TPMI_ALG_RSA_SCHEME_Marshal changed to #define
#endif // TPM_ALG_RSA


// Table 2:155 - Definition of {RSA} TPMT_RSA_SCHEME Structure (StructureTable)
#ifdef TPM_ALG_RSA
TPM_RC
TPMT_RSA_SCHEME_Unmarshal(
    TPMT_RSA_SCHEME *target, BYTE **buffer, INT32 *size, BOOL allowNull)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    if (rc == TPM_RC_SUCCESS)
    {
        rc = TPMI_ALG_RSA_SCHEME_Unmarshal((TPMI_ALG_RSA_SCHEME*)&target->scheme, buffer, size , allowNull);
    }
    if (rc == TPM_RC_SUCCESS)
    {
        rc = TPMU_ASYM_SCHEME_Unmarshal((TPMU_ASYM_SCHEME*)&target->details, buffer, size , (UINT32)(target->scheme));
    }
    return rc;
}

UINT16
TPMT_RSA_SCHEME_Marshal(
    TPMT_RSA_SCHEME *source, BYTE **buffer, INT32 *size)
{
    UINT16 written = 0;
    written += TPMI_ALG_RSA_SCHEME_Marshal((TPMI_ALG_RSA_SCHEME*)&(source->scheme), buffer, size );
    written += TPMU_ASYM_SCHEME_Marshal((TPMU_ASYM_SCHEME*)&(source->details), buffer, size , (UINT32)(source->scheme));
    return written;
}

#endif // TPM_ALG_RSA


// Table 2:156 - Definition of (TPM_ALG_ID) {RSA} TPMI_ALG_RSA_DECRYPT Type (InterfaceTable)
#ifdef TPM_ALG_RSA
TPM_RC
TPMI_ALG_RSA_DECRYPT_Unmarshal(
    TPMI_ALG_RSA_DECRYPT *target, BYTE **buffer, INT32 *size, BOOL allowNull)
{
    TPM_RC rc;
    rc = TPM_ALG_ID_Unmarshal((TPM_ALG_ID *)target, buffer, size);

    if (rc == TPM_RC_SUCCESS) // if unmarshalling succeeds
    {
        switch (*target)
        {
#ifdef TPM_ALG_RSAES
        case TPM_ALG_RSAES:
#endif // TPM_ALG_RSAES
#ifdef TPM_ALG_OAEP
        case TPM_ALG_OAEP:
#endif // TPM_ALG_OAEP
            break;
        case TPM_ALG_NULL:
            if (!allowNull)
                rc = TPM_RC_VALUE;
            break;
        default:
            rc = TPM_RC_VALUE;
        }
    }
    return rc;
}

// TPMI_ALG_RSA_DECRYPT_Marshal changed to #define
#endif // TPM_ALG_RSA


// Table 2:157 - Definition of {RSA} TPMT_RSA_DECRYPT Structure (StructureTable)
#ifdef TPM_ALG_RSA
TPM_RC
TPMT_RSA_DECRYPT_Unmarshal(
    TPMT_RSA_DECRYPT *target, BYTE **buffer, INT32 *size, BOOL allowNull)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    if (rc == TPM_RC_SUCCESS)
    {
        rc = TPMI_ALG_RSA_DECRYPT_Unmarshal((TPMI_ALG_RSA_DECRYPT*)&target->scheme, buffer, size , allowNull);
    }
    if (rc == TPM_RC_SUCCESS)
    {
        rc = TPMU_ASYM_SCHEME_Unmarshal((TPMU_ASYM_SCHEME*)&target->details, buffer, size , (UINT32)(target->scheme));
    }
    return rc;
}

UINT16
TPMT_RSA_DECRYPT_Marshal(
    TPMT_RSA_DECRYPT *source, BYTE **buffer, INT32 *size)
{
    UINT16 written = 0;
    written += TPMI_ALG_RSA_DECRYPT_Marshal((TPMI_ALG_RSA_DECRYPT*)&(source->scheme), buffer, size );
    written += TPMU_ASYM_SCHEME_Marshal((TPMU_ASYM_SCHEME*)&(source->details), buffer, size , (UINT32)(source->scheme));
    return written;
}

#endif // TPM_ALG_RSA


// Table 2:158 - Definition of {RSA} TPM2B_PUBLIC_KEY_RSA Structure (StructureTable)
#ifdef TPM_ALG_RSA
TPM_RC
TPM2B_PUBLIC_KEY_RSA_Unmarshal(
    TPM2B_PUBLIC_KEY_RSA *target, BYTE **buffer, INT32 *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    if (rc == TPM_RC_SUCCESS)
    {
        rc = UINT16_Unmarshal((UINT16*)&target->t.size, buffer, size );
    }
// if size is zero, then the structure is a zero buffer
    if(target->t.size == 0)
        return TPM_RC_SUCCESS;
    if((target->t.size) > MAX_RSA_KEY_BYTES)
        return TPM_RC_SIZE;
    if (rc == TPM_RC_SUCCESS)
    {
        rc = BYTE_Array_Unmarshal((BYTE*)target->t.buffer, buffer, size , (INT32)(target->t.size));
    }
    return rc;
}

UINT16
TPM2B_PUBLIC_KEY_RSA_Marshal(
    TPM2B_PUBLIC_KEY_RSA *source, BYTE **buffer, INT32 *size)
{
    UINT16 written = 0;
    written += UINT16_Marshal((UINT16*)&(source->t.size), buffer, size );
    if(source->t.size == 0)
        return written;

    written += BYTE_Array_Marshal((BYTE*)(source->t.buffer), buffer, size , (INT32)(source->t.size));
    return written;
}

#endif // TPM_ALG_RSA


// Table 2:159 - Definition of {RSA} (TPM_KEY_BITS) TPMI_RSA_KEY_BITS Type (InterfaceTable)
#ifdef TPM_ALG_RSA
TPM_RC
TPMI_RSA_KEY_BITS_Unmarshal(
    TPMI_RSA_KEY_BITS *target, BYTE **buffer, INT32 *size)
{
    TPM_RC rc;
    rc = TPM_KEY_BITS_Unmarshal((TPM_KEY_BITS *)target, buffer, size);

    if (rc == TPM_RC_SUCCESS) // if unmarshalling succeeds
    {
        switch (*target)
        {
        case 1024:
        case 2048:

            break;

        default:
            rc = TPM_RC_VALUE;
        }
    }
    return rc;
}

// TPMI_RSA_KEY_BITS_Marshal changed to #define
#endif // TPM_ALG_RSA


// Table 2:160 - Definition of {RSA} TPM2B_PRIVATE_KEY_RSA Structure (StructureTable)
#ifdef TPM_ALG_RSA
TPM_RC
TPM2B_PRIVATE_KEY_RSA_Unmarshal(
    TPM2B_PRIVATE_KEY_RSA *target, BYTE **buffer, INT32 *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    if (rc == TPM_RC_SUCCESS)
    {
        rc = UINT16_Unmarshal((UINT16*)&target->t.size, buffer, size );
    }
// if size is zero, then the structure is a zero buffer
    if(target->t.size == 0)
        return TPM_RC_SUCCESS;
    if((target->t.size) > MAX_RSA_KEY_BYTES/2)
        return TPM_RC_SIZE;
    if (rc == TPM_RC_SUCCESS)
    {
        rc = BYTE_Array_Unmarshal((BYTE*)target->t.buffer, buffer, size , (INT32)(target->t.size));
    }
    return rc;
}

UINT16
TPM2B_PRIVATE_KEY_RSA_Marshal(
    TPM2B_PRIVATE_KEY_RSA *source, BYTE **buffer, INT32 *size)
{
    UINT16 written = 0;
    written += UINT16_Marshal((UINT16*)&(source->t.size), buffer, size );
    if(source->t.size == 0)
        return written;

    written += BYTE_Array_Marshal((BYTE*)(source->t.buffer), buffer, size , (INT32)(source->t.size));
    return written;
}

#endif // TPM_ALG_RSA


// Table 2:161 - Definition of {ECC} TPM2B_ECC_PARAMETER Structure (StructureTable)
#ifdef TPM_ALG_ECC
TPM_RC
TPM2B_ECC_PARAMETER_Unmarshal(
    TPM2B_ECC_PARAMETER *target, BYTE **buffer, INT32 *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    if (rc == TPM_RC_SUCCESS)
    {
        rc = UINT16_Unmarshal((UINT16*)&target->t.size, buffer, size );
    }
// if size is zero, then the structure is a zero buffer
    if(target->t.size == 0)
        return TPM_RC_SUCCESS;
    if((target->t.size) > MAX_ECC_KEY_BYTES)
        return TPM_RC_SIZE;
    if (rc == TPM_RC_SUCCESS)
    {
        rc = BYTE_Array_Unmarshal((BYTE*)target->t.buffer, buffer, size , (INT32)(target->t.size));
    }
    return rc;
}

UINT16
TPM2B_ECC_PARAMETER_Marshal(
    TPM2B_ECC_PARAMETER *source, BYTE **buffer, INT32 *size)
{
    UINT16 written = 0;
    written += UINT16_Marshal((UINT16*)&(source->t.size), buffer, size );
    if(source->t.size == 0)
        return written;

    written += BYTE_Array_Marshal((BYTE*)(source->t.buffer), buffer, size , (INT32)(source->t.size));
    return written;
}

#endif // TPM_ALG_ECC


// Table 2:162 - Definition of {ECC} TPMS_ECC_POINT Structure (StructureTable)
#ifdef TPM_ALG_ECC
TPM_RC
TPMS_ECC_POINT_Unmarshal(
    TPMS_ECC_POINT *target, BYTE **buffer, INT32 *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    if (rc == TPM_RC_SUCCESS)
    {
        rc = TPM2B_ECC_PARAMETER_Unmarshal((TPM2B_ECC_PARAMETER*)&target->x, buffer, size );
    }
    if (rc == TPM_RC_SUCCESS)
    {
        rc = TPM2B_ECC_PARAMETER_Unmarshal((TPM2B_ECC_PARAMETER*)&target->y, buffer, size );
    }
    return rc;
}

UINT16
TPMS_ECC_POINT_Marshal(
    TPMS_ECC_POINT *source, BYTE **buffer, INT32 *size)
{
    UINT16 written = 0;
    written += TPM2B_ECC_PARAMETER_Marshal((TPM2B_ECC_PARAMETER*)&(source->x), buffer, size );
    written += TPM2B_ECC_PARAMETER_Marshal((TPM2B_ECC_PARAMETER*)&(source->y), buffer, size );
    return written;
}

#endif // TPM_ALG_ECC


// Table 2:163 - Definition of {ECC} TPM2B_ECC_POINT Structure (StructureTable)
#ifdef TPM_ALG_ECC
TPM_RC
TPM2B_ECC_POINT_Unmarshal(
    TPM2B_ECC_POINT *target, BYTE **buffer, INT32 *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    INT32 startSize;
    if (rc == TPM_RC_SUCCESS)
    {
        rc = UINT16_Unmarshal((UINT16*)&target->t.size, buffer, size );
    }
// if size is zero, then the structure is a zero buffer
    if(target->t.size == 0)
        return TPM_RC_SIZE;
    startSize = *size;
    if (rc == TPM_RC_SUCCESS)
    {
        rc = TPMS_ECC_POINT_Unmarshal((TPMS_ECC_POINT*)&target->t.point, buffer, size );
    }

    if (rc == TPM_RC_SUCCESS)
    {
        if(target->t.size != (startSize - *size)) return TPM_RC_SIZE;
    }
    return TPM_RC_SUCCESS;
}

UINT16
TPM2B_ECC_POINT_Marshal(
    TPM2B_ECC_POINT *source, BYTE **buffer, INT32 *size)
{
    UINT16 written = 0;
    BYTE *sizeField = *buffer;
    *buffer += 2;
    written += TPMS_ECC_POINT_Marshal((TPMS_ECC_POINT*)&(source->t.point), buffer, size );
    written += UINT16_Marshal(&written, &sizeField, size);
    return written;
}

#endif // TPM_ALG_ECC


// Table 2:164 - Definition of (TPM_ALG_ID) {ECC} TPMI_ALG_ECC_SCHEME Type (InterfaceTable)
#ifdef TPM_ALG_ECC
TPM_RC
TPMI_ALG_ECC_SCHEME_Unmarshal(
    TPMI_ALG_ECC_SCHEME *target, BYTE **buffer, INT32 *size, BOOL allowNull)
{
    TPM_RC rc;
    rc = TPM_ALG_ID_Unmarshal((TPM_ALG_ID *)target, buffer, size);

    if (rc == TPM_RC_SUCCESS) // if unmarshalling succeeds
    {
        switch (*target)
        {
#ifdef TPM_ALG_ECDSA
        case TPM_ALG_ECDSA:
#endif // TPM_ALG_ECDSA
#ifdef TPM_ALG_SM2
        case TPM_ALG_SM2:
#endif // TPM_ALG_SM2
#ifdef TPM_ALG_ECSCHNORR
        case TPM_ALG_ECSCHNORR:
#endif // TPM_ALG_ECSCHNORR
#ifdef TPM_ALG_ECDAA
        case TPM_ALG_ECDAA:
#endif // TPM_ALG_ECDAA
#ifdef TPM_ALG_ECDH
        case TPM_ALG_ECDH:
#endif // TPM_ALG_ECDH
#ifdef TPM_ALG_ECMQV
        case TPM_ALG_ECMQV:
#endif // TPM_ALG_ECMQV
            break;
        case TPM_ALG_NULL:
            if (!allowNull)
                rc = TPM_RC_SCHEME;
            break;
        default:
            rc = TPM_RC_SCHEME;
        }
    }
    return rc;
}

// TPMI_ALG_ECC_SCHEME_Marshal changed to #define
#endif // TPM_ALG_ECC


// Table 2:165 - Definition of {ECC} (TPM_ECC_CURVE) TPMI_ECC_CURVE Type (InterfaceTable)
#ifdef TPM_ALG_ECC
TPM_RC
TPMI_ECC_CURVE_Unmarshal(
    TPMI_ECC_CURVE *target, BYTE **buffer, INT32 *size)
{
    TPM_RC rc;
    rc = TPM_ECC_CURVE_Unmarshal((TPM_ECC_CURVE *)target, buffer, size);

    if (rc == TPM_RC_SUCCESS) // if unmarshalling succeeds
    {
        switch (*target)
        {
        case TPM_ECC_BN_P256:
        case TPM_ECC_NIST_P256:
        case TPM_ECC_NIST_P384:

            break;

        default:
            rc = TPM_RC_CURVE;
        }
    }
    return rc;
}

// TPMI_ECC_CURVE_Marshal changed to #define
#endif // TPM_ALG_ECC


// Table 2:166 - Definition of (TPMT_SIG_SCHEME) {ECC} TPMT_ECC_SCHEME Structure (StructureTable)
#ifdef TPM_ALG_ECC
TPM_RC
TPMT_ECC_SCHEME_Unmarshal(
    TPMT_ECC_SCHEME *target, BYTE **buffer, INT32 *size, BOOL allowNull)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    if (rc == TPM_RC_SUCCESS)
    {
        rc = TPMI_ALG_ECC_SCHEME_Unmarshal((TPMI_ALG_ECC_SCHEME*)&target->scheme, buffer, size , allowNull);
    }
    if (rc == TPM_RC_SUCCESS)
    {
        rc = TPMU_ASYM_SCHEME_Unmarshal((TPMU_ASYM_SCHEME*)&target->details, buffer, size , (UINT32)(target->scheme));
    }
    return rc;
}

UINT16
TPMT_ECC_SCHEME_Marshal(
    TPMT_ECC_SCHEME *source, BYTE **buffer, INT32 *size)
{
    UINT16 written = 0;
    written += TPMI_ALG_ECC_SCHEME_Marshal((TPMI_ALG_ECC_SCHEME*)&(source->scheme), buffer, size );
    written += TPMU_ASYM_SCHEME_Marshal((TPMU_ASYM_SCHEME*)&(source->details), buffer, size , (UINT32)(source->scheme));
    return written;
}

#endif // TPM_ALG_ECC


// Table 2:167 - Definition of {ECC} TPMS_ALGORITHM_DETAIL_ECC Structure (StructureTable)
#ifdef TPM_ALG_ECC
// TPMS_ALGORITHM_DETAIL_ECC_Unmarshal not required
UINT16
TPMS_ALGORITHM_DETAIL_ECC_Marshal(
    TPMS_ALGORITHM_DETAIL_ECC *source, BYTE **buffer, INT32 *size)
{
    UINT16 written = 0;
    written += TPM_ECC_CURVE_Marshal((TPM_ECC_CURVE*)&(source->curveID), buffer, size );
    written += UINT16_Marshal((UINT16*)&(source->keySize), buffer, size );
    written += TPMT_KDF_SCHEME_Marshal((TPMT_KDF_SCHEME*)&(source->kdf), buffer, size );
    written += TPMT_ECC_SCHEME_Marshal((TPMT_ECC_SCHEME*)&(source->sign), buffer, size );
    written += TPM2B_ECC_PARAMETER_Marshal((TPM2B_ECC_PARAMETER*)&(source->p), buffer, size );
    written += TPM2B_ECC_PARAMETER_Marshal((TPM2B_ECC_PARAMETER*)&(source->a), buffer, size );
    written += TPM2B_ECC_PARAMETER_Marshal((TPM2B_ECC_PARAMETER*)&(source->b), buffer, size );
    written += TPM2B_ECC_PARAMETER_Marshal((TPM2B_ECC_PARAMETER*)&(source->gX), buffer, size );
    written += TPM2B_ECC_PARAMETER_Marshal((TPM2B_ECC_PARAMETER*)&(source->gY), buffer, size );
    written += TPM2B_ECC_PARAMETER_Marshal((TPM2B_ECC_PARAMETER*)&(source->n), buffer, size );
    written += TPM2B_ECC_PARAMETER_Marshal((TPM2B_ECC_PARAMETER*)&(source->h), buffer, size );
    return written;
}

#endif // TPM_ALG_ECC


// Table 2:168 - Definition of {RSA} TPMS_SIGNATURE_RSA Structure (StructureTable)
#ifdef TPM_ALG_RSA
TPM_RC
TPMS_SIGNATURE_RSA_Unmarshal(
    TPMS_SIGNATURE_RSA *target, BYTE **buffer, INT32 *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    if (rc == TPM_RC_SUCCESS)
    {
        rc = TPMI_ALG_HASH_Unmarshal((TPMI_ALG_HASH*)&target->hash, buffer, size , 0);
    }
    if (rc == TPM_RC_SUCCESS)
    {
        rc = TPM2B_PUBLIC_KEY_RSA_Unmarshal((TPM2B_PUBLIC_KEY_RSA*)&target->sig, buffer, size );
    }
    return rc;
}

UINT16
TPMS_SIGNATURE_RSA_Marshal(
    TPMS_SIGNATURE_RSA *source, BYTE **buffer, INT32 *size)
{
    UINT16 written = 0;
    written += TPMI_ALG_HASH_Marshal((TPMI_ALG_HASH*)&(source->hash), buffer, size );
    written += TPM2B_PUBLIC_KEY_RSA_Marshal((TPM2B_PUBLIC_KEY_RSA*)&(source->sig), buffer, size );
    return written;
}

#endif // TPM_ALG_RSA


// Table 2:169 - Definition of Types for {RSA} Signature (TypedefTable)
#ifdef TPM_ALG_RSA
// TPMS_SIGNATURE_RSA definition used from Table 2:168
// TPMS_SIGNATURE_RSASSA_Unmarshal changed to #define
// TPMS_SIGNATURE_RSASSA_Marshal changed to #define
#endif // TPM_ALG_RSA


#ifdef TPM_ALG_RSA
// TPMS_SIGNATURE_RSA definition used from Table 2:168
// TPMS_SIGNATURE_RSAPSS_Unmarshal changed to #define
// TPMS_SIGNATURE_RSAPSS_Marshal changed to #define
#endif // TPM_ALG_RSA



// Table 2:170 - Definition of {ECC} TPMS_SIGNATURE_ECC Structure (StructureTable)
#ifdef TPM_ALG_ECC
TPM_RC
TPMS_SIGNATURE_ECC_Unmarshal(
    TPMS_SIGNATURE_ECC *target, BYTE **buffer, INT32 *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    if (rc == TPM_RC_SUCCESS)
    {
        rc = TPMI_ALG_HASH_Unmarshal((TPMI_ALG_HASH*)&target->hash, buffer, size , 0);
    }
    if (rc == TPM_RC_SUCCESS)
    {
        rc = TPM2B_ECC_PARAMETER_Unmarshal((TPM2B_ECC_PARAMETER*)&target->signatureR, buffer, size );
    }
    if (rc == TPM_RC_SUCCESS)
    {
        rc = TPM2B_ECC_PARAMETER_Unmarshal((TPM2B_ECC_PARAMETER*)&target->signatureS, buffer, size );
    }
    return rc;
}

UINT16
TPMS_SIGNATURE_ECC_Marshal(
    TPMS_SIGNATURE_ECC *source, BYTE **buffer, INT32 *size)
{
    UINT16 written = 0;
    written += TPMI_ALG_HASH_Marshal((TPMI_ALG_HASH*)&(source->hash), buffer, size );
    written += TPM2B_ECC_PARAMETER_Marshal((TPM2B_ECC_PARAMETER*)&(source->signatureR), buffer, size );
    written += TPM2B_ECC_PARAMETER_Marshal((TPM2B_ECC_PARAMETER*)&(source->signatureS), buffer, size );
    return written;
}

#endif // TPM_ALG_ECC


// Table 2:171 - Definition of Types for {ECC} TPMS_SIGNATUE_ECC (TypedefTable)
#ifdef TPM_ALG_ECC
// TPMS_SIGNATURE_ECC definition used from Table 2:170
// TPMS_SIGNATURE_ECDSA_Unmarshal changed to #define
// TPMS_SIGNATURE_ECDSA_Marshal changed to #define
#endif // TPM_ALG_ECC


#ifdef TPM_ALG_ECC
// TPMS_SIGNATURE_ECC definition used from Table 2:170
// TPMS_SIGNATURE_SM2_Unmarshal changed to #define
// TPMS_SIGNATURE_SM2_Marshal changed to #define
#endif // TPM_ALG_ECC


#ifdef TPM_ALG_ECC
// TPMS_SIGNATURE_ECC definition used from Table 2:170
// TPMS_SIGNATURE_ECSCHNORR_Unmarshal changed to #define
// TPMS_SIGNATURE_ECSCHNORR_Marshal changed to #define
#endif // TPM_ALG_ECC


#ifdef TPM_ALG_ECC
// TPMS_SIGNATURE_ECC definition used from Table 2:170
// TPMS_SIGNATURE_ECDAA_Unmarshal changed to #define
// TPMS_SIGNATURE_ECDAA_Marshal changed to #define
#endif // TPM_ALG_ECC



// Table 2:172 - Definition of TPMU_SIGNATURE Union (UnionTable)
TPM_RC
TPMU_SIGNATURE_Unmarshal(
    TPMU_SIGNATURE *target, BYTE **buffer, INT32 *size, UINT32 selector)
{
    switch (selector)
    {
#ifdef TPM_ALG_RSASSA
    case TPM_ALG_RSASSA:
        return TPMS_SIGNATURE_RSASSA_Unmarshal((TPMS_SIGNATURE_RSASSA*)&(target->rsassa), buffer, size );
#endif // TPM_ALG_RSASSA
#ifdef TPM_ALG_RSAPSS
    case TPM_ALG_RSAPSS:
        return TPMS_SIGNATURE_RSAPSS_Unmarshal((TPMS_SIGNATURE_RSAPSS*)&(target->rsapss), buffer, size );
#endif // TPM_ALG_RSAPSS
#ifdef TPM_ALG_ECDSA
    case TPM_ALG_ECDSA:
        return TPMS_SIGNATURE_ECDSA_Unmarshal((TPMS_SIGNATURE_ECDSA*)&(target->ecdsa), buffer, size );
#endif // TPM_ALG_ECDSA
#ifdef TPM_ALG_SM2
    case TPM_ALG_SM2:
        return TPMS_SIGNATURE_SM2_Unmarshal((TPMS_SIGNATURE_SM2*)&(target->sm2), buffer, size );
#endif // TPM_ALG_SM2
#ifdef TPM_ALG_ECSCHNORR
    case TPM_ALG_ECSCHNORR:
        return TPMS_SIGNATURE_ECSCHNORR_Unmarshal((TPMS_SIGNATURE_ECSCHNORR*)&(target->ecschnorr), buffer, size );
#endif // TPM_ALG_ECSCHNORR
#ifdef TPM_ALG_ECDAA
    case TPM_ALG_ECDAA:
        return TPMS_SIGNATURE_ECDAA_Unmarshal((TPMS_SIGNATURE_ECDAA*)&(target->ecdaa), buffer, size );
#endif // TPM_ALG_ECDAA
#ifdef TPM_ALG_HMAC
    case TPM_ALG_HMAC:
        return TPMT_HA_Unmarshal((TPMT_HA*)&(target->hmac), buffer, size , 0);
#endif // TPM_ALG_HMAC

    case TPM_ALG_NULL:
        return TPM_RC_SUCCESS;
    }
    return TPM_RC_SELECTOR;
}

UINT16
TPMU_SIGNATURE_Marshal(
    TPMU_SIGNATURE *source, BYTE **buffer, INT32 *size, UINT32 selector
)
{
    switch (selector)
    {
#ifdef TPM_ALG_RSASSA
    case TPM_ALG_RSASSA:
        return TPMS_SIGNATURE_RSASSA_Marshal((TPMS_SIGNATURE_RSASSA*)&(source->rsassa), buffer, size );
#endif // TPM_ALG_RSASSA
#ifdef TPM_ALG_RSAPSS
    case TPM_ALG_RSAPSS:
        return TPMS_SIGNATURE_RSAPSS_Marshal((TPMS_SIGNATURE_RSAPSS*)&(source->rsapss), buffer, size );
#endif // TPM_ALG_RSAPSS
#ifdef TPM_ALG_ECDSA
    case TPM_ALG_ECDSA:
        return TPMS_SIGNATURE_ECDSA_Marshal((TPMS_SIGNATURE_ECDSA*)&(source->ecdsa), buffer, size );
#endif // TPM_ALG_ECDSA
#ifdef TPM_ALG_SM2
    case TPM_ALG_SM2:
        return TPMS_SIGNATURE_SM2_Marshal((TPMS_SIGNATURE_SM2*)&(source->sm2), buffer, size );
#endif // TPM_ALG_SM2
#ifdef TPM_ALG_ECSCHNORR
    case TPM_ALG_ECSCHNORR:
        return TPMS_SIGNATURE_ECSCHNORR_Marshal((TPMS_SIGNATURE_ECSCHNORR*)&(source->ecschnorr), buffer, size );
#endif // TPM_ALG_ECSCHNORR
#ifdef TPM_ALG_ECDAA
    case TPM_ALG_ECDAA:
        return TPMS_SIGNATURE_ECDAA_Marshal((TPMS_SIGNATURE_ECDAA*)&(source->ecdaa), buffer, size );
#endif // TPM_ALG_ECDAA
#ifdef TPM_ALG_HMAC
    case TPM_ALG_HMAC:
        return TPMT_HA_Marshal((TPMT_HA*)&(source->hmac), buffer, size );
#endif // TPM_ALG_HMAC

    case TPM_ALG_NULL:
        return 0;
    }
    return 0;
}


// Table 2:173 - Definition of TPMT_SIGNATURE Structure (StructureTable)
TPM_RC
TPMT_SIGNATURE_Unmarshal(
    TPMT_SIGNATURE *target, BYTE **buffer, INT32 *size, BOOL allowNull)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    if (rc == TPM_RC_SUCCESS)
    {
        rc = TPMI_ALG_SIG_SCHEME_Unmarshal((TPMI_ALG_SIG_SCHEME*)&target->sigAlg, buffer, size , allowNull);
    }
    if (rc == TPM_RC_SUCCESS)
    {
        rc = TPMU_SIGNATURE_Unmarshal((TPMU_SIGNATURE*)&target->signature, buffer, size , (UINT32)(target->sigAlg));
    }
    return rc;
}

UINT16
TPMT_SIGNATURE_Marshal(
    TPMT_SIGNATURE *source, BYTE **buffer, INT32 *size)
{
    UINT16 written = 0;
    written += TPMI_ALG_SIG_SCHEME_Marshal((TPMI_ALG_SIG_SCHEME*)&(source->sigAlg), buffer, size );
    written += TPMU_SIGNATURE_Marshal((TPMU_SIGNATURE*)&(source->signature), buffer, size , (UINT32)(source->sigAlg));
    return written;
}


// Table 2:174 - Definition of TPMU_ENCRYPTED_SECRET Union (UnionTable)
// TPMU_ENCRYPTED_SECRET_Unmarshal not required
// TPMU_ENCRYPTED_SECRET_Marshal not required

// Table 2:175 - Definition of TPM2B_ENCRYPTED_SECRET Structure (StructureTable)
TPM_RC
TPM2B_ENCRYPTED_SECRET_Unmarshal(
    TPM2B_ENCRYPTED_SECRET *target, BYTE **buffer, INT32 *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    if (rc == TPM_RC_SUCCESS)
    {
        rc = UINT16_Unmarshal((UINT16*)&target->t.size, buffer, size );
    }
// if size is zero, then the structure is a zero buffer
    if(target->t.size == 0)
        return TPM_RC_SUCCESS;
    if((target->t.size) > sizeof(TPMU_ENCRYPTED_SECRET))
        return TPM_RC_SIZE;
    if (rc == TPM_RC_SUCCESS)
    {
        rc = BYTE_Array_Unmarshal((BYTE*)target->t.secret, buffer, size , (INT32)(target->t.size));
    }
    return rc;
}

UINT16
TPM2B_ENCRYPTED_SECRET_Marshal(
    TPM2B_ENCRYPTED_SECRET *source, BYTE **buffer, INT32 *size)
{
    UINT16 written = 0;
    written += UINT16_Marshal((UINT16*)&(source->t.size), buffer, size );
    if(source->t.size == 0)
        return written;

    written += BYTE_Array_Marshal((BYTE*)(source->t.secret), buffer, size , (INT32)(source->t.size));
    return written;
}


// Table 2:176 - Definition of (TPM_ALG_ID) TPMI_ALG_PUBLIC Type (InterfaceTable)
TPM_RC
TPMI_ALG_PUBLIC_Unmarshal(
    TPMI_ALG_PUBLIC *target, BYTE **buffer, INT32 *size)
{
    TPM_RC rc;
    rc = TPM_ALG_ID_Unmarshal((TPM_ALG_ID *)target, buffer, size);

    if (rc == TPM_RC_SUCCESS) // if unmarshalling succeeds
    {
        switch (*target)
        {
#ifdef TPM_ALG_RSA
        case TPM_ALG_RSA:
#endif // TPM_ALG_RSA
#ifdef TPM_ALG_KEYEDHASH
        case TPM_ALG_KEYEDHASH:
#endif // TPM_ALG_KEYEDHASH
#ifdef TPM_ALG_ECC
        case TPM_ALG_ECC:
#endif // TPM_ALG_ECC
#ifdef TPM_ALG_SYMCIPHER
        case TPM_ALG_SYMCIPHER:
#endif // TPM_ALG_SYMCIPHER
            break;

        default:
            rc = TPM_RC_TYPE;
        }
    }
    return rc;
}

// TPMI_ALG_PUBLIC_Marshal changed to #define

// Table 2:177 - Definition of TPMU_PUBLIC_ID Union (UnionTable)
TPM_RC
TPMU_PUBLIC_ID_Unmarshal(
    TPMU_PUBLIC_ID *target, BYTE **buffer, INT32 *size, UINT32 selector)
{
    switch (selector)
    {
#ifdef TPM_ALG_KEYEDHASH
    case TPM_ALG_KEYEDHASH:
        return TPM2B_DIGEST_Unmarshal((TPM2B_DIGEST*)&(target->keyedHash), buffer, size );
#endif // TPM_ALG_KEYEDHASH
#ifdef TPM_ALG_SYMCIPHER
    case TPM_ALG_SYMCIPHER:
        return TPM2B_DIGEST_Unmarshal((TPM2B_DIGEST*)&(target->sym), buffer, size );
#endif // TPM_ALG_SYMCIPHER
#ifdef TPM_ALG_RSA
    case TPM_ALG_RSA:
        return TPM2B_PUBLIC_KEY_RSA_Unmarshal((TPM2B_PUBLIC_KEY_RSA*)&(target->rsa), buffer, size );
#endif // TPM_ALG_RSA
#ifdef TPM_ALG_ECC
    case TPM_ALG_ECC:
        return TPMS_ECC_POINT_Unmarshal((TPMS_ECC_POINT*)&(target->ecc), buffer, size );
#endif // TPM_ALG_ECC


    }
    return TPM_RC_SELECTOR;
}

UINT16
TPMU_PUBLIC_ID_Marshal(
    TPMU_PUBLIC_ID *source, BYTE **buffer, INT32 *size, UINT32 selector
)
{
    switch (selector)
    {
#ifdef TPM_ALG_KEYEDHASH
    case TPM_ALG_KEYEDHASH:
        return TPM2B_DIGEST_Marshal((TPM2B_DIGEST*)&(source->keyedHash), buffer, size );
#endif // TPM_ALG_KEYEDHASH
#ifdef TPM_ALG_SYMCIPHER
    case TPM_ALG_SYMCIPHER:
        return TPM2B_DIGEST_Marshal((TPM2B_DIGEST*)&(source->sym), buffer, size );
#endif // TPM_ALG_SYMCIPHER
#ifdef TPM_ALG_RSA
    case TPM_ALG_RSA:
        return TPM2B_PUBLIC_KEY_RSA_Marshal((TPM2B_PUBLIC_KEY_RSA*)&(source->rsa), buffer, size );
#endif // TPM_ALG_RSA
#ifdef TPM_ALG_ECC
    case TPM_ALG_ECC:
        return TPMS_ECC_POINT_Marshal((TPMS_ECC_POINT*)&(source->ecc), buffer, size );
#endif // TPM_ALG_ECC


    }
    return 0;
}


// Table 2:178 - Definition of TPMS_KEYEDHASH_PARMS Structure (StructureTable)
// TPMS_KEYEDHASH_PARMS_Unmarshal changed to #define
// TPMS_KEYEDHASH_PARMS_Marshal changed to #define

// Table 2:179 - Definition of TPMS_ASYM_PARMS Structure (StructureTable)
// TPMS_ASYM_PARMS_Unmarshal not required
// TPMS_ASYM_PARMS_Marshal not required

// Table 2:180 - Definition of {RSA} TPMS_RSA_PARMS Structure (StructureTable)
#ifdef TPM_ALG_RSA
TPM_RC
TPMS_RSA_PARMS_Unmarshal(
    TPMS_RSA_PARMS *target, BYTE **buffer, INT32 *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    if (rc == TPM_RC_SUCCESS)
    {
        rc = TPMT_SYM_DEF_OBJECT_Unmarshal((TPMT_SYM_DEF_OBJECT*)&target->symmetric, buffer, size , 1);
    }
    if (rc == TPM_RC_SUCCESS)
    {
        rc = TPMT_RSA_SCHEME_Unmarshal((TPMT_RSA_SCHEME*)&target->scheme, buffer, size , 1);
    }
    if (rc == TPM_RC_SUCCESS)
    {
        rc = TPMI_RSA_KEY_BITS_Unmarshal((TPMI_RSA_KEY_BITS*)&target->keyBits, buffer, size );
    }
    if (rc == TPM_RC_SUCCESS)
    {
        rc = UINT32_Unmarshal((UINT32*)&target->exponent, buffer, size );
    }
    return rc;
}

UINT16
TPMS_RSA_PARMS_Marshal(
    TPMS_RSA_PARMS *source, BYTE **buffer, INT32 *size)
{
    UINT16 written = 0;
    written += TPMT_SYM_DEF_OBJECT_Marshal((TPMT_SYM_DEF_OBJECT*)&(source->symmetric), buffer, size );
    written += TPMT_RSA_SCHEME_Marshal((TPMT_RSA_SCHEME*)&(source->scheme), buffer, size );
    written += TPMI_RSA_KEY_BITS_Marshal((TPMI_RSA_KEY_BITS*)&(source->keyBits), buffer, size );
    written += UINT32_Marshal((UINT32*)&(source->exponent), buffer, size );
    return written;
}

#endif // TPM_ALG_RSA


// Table 2:181 - Definition of {ECC} TPMS_ECC_PARMS Structure (StructureTable)
#ifdef TPM_ALG_ECC
TPM_RC
TPMS_ECC_PARMS_Unmarshal(
    TPMS_ECC_PARMS *target, BYTE **buffer, INT32 *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    if (rc == TPM_RC_SUCCESS)
    {
        rc = TPMT_SYM_DEF_OBJECT_Unmarshal((TPMT_SYM_DEF_OBJECT*)&target->symmetric, buffer, size , 1);
    }
    if (rc == TPM_RC_SUCCESS)
    {
        rc = TPMT_ECC_SCHEME_Unmarshal((TPMT_ECC_SCHEME*)&target->scheme, buffer, size , 1);
    }
    if (rc == TPM_RC_SUCCESS)
    {
        rc = TPMI_ECC_CURVE_Unmarshal((TPMI_ECC_CURVE*)&target->curveID, buffer, size );
    }
    if (rc == TPM_RC_SUCCESS)
    {
        rc = TPMT_KDF_SCHEME_Unmarshal((TPMT_KDF_SCHEME*)&target->kdf, buffer, size , 1);
    }
    return rc;
}

UINT16
TPMS_ECC_PARMS_Marshal(
    TPMS_ECC_PARMS *source, BYTE **buffer, INT32 *size)
{
    UINT16 written = 0;
    written += TPMT_SYM_DEF_OBJECT_Marshal((TPMT_SYM_DEF_OBJECT*)&(source->symmetric), buffer, size );
    written += TPMT_ECC_SCHEME_Marshal((TPMT_ECC_SCHEME*)&(source->scheme), buffer, size );
    written += TPMI_ECC_CURVE_Marshal((TPMI_ECC_CURVE*)&(source->curveID), buffer, size );
    written += TPMT_KDF_SCHEME_Marshal((TPMT_KDF_SCHEME*)&(source->kdf), buffer, size );
    return written;
}

#endif // TPM_ALG_ECC


// Table 2:182 - Definition of TPMU_PUBLIC_PARMS Union (UnionTable)
TPM_RC
TPMU_PUBLIC_PARMS_Unmarshal(
    TPMU_PUBLIC_PARMS *target, BYTE **buffer, INT32 *size, UINT32 selector)
{
    switch (selector)
    {
#ifdef TPM_ALG_KEYEDHASH
    case TPM_ALG_KEYEDHASH:
        return TPMS_KEYEDHASH_PARMS_Unmarshal((TPMS_KEYEDHASH_PARMS*)&(target->keyedHashDetail), buffer, size );
#endif // TPM_ALG_KEYEDHASH
#ifdef TPM_ALG_SYMCIPHER
    case TPM_ALG_SYMCIPHER:
        return TPMS_SYMCIPHER_PARMS_Unmarshal((TPMS_SYMCIPHER_PARMS*)&(target->symDetail), buffer, size );
#endif // TPM_ALG_SYMCIPHER
#ifdef TPM_ALG_RSA
    case TPM_ALG_RSA:
        return TPMS_RSA_PARMS_Unmarshal((TPMS_RSA_PARMS*)&(target->rsaDetail), buffer, size );
#endif // TPM_ALG_RSA
#ifdef TPM_ALG_ECC
    case TPM_ALG_ECC:
        return TPMS_ECC_PARMS_Unmarshal((TPMS_ECC_PARMS*)&(target->eccDetail), buffer, size );
#endif // TPM_ALG_ECC


    }
    return TPM_RC_SELECTOR;
}

UINT16
TPMU_PUBLIC_PARMS_Marshal(
    TPMU_PUBLIC_PARMS *source, BYTE **buffer, INT32 *size, UINT32 selector
)
{
    switch (selector)
    {
#ifdef TPM_ALG_KEYEDHASH
    case TPM_ALG_KEYEDHASH:
        return TPMS_KEYEDHASH_PARMS_Marshal((TPMS_KEYEDHASH_PARMS*)&(source->keyedHashDetail), buffer, size );
#endif // TPM_ALG_KEYEDHASH
#ifdef TPM_ALG_SYMCIPHER
    case TPM_ALG_SYMCIPHER:
        return TPMS_SYMCIPHER_PARMS_Marshal((TPMS_SYMCIPHER_PARMS*)&(source->symDetail), buffer, size );
#endif // TPM_ALG_SYMCIPHER
#ifdef TPM_ALG_RSA
    case TPM_ALG_RSA:
        return TPMS_RSA_PARMS_Marshal((TPMS_RSA_PARMS*)&(source->rsaDetail), buffer, size );
#endif // TPM_ALG_RSA
#ifdef TPM_ALG_ECC
    case TPM_ALG_ECC:
        return TPMS_ECC_PARMS_Marshal((TPMS_ECC_PARMS*)&(source->eccDetail), buffer, size );
#endif // TPM_ALG_ECC


    }
    return 0;
}


// Table 2:183 - Definition of TPMT_PUBLIC_PARMS Structure (StructureTable)
TPM_RC
TPMT_PUBLIC_PARMS_Unmarshal(
    TPMT_PUBLIC_PARMS *target, BYTE **buffer, INT32 *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    if (rc == TPM_RC_SUCCESS)
    {
        rc = TPMI_ALG_PUBLIC_Unmarshal((TPMI_ALG_PUBLIC*)&target->type, buffer, size );
    }
    if (rc == TPM_RC_SUCCESS)
    {
        rc = TPMU_PUBLIC_PARMS_Unmarshal((TPMU_PUBLIC_PARMS*)&target->parameters, buffer, size , (UINT32)(target->type));
    }
    return rc;
}

UINT16
TPMT_PUBLIC_PARMS_Marshal(
    TPMT_PUBLIC_PARMS *source, BYTE **buffer, INT32 *size)
{
    UINT16 written = 0;
    written += TPMI_ALG_PUBLIC_Marshal((TPMI_ALG_PUBLIC*)&(source->type), buffer, size );
    written += TPMU_PUBLIC_PARMS_Marshal((TPMU_PUBLIC_PARMS*)&(source->parameters), buffer, size , (UINT32)(source->type));
    return written;
}


// Table 2:184 - Definition of TPMT_PUBLIC Structure (StructureTable)
TPM_RC
TPMT_PUBLIC_Unmarshal(
    TPMT_PUBLIC *target, BYTE **buffer, INT32 *size, BOOL allowNull)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    if (rc == TPM_RC_SUCCESS)
    {
        rc = TPMI_ALG_PUBLIC_Unmarshal((TPMI_ALG_PUBLIC*)&target->type, buffer, size );
    }
    if (rc == TPM_RC_SUCCESS)
    {
        rc = TPMI_ALG_HASH_Unmarshal((TPMI_ALG_HASH*)&target->nameAlg, buffer, size , allowNull);
    }
    if (rc == TPM_RC_SUCCESS)
    {
        rc = TPMA_OBJECT_Unmarshal((TPMA_OBJECT*)&target->objectAttributes, buffer, size );
    }
    if (rc == TPM_RC_SUCCESS)
    {
        rc = TPM2B_DIGEST_Unmarshal((TPM2B_DIGEST*)&target->authPolicy, buffer, size );
    }
    if (rc == TPM_RC_SUCCESS)
    {
        rc = TPMU_PUBLIC_PARMS_Unmarshal((TPMU_PUBLIC_PARMS*)&target->parameters, buffer, size , (UINT32)(target->type));
    }
    if (rc == TPM_RC_SUCCESS)
    {
        rc = TPMU_PUBLIC_ID_Unmarshal((TPMU_PUBLIC_ID*)&target->unique, buffer, size , (UINT32)(target->type));
    }
    return rc;
}

UINT16
TPMT_PUBLIC_Marshal(
    TPMT_PUBLIC *source, BYTE **buffer, INT32 *size)
{
    UINT16 written = 0;
    written += TPMI_ALG_PUBLIC_Marshal((TPMI_ALG_PUBLIC*)&(source->type), buffer, size );
    written += TPMI_ALG_HASH_Marshal((TPMI_ALG_HASH*)&(source->nameAlg), buffer, size );
    written += TPMA_OBJECT_Marshal((TPMA_OBJECT*)&(source->objectAttributes), buffer, size );
    written += TPM2B_DIGEST_Marshal((TPM2B_DIGEST*)&(source->authPolicy), buffer, size );
    written += TPMU_PUBLIC_PARMS_Marshal((TPMU_PUBLIC_PARMS*)&(source->parameters), buffer, size , (UINT32)(source->type));
    written += TPMU_PUBLIC_ID_Marshal((TPMU_PUBLIC_ID*)&(source->unique), buffer, size , (UINT32)(source->type));
    return written;
}


// Table 2:185 - Definition of TPM2B_PUBLIC Structure (StructureTable)
TPM_RC
TPM2B_PUBLIC_Unmarshal(
    TPM2B_PUBLIC *target, BYTE **buffer, INT32 *size, BOOL allowNull)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    INT32 startSize;
    if (rc == TPM_RC_SUCCESS)
    {
        rc = UINT16_Unmarshal((UINT16*)&target->t.size, buffer, size );
    }
// if size is zero, then the structure is a zero buffer
    if(target->t.size == 0)
        return TPM_RC_SIZE;
    startSize = *size;
    if (rc == TPM_RC_SUCCESS)
    {
        rc = TPMT_PUBLIC_Unmarshal((TPMT_PUBLIC*)&target->t.publicArea, buffer, size , allowNull);
    }

    if (rc == TPM_RC_SUCCESS)
    {
        if(target->t.size != (startSize - *size)) return TPM_RC_SIZE;
    }
    return TPM_RC_SUCCESS;
}

UINT16
TPM2B_PUBLIC_Marshal(
    TPM2B_PUBLIC *source, BYTE **buffer, INT32 *size)
{
    UINT16 written = 0;
    BYTE *sizeField = *buffer;
    *buffer += 2;
    written += TPMT_PUBLIC_Marshal((TPMT_PUBLIC*)&(source->t.publicArea), buffer, size );
    written += UINT16_Marshal(&written, &sizeField, size);
    return written;
}


// Table 2:186 - Definition of TPM2B_PRIVATE_VENDOR_SPECIFIC Structure (StructureTable)
// TPM2B_PRIVATE_VENDOR_SPECIFIC_Unmarshal not required
// TPM2B_PRIVATE_VENDOR_SPECIFIC_Marshal not required

// Table 2:187 - Definition of TPMU_SENSITIVE_COMPOSITE Union (UnionTable)
TPM_RC
TPMU_SENSITIVE_COMPOSITE_Unmarshal(
    TPMU_SENSITIVE_COMPOSITE *target, BYTE **buffer, INT32 *size, UINT32 selector)
{
    switch (selector)
    {
#ifdef TPM_ALG_RSA
    case TPM_ALG_RSA:
        return TPM2B_PRIVATE_KEY_RSA_Unmarshal((TPM2B_PRIVATE_KEY_RSA*)&(target->rsa), buffer, size );
#endif // TPM_ALG_RSA
#ifdef TPM_ALG_ECC
    case TPM_ALG_ECC:
        return TPM2B_ECC_PARAMETER_Unmarshal((TPM2B_ECC_PARAMETER*)&(target->ecc), buffer, size );
#endif // TPM_ALG_ECC
#ifdef TPM_ALG_KEYEDHASH
    case TPM_ALG_KEYEDHASH:
        return TPM2B_SENSITIVE_DATA_Unmarshal((TPM2B_SENSITIVE_DATA*)&(target->bits), buffer, size );
#endif // TPM_ALG_KEYEDHASH
#ifdef TPM_ALG_SYMCIPHER
    case TPM_ALG_SYMCIPHER:
        return TPM2B_SYM_KEY_Unmarshal((TPM2B_SYM_KEY*)&(target->sym), buffer, size );
#endif // TPM_ALG_SYMCIPHER


    }
    return TPM_RC_SELECTOR;
}

UINT16
TPMU_SENSITIVE_COMPOSITE_Marshal(
    TPMU_SENSITIVE_COMPOSITE *source, BYTE **buffer, INT32 *size, UINT32 selector
)
{
    switch (selector)
    {
#ifdef TPM_ALG_RSA
    case TPM_ALG_RSA:
        return TPM2B_PRIVATE_KEY_RSA_Marshal((TPM2B_PRIVATE_KEY_RSA*)&(source->rsa), buffer, size );
#endif // TPM_ALG_RSA
#ifdef TPM_ALG_ECC
    case TPM_ALG_ECC:
        return TPM2B_ECC_PARAMETER_Marshal((TPM2B_ECC_PARAMETER*)&(source->ecc), buffer, size );
#endif // TPM_ALG_ECC
#ifdef TPM_ALG_KEYEDHASH
    case TPM_ALG_KEYEDHASH:
        return TPM2B_SENSITIVE_DATA_Marshal((TPM2B_SENSITIVE_DATA*)&(source->bits), buffer, size );
#endif // TPM_ALG_KEYEDHASH
#ifdef TPM_ALG_SYMCIPHER
    case TPM_ALG_SYMCIPHER:
        return TPM2B_SYM_KEY_Marshal((TPM2B_SYM_KEY*)&(source->sym), buffer, size );
#endif // TPM_ALG_SYMCIPHER


    }
    return 0;
}


// Table 2:188 - Definition of TPMT_SENSITIVE Structure (StructureTable)
TPM_RC
TPMT_SENSITIVE_Unmarshal(
    TPMT_SENSITIVE *target, BYTE **buffer, INT32 *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    if (rc == TPM_RC_SUCCESS)
    {
        rc = TPMI_ALG_PUBLIC_Unmarshal((TPMI_ALG_PUBLIC*)&target->sensitiveType, buffer, size );
    }
    if (rc == TPM_RC_SUCCESS)
    {
        rc = TPM2B_AUTH_Unmarshal((TPM2B_AUTH*)&target->authValue, buffer, size );
    }
    if (rc == TPM_RC_SUCCESS)
    {
        rc = TPM2B_DIGEST_Unmarshal((TPM2B_DIGEST*)&target->seedValue, buffer, size );
    }
    if (rc == TPM_RC_SUCCESS)
    {
        rc = TPMU_SENSITIVE_COMPOSITE_Unmarshal((TPMU_SENSITIVE_COMPOSITE*)&target->sensitive, buffer, size , (UINT32)(target->sensitiveType));
    }
    return rc;
}

UINT16
TPMT_SENSITIVE_Marshal(
    TPMT_SENSITIVE *source, BYTE **buffer, INT32 *size)
{
    UINT16 written = 0;
    written += TPMI_ALG_PUBLIC_Marshal((TPMI_ALG_PUBLIC*)&(source->sensitiveType), buffer, size );
    written += TPM2B_AUTH_Marshal((TPM2B_AUTH*)&(source->authValue), buffer, size );
    written += TPM2B_DIGEST_Marshal((TPM2B_DIGEST*)&(source->seedValue), buffer, size );
    written += TPMU_SENSITIVE_COMPOSITE_Marshal((TPMU_SENSITIVE_COMPOSITE*)&(source->sensitive), buffer, size , (UINT32)(source->sensitiveType));
    return written;
}


// Table 2:189 - Definition of TPM2B_SENSITIVE Structure (StructureTable)
TPM_RC
TPM2B_SENSITIVE_Unmarshal(
    TPM2B_SENSITIVE *target, BYTE **buffer, INT32 *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    INT32 startSize;
    if (rc == TPM_RC_SUCCESS)
    {
        rc = UINT16_Unmarshal((UINT16*)&target->t.size, buffer, size );
    }
// if size is zero, then the structure is a zero buffer
    if(target->t.size == 0)
        return TPM_RC_SUCCESS;
    startSize = *size;
    if (rc == TPM_RC_SUCCESS)
    {
        rc = TPMT_SENSITIVE_Unmarshal((TPMT_SENSITIVE*)&target->t.sensitiveArea, buffer, size );
    }

    if (rc == TPM_RC_SUCCESS)
    {
        if(target->t.size != (startSize - *size)) return TPM_RC_SIZE;
    }
    return TPM_RC_SUCCESS;
}

UINT16
TPM2B_SENSITIVE_Marshal(
    TPM2B_SENSITIVE *source, BYTE **buffer, INT32 *size)
{
    UINT16 written = 0;
    written += UINT16_Marshal((UINT16*)&(source->t.size), buffer, size );
    if(source->t.size == 0)
        return written;

    written += TPMT_SENSITIVE_Marshal((TPMT_SENSITIVE*)&(source->t.sensitiveArea), buffer, size );
    return written;
}


// Table 2:190 - Definition of _PRIVATE Structure (StructureTable)
// _PRIVATE_Unmarshal not required
// _PRIVATE_Marshal not required

// Table 2:191 - Definition of TPM2B_PRIVATE Structure (StructureTable)
TPM_RC
TPM2B_PRIVATE_Unmarshal(
    TPM2B_PRIVATE *target, BYTE **buffer, INT32 *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    if (rc == TPM_RC_SUCCESS)
    {
        rc = UINT16_Unmarshal((UINT16*)&target->t.size, buffer, size );
    }
// if size is zero, then the structure is a zero buffer
    if(target->t.size == 0)
        return TPM_RC_SUCCESS;
    if((target->t.size) > sizeof(_PRIVATE))
        return TPM_RC_SIZE;
    if (rc == TPM_RC_SUCCESS)
    {
        rc = BYTE_Array_Unmarshal((BYTE*)target->t.buffer, buffer, size , (INT32)(target->t.size));
    }
    return rc;
}

UINT16
TPM2B_PRIVATE_Marshal(
    TPM2B_PRIVATE *source, BYTE **buffer, INT32 *size)
{
    UINT16 written = 0;
    written += UINT16_Marshal((UINT16*)&(source->t.size), buffer, size );
    if(source->t.size == 0)
        return written;

    written += BYTE_Array_Marshal((BYTE*)(source->t.buffer), buffer, size , (INT32)(source->t.size));
    return written;
}


// Table 2:192 - Definition of _ID_OBJECT Structure (StructureTable)
// _ID_OBJECT_Unmarshal not required
// _ID_OBJECT_Marshal not required

// Table 2:193 - Definition of TPM2B_ID_OBJECT Structure (StructureTable)
TPM_RC
TPM2B_ID_OBJECT_Unmarshal(
    TPM2B_ID_OBJECT *target, BYTE **buffer, INT32 *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    if (rc == TPM_RC_SUCCESS)
    {
        rc = UINT16_Unmarshal((UINT16*)&target->t.size, buffer, size );
    }
// if size is zero, then the structure is a zero buffer
    if(target->t.size == 0)
        return TPM_RC_SUCCESS;
    if((target->t.size) > sizeof(_ID_OBJECT))
        return TPM_RC_SIZE;
    if (rc == TPM_RC_SUCCESS)
    {
        rc = BYTE_Array_Unmarshal((BYTE*)target->t.credential, buffer, size , (INT32)(target->t.size));
    }
    return rc;
}

UINT16
TPM2B_ID_OBJECT_Marshal(
    TPM2B_ID_OBJECT *source, BYTE **buffer, INT32 *size)
{
    UINT16 written = 0;
    written += UINT16_Marshal((UINT16*)&(source->t.size), buffer, size );
    if(source->t.size == 0)
        return written;

    written += BYTE_Array_Marshal((BYTE*)(source->t.credential), buffer, size , (INT32)(source->t.size));
    return written;
}


// Table 2:194 - Definition of (UINT32) TPM_NV_INDEX Bits (BitsTable)
// TPM_NV_INDEX_Unmarshal changed to #define
// TPM_NV_INDEX_Marshal changed to #define

// Table 2:195 - Definition of (UINT32) TPMA_NV Bits (BitsTable)
TPM_RC
TPMA_NV_Unmarshal(
    TPMA_NV *target, BYTE **buffer, INT32 *size)
{
    TPM_RC rc;
    rc = UINT32_Unmarshal(&target->val, buffer, size);

    if(rc == TPM_RC_SUCCESS)
        if(target->val & (UINT32)0x1f00380)
            rc = TPM_RC_RESERVED_BITS;

    return rc;
}

// TPMA_NV_Marshal changed to #define

// Table 2:196 - Definition of TPMS_NV_PUBLIC Structure (StructureTable)
TPM_RC
TPMS_NV_PUBLIC_Unmarshal(
    TPMS_NV_PUBLIC *target, BYTE **buffer, INT32 *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    if (rc == TPM_RC_SUCCESS)
    {
        rc = TPMI_RH_NV_INDEX_Unmarshal((TPMI_RH_NV_INDEX*)&target->nvIndex, buffer, size );
    }
    if (rc == TPM_RC_SUCCESS)
    {
        rc = TPMI_ALG_HASH_Unmarshal((TPMI_ALG_HASH*)&target->nameAlg, buffer, size , 0);
    }
    if (rc == TPM_RC_SUCCESS)
    {
        rc = TPMA_NV_Unmarshal((TPMA_NV*)&target->attributes, buffer, size );
    }
    if (rc == TPM_RC_SUCCESS)
    {
        rc = TPM2B_DIGEST_Unmarshal((TPM2B_DIGEST*)&target->authPolicy, buffer, size );
    }
    if (rc == TPM_RC_SUCCESS)
    {
        rc = UINT16_Unmarshal((UINT16*)&target->dataSize, buffer, size );
    }
    if((target->dataSize) > MAX_NV_INDEX_SIZE)
        return TPM_RC_SIZE;
    return rc;
}

UINT16
TPMS_NV_PUBLIC_Marshal(
    TPMS_NV_PUBLIC *source, BYTE **buffer, INT32 *size)
{
    UINT16 written = 0;
    written += TPMI_RH_NV_INDEX_Marshal((TPMI_RH_NV_INDEX*)&(source->nvIndex), buffer, size );
    written += TPMI_ALG_HASH_Marshal((TPMI_ALG_HASH*)&(source->nameAlg), buffer, size );
    written += TPMA_NV_Marshal((TPMA_NV*)&(source->attributes), buffer, size );
    written += TPM2B_DIGEST_Marshal((TPM2B_DIGEST*)&(source->authPolicy), buffer, size );
    written += UINT16_Marshal((UINT16*)&(source->dataSize), buffer, size );
    return written;
}


// Table 2:197 - Definition of TPM2B_NV_PUBLIC Structure (StructureTable)
TPM_RC
TPM2B_NV_PUBLIC_Unmarshal(
    TPM2B_NV_PUBLIC *target, BYTE **buffer, INT32 *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    INT32 startSize;
    if (rc == TPM_RC_SUCCESS)
    {
        rc = UINT16_Unmarshal((UINT16*)&target->t.size, buffer, size );
    }
// if size is zero, then the structure is a zero buffer
    if(target->t.size == 0)
        return TPM_RC_SIZE;
    startSize = *size;
    if (rc == TPM_RC_SUCCESS)
    {
        rc = TPMS_NV_PUBLIC_Unmarshal((TPMS_NV_PUBLIC*)&target->t.nvPublic, buffer, size );
    }

    if (rc == TPM_RC_SUCCESS)
    {
        if(target->t.size != (startSize - *size)) return TPM_RC_SIZE;
    }
    return TPM_RC_SUCCESS;
}

UINT16
TPM2B_NV_PUBLIC_Marshal(
    TPM2B_NV_PUBLIC *source, BYTE **buffer, INT32 *size)
{
    UINT16 written = 0;
    BYTE *sizeField = *buffer;
    *buffer += 2;
    written += TPMS_NV_PUBLIC_Marshal((TPMS_NV_PUBLIC*)&(source->t.nvPublic), buffer, size );
    written += UINT16_Marshal(&written, &sizeField, size);
    return written;
}


// Table 2:198 - Definition of TPM2B_CONTEXT_SENSITIVE Structure (StructureTable)
TPM_RC
TPM2B_CONTEXT_SENSITIVE_Unmarshal(
    TPM2B_CONTEXT_SENSITIVE *target, BYTE **buffer, INT32 *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    if (rc == TPM_RC_SUCCESS)
    {
        rc = UINT16_Unmarshal((UINT16*)&target->t.size, buffer, size );
    }
// if size is zero, then the structure is a zero buffer
    if(target->t.size == 0)
        return TPM_RC_SUCCESS;
    if((target->t.size) > MAX_CONTEXT_SIZE)
        return TPM_RC_SIZE;
    if (rc == TPM_RC_SUCCESS)
    {
        rc = BYTE_Array_Unmarshal((BYTE*)target->t.buffer, buffer, size , (INT32)(target->t.size));
    }
    return rc;
}

UINT16
TPM2B_CONTEXT_SENSITIVE_Marshal(
    TPM2B_CONTEXT_SENSITIVE *source, BYTE **buffer, INT32 *size)
{
    UINT16 written = 0;
    written += UINT16_Marshal((UINT16*)&(source->t.size), buffer, size );
    if(source->t.size == 0)
        return written;

    written += BYTE_Array_Marshal((BYTE*)(source->t.buffer), buffer, size , (INT32)(source->t.size));
    return written;
}


// Table 2:199 - Definition of TPMS_CONTEXT_DATA Structure (StructureTable)
TPM_RC
TPMS_CONTEXT_DATA_Unmarshal(
    TPMS_CONTEXT_DATA *target, BYTE **buffer, INT32 *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    if (rc == TPM_RC_SUCCESS)
    {
        rc = TPM2B_DIGEST_Unmarshal((TPM2B_DIGEST*)&target->integrity, buffer, size );
    }
    if (rc == TPM_RC_SUCCESS)
    {
        rc = TPM2B_CONTEXT_SENSITIVE_Unmarshal((TPM2B_CONTEXT_SENSITIVE*)&target->encrypted, buffer, size );
    }
    return rc;
}

UINT16
TPMS_CONTEXT_DATA_Marshal(
    TPMS_CONTEXT_DATA *source, BYTE **buffer, INT32 *size)
{
    UINT16 written = 0;
    written += TPM2B_DIGEST_Marshal((TPM2B_DIGEST*)&(source->integrity), buffer, size );
    written += TPM2B_CONTEXT_SENSITIVE_Marshal((TPM2B_CONTEXT_SENSITIVE*)&(source->encrypted), buffer, size );
    return written;
}


// Table 2:200 - Definition of TPM2B_CONTEXT_DATA Structure (StructureTable)
TPM_RC
TPM2B_CONTEXT_DATA_Unmarshal(
    TPM2B_CONTEXT_DATA *target, BYTE **buffer, INT32 *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    if (rc == TPM_RC_SUCCESS)
    {
        rc = UINT16_Unmarshal((UINT16*)&target->t.size, buffer, size );
    }
// if size is zero, then the structure is a zero buffer
    if(target->t.size == 0)
        return TPM_RC_SUCCESS;
    if((target->t.size) > sizeof(TPMS_CONTEXT_DATA))
        return TPM_RC_SIZE;
    if (rc == TPM_RC_SUCCESS)
    {
        rc = BYTE_Array_Unmarshal((BYTE*)target->t.buffer, buffer, size , (INT32)(target->t.size));
    }
    return rc;
}

UINT16
TPM2B_CONTEXT_DATA_Marshal(
    TPM2B_CONTEXT_DATA *source, BYTE **buffer, INT32 *size)
{
    UINT16 written = 0;
    written += UINT16_Marshal((UINT16*)&(source->t.size), buffer, size );
    if(source->t.size == 0)
        return written;

    written += BYTE_Array_Marshal((BYTE*)(source->t.buffer), buffer, size , (INT32)(source->t.size));
    return written;
}


// Table 2:201 - Definition of TPMS_CONTEXT Structure (StructureTable)
TPM_RC
TPMS_CONTEXT_Unmarshal(
    TPMS_CONTEXT *target, BYTE **buffer, INT32 *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    if (rc == TPM_RC_SUCCESS)
    {
        rc = UINT64_Unmarshal((UINT64*)&target->sequence, buffer, size );
    }
    if (rc == TPM_RC_SUCCESS)
    {
        rc = TPMI_DH_CONTEXT_Unmarshal((TPMI_DH_CONTEXT*)&target->savedHandle, buffer, size );
    }
    if (rc == TPM_RC_SUCCESS)
    {
        rc = TPMI_RH_HIERARCHY_Unmarshal((TPMI_RH_HIERARCHY*)&target->hierarchy, buffer, size , 1);
    }
    if (rc == TPM_RC_SUCCESS)
    {
        rc = TPM2B_CONTEXT_DATA_Unmarshal((TPM2B_CONTEXT_DATA*)&target->contextBlob, buffer, size );
    }
    return rc;
}

UINT16
TPMS_CONTEXT_Marshal(
    TPMS_CONTEXT *source, BYTE **buffer, INT32 *size)
{
    UINT16 written = 0;
    written += UINT64_Marshal((UINT64*)&(source->sequence), buffer, size );
    written += TPMI_DH_CONTEXT_Marshal((TPMI_DH_CONTEXT*)&(source->savedHandle), buffer, size );
    written += TPMI_RH_HIERARCHY_Marshal((TPMI_RH_HIERARCHY*)&(source->hierarchy), buffer, size );
    written += TPM2B_CONTEXT_DATA_Marshal((TPM2B_CONTEXT_DATA*)&(source->contextBlob), buffer, size );
    return written;
}


// Table 2:203 - Definition of TPMS_CREATION_DATA Structure (StructureTable)
// TPMS_CREATION_DATA_Unmarshal not required
UINT16
TPMS_CREATION_DATA_Marshal(
    TPMS_CREATION_DATA *source, BYTE **buffer, INT32 *size)
{
    UINT16 written = 0;
    written += TPML_PCR_SELECTION_Marshal((TPML_PCR_SELECTION*)&(source->pcrSelect), buffer, size );
    written += TPM2B_DIGEST_Marshal((TPM2B_DIGEST*)&(source->pcrDigest), buffer, size );
    written += TPMA_LOCALITY_Marshal((TPMA_LOCALITY*)&(source->locality), buffer, size );
    written += TPM_ALG_ID_Marshal((TPM_ALG_ID*)&(source->parentNameAlg), buffer, size );
    written += TPM2B_NAME_Marshal((TPM2B_NAME*)&(source->parentName), buffer, size );
    written += TPM2B_NAME_Marshal((TPM2B_NAME*)&(source->parentQualifiedName), buffer, size );
    written += TPM2B_DATA_Marshal((TPM2B_DATA*)&(source->outsideInfo), buffer, size );
    return written;
}


// Table 2:204 - Definition of TPM2B_CREATION_DATA Structure (StructureTable)
// TPM2B_CREATION_DATA_Unmarshal not required
UINT16
TPM2B_CREATION_DATA_Marshal(
    TPM2B_CREATION_DATA *source, BYTE **buffer, INT32 *size)
{
    UINT16 written = 0;
    BYTE *sizeField = *buffer;
    *buffer += 2;
    written += TPMS_CREATION_DATA_Marshal((TPMS_CREATION_DATA*)&(source->t.creationData), buffer, size );
    written += UINT16_Marshal(&written, &sizeField, size);
    return written;
}

// Array Marshal/Unmarshal for TPM2B_DIGEST
TPM_RC
TPM2B_DIGEST_Array_Unmarshal(
    TPM2B_DIGEST *target, BYTE **buffer, INT32 *size, INT32 count)
{
    TPM_RC rc;
    UINT32 i;
    for(i = 0; i < count; i++) { // loop to process given amount of values
        rc = TPM2B_DIGEST_Unmarshal(&target[i], buffer, size);
        if(rc != TPM_RC_SUCCESS) // if unmarshalling fails
            return rc;  // return error code
    }
    return TPM_RC_SUCCESS;
}

UINT16
TPM2B_DIGEST_Array_Marshal(
    TPM2B_DIGEST *source, BYTE **buffer, INT32 *size, INT32 count)
{
    UINT16 rc = 0;
    UINT32 i;
    for(i = 0; i < count; i++)   // loop to process given amount of values
    {
        rc = (UINT16)(rc + TPM2B_DIGEST_Marshal(&source[i], buffer, size));
    }
    return rc;
}

// Array Marshal/Unmarshal for TPMS_TAGGED_PCR_SELECT
// TPMS_TAGGED_PCR_SELECT_Array_Unmarshal not required
UINT16
TPMS_TAGGED_PCR_SELECT_Array_Marshal(
    TPMS_TAGGED_PCR_SELECT *source, BYTE **buffer, INT32 *size, INT32 count)
{
    UINT16 rc = 0;
    UINT32 i;
    for(i = 0; i < count; i++)   // loop to process given amount of values
    {
        rc = (UINT16)(rc + TPMS_TAGGED_PCR_SELECT_Marshal(&source[i], buffer, size));
    }
    return rc;
}

// Array Marshal/Unmarshal for TPMS_PCR_SELECTION
TPM_RC
TPMS_PCR_SELECTION_Array_Unmarshal(
    TPMS_PCR_SELECTION *target, BYTE **buffer, INT32 *size, INT32 count)
{
    TPM_RC rc;
    UINT32 i;
    for(i = 0; i < count; i++) { // loop to process given amount of values
        rc = TPMS_PCR_SELECTION_Unmarshal(&target[i], buffer, size);
        if(rc != TPM_RC_SUCCESS) // if unmarshalling fails
            return rc;  // return error code
    }
    return TPM_RC_SUCCESS;
}

UINT16
TPMS_PCR_SELECTION_Array_Marshal(
    TPMS_PCR_SELECTION *source, BYTE **buffer, INT32 *size, INT32 count)
{
    UINT16 rc = 0;
    UINT32 i;
    for(i = 0; i < count; i++)   // loop to process given amount of values
    {
        rc = (UINT16)(rc + TPMS_PCR_SELECTION_Marshal(&source[i], buffer, size));
    }
    return rc;
}

// Array Marshal/Unmarshal for TPM_ALG_ID
TPM_RC
TPM_ALG_ID_Array_Unmarshal(
    TPM_ALG_ID *target, BYTE **buffer, INT32 *size, INT32 count)
{
    TPM_RC rc;
    UINT32 i;
    for(i = 0; i < count; i++) { // loop to process given amount of values
        rc = TPM_ALG_ID_Unmarshal(&target[i], buffer, size);
        if(rc != TPM_RC_SUCCESS) // if unmarshalling fails
            return rc;  // return error code
    }
    return TPM_RC_SUCCESS;
}

UINT16
TPM_ALG_ID_Array_Marshal(
    TPM_ALG_ID *source, BYTE **buffer, INT32 *size, INT32 count)
{
    UINT16 rc = 0;
    UINT32 i;
    for(i = 0; i < count; i++)   // loop to process given amount of values
    {
        rc = (UINT16)(rc + TPM_ALG_ID_Marshal(&source[i], buffer, size));
    }
    return rc;
}

// Array Marshal/Unmarshal for TPM_CC
TPM_RC
TPM_CC_Array_Unmarshal(
    TPM_CC *target, BYTE **buffer, INT32 *size, INT32 count)
{
    TPM_RC rc;
    UINT32 i;
    for(i = 0; i < count; i++) { // loop to process given amount of values
        rc = TPM_CC_Unmarshal(&target[i], buffer, size);
        if(rc != TPM_RC_SUCCESS) // if unmarshalling fails
            return rc;  // return error code
    }
    return TPM_RC_SUCCESS;
}

UINT16
TPM_CC_Array_Marshal(
    TPM_CC *source, BYTE **buffer, INT32 *size, INT32 count)
{
    UINT16 rc = 0;
    UINT32 i;
    for(i = 0; i < count; i++)   // loop to process given amount of values
    {
        rc = (UINT16)(rc + TPM_CC_Marshal(&source[i], buffer, size));
    }
    return rc;
}

// Array Marshal/Unmarshal for TPMT_HA
TPM_RC
TPMT_HA_Array_Unmarshal(
    TPMT_HA *target, BYTE **buffer, INT32 *size, BOOL allowNull, INT32 count)
{
    TPM_RC rc;
    UINT32 i;
    for(i = 0; i < count; i++) { // loop to process given amount of values
        rc = TPMT_HA_Unmarshal(&target[i], buffer, size, allowNull);
        if(rc != TPM_RC_SUCCESS) // if unmarshalling fails
            return rc;  // return error code
    }
    return TPM_RC_SUCCESS;
}

UINT16
TPMT_HA_Array_Marshal(
    TPMT_HA *source, BYTE **buffer, INT32 *size, INT32 count)
{
    UINT16 rc = 0;
    UINT32 i;
    for(i = 0; i < count; i++)   // loop to process given amount of values
    {
        rc = (UINT16)(rc + TPMT_HA_Marshal(&source[i], buffer, size));
    }
    return rc;
}

// Array Marshal/Unmarshal for TPM_ECC_CURVE
#ifdef TPM_ALG_ECC
// TPM_ECC_CURVE_Array_Unmarshal not required
UINT16
TPM_ECC_CURVE_Array_Marshal(
    TPM_ECC_CURVE *source, BYTE **buffer, INT32 *size, INT32 count)
{
    UINT16 rc = 0;
    UINT32 i;
    for(i = 0; i < count; i++)   // loop to process given amount of values
    {
        rc = (UINT16)(rc + TPM_ECC_CURVE_Marshal(&source[i], buffer, size));
    }
    return rc;
}

#endif // TPM_ALG_ECC

// Array Marshal/Unmarshal for TPMS_ALG_PROPERTY
// TPMS_ALG_PROPERTY_Array_Unmarshal not required
UINT16
TPMS_ALG_PROPERTY_Array_Marshal(
    TPMS_ALG_PROPERTY *source, BYTE **buffer, INT32 *size, INT32 count)
{
    UINT16 rc = 0;
    UINT32 i;
    for(i = 0; i < count; i++)   // loop to process given amount of values
    {
        rc = (UINT16)(rc + TPMS_ALG_PROPERTY_Marshal(&source[i], buffer, size));
    }
    return rc;
}

// Array Marshal/Unmarshal for TPMA_CC
// TPMA_CC_Array_Unmarshal not required
UINT16
TPMA_CC_Array_Marshal(
    TPMA_CC *source, BYTE **buffer, INT32 *size, INT32 count)
{
    UINT16 rc = 0;
    UINT32 i;
    for(i = 0; i < count; i++)   // loop to process given amount of values
    {
        rc = (UINT16)(rc + TPMA_CC_Marshal(&source[i], buffer, size));
    }
    return rc;
}

// Array Marshal/Unmarshal for TPMS_TAGGED_PROPERTY
// TPMS_TAGGED_PROPERTY_Array_Unmarshal not required
UINT16
TPMS_TAGGED_PROPERTY_Array_Marshal(
    TPMS_TAGGED_PROPERTY *source, BYTE **buffer, INT32 *size, INT32 count)
{
    UINT16 rc = 0;
    UINT32 i;
    for(i = 0; i < count; i++)   // loop to process given amount of values
    {
        rc = (UINT16)(rc + TPMS_TAGGED_PROPERTY_Marshal(&source[i], buffer, size));
    }
    return rc;
}

// Array Marshal/Unmarshal for BYTE
#include <string.h>
TPM_RC
BYTE_Array_Unmarshal(
    BYTE *target, BYTE **buffer, INT32 *size, INT32 count)
{
    if(*size < count)       // if buffer size not sufficient
        return TPM_RC_INSUFFICIENT;   // return corresponding error code

    memcpy(target, *buffer, count);   // copy the given amount of bytes from buffer to target
    *buffer += count;           // set the buffer pointer to the empty part of the buffer
    *size -= count;             // adjust size of empty buffer
    return TPM_RC_SUCCESS;      // return success
}

UINT16
BYTE_Array_Marshal(
    BYTE *source, BYTE **buffer, INT32 *size, INT32 count)
{
    if (buffer != 0) // if buffer pointer is not a nullpointer
    {
        if ((size == 0) || ((*size -= count) >= 0))  // if size of buffer is large enough
        {
            memcpy(*buffer, source, count); // copy given amount of bytes from source to buffer
            *buffer += count;       // set buffer pointer to the empty part of the buffer
        }
        pAssert(size == 0 || (*size >= 0));
    }
    pAssert(count < UINT16_MAX);
    return ((UINT16)count);
}

// Array Marshal/Unmarshal for TPM_HANDLE
// TPM_HANDLE_Array_Unmarshal not required
UINT16
TPM_HANDLE_Array_Marshal(
    TPM_HANDLE *source, BYTE **buffer, INT32 *size, INT32 count)
{
    UINT16 rc = 0;
    UINT32 i;
    for(i = 0; i < count; i++)   // loop to process given amount of values
    {
        rc = (UINT16)(rc + TPM_HANDLE_Marshal(&source[i], buffer, size));
    }
    return rc;
}

