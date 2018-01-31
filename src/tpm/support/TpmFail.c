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

// 9.15.1 Includes, Defines, and Types
#define TPM_FAIL_C
#include "InternalRoutines.h"
#include <assert.h>
#pragma pack(push, 1)
#include "TPM_Types.h"
#pragma pack (pop)
#include "swap.h"
#pragma pack(push,1)
typedef struct {
    TPM_ST tag;
    UINT32 size;
    TPM_RC code;
} HEADER;
typedef struct {
    UINT16 size;
    struct {
        UINT32 function;
        UINT32 line;
        UINT32 code;
    } values;
    TPM_RC returnCode;
} GET_TEST_RESULT_PARAMETERS;
typedef struct {
    TPMI_YES_NO moreData;
    TPM_CAP capability;   // Always TPM_CAP_TPM_PROPERTIES
    TPML_TAGGED_TPM_PROPERTY tpmProperty;     // a single tagged property
} GET_CAPABILITY_PARAMETERS;
typedef struct {
    HEADER header;
    GET_TEST_RESULT_PARAMETERS getTestResult;
} TEST_RESPONSE;
typedef struct {
    HEADER header;
    GET_CAPABILITY_PARAMETERS getCap;
} CAPABILITY_RESPONSE;
typedef union {
    TEST_RESPONSE test;
    CAPABILITY_RESPONSE cap;
} RESPONSES;
#pragma pack(pop)
#ifndef __IGNORE_STATE__      // Don't define this value
static BYTE response[sizeof(RESPONSES)];
#endif
static INT32
MarshalUint16(
    UINT16 integer,
    BYTE **buffer
)
{
    return UINT16_Marshal(&integer, buffer, NULL);
}
static INT32
MarshalUint32(
    UINT32 integer,
    BYTE **buffer
)
{
    return UINT32_Marshal(&integer, buffer, NULL);
}
static BOOL
UnmarshalHeader(
    HEADER *header,
    BYTE **buffer,
    INT32 *size
)
{
    UINT32 usize;
    TPM_RC ucode;
    if( UINT16_Unmarshal(&header->tag, buffer, size) != TPM_RC_SUCCESS
            || UINT32_Unmarshal(&usize, buffer, size) != TPM_RC_SUCCESS
            || UINT32_Unmarshal(&ucode, buffer, size) != TPM_RC_SUCCESS
      )
        return FALSE;
    header->size = usize;
    header->code = ucode;
    return TRUE;
}
LIB_EXPORT void
SetForceFailureMode(
    void
)
{
    g_forceFailureMode = TRUE;
    return;
}
/*
Commented due to function name conflict on static linking
void
TpmFail(
    const char *function,
    int line, int code
)
{
    // Save the values that indicate where the error occurred.
    // On a 64-bit machine, this may truncate the address of the string
    // of the function name where the error occurred.
    s_failFunction = *(UINT32*)&function;
    s_failLine = line;
    s_failCode = code;

    // if asserts are enabled, then do an assert unless the failure mode code
    // is being tested
    assert(g_forceFailureMode);

    // Clear this flag
    g_forceFailureMode = FALSE;

    // Jump to the failure mode code.
    // Note: only get here if asserts are off or if we are testing failure mode
    longjmp(&g_jumpBuffer[0], 1);
}*/
void
TpmFailureMode (
    unsigned int inRequestSize,                     // IN: command buffer size
    unsigned char *inRequest,                           // IN: command buffer
    unsigned int *outResponseSize,                     // OUT: response buffer size
    unsigned char **outResponse                         // OUT: response buffer
)
{
    BYTE *buffer;
    UINT32 marshalSize;
    UINT32 capability;
    HEADER header;                // unmarshaled command header
    UINT32 pt;              // unmarshaled property type
    UINT32 count;           // unmarshaled property count

    // If there is no command buffer, then just return TPM_RC_FAILURE
    if(inRequestSize == 0 || inRequest == NULL)
        goto FailureModeReturn;

    // If the header is not correct for TPM2_GetCapability() or
    // TPM2_GetTestResult() then just return the in failure mode response;
    buffer = inRequest;
    if(!UnmarshalHeader(&header, &inRequest, (INT32 *)&inRequestSize))
        goto FailureModeReturn;
    if( header.tag != TPM_ST_NO_SESSIONS
            || header.size < 10)
        goto FailureModeReturn;

    switch (header.code) {
    case TPM_CC_GetTestResult:

        // make sure that the command size is correct
        if(header.size != 10)
            goto FailureModeReturn;
        buffer = &response[10];
        marshalSize = MarshalUint16(3 * sizeof(UINT32), &buffer);
        marshalSize += MarshalUint32(s_failFunction, &buffer);
        marshalSize += MarshalUint32(s_failLine, &buffer);
        marshalSize += MarshalUint32(s_failCode, &buffer);
        if(s_failCode == FATAL_ERROR_NV_UNRECOVERABLE)
            marshalSize += MarshalUint32(TPM_RC_NV_UNINITIALIZED, &buffer);
        else
            marshalSize += MarshalUint32(TPM_RC_FAILURE, &buffer);
        break;

    case TPM_CC_GetCapability:
        // make sure that the size of the command is exactly the size
        // returned for the capability, property, and count
        if( header.size!= (10 + (3 * sizeof(UINT32)))
                // also verify that this is requesting TPM properties
                || (UINT32_Unmarshal(&capability, &inRequest,
                                     (INT32 *)&inRequestSize)
                    != TPM_RC_SUCCESS)
                || (capability != TPM_CAP_TPM_PROPERTIES)
                || (UINT32_Unmarshal(&pt, &inRequest, (INT32 *)&inRequestSize)
                    != TPM_RC_SUCCESS)
                || (UINT32_Unmarshal(&count, &inRequest, (INT32 *)&inRequestSize)
                    != TPM_RC_SUCCESS)
          )

            goto FailureModeReturn;

        // If in failure mode because of an unrecoverable read error, and the
        // property is 0 and the count is 0, then this is an indication to
        // re-manufacture the TPM. Do the re-manufacture but stay in failure
        // mode until the TPM is reset.
        // Note: this behavior is not required by the specification and it is
        // OK to leave the TPM permanently bricked due to an unrecoverable NV
        // error.
        if( count == 0 && pt == 0 && s_failCode == FATAL_ERROR_NV_UNRECOVERABLE)
        {
            g_manufactured = FALSE;
            TPM_Manufacture(0);
        }

        if(count > 0)
            count = 1;
        else if(pt > TPM_PT_FIRMWARE_VERSION_2)
            count = 0;
        if(pt < TPM_PT_MANUFACTURER)
            pt = TPM_PT_MANUFACTURER;

        // set up for return
        buffer = &response[10];
        // if the request was for a PT less than the last one
        // then we indicate more, otherwise, not.
        if(pt < TPM_PT_FIRMWARE_VERSION_2)
            *buffer++ = YES;
        else
            *buffer++ = NO;

        marshalSize = 1;

        // indicate the capability type
        marshalSize += MarshalUint32(capability, &buffer);
        // indicate the number of values that are being returned (0 or 1)
        marshalSize += MarshalUint32(count, &buffer);
        // indicate the property
        marshalSize += MarshalUint32(pt, &buffer);

        if(count > 0)
            switch (pt) {
            case TPM_PT_MANUFACTURER:
                // the vendor ID unique to each TPM manufacturer
#ifdef MANUFACTURER
                pt = *(UINT32*)MANUFACTURER;
#else
                pt = 0;
#endif
                break;
            case TPM_PT_VENDOR_STRING_1:
                // the first four characters of the vendor ID string
#ifdef VENDOR_STRING_1
                pt = *(UINT32*)VENDOR_STRING_1;
#else
                pt = 0;
#endif
                break;
            case TPM_PT_VENDOR_STRING_2:
                // the second four characters of the vendor ID string
#ifdef VENDOR_STRING_2
                pt = *(UINT32*)VENDOR_STRING_2;
#else
                pt = 0;
#endif
                break;
            case TPM_PT_VENDOR_STRING_3:
                // the third four characters of the vendor ID string
#ifdef VENDOR_STRING_3
                pt = *(UINT32*)VENDOR_STRING_3;
#else
                pt = 0;
#endif
                break;
            case TPM_PT_VENDOR_STRING_4:
                // the fourth four characters of the vendor ID string
#ifdef VENDOR_STRING_4
                pt = *(UINT32*)VENDOR_STRING_4;
#else
                pt = 0;
#endif

                break;
            case TPM_PT_VENDOR_TPM_TYPE:
                // vendor-defined value indicating the TPM model
                // We just make up a number here
                pt = 1;
                break;
            case TPM_PT_FIRMWARE_VERSION_1:
                // the more significant 32-bits of a vendor-specific value
                // indicating the version of the firmware
#ifdef FIRMWARE_V1
                pt = FIRMWARE_V1;
#else
                pt = 0;
#endif
                break;
            default:           // TPM_PT_FIRMWARE_VERSION_2:
                // the less significant 32-bits of a vendor-specific value
                // indicating the version of the firmware
#ifdef FIRMWARE_V2
                pt = FIRMWARE_V2;
#else
                pt = 0;
#endif
                break;
            }
        marshalSize += MarshalUint32(pt, &buffer);
        break;
    default:         // default for switch (cc)
        goto FailureModeReturn;
    }
    // Now do the header
    buffer = response;
    marshalSize = marshalSize + 10;  // Add the header size to the
    // stuff already marshaled
    MarshalUint16(TPM_ST_NO_SESSIONS, &buffer);  // structure tag
    MarshalUint32(marshalSize, &buffer);    // responseSize
    MarshalUint32(TPM_RC_SUCCESS, &buffer);     // response code

    *outResponseSize = marshalSize;
    *outResponse = (unsigned char *)&response;
    return;

FailureModeReturn:

    buffer = response;

    marshalSize = MarshalUint16(TPM_ST_NO_SESSIONS, &buffer);
    marshalSize += MarshalUint32(10, &buffer);
    marshalSize += MarshalUint32(TPM_RC_FAILURE, &buffer);

    *outResponseSize = marshalSize;
    *outResponse = (unsigned char *)response;
    return;
}
