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

// Includes based on
#include "InternalRoutines.h"                                    // include basic header files
#include "Commands.h"                                            // include prototype files
#include "SessionProcess_fp.h"                                   // Spec. Version 01.19+

#ifndef TABLE_DRIVEN_DISPATCH //%                                   // Spec. Version 01.19+

// This function is based on Part 4, Section "Main", CommandDispatcher():
// ----------------------------------------------------------------------
// CommandDispatcher() performs the following operations:
// * unmarshals command parameters from the input buffer;
// * invokes the function that performs the command actions;
// * marshals the returned handles, if any; and
// * marshals the returned parameters, if any, into the output buffer putting in the parameterSize field
// if authorization sessions are present.
//
// -> This function basically consists of a switch-case-statement for each command.
TPM_RC
CommandDispatcher(
    TPMI_ST_COMMAND_TAG tag,                                    // IN: Input command tag
    TPM_CC commandCode,                            // IN: Command code/index
    INT32 *parmBufferSize,                        // IN: size of parameter buffer
    BYTE *parmBufferStart,                       // IN: pointer to start of parameter buffer
    TPM_HANDLE handles[],                              // IN: handle array
    UINT32 *responseHandleSize,                    // OUT: size of handle buffer in response
    UINT32 *respParmSize                           // OUT: size of parameter buffer in response
)
{
    TPM_RC rc = TPM_RC_SUCCESS;                                // the return code of the function

    // Initialization of OUT parameters
    *responseHandleSize = 0;                                        // initialize the size of the response handle buffer
    *respParmSize = 0;                                              // initialize the size of the parameter buffer

    // Get the global response buffer
    UINT8 *buffer = MemoryGetResponseBuffer(commandCode)
                    + sizeof(TPM_ST)                          // tag
                    + sizeof(UINT32)                          // responseSize
                    + sizeof(TPM_RC);                         // return code

    // Local variables
    INT32 size;                                               // size (limitation) used in marshal functions
    UINT8 *responseHandlePtr = NULL;                          // pointer to handle area
    UINT8 *respParamSizePtr = NULL;                           // pointer to size of parameter
    // used to marshal respParmSize

    if(IsHandleInResponse(commandCode))                          // check for handle area in response
    {
        responseHandlePtr = buffer;
        buffer += sizeof(TPM_HANDLE);                               // adjust pointer
    }

    if(tag == TPM_ST_SESSIONS)                                      // cf. ExecCommand.c
    {
        respParamSizePtr = buffer;
        buffer += sizeof(UINT32);                                   // adjust pointer
    }

    // dispatch based on command code/index, i.e., invokes the function that performs the command actions
    switch(commandCode)
    {
#if defined CC_Startup && CC_Startup == YES                  // based on Part 4
    case TPM_CC_Startup:
    {
        // Get a buffer for input parameters (uses function from MemoryLib.c)
        Startup_In *in_params = (Startup_In *) MemoryGetActionInputBuffer(sizeof(Startup_In));

        // No buffer for output parameters required

        // No handles required
        rc = TPM_SU_Unmarshal(&in_params->startupType, &parmBufferStart, parmBufferSize);
        if(rc != TPM_RC_SUCCESS)
            return rc + RC_Startup_startupType;

        if(*parmBufferSize != 0)
            return TPM_RC_SIZE;

        // Call to the action routine for TPM2_Startup
        rc = TPM2_Startup(in_params);

        // Check the return code of action routine for TPM2_Startup
        if(rc != TPM_RC_SUCCESS)
            return rc;


    }
    break;
#endif     // CC_Startup == YES
#if defined CC_Shutdown && CC_Shutdown == YES                  // based on Part 4
    case TPM_CC_Shutdown:
    {
        // Get a buffer for input parameters (uses function from MemoryLib.c)
        Shutdown_In *in_params = (Shutdown_In *) MemoryGetActionInputBuffer(sizeof(Shutdown_In));

        // No buffer for output parameters required

        // No handles required
        rc = TPM_SU_Unmarshal(&in_params->shutdownType, &parmBufferStart, parmBufferSize);
        if(rc != TPM_RC_SUCCESS)
            return rc + RC_Shutdown_shutdownType;

        if(*parmBufferSize != 0)
            return TPM_RC_SIZE;

        // Call to the action routine for TPM2_Shutdown
        rc = TPM2_Shutdown(in_params);

        // Check the return code of action routine for TPM2_Shutdown
        if(rc != TPM_RC_SUCCESS)
            return rc;


    }
    break;
#endif     // CC_Shutdown == YES
#if defined CC_SelfTest && CC_SelfTest == YES                  // based on Part 4
    case TPM_CC_SelfTest:
    {
        // Get a buffer for input parameters (uses function from MemoryLib.c)
        SelfTest_In *in_params = (SelfTest_In *) MemoryGetActionInputBuffer(sizeof(SelfTest_In));

        // No buffer for output parameters required

        // No handles required
        rc = TPMI_YES_NO_Unmarshal(&in_params->fullTest, &parmBufferStart, parmBufferSize);
        if(rc != TPM_RC_SUCCESS)
            return rc + RC_SelfTest_fullTest;

        if(*parmBufferSize != 0)
            return TPM_RC_SIZE;

        // Call to the action routine for TPM2_SelfTest
        rc = TPM2_SelfTest(in_params);

        // Check the return code of action routine for TPM2_SelfTest
        if(rc != TPM_RC_SUCCESS)
            return rc;


    }
    break;
#endif     // CC_SelfTest == YES
#if defined CC_IncrementalSelfTest && CC_IncrementalSelfTest == YES                  // based on Part 4
    case TPM_CC_IncrementalSelfTest:
    {
        // Get a buffer for input parameters (uses function from MemoryLib.c)
        IncrementalSelfTest_In *in_params = (IncrementalSelfTest_In *) MemoryGetActionInputBuffer(sizeof(IncrementalSelfTest_In));

        // Get a buffer for output parameters (uses function from MemoryLib.c)
        IncrementalSelfTest_Out *out_params = (IncrementalSelfTest_Out *) MemoryGetActionOutputBuffer(sizeof(IncrementalSelfTest_Out));

        // No handles required
        rc = TPML_ALG_Unmarshal(&in_params->toTest, &parmBufferStart, parmBufferSize);
        if(rc != TPM_RC_SUCCESS)
            return rc + RC_IncrementalSelfTest_toTest;

        if(*parmBufferSize != 0)
            return TPM_RC_SIZE;

        // Call to the action routine for TPM2_IncrementalSelfTest
        rc = TPM2_IncrementalSelfTest(in_params, out_params);

        // Check the return code of action routine for TPM2_IncrementalSelfTest
        if(rc != TPM_RC_SUCCESS)
            return rc;

        // Calculate size of IncrementalSelfTest_Out
        size = sizeof(IncrementalSelfTest_Out);

        // Marshal parameter 'toDoList'
        *respParmSize += TPML_ALG_Marshal(&out_params->toDoList, &buffer, &size);

    }
    break;
#endif     // CC_IncrementalSelfTest == YES
#if defined CC_GetTestResult && CC_GetTestResult == YES                  // based on Part 4
    case TPM_CC_GetTestResult:
    {
        // No buffer for input parameters required

        // Get a buffer for output parameters (uses function from MemoryLib.c)
        GetTestResult_Out *out_params = (GetTestResult_Out *) MemoryGetActionOutputBuffer(sizeof(GetTestResult_Out));

        // No handles required

        if(*parmBufferSize != 0)
            return TPM_RC_SIZE;

        // Call to the action routine for TPM2_GetTestResult
        rc = TPM2_GetTestResult(out_params);

        // Check the return code of action routine for TPM2_GetTestResult
        if(rc != TPM_RC_SUCCESS)
            return rc;

        // Calculate size of GetTestResult_Out
        size = sizeof(GetTestResult_Out);

        // Marshal parameter 'outData'
        *respParmSize += TPM2B_MAX_BUFFER_Marshal(&out_params->outData, &buffer, &size);
        // Marshal parameter 'testResult'
        *respParmSize += TPM_RC_Marshal(&out_params->testResult, &buffer, &size);

    }
    break;
#endif     // CC_GetTestResult == YES
#if defined CC_StartAuthSession && CC_StartAuthSession == YES                  // based on Part 4
    case TPM_CC_StartAuthSession:
    {
        // Get a buffer for input parameters (uses function from MemoryLib.c)
        StartAuthSession_In *in_params = (StartAuthSession_In *) MemoryGetActionInputBuffer(sizeof(StartAuthSession_In));

        // Get a buffer for output parameters (uses function from MemoryLib.c)
        StartAuthSession_Out *out_params = (StartAuthSession_Out *) MemoryGetActionOutputBuffer(sizeof(StartAuthSession_Out));

        // Get handle 0 (tpmKey) from handles array
        in_params->tpmKey = handles[0];
        // Get handle 1 (bind) from handles array
        in_params->bind = handles[1];

        rc = TPM2B_NONCE_Unmarshal(&in_params->nonceCaller, &parmBufferStart, parmBufferSize);
        if(rc != TPM_RC_SUCCESS)
            return rc + RC_StartAuthSession_nonceCaller;
        rc = TPM2B_ENCRYPTED_SECRET_Unmarshal(&in_params->encryptedSalt, &parmBufferStart, parmBufferSize);
        if(rc != TPM_RC_SUCCESS)
            return rc + RC_StartAuthSession_encryptedSalt;
        rc = TPM_SE_Unmarshal(&in_params->sessionType, &parmBufferStart, parmBufferSize);
        if(rc != TPM_RC_SUCCESS)
            return rc + RC_StartAuthSession_sessionType;
        rc = TPMT_SYM_DEF_Unmarshal(&in_params->symmetric, &parmBufferStart, parmBufferSize, TRUE);
        if(rc != TPM_RC_SUCCESS)
            return rc + RC_StartAuthSession_symmetric;
        rc = TPMI_ALG_HASH_Unmarshal(&in_params->authHash, &parmBufferStart, parmBufferSize, FALSE);
        if(rc != TPM_RC_SUCCESS)
            return rc + RC_StartAuthSession_authHash;

        if(*parmBufferSize != 0)
            return TPM_RC_SIZE;

        // Call to the action routine for TPM2_StartAuthSession
        rc = TPM2_StartAuthSession(in_params, out_params);

        // Check the return code of action routine for TPM2_StartAuthSession
        if(rc != TPM_RC_SUCCESS)
            return rc;

        // Calculate size of StartAuthSession_Out
        size = sizeof(StartAuthSession_Out);

        // Marshal handle 'sessionHandle'
        *responseHandleSize += TPMI_SH_AUTH_SESSION_Marshal(&out_params->sessionHandle, &responseHandlePtr, &size);
        // Marshal parameter 'nonceTPM'
        *respParmSize += TPM2B_NONCE_Marshal(&out_params->nonceTPM, &buffer, &size);

    }
    break;
#endif     // CC_StartAuthSession == YES
#if defined CC_PolicyRestart && CC_PolicyRestart == YES                  // based on Part 4
    case TPM_CC_PolicyRestart:
    {
        // Get a buffer for input parameters (uses function from MemoryLib.c)
        PolicyRestart_In *in_params = (PolicyRestart_In *) MemoryGetActionInputBuffer(sizeof(PolicyRestart_In));

        // No buffer for output parameters required

        // Get handle 0 (sessionHandle) from handles array
        in_params->sessionHandle = handles[0];


        if(*parmBufferSize != 0)
            return TPM_RC_SIZE;

        // Call to the action routine for TPM2_PolicyRestart
        rc = TPM2_PolicyRestart(in_params);

        // Check the return code of action routine for TPM2_PolicyRestart
        if(rc != TPM_RC_SUCCESS)
            return rc;


    }
    break;
#endif     // CC_PolicyRestart == YES
#if defined CC_Create && CC_Create == YES                  // based on Part 4
    case TPM_CC_Create:
    {
        // Get a buffer for input parameters (uses function from MemoryLib.c)
        Create_In *in_params = (Create_In *) MemoryGetActionInputBuffer(sizeof(Create_In));

        // Get a buffer for output parameters (uses function from MemoryLib.c)
        Create_Out *out_params = (Create_Out *) MemoryGetActionOutputBuffer(sizeof(Create_Out));

        // Get handle 0 (parentHandle) from handles array
        in_params->parentHandle = handles[0];

        rc = TPM2B_SENSITIVE_CREATE_Unmarshal(&in_params->inSensitive, &parmBufferStart, parmBufferSize);
        if(rc != TPM_RC_SUCCESS)
            return rc + RC_Create_inSensitive;
        rc = TPM2B_PUBLIC_Unmarshal(&in_params->inPublic, &parmBufferStart, parmBufferSize, FALSE);
        if(rc != TPM_RC_SUCCESS)
            return rc + RC_Create_inPublic;
        rc = TPM2B_DATA_Unmarshal(&in_params->outsideInfo, &parmBufferStart, parmBufferSize);
        if(rc != TPM_RC_SUCCESS)
            return rc + RC_Create_outsideInfo;
        rc = TPML_PCR_SELECTION_Unmarshal(&in_params->creationPCR, &parmBufferStart, parmBufferSize);
        if(rc != TPM_RC_SUCCESS)
            return rc + RC_Create_creationPCR;

        if(*parmBufferSize != 0)
            return TPM_RC_SIZE;

        // Call to the action routine for TPM2_Create
        rc = TPM2_Create(in_params, out_params);

        // Check the return code of action routine for TPM2_Create
        if(rc != TPM_RC_SUCCESS)
            return rc;

        // Calculate size of Create_Out
        size = sizeof(Create_Out);

        // Marshal parameter 'outPrivate'
        *respParmSize += TPM2B_PRIVATE_Marshal(&out_params->outPrivate, &buffer, &size);
        // Marshal parameter 'outPublic'
        *respParmSize += TPM2B_PUBLIC_Marshal(&out_params->outPublic, &buffer, &size);
        // Marshal parameter 'creationData'
        *respParmSize += TPM2B_CREATION_DATA_Marshal(&out_params->creationData, &buffer, &size);
        // Marshal parameter 'creationHash'
        *respParmSize += TPM2B_DIGEST_Marshal(&out_params->creationHash, &buffer, &size);
        // Marshal parameter 'creationTicket'
        *respParmSize += TPMT_TK_CREATION_Marshal(&out_params->creationTicket, &buffer, &size);

    }
    break;
#endif     // CC_Create == YES
#if defined CC_Load && CC_Load == YES                  // based on Part 4
    case TPM_CC_Load:
    {
        // Get a buffer for input parameters (uses function from MemoryLib.c)
        Load_In *in_params = (Load_In *) MemoryGetActionInputBuffer(sizeof(Load_In));

        // Get a buffer for output parameters (uses function from MemoryLib.c)
        Load_Out *out_params = (Load_Out *) MemoryGetActionOutputBuffer(sizeof(Load_Out));

        // Get handle 0 (parentHandle) from handles array
        in_params->parentHandle = handles[0];

        rc = TPM2B_PRIVATE_Unmarshal(&in_params->inPrivate, &parmBufferStart, parmBufferSize);
        if(rc != TPM_RC_SUCCESS)
            return rc + RC_Load_inPrivate;
        rc = TPM2B_PUBLIC_Unmarshal(&in_params->inPublic, &parmBufferStart, parmBufferSize, FALSE);
        if(rc != TPM_RC_SUCCESS)
            return rc + RC_Load_inPublic;

        if(*parmBufferSize != 0)
            return TPM_RC_SIZE;

        // Call to the action routine for TPM2_Load
        rc = TPM2_Load(in_params, out_params);

        // Check the return code of action routine for TPM2_Load
        if(rc != TPM_RC_SUCCESS)
            return rc;

        // Calculate size of Load_Out
        size = sizeof(Load_Out);

        // Marshal handle 'objectHandle'
        *responseHandleSize += TPM_HANDLE_Marshal(&out_params->objectHandle, &responseHandlePtr, &size);
        // Marshal parameter 'name'
        *respParmSize += TPM2B_NAME_Marshal(&out_params->name, &buffer, &size);

    }
    break;
#endif     // CC_Load == YES
#if defined CC_LoadExternal && CC_LoadExternal == YES                  // based on Part 4
    case TPM_CC_LoadExternal:
    {
        // Get a buffer for input parameters (uses function from MemoryLib.c)
        LoadExternal_In *in_params = (LoadExternal_In *) MemoryGetActionInputBuffer(sizeof(LoadExternal_In));

        // Get a buffer for output parameters (uses function from MemoryLib.c)
        LoadExternal_Out *out_params = (LoadExternal_Out *) MemoryGetActionOutputBuffer(sizeof(LoadExternal_Out));

        // No handles required
        rc = TPM2B_SENSITIVE_Unmarshal(&in_params->inPrivate, &parmBufferStart, parmBufferSize);
        if(rc != TPM_RC_SUCCESS)
            return rc + RC_LoadExternal_inPrivate;
        rc = TPM2B_PUBLIC_Unmarshal(&in_params->inPublic, &parmBufferStart, parmBufferSize, TRUE);
        if(rc != TPM_RC_SUCCESS)
            return rc + RC_LoadExternal_inPublic;
        rc = TPMI_RH_HIERARCHY_Unmarshal(&in_params->hierarchy, &parmBufferStart, parmBufferSize, TRUE);
        if(rc != TPM_RC_SUCCESS)
            return rc + RC_LoadExternal_hierarchy;

        if(*parmBufferSize != 0)
            return TPM_RC_SIZE;

        // Call to the action routine for TPM2_LoadExternal
        rc = TPM2_LoadExternal(in_params, out_params);

        // Check the return code of action routine for TPM2_LoadExternal
        if(rc != TPM_RC_SUCCESS)
            return rc;

        // Calculate size of LoadExternal_Out
        size = sizeof(LoadExternal_Out);

        // Marshal handle 'objectHandle'
        *responseHandleSize += TPM_HANDLE_Marshal(&out_params->objectHandle, &responseHandlePtr, &size);
        // Marshal parameter 'name'
        *respParmSize += TPM2B_NAME_Marshal(&out_params->name, &buffer, &size);

    }
    break;
#endif     // CC_LoadExternal == YES
#if defined CC_ReadPublic && CC_ReadPublic == YES                  // based on Part 4
    case TPM_CC_ReadPublic:
    {
        // Get a buffer for input parameters (uses function from MemoryLib.c)
        ReadPublic_In *in_params = (ReadPublic_In *) MemoryGetActionInputBuffer(sizeof(ReadPublic_In));

        // Get a buffer for output parameters (uses function from MemoryLib.c)
        ReadPublic_Out *out_params = (ReadPublic_Out *) MemoryGetActionOutputBuffer(sizeof(ReadPublic_Out));

        // Get handle 0 (objectHandle) from handles array
        in_params->objectHandle = handles[0];


        if(*parmBufferSize != 0)
            return TPM_RC_SIZE;

        // Call to the action routine for TPM2_ReadPublic
        rc = TPM2_ReadPublic(in_params, out_params);

        // Check the return code of action routine for TPM2_ReadPublic
        if(rc != TPM_RC_SUCCESS)
            return rc;

        // Calculate size of ReadPublic_Out
        size = sizeof(ReadPublic_Out);

        // Marshal parameter 'outPublic'
        *respParmSize += TPM2B_PUBLIC_Marshal(&out_params->outPublic, &buffer, &size);
        // Marshal parameter 'name'
        *respParmSize += TPM2B_NAME_Marshal(&out_params->name, &buffer, &size);
        // Marshal parameter 'qualifiedName'
        *respParmSize += TPM2B_NAME_Marshal(&out_params->qualifiedName, &buffer, &size);

    }
    break;
#endif     // CC_ReadPublic == YES
#if defined CC_ActivateCredential && CC_ActivateCredential == YES                  // based on Part 4
    case TPM_CC_ActivateCredential:
    {
        // Get a buffer for input parameters (uses function from MemoryLib.c)
        ActivateCredential_In *in_params = (ActivateCredential_In *) MemoryGetActionInputBuffer(sizeof(ActivateCredential_In));

        // Get a buffer for output parameters (uses function from MemoryLib.c)
        ActivateCredential_Out *out_params = (ActivateCredential_Out *) MemoryGetActionOutputBuffer(sizeof(ActivateCredential_Out));

        // Get handle 0 (activateHandle) from handles array
        in_params->activateHandle = handles[0];
        // Get handle 1 (keyHandle) from handles array
        in_params->keyHandle = handles[1];

        rc = TPM2B_ID_OBJECT_Unmarshal(&in_params->credentialBlob, &parmBufferStart, parmBufferSize);
        if(rc != TPM_RC_SUCCESS)
            return rc + RC_ActivateCredential_credentialBlob;
        rc = TPM2B_ENCRYPTED_SECRET_Unmarshal(&in_params->secret, &parmBufferStart, parmBufferSize);
        if(rc != TPM_RC_SUCCESS)
            return rc + RC_ActivateCredential_secret;

        if(*parmBufferSize != 0)
            return TPM_RC_SIZE;

        // Call to the action routine for TPM2_ActivateCredential
        rc = TPM2_ActivateCredential(in_params, out_params);

        // Check the return code of action routine for TPM2_ActivateCredential
        if(rc != TPM_RC_SUCCESS)
            return rc;

        // Calculate size of ActivateCredential_Out
        size = sizeof(ActivateCredential_Out);

        // Marshal parameter 'certInfo'
        *respParmSize += TPM2B_DIGEST_Marshal(&out_params->certInfo, &buffer, &size);

    }
    break;
#endif     // CC_ActivateCredential == YES
#if defined CC_MakeCredential && CC_MakeCredential == YES                  // based on Part 4
    case TPM_CC_MakeCredential:
    {
        // Get a buffer for input parameters (uses function from MemoryLib.c)
        MakeCredential_In *in_params = (MakeCredential_In *) MemoryGetActionInputBuffer(sizeof(MakeCredential_In));

        // Get a buffer for output parameters (uses function from MemoryLib.c)
        MakeCredential_Out *out_params = (MakeCredential_Out *) MemoryGetActionOutputBuffer(sizeof(MakeCredential_Out));

        // Get handle 0 (handle) from handles array
        in_params->handle = handles[0];

        rc = TPM2B_DIGEST_Unmarshal(&in_params->credential, &parmBufferStart, parmBufferSize);
        if(rc != TPM_RC_SUCCESS)
            return rc + RC_MakeCredential_credential;
        rc = TPM2B_NAME_Unmarshal(&in_params->objectName, &parmBufferStart, parmBufferSize);
        if(rc != TPM_RC_SUCCESS)
            return rc + RC_MakeCredential_objectName;

        if(*parmBufferSize != 0)
            return TPM_RC_SIZE;

        // Call to the action routine for TPM2_MakeCredential
        rc = TPM2_MakeCredential(in_params, out_params);

        // Check the return code of action routine for TPM2_MakeCredential
        if(rc != TPM_RC_SUCCESS)
            return rc;

        // Calculate size of MakeCredential_Out
        size = sizeof(MakeCredential_Out);

        // Marshal parameter 'credentialBlob'
        *respParmSize += TPM2B_ID_OBJECT_Marshal(&out_params->credentialBlob, &buffer, &size);
        // Marshal parameter 'secret'
        *respParmSize += TPM2B_ENCRYPTED_SECRET_Marshal(&out_params->secret, &buffer, &size);

    }
    break;
#endif     // CC_MakeCredential == YES
#if defined CC_Unseal && CC_Unseal == YES                  // based on Part 4
    case TPM_CC_Unseal:
    {
        // Get a buffer for input parameters (uses function from MemoryLib.c)
        Unseal_In *in_params = (Unseal_In *) MemoryGetActionInputBuffer(sizeof(Unseal_In));

        // Get a buffer for output parameters (uses function from MemoryLib.c)
        Unseal_Out *out_params = (Unseal_Out *) MemoryGetActionOutputBuffer(sizeof(Unseal_Out));

        // Get handle 0 (itemHandle) from handles array
        in_params->itemHandle = handles[0];


        if(*parmBufferSize != 0)
            return TPM_RC_SIZE;

        // Call to the action routine for TPM2_Unseal
        rc = TPM2_Unseal(in_params, out_params);

        // Check the return code of action routine for TPM2_Unseal
        if(rc != TPM_RC_SUCCESS)
            return rc;

        // Calculate size of Unseal_Out
        size = sizeof(Unseal_Out);

        // Marshal parameter 'outData'
        *respParmSize += TPM2B_SENSITIVE_DATA_Marshal(&out_params->outData, &buffer, &size);

    }
    break;
#endif     // CC_Unseal == YES
#if defined CC_ObjectChangeAuth && CC_ObjectChangeAuth == YES                  // based on Part 4
    case TPM_CC_ObjectChangeAuth:
    {
        // Get a buffer for input parameters (uses function from MemoryLib.c)
        ObjectChangeAuth_In *in_params = (ObjectChangeAuth_In *) MemoryGetActionInputBuffer(sizeof(ObjectChangeAuth_In));

        // Get a buffer for output parameters (uses function from MemoryLib.c)
        ObjectChangeAuth_Out *out_params = (ObjectChangeAuth_Out *) MemoryGetActionOutputBuffer(sizeof(ObjectChangeAuth_Out));

        // Get handle 0 (objectHandle) from handles array
        in_params->objectHandle = handles[0];
        // Get handle 1 (parentHandle) from handles array
        in_params->parentHandle = handles[1];

        rc = TPM2B_AUTH_Unmarshal(&in_params->newAuth, &parmBufferStart, parmBufferSize);
        if(rc != TPM_RC_SUCCESS)
            return rc + RC_ObjectChangeAuth_newAuth;

        if(*parmBufferSize != 0)
            return TPM_RC_SIZE;

        // Call to the action routine for TPM2_ObjectChangeAuth
        rc = TPM2_ObjectChangeAuth(in_params, out_params);

        // Check the return code of action routine for TPM2_ObjectChangeAuth
        if(rc != TPM_RC_SUCCESS)
            return rc;

        // Calculate size of ObjectChangeAuth_Out
        size = sizeof(ObjectChangeAuth_Out);

        // Marshal parameter 'outPrivate'
        *respParmSize += TPM2B_PRIVATE_Marshal(&out_params->outPrivate, &buffer, &size);

    }
    break;
#endif     // CC_ObjectChangeAuth == YES
#if defined CC_Duplicate && CC_Duplicate == YES                  // based on Part 4
    case TPM_CC_Duplicate:
    {
        // Get a buffer for input parameters (uses function from MemoryLib.c)
        Duplicate_In *in_params = (Duplicate_In *) MemoryGetActionInputBuffer(sizeof(Duplicate_In));

        // Get a buffer for output parameters (uses function from MemoryLib.c)
        Duplicate_Out *out_params = (Duplicate_Out *) MemoryGetActionOutputBuffer(sizeof(Duplicate_Out));

        // Get handle 0 (objectHandle) from handles array
        in_params->objectHandle = handles[0];
        // Get handle 1 (newParentHandle) from handles array
        in_params->newParentHandle = handles[1];

        rc = TPM2B_DATA_Unmarshal(&in_params->encryptionKeyIn, &parmBufferStart, parmBufferSize);
        if(rc != TPM_RC_SUCCESS)
            return rc + RC_Duplicate_encryptionKeyIn;
        rc = TPMT_SYM_DEF_OBJECT_Unmarshal(&in_params->symmetricAlg, &parmBufferStart, parmBufferSize, TRUE);
        if(rc != TPM_RC_SUCCESS)
            return rc + RC_Duplicate_symmetricAlg;

        if(*parmBufferSize != 0)
            return TPM_RC_SIZE;

        // Call to the action routine for TPM2_Duplicate
        rc = TPM2_Duplicate(in_params, out_params);

        // Check the return code of action routine for TPM2_Duplicate
        if(rc != TPM_RC_SUCCESS)
            return rc;

        // Calculate size of Duplicate_Out
        size = sizeof(Duplicate_Out);

        // Marshal parameter 'encryptionKeyOut'
        *respParmSize += TPM2B_DATA_Marshal(&out_params->encryptionKeyOut, &buffer, &size);
        // Marshal parameter 'duplicate'
        *respParmSize += TPM2B_PRIVATE_Marshal(&out_params->duplicate, &buffer, &size);
        // Marshal parameter 'outSymSeed'
        *respParmSize += TPM2B_ENCRYPTED_SECRET_Marshal(&out_params->outSymSeed, &buffer, &size);

    }
    break;
#endif     // CC_Duplicate == YES
#if defined CC_Rewrap && CC_Rewrap == YES                  // based on Part 4
    case TPM_CC_Rewrap:
    {
        // Get a buffer for input parameters (uses function from MemoryLib.c)
        Rewrap_In *in_params = (Rewrap_In *) MemoryGetActionInputBuffer(sizeof(Rewrap_In));

        // Get a buffer for output parameters (uses function from MemoryLib.c)
        Rewrap_Out *out_params = (Rewrap_Out *) MemoryGetActionOutputBuffer(sizeof(Rewrap_Out));

        // Get handle 0 (oldParent) from handles array
        in_params->oldParent = handles[0];
        // Get handle 1 (newParent) from handles array
        in_params->newParent = handles[1];

        rc = TPM2B_PRIVATE_Unmarshal(&in_params->inDuplicate, &parmBufferStart, parmBufferSize);
        if(rc != TPM_RC_SUCCESS)
            return rc + RC_Rewrap_inDuplicate;
        rc = TPM2B_NAME_Unmarshal(&in_params->name, &parmBufferStart, parmBufferSize);
        if(rc != TPM_RC_SUCCESS)
            return rc + RC_Rewrap_name;
        rc = TPM2B_ENCRYPTED_SECRET_Unmarshal(&in_params->inSymSeed, &parmBufferStart, parmBufferSize);
        if(rc != TPM_RC_SUCCESS)
            return rc + RC_Rewrap_inSymSeed;

        if(*parmBufferSize != 0)
            return TPM_RC_SIZE;

        // Call to the action routine for TPM2_Rewrap
        rc = TPM2_Rewrap(in_params, out_params);

        // Check the return code of action routine for TPM2_Rewrap
        if(rc != TPM_RC_SUCCESS)
            return rc;

        // Calculate size of Rewrap_Out
        size = sizeof(Rewrap_Out);

        // Marshal parameter 'outDuplicate'
        *respParmSize += TPM2B_PRIVATE_Marshal(&out_params->outDuplicate, &buffer, &size);
        // Marshal parameter 'outSymSeed'
        *respParmSize += TPM2B_ENCRYPTED_SECRET_Marshal(&out_params->outSymSeed, &buffer, &size);

    }
    break;
#endif     // CC_Rewrap == YES
#if defined CC_Import && CC_Import == YES                  // based on Part 4
    case TPM_CC_Import:
    {
        // Get a buffer for input parameters (uses function from MemoryLib.c)
        Import_In *in_params = (Import_In *) MemoryGetActionInputBuffer(sizeof(Import_In));

        // Get a buffer for output parameters (uses function from MemoryLib.c)
        Import_Out *out_params = (Import_Out *) MemoryGetActionOutputBuffer(sizeof(Import_Out));

        // Get handle 0 (parentHandle) from handles array
        in_params->parentHandle = handles[0];

        rc = TPM2B_DATA_Unmarshal(&in_params->encryptionKey, &parmBufferStart, parmBufferSize);
        if(rc != TPM_RC_SUCCESS)
            return rc + RC_Import_encryptionKey;
        rc = TPM2B_PUBLIC_Unmarshal(&in_params->objectPublic, &parmBufferStart, parmBufferSize, FALSE);
        if(rc != TPM_RC_SUCCESS)
            return rc + RC_Import_objectPublic;
        rc = TPM2B_PRIVATE_Unmarshal(&in_params->duplicate, &parmBufferStart, parmBufferSize);
        if(rc != TPM_RC_SUCCESS)
            return rc + RC_Import_duplicate;
        rc = TPM2B_ENCRYPTED_SECRET_Unmarshal(&in_params->inSymSeed, &parmBufferStart, parmBufferSize);
        if(rc != TPM_RC_SUCCESS)
            return rc + RC_Import_inSymSeed;
        rc = TPMT_SYM_DEF_OBJECT_Unmarshal(&in_params->symmetricAlg, &parmBufferStart, parmBufferSize, TRUE);
        if(rc != TPM_RC_SUCCESS)
            return rc + RC_Import_symmetricAlg;

        if(*parmBufferSize != 0)
            return TPM_RC_SIZE;

        // Call to the action routine for TPM2_Import
        rc = TPM2_Import(in_params, out_params);

        // Check the return code of action routine for TPM2_Import
        if(rc != TPM_RC_SUCCESS)
            return rc;

        // Calculate size of Import_Out
        size = sizeof(Import_Out);

        // Marshal parameter 'outPrivate'
        *respParmSize += TPM2B_PRIVATE_Marshal(&out_params->outPrivate, &buffer, &size);

    }
    break;
#endif     // CC_Import == YES
#if defined CC_RSA_Encrypt && CC_RSA_Encrypt == YES                  // based on Part 4
    case TPM_CC_RSA_Encrypt:
    {
        // Get a buffer for input parameters (uses function from MemoryLib.c)
        RSA_Encrypt_In *in_params = (RSA_Encrypt_In *) MemoryGetActionInputBuffer(sizeof(RSA_Encrypt_In));

        // Get a buffer for output parameters (uses function from MemoryLib.c)
        RSA_Encrypt_Out *out_params = (RSA_Encrypt_Out *) MemoryGetActionOutputBuffer(sizeof(RSA_Encrypt_Out));

        // Get handle 0 (keyHandle) from handles array
        in_params->keyHandle = handles[0];

        rc = TPM2B_PUBLIC_KEY_RSA_Unmarshal(&in_params->message, &parmBufferStart, parmBufferSize);
        if(rc != TPM_RC_SUCCESS)
            return rc + RC_RSA_Encrypt_message;
        rc = TPMT_RSA_DECRYPT_Unmarshal(&in_params->inScheme, &parmBufferStart, parmBufferSize, TRUE);
        if(rc != TPM_RC_SUCCESS)
            return rc + RC_RSA_Encrypt_inScheme;
        rc = TPM2B_DATA_Unmarshal(&in_params->label, &parmBufferStart, parmBufferSize);
        if(rc != TPM_RC_SUCCESS)
            return rc + RC_RSA_Encrypt_label;

        if(*parmBufferSize != 0)
            return TPM_RC_SIZE;

        // Call to the action routine for TPM2_RSA_Encrypt
        rc = TPM2_RSA_Encrypt(in_params, out_params);

        // Check the return code of action routine for TPM2_RSA_Encrypt
        if(rc != TPM_RC_SUCCESS)
            return rc;

        // Calculate size of RSA_Encrypt_Out
        size = sizeof(RSA_Encrypt_Out);

        // Marshal parameter 'outData'
        *respParmSize += TPM2B_PUBLIC_KEY_RSA_Marshal(&out_params->outData, &buffer, &size);

    }
    break;
#endif     // CC_RSA_Encrypt == YES
#if defined CC_RSA_Decrypt && CC_RSA_Decrypt == YES                  // based on Part 4
    case TPM_CC_RSA_Decrypt:
    {
        // Get a buffer for input parameters (uses function from MemoryLib.c)
        RSA_Decrypt_In *in_params = (RSA_Decrypt_In *) MemoryGetActionInputBuffer(sizeof(RSA_Decrypt_In));

        // Get a buffer for output parameters (uses function from MemoryLib.c)
        RSA_Decrypt_Out *out_params = (RSA_Decrypt_Out *) MemoryGetActionOutputBuffer(sizeof(RSA_Decrypt_Out));

        // Get handle 0 (keyHandle) from handles array
        in_params->keyHandle = handles[0];

        rc = TPM2B_PUBLIC_KEY_RSA_Unmarshal(&in_params->cipherText, &parmBufferStart, parmBufferSize);
        if(rc != TPM_RC_SUCCESS)
            return rc + RC_RSA_Decrypt_cipherText;
        rc = TPMT_RSA_DECRYPT_Unmarshal(&in_params->inScheme, &parmBufferStart, parmBufferSize, TRUE);
        if(rc != TPM_RC_SUCCESS)
            return rc + RC_RSA_Decrypt_inScheme;
        rc = TPM2B_DATA_Unmarshal(&in_params->label, &parmBufferStart, parmBufferSize);
        if(rc != TPM_RC_SUCCESS)
            return rc + RC_RSA_Decrypt_label;

        if(*parmBufferSize != 0)
            return TPM_RC_SIZE;

        // Call to the action routine for TPM2_RSA_Decrypt
        rc = TPM2_RSA_Decrypt(in_params, out_params);

        // Check the return code of action routine for TPM2_RSA_Decrypt
        if(rc != TPM_RC_SUCCESS)
            return rc;

        // Calculate size of RSA_Decrypt_Out
        size = sizeof(RSA_Decrypt_Out);

        // Marshal parameter 'message'
        *respParmSize += TPM2B_PUBLIC_KEY_RSA_Marshal(&out_params->message, &buffer, &size);

    }
    break;
#endif     // CC_RSA_Decrypt == YES
#if defined CC_ECDH_KeyGen && CC_ECDH_KeyGen == YES                  // based on Part 4
    case TPM_CC_ECDH_KeyGen:
    {
        // Get a buffer for input parameters (uses function from MemoryLib.c)
        ECDH_KeyGen_In *in_params = (ECDH_KeyGen_In *) MemoryGetActionInputBuffer(sizeof(ECDH_KeyGen_In));

        // Get a buffer for output parameters (uses function from MemoryLib.c)
        ECDH_KeyGen_Out *out_params = (ECDH_KeyGen_Out *) MemoryGetActionOutputBuffer(sizeof(ECDH_KeyGen_Out));

        // Get handle 0 (keyHandle) from handles array
        in_params->keyHandle = handles[0];


        if(*parmBufferSize != 0)
            return TPM_RC_SIZE;

        // Call to the action routine for TPM2_ECDH_KeyGen
        rc = TPM2_ECDH_KeyGen(in_params, out_params);

        // Check the return code of action routine for TPM2_ECDH_KeyGen
        if(rc != TPM_RC_SUCCESS)
            return rc;

        // Calculate size of ECDH_KeyGen_Out
        size = sizeof(ECDH_KeyGen_Out);

        // Marshal parameter 'zPoint'
        *respParmSize += TPM2B_ECC_POINT_Marshal(&out_params->zPoint, &buffer, &size);
        // Marshal parameter 'pubPoint'
        *respParmSize += TPM2B_ECC_POINT_Marshal(&out_params->pubPoint, &buffer, &size);

    }
    break;
#endif     // CC_ECDH_KeyGen == YES
#if defined CC_ECDH_ZGen && CC_ECDH_ZGen == YES                  // based on Part 4
    case TPM_CC_ECDH_ZGen:
    {
        // Get a buffer for input parameters (uses function from MemoryLib.c)
        ECDH_ZGen_In *in_params = (ECDH_ZGen_In *) MemoryGetActionInputBuffer(sizeof(ECDH_ZGen_In));

        // Get a buffer for output parameters (uses function from MemoryLib.c)
        ECDH_ZGen_Out *out_params = (ECDH_ZGen_Out *) MemoryGetActionOutputBuffer(sizeof(ECDH_ZGen_Out));

        // Get handle 0 (keyHandle) from handles array
        in_params->keyHandle = handles[0];

        rc = TPM2B_ECC_POINT_Unmarshal(&in_params->inPoint, &parmBufferStart, parmBufferSize);
        if(rc != TPM_RC_SUCCESS)
            return rc + RC_ECDH_ZGen_inPoint;

        if(*parmBufferSize != 0)
            return TPM_RC_SIZE;

        // Call to the action routine for TPM2_ECDH_ZGen
        rc = TPM2_ECDH_ZGen(in_params, out_params);

        // Check the return code of action routine for TPM2_ECDH_ZGen
        if(rc != TPM_RC_SUCCESS)
            return rc;

        // Calculate size of ECDH_ZGen_Out
        size = sizeof(ECDH_ZGen_Out);

        // Marshal parameter 'outPoint'
        *respParmSize += TPM2B_ECC_POINT_Marshal(&out_params->outPoint, &buffer, &size);

    }
    break;
#endif     // CC_ECDH_ZGen == YES
#if defined CC_ECC_Parameters && CC_ECC_Parameters == YES                  // based on Part 4
    case TPM_CC_ECC_Parameters:
    {
        // Get a buffer for input parameters (uses function from MemoryLib.c)
        ECC_Parameters_In *in_params = (ECC_Parameters_In *) MemoryGetActionInputBuffer(sizeof(ECC_Parameters_In));

        // Get a buffer for output parameters (uses function from MemoryLib.c)
        ECC_Parameters_Out *out_params = (ECC_Parameters_Out *) MemoryGetActionOutputBuffer(sizeof(ECC_Parameters_Out));

        // No handles required
        rc = TPMI_ECC_CURVE_Unmarshal(&in_params->curveID, &parmBufferStart, parmBufferSize);
        if(rc != TPM_RC_SUCCESS)
            return rc + RC_ECC_Parameters_curveID;

        if(*parmBufferSize != 0)
            return TPM_RC_SIZE;

        // Call to the action routine for TPM2_ECC_Parameters
        rc = TPM2_ECC_Parameters(in_params, out_params);

        // Check the return code of action routine for TPM2_ECC_Parameters
        if(rc != TPM_RC_SUCCESS)
            return rc;

        // Calculate size of ECC_Parameters_Out
        size = sizeof(ECC_Parameters_Out);

        // Marshal parameter 'parameters'
        *respParmSize += TPMS_ALGORITHM_DETAIL_ECC_Marshal(&out_params->parameters, &buffer, &size);

    }
    break;
#endif     // CC_ECC_Parameters == YES
#if defined CC_ZGen_2Phase && CC_ZGen_2Phase == YES                  // based on Part 4
    case TPM_CC_ZGen_2Phase:
    {
        // Get a buffer for input parameters (uses function from MemoryLib.c)
        ZGen_2Phase_In *in_params = (ZGen_2Phase_In *) MemoryGetActionInputBuffer(sizeof(ZGen_2Phase_In));

        // Get a buffer for output parameters (uses function from MemoryLib.c)
        ZGen_2Phase_Out *out_params = (ZGen_2Phase_Out *) MemoryGetActionOutputBuffer(sizeof(ZGen_2Phase_Out));

        // Get handle 0 (keyA) from handles array
        in_params->keyA = handles[0];

        rc = TPM2B_ECC_POINT_Unmarshal(&in_params->inQsB, &parmBufferStart, parmBufferSize);
        if(rc != TPM_RC_SUCCESS)
            return rc + RC_ZGen_2Phase_inQsB;
        rc = TPM2B_ECC_POINT_Unmarshal(&in_params->inQeB, &parmBufferStart, parmBufferSize);
        if(rc != TPM_RC_SUCCESS)
            return rc + RC_ZGen_2Phase_inQeB;
        rc = TPMI_ECC_KEY_EXCHANGE_Unmarshal(&in_params->inScheme, &parmBufferStart, parmBufferSize, FALSE);
        if(rc != TPM_RC_SUCCESS)
            return rc + RC_ZGen_2Phase_inScheme;
        rc = UINT16_Unmarshal(&in_params->counter, &parmBufferStart, parmBufferSize);
        if(rc != TPM_RC_SUCCESS)
            return rc + RC_ZGen_2Phase_counter;

        if(*parmBufferSize != 0)
            return TPM_RC_SIZE;

        // Call to the action routine for TPM2_ZGen_2Phase
        rc = TPM2_ZGen_2Phase(in_params, out_params);

        // Check the return code of action routine for TPM2_ZGen_2Phase
        if(rc != TPM_RC_SUCCESS)
            return rc;

        // Calculate size of ZGen_2Phase_Out
        size = sizeof(ZGen_2Phase_Out);

        // Marshal parameter 'outZ1'
        *respParmSize += TPM2B_ECC_POINT_Marshal(&out_params->outZ1, &buffer, &size);
        // Marshal parameter 'outZ2'
        *respParmSize += TPM2B_ECC_POINT_Marshal(&out_params->outZ2, &buffer, &size);

    }
    break;
#endif     // CC_ZGen_2Phase == YES
#if defined CC_EncryptDecrypt && CC_EncryptDecrypt == YES                  // based on Part 4
    case TPM_CC_EncryptDecrypt:
    {
        // Get a buffer for input parameters (uses function from MemoryLib.c)
        EncryptDecrypt_In *in_params = (EncryptDecrypt_In *) MemoryGetActionInputBuffer(sizeof(EncryptDecrypt_In));

        // Get a buffer for output parameters (uses function from MemoryLib.c)
        EncryptDecrypt_Out *out_params = (EncryptDecrypt_Out *) MemoryGetActionOutputBuffer(sizeof(EncryptDecrypt_Out));

        // Get handle 0 (keyHandle) from handles array
        in_params->keyHandle = handles[0];

        rc = TPMI_YES_NO_Unmarshal(&in_params->decrypt, &parmBufferStart, parmBufferSize);
        if(rc != TPM_RC_SUCCESS)
            return rc + RC_EncryptDecrypt_decrypt;
        rc = TPMI_ALG_SYM_MODE_Unmarshal(&in_params->mode, &parmBufferStart, parmBufferSize, TRUE);
        if(rc != TPM_RC_SUCCESS)
            return rc + RC_EncryptDecrypt_mode;
        rc = TPM2B_IV_Unmarshal(&in_params->ivIn, &parmBufferStart, parmBufferSize);
        if(rc != TPM_RC_SUCCESS)
            return rc + RC_EncryptDecrypt_ivIn;
        rc = TPM2B_MAX_BUFFER_Unmarshal(&in_params->inData, &parmBufferStart, parmBufferSize);
        if(rc != TPM_RC_SUCCESS)
            return rc + RC_EncryptDecrypt_inData;

        if(*parmBufferSize != 0)
            return TPM_RC_SIZE;

        // Call to the action routine for TPM2_EncryptDecrypt
        rc = TPM2_EncryptDecrypt(in_params, out_params);

        // Check the return code of action routine for TPM2_EncryptDecrypt
        if(rc != TPM_RC_SUCCESS)
            return rc;

        // Calculate size of EncryptDecrypt_Out
        size = sizeof(EncryptDecrypt_Out);

        // Marshal parameter 'outData'
        *respParmSize += TPM2B_MAX_BUFFER_Marshal(&out_params->outData, &buffer, &size);
        // Marshal parameter 'ivOut'
        *respParmSize += TPM2B_IV_Marshal(&out_params->ivOut, &buffer, &size);

    }
    break;
#endif     // CC_EncryptDecrypt == YES
#if defined CC_Hash && CC_Hash == YES                  // based on Part 4
    case TPM_CC_Hash:
    {
        // Get a buffer for input parameters (uses function from MemoryLib.c)
        Hash_In *in_params = (Hash_In *) MemoryGetActionInputBuffer(sizeof(Hash_In));

        // Get a buffer for output parameters (uses function from MemoryLib.c)
        Hash_Out *out_params = (Hash_Out *) MemoryGetActionOutputBuffer(sizeof(Hash_Out));

        // No handles required
        rc = TPM2B_MAX_BUFFER_Unmarshal(&in_params->data, &parmBufferStart, parmBufferSize);
        if(rc != TPM_RC_SUCCESS)
            return rc + RC_Hash_data;
        rc = TPMI_ALG_HASH_Unmarshal(&in_params->hashAlg, &parmBufferStart, parmBufferSize, FALSE);
        if(rc != TPM_RC_SUCCESS)
            return rc + RC_Hash_hashAlg;
        rc = TPMI_RH_HIERARCHY_Unmarshal(&in_params->hierarchy, &parmBufferStart, parmBufferSize, TRUE);
        if(rc != TPM_RC_SUCCESS)
            return rc + RC_Hash_hierarchy;

        if(*parmBufferSize != 0)
            return TPM_RC_SIZE;

        // Call to the action routine for TPM2_Hash
        rc = TPM2_Hash(in_params, out_params);

        // Check the return code of action routine for TPM2_Hash
        if(rc != TPM_RC_SUCCESS)
            return rc;

        // Calculate size of Hash_Out
        size = sizeof(Hash_Out);

        // Marshal parameter 'outHash'
        *respParmSize += TPM2B_DIGEST_Marshal(&out_params->outHash, &buffer, &size);
        // Marshal parameter 'validation'
        *respParmSize += TPMT_TK_HASHCHECK_Marshal(&out_params->validation, &buffer, &size);

    }
    break;
#endif     // CC_Hash == YES
#if defined CC_HMAC && CC_HMAC == YES                  // based on Part 4
    case TPM_CC_HMAC:
    {
        // Get a buffer for input parameters (uses function from MemoryLib.c)
        HMAC_In *in_params = (HMAC_In *) MemoryGetActionInputBuffer(sizeof(HMAC_In));

        // Get a buffer for output parameters (uses function from MemoryLib.c)
        HMAC_Out *out_params = (HMAC_Out *) MemoryGetActionOutputBuffer(sizeof(HMAC_Out));

        // Get handle 0 (handle) from handles array
        in_params->handle = handles[0];

        rc = TPM2B_MAX_BUFFER_Unmarshal(&in_params->buffer, &parmBufferStart, parmBufferSize);
        if(rc != TPM_RC_SUCCESS)
            return rc + RC_HMAC_buffer;
        rc = TPMI_ALG_HASH_Unmarshal(&in_params->hashAlg, &parmBufferStart, parmBufferSize, TRUE);
        if(rc != TPM_RC_SUCCESS)
            return rc + RC_HMAC_hashAlg;

        if(*parmBufferSize != 0)
            return TPM_RC_SIZE;

        // Call to the action routine for TPM2_HMAC
        rc = TPM2_HMAC(in_params, out_params);

        // Check the return code of action routine for TPM2_HMAC
        if(rc != TPM_RC_SUCCESS)
            return rc;

        // Calculate size of HMAC_Out
        size = sizeof(HMAC_Out);

        // Marshal parameter 'outHMAC'
        *respParmSize += TPM2B_DIGEST_Marshal(&out_params->outHMAC, &buffer, &size);

    }
    break;
#endif     // CC_HMAC == YES
#if defined CC_GetRandom && CC_GetRandom == YES                  // based on Part 4
    case TPM_CC_GetRandom:
    {
        // Get a buffer for input parameters (uses function from MemoryLib.c)
        GetRandom_In *in_params = (GetRandom_In *) MemoryGetActionInputBuffer(sizeof(GetRandom_In));

        // Get a buffer for output parameters (uses function from MemoryLib.c)
        GetRandom_Out *out_params = (GetRandom_Out *) MemoryGetActionOutputBuffer(sizeof(GetRandom_Out));

        // No handles required
        rc = UINT16_Unmarshal(&in_params->bytesRequested, &parmBufferStart, parmBufferSize);
        if(rc != TPM_RC_SUCCESS)
            return rc + RC_GetRandom_bytesRequested;

        if(*parmBufferSize != 0)
            return TPM_RC_SIZE;

        // Call to the action routine for TPM2_GetRandom
        rc = TPM2_GetRandom(in_params, out_params);

        // Check the return code of action routine for TPM2_GetRandom
        if(rc != TPM_RC_SUCCESS)
            return rc;

        // Calculate size of GetRandom_Out
        size = sizeof(GetRandom_Out);

        // Marshal parameter 'randomBytes'
        *respParmSize += TPM2B_DIGEST_Marshal(&out_params->randomBytes, &buffer, &size);

    }
    break;
#endif     // CC_GetRandom == YES
#if defined CC_StirRandom && CC_StirRandom == YES                  // based on Part 4
    case TPM_CC_StirRandom:
    {
        // Get a buffer for input parameters (uses function from MemoryLib.c)
        StirRandom_In *in_params = (StirRandom_In *) MemoryGetActionInputBuffer(sizeof(StirRandom_In));

        // No buffer for output parameters required

        // No handles required
        rc = TPM2B_SENSITIVE_DATA_Unmarshal(&in_params->inData, &parmBufferStart, parmBufferSize);
        if(rc != TPM_RC_SUCCESS)
            return rc + RC_StirRandom_inData;

        if(*parmBufferSize != 0)
            return TPM_RC_SIZE;

        // Call to the action routine for TPM2_StirRandom
        rc = TPM2_StirRandom(in_params);

        // Check the return code of action routine for TPM2_StirRandom
        if(rc != TPM_RC_SUCCESS)
            return rc;


    }
    break;
#endif     // CC_StirRandom == YES
#if defined CC_HMAC_Start && CC_HMAC_Start == YES                  // based on Part 4
    case TPM_CC_HMAC_Start:
    {
        // Get a buffer for input parameters (uses function from MemoryLib.c)
        HMAC_Start_In *in_params = (HMAC_Start_In *) MemoryGetActionInputBuffer(sizeof(HMAC_Start_In));

        // Get a buffer for output parameters (uses function from MemoryLib.c)
        HMAC_Start_Out *out_params = (HMAC_Start_Out *) MemoryGetActionOutputBuffer(sizeof(HMAC_Start_Out));

        // Get handle 0 (handle) from handles array
        in_params->handle = handles[0];

        rc = TPM2B_AUTH_Unmarshal(&in_params->auth, &parmBufferStart, parmBufferSize);
        if(rc != TPM_RC_SUCCESS)
            return rc + RC_HMAC_Start_auth;
        rc = TPMI_ALG_HASH_Unmarshal(&in_params->hashAlg, &parmBufferStart, parmBufferSize, TRUE);
        if(rc != TPM_RC_SUCCESS)
            return rc + RC_HMAC_Start_hashAlg;

        if(*parmBufferSize != 0)
            return TPM_RC_SIZE;

        // Call to the action routine for TPM2_HMAC_Start
        rc = TPM2_HMAC_Start(in_params, out_params);

        // Check the return code of action routine for TPM2_HMAC_Start
        if(rc != TPM_RC_SUCCESS)
            return rc;

        // Calculate size of HMAC_Start_Out
        size = sizeof(HMAC_Start_Out);

        // Marshal handle 'sequenceHandle'
        *responseHandleSize += TPMI_DH_OBJECT_Marshal(&out_params->sequenceHandle, &responseHandlePtr, &size);

    }
    break;
#endif     // CC_HMAC_Start == YES
#if defined CC_HashSequenceStart && CC_HashSequenceStart == YES                  // based on Part 4
    case TPM_CC_HashSequenceStart:
    {
        // Get a buffer for input parameters (uses function from MemoryLib.c)
        HashSequenceStart_In *in_params = (HashSequenceStart_In *) MemoryGetActionInputBuffer(sizeof(HashSequenceStart_In));

        // Get a buffer for output parameters (uses function from MemoryLib.c)
        HashSequenceStart_Out *out_params = (HashSequenceStart_Out *) MemoryGetActionOutputBuffer(sizeof(HashSequenceStart_Out));

        // No handles required
        rc = TPM2B_AUTH_Unmarshal(&in_params->auth, &parmBufferStart, parmBufferSize);
        if(rc != TPM_RC_SUCCESS)
            return rc + RC_HashSequenceStart_auth;
        rc = TPMI_ALG_HASH_Unmarshal(&in_params->hashAlg, &parmBufferStart, parmBufferSize, TRUE);
        if(rc != TPM_RC_SUCCESS)
            return rc + RC_HashSequenceStart_hashAlg;

        if(*parmBufferSize != 0)
            return TPM_RC_SIZE;

        // Call to the action routine for TPM2_HashSequenceStart
        rc = TPM2_HashSequenceStart(in_params, out_params);

        // Check the return code of action routine for TPM2_HashSequenceStart
        if(rc != TPM_RC_SUCCESS)
            return rc;

        // Calculate size of HashSequenceStart_Out
        size = sizeof(HashSequenceStart_Out);

        // Marshal handle 'sequenceHandle'
        *responseHandleSize += TPMI_DH_OBJECT_Marshal(&out_params->sequenceHandle, &responseHandlePtr, &size);

    }
    break;
#endif     // CC_HashSequenceStart == YES
#if defined CC_SequenceUpdate && CC_SequenceUpdate == YES                  // based on Part 4
    case TPM_CC_SequenceUpdate:
    {
        // Get a buffer for input parameters (uses function from MemoryLib.c)
        SequenceUpdate_In *in_params = (SequenceUpdate_In *) MemoryGetActionInputBuffer(sizeof(SequenceUpdate_In));

        // No buffer for output parameters required

        // Get handle 0 (sequenceHandle) from handles array
        in_params->sequenceHandle = handles[0];

        rc = TPM2B_MAX_BUFFER_Unmarshal(&in_params->buffer, &parmBufferStart, parmBufferSize);
        if(rc != TPM_RC_SUCCESS)
            return rc + RC_SequenceUpdate_buffer;

        if(*parmBufferSize != 0)
            return TPM_RC_SIZE;

        // Call to the action routine for TPM2_SequenceUpdate
        rc = TPM2_SequenceUpdate(in_params);

        // Check the return code of action routine for TPM2_SequenceUpdate
        if(rc != TPM_RC_SUCCESS)
            return rc;


    }
    break;
#endif     // CC_SequenceUpdate == YES
#if defined CC_SequenceComplete && CC_SequenceComplete == YES                  // based on Part 4
    case TPM_CC_SequenceComplete:
    {
        // Get a buffer for input parameters (uses function from MemoryLib.c)
        SequenceComplete_In *in_params = (SequenceComplete_In *) MemoryGetActionInputBuffer(sizeof(SequenceComplete_In));

        // Get a buffer for output parameters (uses function from MemoryLib.c)
        SequenceComplete_Out *out_params = (SequenceComplete_Out *) MemoryGetActionOutputBuffer(sizeof(SequenceComplete_Out));

        // Get handle 0 (sequenceHandle) from handles array
        in_params->sequenceHandle = handles[0];

        rc = TPM2B_MAX_BUFFER_Unmarshal(&in_params->buffer, &parmBufferStart, parmBufferSize);
        if(rc != TPM_RC_SUCCESS)
            return rc + RC_SequenceComplete_buffer;
        rc = TPMI_RH_HIERARCHY_Unmarshal(&in_params->hierarchy, &parmBufferStart, parmBufferSize, TRUE);
        if(rc != TPM_RC_SUCCESS)
            return rc + RC_SequenceComplete_hierarchy;

        if(*parmBufferSize != 0)
            return TPM_RC_SIZE;

        // Call to the action routine for TPM2_SequenceComplete
        rc = TPM2_SequenceComplete(in_params, out_params);

        // Check the return code of action routine for TPM2_SequenceComplete
        if(rc != TPM_RC_SUCCESS)
            return rc;

        // Calculate size of SequenceComplete_Out
        size = sizeof(SequenceComplete_Out);

        // Marshal parameter 'result'
        *respParmSize += TPM2B_DIGEST_Marshal(&out_params->result, &buffer, &size);
        // Marshal parameter 'validation'
        *respParmSize += TPMT_TK_HASHCHECK_Marshal(&out_params->validation, &buffer, &size);

    }
    break;
#endif     // CC_SequenceComplete == YES
#if defined CC_EventSequenceComplete && CC_EventSequenceComplete == YES                  // based on Part 4
    case TPM_CC_EventSequenceComplete:
    {
        // Get a buffer for input parameters (uses function from MemoryLib.c)
        EventSequenceComplete_In *in_params = (EventSequenceComplete_In *) MemoryGetActionInputBuffer(sizeof(EventSequenceComplete_In));

        // Get a buffer for output parameters (uses function from MemoryLib.c)
        EventSequenceComplete_Out *out_params = (EventSequenceComplete_Out *) MemoryGetActionOutputBuffer(sizeof(EventSequenceComplete_Out));

        // Get handle 0 (pcrHandle) from handles array
        in_params->pcrHandle = handles[0];
        // Get handle 1 (sequenceHandle) from handles array
        in_params->sequenceHandle = handles[1];

        rc = TPM2B_MAX_BUFFER_Unmarshal(&in_params->buffer, &parmBufferStart, parmBufferSize);
        if(rc != TPM_RC_SUCCESS)
            return rc + RC_EventSequenceComplete_buffer;

        if(*parmBufferSize != 0)
            return TPM_RC_SIZE;

        // Call to the action routine for TPM2_EventSequenceComplete
        rc = TPM2_EventSequenceComplete(in_params, out_params);

        // Check the return code of action routine for TPM2_EventSequenceComplete
        if(rc != TPM_RC_SUCCESS)
            return rc;

        // Calculate size of EventSequenceComplete_Out
        size = sizeof(EventSequenceComplete_Out);

        // Marshal parameter 'results'
        *respParmSize += TPML_DIGEST_VALUES_Marshal(&out_params->results, &buffer, &size);

    }
    break;
#endif     // CC_EventSequenceComplete == YES
#if defined CC_Certify && CC_Certify == YES                  // based on Part 4
    case TPM_CC_Certify:
    {
        // Get a buffer for input parameters (uses function from MemoryLib.c)
        Certify_In *in_params = (Certify_In *) MemoryGetActionInputBuffer(sizeof(Certify_In));

        // Get a buffer for output parameters (uses function from MemoryLib.c)
        Certify_Out *out_params = (Certify_Out *) MemoryGetActionOutputBuffer(sizeof(Certify_Out));

        // Get handle 0 (objectHandle) from handles array
        in_params->objectHandle = handles[0];
        // Get handle 1 (signHandle) from handles array
        in_params->signHandle = handles[1];

        rc = TPM2B_DATA_Unmarshal(&in_params->qualifyingData, &parmBufferStart, parmBufferSize);
        if(rc != TPM_RC_SUCCESS)
            return rc + RC_Certify_qualifyingData;
        rc = TPMT_SIG_SCHEME_Unmarshal(&in_params->inScheme, &parmBufferStart, parmBufferSize, TRUE);
        if(rc != TPM_RC_SUCCESS)
            return rc + RC_Certify_inScheme;

        if(*parmBufferSize != 0)
            return TPM_RC_SIZE;

        // Call to the action routine for TPM2_Certify
        rc = TPM2_Certify(in_params, out_params);

        // Check the return code of action routine for TPM2_Certify
        if(rc != TPM_RC_SUCCESS)
            return rc;

        // Calculate size of Certify_Out
        size = sizeof(Certify_Out);

        // Marshal parameter 'certifyInfo'
        *respParmSize += TPM2B_ATTEST_Marshal(&out_params->certifyInfo, &buffer, &size);
        // Marshal parameter 'signature'
        *respParmSize += TPMT_SIGNATURE_Marshal(&out_params->signature, &buffer, &size);

    }
    break;
#endif     // CC_Certify == YES
#if defined CC_CertifyCreation && CC_CertifyCreation == YES                  // based on Part 4
    case TPM_CC_CertifyCreation:
    {
        // Get a buffer for input parameters (uses function from MemoryLib.c)
        CertifyCreation_In *in_params = (CertifyCreation_In *) MemoryGetActionInputBuffer(sizeof(CertifyCreation_In));

        // Get a buffer for output parameters (uses function from MemoryLib.c)
        CertifyCreation_Out *out_params = (CertifyCreation_Out *) MemoryGetActionOutputBuffer(sizeof(CertifyCreation_Out));

        // Get handle 0 (signHandle) from handles array
        in_params->signHandle = handles[0];
        // Get handle 1 (objectHandle) from handles array
        in_params->objectHandle = handles[1];

        rc = TPM2B_DATA_Unmarshal(&in_params->qualifyingData, &parmBufferStart, parmBufferSize);
        if(rc != TPM_RC_SUCCESS)
            return rc + RC_CertifyCreation_qualifyingData;
        rc = TPM2B_DIGEST_Unmarshal(&in_params->creationHash, &parmBufferStart, parmBufferSize);
        if(rc != TPM_RC_SUCCESS)
            return rc + RC_CertifyCreation_creationHash;
        rc = TPMT_SIG_SCHEME_Unmarshal(&in_params->inScheme, &parmBufferStart, parmBufferSize, TRUE);
        if(rc != TPM_RC_SUCCESS)
            return rc + RC_CertifyCreation_inScheme;
        rc = TPMT_TK_CREATION_Unmarshal(&in_params->creationTicket, &parmBufferStart, parmBufferSize);
        if(rc != TPM_RC_SUCCESS)
            return rc + RC_CertifyCreation_creationTicket;

        if(*parmBufferSize != 0)
            return TPM_RC_SIZE;

        // Call to the action routine for TPM2_CertifyCreation
        rc = TPM2_CertifyCreation(in_params, out_params);

        // Check the return code of action routine for TPM2_CertifyCreation
        if(rc != TPM_RC_SUCCESS)
            return rc;

        // Calculate size of CertifyCreation_Out
        size = sizeof(CertifyCreation_Out);

        // Marshal parameter 'certifyInfo'
        *respParmSize += TPM2B_ATTEST_Marshal(&out_params->certifyInfo, &buffer, &size);
        // Marshal parameter 'signature'
        *respParmSize += TPMT_SIGNATURE_Marshal(&out_params->signature, &buffer, &size);

    }
    break;
#endif     // CC_CertifyCreation == YES
#if defined CC_Quote && CC_Quote == YES                  // based on Part 4
    case TPM_CC_Quote:
    {
        // Get a buffer for input parameters (uses function from MemoryLib.c)
        Quote_In *in_params = (Quote_In *) MemoryGetActionInputBuffer(sizeof(Quote_In));

        // Get a buffer for output parameters (uses function from MemoryLib.c)
        Quote_Out *out_params = (Quote_Out *) MemoryGetActionOutputBuffer(sizeof(Quote_Out));

        // Get handle 0 (signHandle) from handles array
        in_params->signHandle = handles[0];

        rc = TPM2B_DATA_Unmarshal(&in_params->qualifyingData, &parmBufferStart, parmBufferSize);
        if(rc != TPM_RC_SUCCESS)
            return rc + RC_Quote_qualifyingData;
        rc = TPMT_SIG_SCHEME_Unmarshal(&in_params->inScheme, &parmBufferStart, parmBufferSize, TRUE);
        if(rc != TPM_RC_SUCCESS)
            return rc + RC_Quote_inScheme;
        rc = TPML_PCR_SELECTION_Unmarshal(&in_params->PCRselect, &parmBufferStart, parmBufferSize);
        if(rc != TPM_RC_SUCCESS)
            return rc + RC_Quote_PCRselect;

        if(*parmBufferSize != 0)
            return TPM_RC_SIZE;

        // Call to the action routine for TPM2_Quote
        rc = TPM2_Quote(in_params, out_params);

        // Check the return code of action routine for TPM2_Quote
        if(rc != TPM_RC_SUCCESS)
            return rc;

        // Calculate size of Quote_Out
        size = sizeof(Quote_Out);

        // Marshal parameter 'quoted'
        *respParmSize += TPM2B_ATTEST_Marshal(&out_params->quoted, &buffer, &size);
        // Marshal parameter 'signature'
        *respParmSize += TPMT_SIGNATURE_Marshal(&out_params->signature, &buffer, &size);

    }
    break;
#endif     // CC_Quote == YES
#if defined CC_GetSessionAuditDigest && CC_GetSessionAuditDigest == YES                  // based on Part 4
    case TPM_CC_GetSessionAuditDigest:
    {
        // Get a buffer for input parameters (uses function from MemoryLib.c)
        GetSessionAuditDigest_In *in_params = (GetSessionAuditDigest_In *) MemoryGetActionInputBuffer(sizeof(GetSessionAuditDigest_In));

        // Get a buffer for output parameters (uses function from MemoryLib.c)
        GetSessionAuditDigest_Out *out_params = (GetSessionAuditDigest_Out *) MemoryGetActionOutputBuffer(sizeof(GetSessionAuditDigest_Out));

        // Get handle 0 (privacyAdminHandle) from handles array
        in_params->privacyAdminHandle = handles[0];
        // Get handle 1 (signHandle) from handles array
        in_params->signHandle = handles[1];
        // Get handle 2 (sessionHandle) from handles array
        in_params->sessionHandle = handles[2];

        rc = TPM2B_DATA_Unmarshal(&in_params->qualifyingData, &parmBufferStart, parmBufferSize);
        if(rc != TPM_RC_SUCCESS)
            return rc + RC_GetSessionAuditDigest_qualifyingData;
        rc = TPMT_SIG_SCHEME_Unmarshal(&in_params->inScheme, &parmBufferStart, parmBufferSize, TRUE);
        if(rc != TPM_RC_SUCCESS)
            return rc + RC_GetSessionAuditDigest_inScheme;

        if(*parmBufferSize != 0)
            return TPM_RC_SIZE;

        // Call to the action routine for TPM2_GetSessionAuditDigest
        rc = TPM2_GetSessionAuditDigest(in_params, out_params);

        // Check the return code of action routine for TPM2_GetSessionAuditDigest
        if(rc != TPM_RC_SUCCESS)
            return rc;

        // Calculate size of GetSessionAuditDigest_Out
        size = sizeof(GetSessionAuditDigest_Out);

        // Marshal parameter 'auditInfo'
        *respParmSize += TPM2B_ATTEST_Marshal(&out_params->auditInfo, &buffer, &size);
        // Marshal parameter 'signature'
        *respParmSize += TPMT_SIGNATURE_Marshal(&out_params->signature, &buffer, &size);

    }
    break;
#endif     // CC_GetSessionAuditDigest == YES
#if defined CC_GetCommandAuditDigest && CC_GetCommandAuditDigest == YES                  // based on Part 4
    case TPM_CC_GetCommandAuditDigest:
    {
        // Get a buffer for input parameters (uses function from MemoryLib.c)
        GetCommandAuditDigest_In *in_params = (GetCommandAuditDigest_In *) MemoryGetActionInputBuffer(sizeof(GetCommandAuditDigest_In));

        // Get a buffer for output parameters (uses function from MemoryLib.c)
        GetCommandAuditDigest_Out *out_params = (GetCommandAuditDigest_Out *) MemoryGetActionOutputBuffer(sizeof(GetCommandAuditDigest_Out));

        // Get handle 0 (privacyHandle) from handles array
        in_params->privacyHandle = handles[0];
        // Get handle 1 (signHandle) from handles array
        in_params->signHandle = handles[1];

        rc = TPM2B_DATA_Unmarshal(&in_params->qualifyingData, &parmBufferStart, parmBufferSize);
        if(rc != TPM_RC_SUCCESS)
            return rc + RC_GetCommandAuditDigest_qualifyingData;
        rc = TPMT_SIG_SCHEME_Unmarshal(&in_params->inScheme, &parmBufferStart, parmBufferSize, TRUE);
        if(rc != TPM_RC_SUCCESS)
            return rc + RC_GetCommandAuditDigest_inScheme;

        if(*parmBufferSize != 0)
            return TPM_RC_SIZE;

        // Call to the action routine for TPM2_GetCommandAuditDigest
        rc = TPM2_GetCommandAuditDigest(in_params, out_params);

        // Check the return code of action routine for TPM2_GetCommandAuditDigest
        if(rc != TPM_RC_SUCCESS)
            return rc;

        // Calculate size of GetCommandAuditDigest_Out
        size = sizeof(GetCommandAuditDigest_Out);

        // Marshal parameter 'auditInfo'
        *respParmSize += TPM2B_ATTEST_Marshal(&out_params->auditInfo, &buffer, &size);
        // Marshal parameter 'signature'
        *respParmSize += TPMT_SIGNATURE_Marshal(&out_params->signature, &buffer, &size);

    }
    break;
#endif     // CC_GetCommandAuditDigest == YES
#if defined CC_GetTime && CC_GetTime == YES                  // based on Part 4
    case TPM_CC_GetTime:
    {
        // Get a buffer for input parameters (uses function from MemoryLib.c)
        GetTime_In *in_params = (GetTime_In *) MemoryGetActionInputBuffer(sizeof(GetTime_In));

        // Get a buffer for output parameters (uses function from MemoryLib.c)
        GetTime_Out *out_params = (GetTime_Out *) MemoryGetActionOutputBuffer(sizeof(GetTime_Out));

        // Get handle 0 (privacyAdminHandle) from handles array
        in_params->privacyAdminHandle = handles[0];
        // Get handle 1 (signHandle) from handles array
        in_params->signHandle = handles[1];

        rc = TPM2B_DATA_Unmarshal(&in_params->qualifyingData, &parmBufferStart, parmBufferSize);
        if(rc != TPM_RC_SUCCESS)
            return rc + RC_GetTime_qualifyingData;
        rc = TPMT_SIG_SCHEME_Unmarshal(&in_params->inScheme, &parmBufferStart, parmBufferSize, TRUE);
        if(rc != TPM_RC_SUCCESS)
            return rc + RC_GetTime_inScheme;

        if(*parmBufferSize != 0)
            return TPM_RC_SIZE;

        // Call to the action routine for TPM2_GetTime
        rc = TPM2_GetTime(in_params, out_params);

        // Check the return code of action routine for TPM2_GetTime
        if(rc != TPM_RC_SUCCESS)
            return rc;

        // Calculate size of GetTime_Out
        size = sizeof(GetTime_Out);

        // Marshal parameter 'timeInfo'
        *respParmSize += TPM2B_ATTEST_Marshal(&out_params->timeInfo, &buffer, &size);
        // Marshal parameter 'signature'
        *respParmSize += TPMT_SIGNATURE_Marshal(&out_params->signature, &buffer, &size);

    }
    break;
#endif     // CC_GetTime == YES
#if defined CC_Commit && CC_Commit == YES                  // based on Part 4
    case TPM_CC_Commit:
    {
        // Get a buffer for input parameters (uses function from MemoryLib.c)
        Commit_In *in_params = (Commit_In *) MemoryGetActionInputBuffer(sizeof(Commit_In));

        // Get a buffer for output parameters (uses function from MemoryLib.c)
        Commit_Out *out_params = (Commit_Out *) MemoryGetActionOutputBuffer(sizeof(Commit_Out));

        // Get handle 0 (signHandle) from handles array
        in_params->signHandle = handles[0];

        rc = TPM2B_ECC_POINT_Unmarshal(&in_params->P1, &parmBufferStart, parmBufferSize);
        if(rc != TPM_RC_SUCCESS)
            return rc + RC_Commit_P1;
        rc = TPM2B_SENSITIVE_DATA_Unmarshal(&in_params->s2, &parmBufferStart, parmBufferSize);
        if(rc != TPM_RC_SUCCESS)
            return rc + RC_Commit_s2;
        rc = TPM2B_ECC_PARAMETER_Unmarshal(&in_params->y2, &parmBufferStart, parmBufferSize);
        if(rc != TPM_RC_SUCCESS)
            return rc + RC_Commit_y2;

        if(*parmBufferSize != 0)
            return TPM_RC_SIZE;

        // Call to the action routine for TPM2_Commit
        rc = TPM2_Commit(in_params, out_params);

        // Check the return code of action routine for TPM2_Commit
        if(rc != TPM_RC_SUCCESS)
            return rc;

        // Calculate size of Commit_Out
        size = sizeof(Commit_Out);

        // Marshal parameter 'K'
        *respParmSize += TPM2B_ECC_POINT_Marshal(&out_params->K, &buffer, &size);
        // Marshal parameter 'L'
        *respParmSize += TPM2B_ECC_POINT_Marshal(&out_params->L, &buffer, &size);
        // Marshal parameter 'E'
        *respParmSize += TPM2B_ECC_POINT_Marshal(&out_params->E, &buffer, &size);
        // Marshal parameter 'counter'
        *respParmSize += UINT16_Marshal(&out_params->counter, &buffer, &size);

    }
    break;
#endif     // CC_Commit == YES
#if defined CC_EC_Ephemeral && CC_EC_Ephemeral == YES                  // based on Part 4
    case TPM_CC_EC_Ephemeral:
    {
        // Get a buffer for input parameters (uses function from MemoryLib.c)
        EC_Ephemeral_In *in_params = (EC_Ephemeral_In *) MemoryGetActionInputBuffer(sizeof(EC_Ephemeral_In));

        // Get a buffer for output parameters (uses function from MemoryLib.c)
        EC_Ephemeral_Out *out_params = (EC_Ephemeral_Out *) MemoryGetActionOutputBuffer(sizeof(EC_Ephemeral_Out));

        // No handles required
        rc = TPMI_ECC_CURVE_Unmarshal(&in_params->curveID, &parmBufferStart, parmBufferSize);
        if(rc != TPM_RC_SUCCESS)
            return rc + RC_EC_Ephemeral_curveID;

        if(*parmBufferSize != 0)
            return TPM_RC_SIZE;

        // Call to the action routine for TPM2_EC_Ephemeral
        rc = TPM2_EC_Ephemeral(in_params, out_params);

        // Check the return code of action routine for TPM2_EC_Ephemeral
        if(rc != TPM_RC_SUCCESS)
            return rc;

        // Calculate size of EC_Ephemeral_Out
        size = sizeof(EC_Ephemeral_Out);

        // Marshal parameter 'Q'
        *respParmSize += TPM2B_ECC_POINT_Marshal(&out_params->Q, &buffer, &size);
        // Marshal parameter 'counter'
        *respParmSize += UINT16_Marshal(&out_params->counter, &buffer, &size);

    }
    break;
#endif     // CC_EC_Ephemeral == YES
#if defined CC_VerifySignature && CC_VerifySignature == YES                  // based on Part 4
    case TPM_CC_VerifySignature:
    {
        // Get a buffer for input parameters (uses function from MemoryLib.c)
        VerifySignature_In *in_params = (VerifySignature_In *) MemoryGetActionInputBuffer(sizeof(VerifySignature_In));

        // Get a buffer for output parameters (uses function from MemoryLib.c)
        VerifySignature_Out *out_params = (VerifySignature_Out *) MemoryGetActionOutputBuffer(sizeof(VerifySignature_Out));

        // Get handle 0 (keyHandle) from handles array
        in_params->keyHandle = handles[0];

        rc = TPM2B_DIGEST_Unmarshal(&in_params->digest, &parmBufferStart, parmBufferSize);
        if(rc != TPM_RC_SUCCESS)
            return rc + RC_VerifySignature_digest;
        rc = TPMT_SIGNATURE_Unmarshal(&in_params->signature, &parmBufferStart, parmBufferSize, FALSE);
        if(rc != TPM_RC_SUCCESS)
            return rc + RC_VerifySignature_signature;

        if(*parmBufferSize != 0)
            return TPM_RC_SIZE;

        // Call to the action routine for TPM2_VerifySignature
        rc = TPM2_VerifySignature(in_params, out_params);

        // Check the return code of action routine for TPM2_VerifySignature
        if(rc != TPM_RC_SUCCESS)
            return rc;

        // Calculate size of VerifySignature_Out
        size = sizeof(VerifySignature_Out);

        // Marshal parameter 'validation'
        *respParmSize += TPMT_TK_VERIFIED_Marshal(&out_params->validation, &buffer, &size);

    }
    break;
#endif     // CC_VerifySignature == YES
#if defined CC_Sign && CC_Sign == YES                  // based on Part 4
    case TPM_CC_Sign:
    {
        // Get a buffer for input parameters (uses function from MemoryLib.c)
        Sign_In *in_params = (Sign_In *) MemoryGetActionInputBuffer(sizeof(Sign_In));

        // Get a buffer for output parameters (uses function from MemoryLib.c)
        Sign_Out *out_params = (Sign_Out *) MemoryGetActionOutputBuffer(sizeof(Sign_Out));

        // Get handle 0 (keyHandle) from handles array
        in_params->keyHandle = handles[0];

        rc = TPM2B_DIGEST_Unmarshal(&in_params->digest, &parmBufferStart, parmBufferSize);
        if(rc != TPM_RC_SUCCESS)
            return rc + RC_Sign_digest;
        rc = TPMT_SIG_SCHEME_Unmarshal(&in_params->inScheme, &parmBufferStart, parmBufferSize, TRUE);
        if(rc != TPM_RC_SUCCESS)
            return rc + RC_Sign_inScheme;
        rc = TPMT_TK_HASHCHECK_Unmarshal(&in_params->validation, &parmBufferStart, parmBufferSize);
        if(rc != TPM_RC_SUCCESS)
            return rc + RC_Sign_validation;

        if(*parmBufferSize != 0)
            return TPM_RC_SIZE;

        // Call to the action routine for TPM2_Sign
        rc = TPM2_Sign(in_params, out_params);

        // Check the return code of action routine for TPM2_Sign
        if(rc != TPM_RC_SUCCESS)
            return rc;

        // Calculate size of Sign_Out
        size = sizeof(Sign_Out);

        // Marshal parameter 'signature'
        *respParmSize += TPMT_SIGNATURE_Marshal(&out_params->signature, &buffer, &size);

    }
    break;
#endif     // CC_Sign == YES
#if defined CC_SetCommandCodeAuditStatus && CC_SetCommandCodeAuditStatus == YES                  // based on Part 4
    case TPM_CC_SetCommandCodeAuditStatus:
    {
        // Get a buffer for input parameters (uses function from MemoryLib.c)
        SetCommandCodeAuditStatus_In *in_params = (SetCommandCodeAuditStatus_In *) MemoryGetActionInputBuffer(sizeof(SetCommandCodeAuditStatus_In));

        // No buffer for output parameters required

        // Get handle 0 (auth) from handles array
        in_params->auth = handles[0];

        rc = TPMI_ALG_HASH_Unmarshal(&in_params->auditAlg, &parmBufferStart, parmBufferSize, TRUE);
        if(rc != TPM_RC_SUCCESS)
            return rc + RC_SetCommandCodeAuditStatus_auditAlg;
        rc = TPML_CC_Unmarshal(&in_params->setList, &parmBufferStart, parmBufferSize);
        if(rc != TPM_RC_SUCCESS)
            return rc + RC_SetCommandCodeAuditStatus_setList;
        rc = TPML_CC_Unmarshal(&in_params->clearList, &parmBufferStart, parmBufferSize);
        if(rc != TPM_RC_SUCCESS)
            return rc + RC_SetCommandCodeAuditStatus_clearList;

        if(*parmBufferSize != 0)
            return TPM_RC_SIZE;

        // Call to the action routine for TPM2_SetCommandCodeAuditStatus
        rc = TPM2_SetCommandCodeAuditStatus(in_params);

        // Check the return code of action routine for TPM2_SetCommandCodeAuditStatus
        if(rc != TPM_RC_SUCCESS)
            return rc;


    }
    break;
#endif     // CC_SetCommandCodeAuditStatus == YES
#if defined CC_PCR_Extend && CC_PCR_Extend == YES                  // based on Part 4
    case TPM_CC_PCR_Extend:
    {
        // Get a buffer for input parameters (uses function from MemoryLib.c)
        PCR_Extend_In *in_params = (PCR_Extend_In *) MemoryGetActionInputBuffer(sizeof(PCR_Extend_In));

        // No buffer for output parameters required

        // Get handle 0 (pcrHandle) from handles array
        in_params->pcrHandle = handles[0];

        rc = TPML_DIGEST_VALUES_Unmarshal(&in_params->digests, &parmBufferStart, parmBufferSize);
        if(rc != TPM_RC_SUCCESS)
            return rc + RC_PCR_Extend_digests;

        if(*parmBufferSize != 0)
            return TPM_RC_SIZE;

        // Call to the action routine for TPM2_PCR_Extend
        rc = TPM2_PCR_Extend(in_params);

        // Check the return code of action routine for TPM2_PCR_Extend
        if(rc != TPM_RC_SUCCESS)
            return rc;


    }
    break;
#endif     // CC_PCR_Extend == YES
#if defined CC_PCR_Event && CC_PCR_Event == YES                  // based on Part 4
    case TPM_CC_PCR_Event:
    {
        // Get a buffer for input parameters (uses function from MemoryLib.c)
        PCR_Event_In *in_params = (PCR_Event_In *) MemoryGetActionInputBuffer(sizeof(PCR_Event_In));

        // Get a buffer for output parameters (uses function from MemoryLib.c)
        PCR_Event_Out *out_params = (PCR_Event_Out *) MemoryGetActionOutputBuffer(sizeof(PCR_Event_Out));

        // Get handle 0 (pcrHandle) from handles array
        in_params->pcrHandle = handles[0];

        rc = TPM2B_EVENT_Unmarshal(&in_params->eventData, &parmBufferStart, parmBufferSize);
        if(rc != TPM_RC_SUCCESS)
            return rc + RC_PCR_Event_eventData;

        if(*parmBufferSize != 0)
            return TPM_RC_SIZE;

        // Call to the action routine for TPM2_PCR_Event
        rc = TPM2_PCR_Event(in_params, out_params);

        // Check the return code of action routine for TPM2_PCR_Event
        if(rc != TPM_RC_SUCCESS)
            return rc;

        // Calculate size of PCR_Event_Out
        size = sizeof(PCR_Event_Out);

        // Marshal parameter 'digests'
        *respParmSize += TPML_DIGEST_VALUES_Marshal(&out_params->digests, &buffer, &size);

    }
    break;
#endif     // CC_PCR_Event == YES
#if defined CC_PCR_Read && CC_PCR_Read == YES                  // based on Part 4
    case TPM_CC_PCR_Read:
    {
        // Get a buffer for input parameters (uses function from MemoryLib.c)
        PCR_Read_In *in_params = (PCR_Read_In *) MemoryGetActionInputBuffer(sizeof(PCR_Read_In));

        // Get a buffer for output parameters (uses function from MemoryLib.c)
        PCR_Read_Out *out_params = (PCR_Read_Out *) MemoryGetActionOutputBuffer(sizeof(PCR_Read_Out));

        // No handles required
        rc = TPML_PCR_SELECTION_Unmarshal(&in_params->pcrSelectionIn, &parmBufferStart, parmBufferSize);
        if(rc != TPM_RC_SUCCESS)
            return rc + RC_PCR_Read_pcrSelectionIn;

        if(*parmBufferSize != 0)
            return TPM_RC_SIZE;

        // Call to the action routine for TPM2_PCR_Read
        rc = TPM2_PCR_Read(in_params, out_params);

        // Check the return code of action routine for TPM2_PCR_Read
        if(rc != TPM_RC_SUCCESS)
            return rc;

        // Calculate size of PCR_Read_Out
        size = sizeof(PCR_Read_Out);

        // Marshal parameter 'pcrUpdateCounter'
        *respParmSize += UINT32_Marshal(&out_params->pcrUpdateCounter, &buffer, &size);
        // Marshal parameter 'pcrSelectionOut'
        *respParmSize += TPML_PCR_SELECTION_Marshal(&out_params->pcrSelectionOut, &buffer, &size);
        // Marshal parameter 'pcrValues'
        *respParmSize += TPML_DIGEST_Marshal(&out_params->pcrValues, &buffer, &size);

    }
    break;
#endif     // CC_PCR_Read == YES
#if defined CC_PCR_Allocate && CC_PCR_Allocate == YES                  // based on Part 4
    case TPM_CC_PCR_Allocate:
    {
        // Get a buffer for input parameters (uses function from MemoryLib.c)
        PCR_Allocate_In *in_params = (PCR_Allocate_In *) MemoryGetActionInputBuffer(sizeof(PCR_Allocate_In));

        // Get a buffer for output parameters (uses function from MemoryLib.c)
        PCR_Allocate_Out *out_params = (PCR_Allocate_Out *) MemoryGetActionOutputBuffer(sizeof(PCR_Allocate_Out));

        // Get handle 0 (authHandle) from handles array
        in_params->authHandle = handles[0];

        rc = TPML_PCR_SELECTION_Unmarshal(&in_params->pcrAllocation, &parmBufferStart, parmBufferSize);
        if(rc != TPM_RC_SUCCESS)
            return rc + RC_PCR_Allocate_pcrAllocation;

        if(*parmBufferSize != 0)
            return TPM_RC_SIZE;

        // Call to the action routine for TPM2_PCR_Allocate
        rc = TPM2_PCR_Allocate(in_params, out_params);

        // Check the return code of action routine for TPM2_PCR_Allocate
        if(rc != TPM_RC_SUCCESS)
            return rc;

        // Calculate size of PCR_Allocate_Out
        size = sizeof(PCR_Allocate_Out);

        // Marshal parameter 'allocationSuccess'
        *respParmSize += TPMI_YES_NO_Marshal(&out_params->allocationSuccess, &buffer, &size);
        // Marshal parameter 'maxPCR'
        *respParmSize += UINT32_Marshal(&out_params->maxPCR, &buffer, &size);
        // Marshal parameter 'sizeNeeded'
        *respParmSize += UINT32_Marshal(&out_params->sizeNeeded, &buffer, &size);
        // Marshal parameter 'sizeAvailable'
        *respParmSize += UINT32_Marshal(&out_params->sizeAvailable, &buffer, &size);

    }
    break;
#endif     // CC_PCR_Allocate == YES
#if defined CC_PCR_SetAuthPolicy && CC_PCR_SetAuthPolicy == YES                  // based on Part 4
    case TPM_CC_PCR_SetAuthPolicy:
    {
        // Get a buffer for input parameters (uses function from MemoryLib.c)
        PCR_SetAuthPolicy_In *in_params = (PCR_SetAuthPolicy_In *) MemoryGetActionInputBuffer(sizeof(PCR_SetAuthPolicy_In));

        // No buffer for output parameters required

        // Get handle 0 (authHandle) from handles array
        in_params->authHandle = handles[0];

        rc = TPM2B_DIGEST_Unmarshal(&in_params->authPolicy, &parmBufferStart, parmBufferSize);
        if(rc != TPM_RC_SUCCESS)
            return rc + RC_PCR_SetAuthPolicy_authPolicy;
        rc = TPMI_ALG_HASH_Unmarshal(&in_params->hashAlg, &parmBufferStart, parmBufferSize, TRUE);
        if(rc != TPM_RC_SUCCESS)
            return rc + RC_PCR_SetAuthPolicy_hashAlg;
        rc = TPMI_DH_PCR_Unmarshal(&in_params->pcrNum, &parmBufferStart, parmBufferSize, FALSE);
        if(rc != TPM_RC_SUCCESS)
            return rc + RC_PCR_SetAuthPolicy_pcrNum;

        if(*parmBufferSize != 0)
            return TPM_RC_SIZE;

        // Call to the action routine for TPM2_PCR_SetAuthPolicy
        rc = TPM2_PCR_SetAuthPolicy(in_params);

        // Check the return code of action routine for TPM2_PCR_SetAuthPolicy
        if(rc != TPM_RC_SUCCESS)
            return rc;


    }
    break;
#endif     // CC_PCR_SetAuthPolicy == YES
#if defined CC_PCR_SetAuthValue && CC_PCR_SetAuthValue == YES                  // based on Part 4
    case TPM_CC_PCR_SetAuthValue:
    {
        // Get a buffer for input parameters (uses function from MemoryLib.c)
        PCR_SetAuthValue_In *in_params = (PCR_SetAuthValue_In *) MemoryGetActionInputBuffer(sizeof(PCR_SetAuthValue_In));

        // No buffer for output parameters required

        // Get handle 0 (pcrHandle) from handles array
        in_params->pcrHandle = handles[0];

        rc = TPM2B_DIGEST_Unmarshal(&in_params->auth, &parmBufferStart, parmBufferSize);
        if(rc != TPM_RC_SUCCESS)
            return rc + RC_PCR_SetAuthValue_auth;

        if(*parmBufferSize != 0)
            return TPM_RC_SIZE;

        // Call to the action routine for TPM2_PCR_SetAuthValue
        rc = TPM2_PCR_SetAuthValue(in_params);

        // Check the return code of action routine for TPM2_PCR_SetAuthValue
        if(rc != TPM_RC_SUCCESS)
            return rc;


    }
    break;
#endif     // CC_PCR_SetAuthValue == YES
#if defined CC_PCR_Reset && CC_PCR_Reset == YES                  // based on Part 4
    case TPM_CC_PCR_Reset:
    {
        // Get a buffer for input parameters (uses function from MemoryLib.c)
        PCR_Reset_In *in_params = (PCR_Reset_In *) MemoryGetActionInputBuffer(sizeof(PCR_Reset_In));

        // No buffer for output parameters required

        // Get handle 0 (pcrHandle) from handles array
        in_params->pcrHandle = handles[0];


        if(*parmBufferSize != 0)
            return TPM_RC_SIZE;

        // Call to the action routine for TPM2_PCR_Reset
        rc = TPM2_PCR_Reset(in_params);

        // Check the return code of action routine for TPM2_PCR_Reset
        if(rc != TPM_RC_SUCCESS)
            return rc;


    }
    break;
#endif     // CC_PCR_Reset == YES
#if defined CC_PolicySigned && CC_PolicySigned == YES                  // based on Part 4
    case TPM_CC_PolicySigned:
    {
        // Get a buffer for input parameters (uses function from MemoryLib.c)
        PolicySigned_In *in_params = (PolicySigned_In *) MemoryGetActionInputBuffer(sizeof(PolicySigned_In));

        // Get a buffer for output parameters (uses function from MemoryLib.c)
        PolicySigned_Out *out_params = (PolicySigned_Out *) MemoryGetActionOutputBuffer(sizeof(PolicySigned_Out));

        // Get handle 0 (authObject) from handles array
        in_params->authObject = handles[0];
        // Get handle 1 (policySession) from handles array
        in_params->policySession = handles[1];

        rc = TPM2B_NONCE_Unmarshal(&in_params->nonceTPM, &parmBufferStart, parmBufferSize);
        if(rc != TPM_RC_SUCCESS)
            return rc + RC_PolicySigned_nonceTPM;
        rc = TPM2B_DIGEST_Unmarshal(&in_params->cpHashA, &parmBufferStart, parmBufferSize);
        if(rc != TPM_RC_SUCCESS)
            return rc + RC_PolicySigned_cpHashA;
        rc = TPM2B_NONCE_Unmarshal(&in_params->policyRef, &parmBufferStart, parmBufferSize);
        if(rc != TPM_RC_SUCCESS)
            return rc + RC_PolicySigned_policyRef;
        rc = INT32_Unmarshal(&in_params->expiration, &parmBufferStart, parmBufferSize);
        if(rc != TPM_RC_SUCCESS)
            return rc + RC_PolicySigned_expiration;
        rc = TPMT_SIGNATURE_Unmarshal(&in_params->auth, &parmBufferStart, parmBufferSize, FALSE);
        if(rc != TPM_RC_SUCCESS)
            return rc + RC_PolicySigned_auth;

        if(*parmBufferSize != 0)
            return TPM_RC_SIZE;

        // Call to the action routine for TPM2_PolicySigned
        rc = TPM2_PolicySigned(in_params, out_params);

        // Check the return code of action routine for TPM2_PolicySigned
        if(rc != TPM_RC_SUCCESS)
            return rc;

        // Calculate size of PolicySigned_Out
        size = sizeof(PolicySigned_Out);

        // Marshal parameter 'timeout'
        *respParmSize += TPM2B_TIMEOUT_Marshal(&out_params->timeout, &buffer, &size);
        // Marshal parameter 'policyTicket'
        *respParmSize += TPMT_TK_AUTH_Marshal(&out_params->policyTicket, &buffer, &size);

    }
    break;
#endif     // CC_PolicySigned == YES
#if defined CC_PolicySecret && CC_PolicySecret == YES                  // based on Part 4
    case TPM_CC_PolicySecret:
    {
        // Get a buffer for input parameters (uses function from MemoryLib.c)
        PolicySecret_In *in_params = (PolicySecret_In *) MemoryGetActionInputBuffer(sizeof(PolicySecret_In));

        // Get a buffer for output parameters (uses function from MemoryLib.c)
        PolicySecret_Out *out_params = (PolicySecret_Out *) MemoryGetActionOutputBuffer(sizeof(PolicySecret_Out));

        // Get handle 0 (authHandle) from handles array
        in_params->authHandle = handles[0];
        // Get handle 1 (policySession) from handles array
        in_params->policySession = handles[1];

        rc = TPM2B_NONCE_Unmarshal(&in_params->nonceTPM, &parmBufferStart, parmBufferSize);
        if(rc != TPM_RC_SUCCESS)
            return rc + RC_PolicySecret_nonceTPM;
        rc = TPM2B_DIGEST_Unmarshal(&in_params->cpHashA, &parmBufferStart, parmBufferSize);
        if(rc != TPM_RC_SUCCESS)
            return rc + RC_PolicySecret_cpHashA;
        rc = TPM2B_NONCE_Unmarshal(&in_params->policyRef, &parmBufferStart, parmBufferSize);
        if(rc != TPM_RC_SUCCESS)
            return rc + RC_PolicySecret_policyRef;
        rc = INT32_Unmarshal(&in_params->expiration, &parmBufferStart, parmBufferSize);
        if(rc != TPM_RC_SUCCESS)
            return rc + RC_PolicySecret_expiration;

        if(*parmBufferSize != 0)
            return TPM_RC_SIZE;

        // Call to the action routine for TPM2_PolicySecret
        rc = TPM2_PolicySecret(in_params, out_params);

        // Check the return code of action routine for TPM2_PolicySecret
        if(rc != TPM_RC_SUCCESS)
            return rc;

        // Calculate size of PolicySecret_Out
        size = sizeof(PolicySecret_Out);

        // Marshal parameter 'timeout'
        *respParmSize += TPM2B_TIMEOUT_Marshal(&out_params->timeout, &buffer, &size);
        // Marshal parameter 'policyTicket'
        *respParmSize += TPMT_TK_AUTH_Marshal(&out_params->policyTicket, &buffer, &size);

    }
    break;
#endif     // CC_PolicySecret == YES
#if defined CC_PolicyTicket && CC_PolicyTicket == YES                  // based on Part 4
    case TPM_CC_PolicyTicket:
    {
        // Get a buffer for input parameters (uses function from MemoryLib.c)
        PolicyTicket_In *in_params = (PolicyTicket_In *) MemoryGetActionInputBuffer(sizeof(PolicyTicket_In));

        // No buffer for output parameters required

        // Get handle 0 (policySession) from handles array
        in_params->policySession = handles[0];

        rc = TPM2B_TIMEOUT_Unmarshal(&in_params->timeout, &parmBufferStart, parmBufferSize);
        if(rc != TPM_RC_SUCCESS)
            return rc + RC_PolicyTicket_timeout;
        rc = TPM2B_DIGEST_Unmarshal(&in_params->cpHashA, &parmBufferStart, parmBufferSize);
        if(rc != TPM_RC_SUCCESS)
            return rc + RC_PolicyTicket_cpHashA;
        rc = TPM2B_NONCE_Unmarshal(&in_params->policyRef, &parmBufferStart, parmBufferSize);
        if(rc != TPM_RC_SUCCESS)
            return rc + RC_PolicyTicket_policyRef;
        rc = TPM2B_NAME_Unmarshal(&in_params->authName, &parmBufferStart, parmBufferSize);
        if(rc != TPM_RC_SUCCESS)
            return rc + RC_PolicyTicket_authName;
        rc = TPMT_TK_AUTH_Unmarshal(&in_params->ticket, &parmBufferStart, parmBufferSize);
        if(rc != TPM_RC_SUCCESS)
            return rc + RC_PolicyTicket_ticket;

        if(*parmBufferSize != 0)
            return TPM_RC_SIZE;

        // Call to the action routine for TPM2_PolicyTicket
        rc = TPM2_PolicyTicket(in_params);

        // Check the return code of action routine for TPM2_PolicyTicket
        if(rc != TPM_RC_SUCCESS)
            return rc;


    }
    break;
#endif     // CC_PolicyTicket == YES
#if defined CC_PolicyOR && CC_PolicyOR == YES                  // based on Part 4
    case TPM_CC_PolicyOR:
    {
        // Get a buffer for input parameters (uses function from MemoryLib.c)
        PolicyOR_In *in_params = (PolicyOR_In *) MemoryGetActionInputBuffer(sizeof(PolicyOR_In));

        // No buffer for output parameters required

        // Get handle 0 (policySession) from handles array
        in_params->policySession = handles[0];

        rc = TPML_DIGEST_Unmarshal(&in_params->pHashList, &parmBufferStart, parmBufferSize);
        if(rc != TPM_RC_SUCCESS)
            return rc + RC_PolicyOR_pHashList;

        if(*parmBufferSize != 0)
            return TPM_RC_SIZE;

        // Call to the action routine for TPM2_PolicyOR
        rc = TPM2_PolicyOR(in_params);

        // Check the return code of action routine for TPM2_PolicyOR
        if(rc != TPM_RC_SUCCESS)
            return rc;


    }
    break;
#endif     // CC_PolicyOR == YES
#if defined CC_PolicyPCR && CC_PolicyPCR == YES                  // based on Part 4
    case TPM_CC_PolicyPCR:
    {
        // Get a buffer for input parameters (uses function from MemoryLib.c)
        PolicyPCR_In *in_params = (PolicyPCR_In *) MemoryGetActionInputBuffer(sizeof(PolicyPCR_In));

        // No buffer for output parameters required

        // Get handle 0 (policySession) from handles array
        in_params->policySession = handles[0];

        rc = TPM2B_DIGEST_Unmarshal(&in_params->pcrDigest, &parmBufferStart, parmBufferSize);
        if(rc != TPM_RC_SUCCESS)
            return rc + RC_PolicyPCR_pcrDigest;
        rc = TPML_PCR_SELECTION_Unmarshal(&in_params->pcrs, &parmBufferStart, parmBufferSize);
        if(rc != TPM_RC_SUCCESS)
            return rc + RC_PolicyPCR_pcrs;

        if(*parmBufferSize != 0)
            return TPM_RC_SIZE;

        // Call to the action routine for TPM2_PolicyPCR
        rc = TPM2_PolicyPCR(in_params);

        // Check the return code of action routine for TPM2_PolicyPCR
        if(rc != TPM_RC_SUCCESS)
            return rc;


    }
    break;
#endif     // CC_PolicyPCR == YES
#if defined CC_PolicyLocality && CC_PolicyLocality == YES                  // based on Part 4
    case TPM_CC_PolicyLocality:
    {
        // Get a buffer for input parameters (uses function from MemoryLib.c)
        PolicyLocality_In *in_params = (PolicyLocality_In *) MemoryGetActionInputBuffer(sizeof(PolicyLocality_In));

        // No buffer for output parameters required

        // Get handle 0 (policySession) from handles array
        in_params->policySession = handles[0];

        rc = TPMA_LOCALITY_Unmarshal(&in_params->locality, &parmBufferStart, parmBufferSize);
        if(rc != TPM_RC_SUCCESS)
            return rc + RC_PolicyLocality_locality;

        if(*parmBufferSize != 0)
            return TPM_RC_SIZE;

        // Call to the action routine for TPM2_PolicyLocality
        rc = TPM2_PolicyLocality(in_params);

        // Check the return code of action routine for TPM2_PolicyLocality
        if(rc != TPM_RC_SUCCESS)
            return rc;


    }
    break;
#endif     // CC_PolicyLocality == YES
#if defined CC_PolicyNV && CC_PolicyNV == YES                  // based on Part 4
    case TPM_CC_PolicyNV:
    {
        // Get a buffer for input parameters (uses function from MemoryLib.c)
        PolicyNV_In *in_params = (PolicyNV_In *) MemoryGetActionInputBuffer(sizeof(PolicyNV_In));

        // No buffer for output parameters required

        // Get handle 0 (authHandle) from handles array
        in_params->authHandle = handles[0];
        // Get handle 1 (nvIndex) from handles array
        in_params->nvIndex = handles[1];
        // Get handle 2 (policySession) from handles array
        in_params->policySession = handles[2];

        rc = TPM2B_OPERAND_Unmarshal(&in_params->operandB, &parmBufferStart, parmBufferSize);
        if(rc != TPM_RC_SUCCESS)
            return rc + RC_PolicyNV_operandB;
        rc = UINT16_Unmarshal(&in_params->offset, &parmBufferStart, parmBufferSize);
        if(rc != TPM_RC_SUCCESS)
            return rc + RC_PolicyNV_offset;
        rc = TPM_EO_Unmarshal(&in_params->operation, &parmBufferStart, parmBufferSize);
        if(rc != TPM_RC_SUCCESS)
            return rc + RC_PolicyNV_operation;

        if(*parmBufferSize != 0)
            return TPM_RC_SIZE;

        // Call to the action routine for TPM2_PolicyNV
        rc = TPM2_PolicyNV(in_params);

        // Check the return code of action routine for TPM2_PolicyNV
        if(rc != TPM_RC_SUCCESS)
            return rc;


    }
    break;
#endif     // CC_PolicyNV == YES
#if defined CC_PolicyCounterTimer && CC_PolicyCounterTimer == YES                  // based on Part 4
    case TPM_CC_PolicyCounterTimer:
    {
        // Get a buffer for input parameters (uses function from MemoryLib.c)
        PolicyCounterTimer_In *in_params = (PolicyCounterTimer_In *) MemoryGetActionInputBuffer(sizeof(PolicyCounterTimer_In));

        // No buffer for output parameters required

        // Get handle 0 (policySession) from handles array
        in_params->policySession = handles[0];

        rc = TPM2B_OPERAND_Unmarshal(&in_params->operandB, &parmBufferStart, parmBufferSize);
        if(rc != TPM_RC_SUCCESS)
            return rc + RC_PolicyCounterTimer_operandB;
        rc = UINT16_Unmarshal(&in_params->offset, &parmBufferStart, parmBufferSize);
        if(rc != TPM_RC_SUCCESS)
            return rc + RC_PolicyCounterTimer_offset;
        rc = TPM_EO_Unmarshal(&in_params->operation, &parmBufferStart, parmBufferSize);
        if(rc != TPM_RC_SUCCESS)
            return rc + RC_PolicyCounterTimer_operation;

        if(*parmBufferSize != 0)
            return TPM_RC_SIZE;

        // Call to the action routine for TPM2_PolicyCounterTimer
        rc = TPM2_PolicyCounterTimer(in_params);

        // Check the return code of action routine for TPM2_PolicyCounterTimer
        if(rc != TPM_RC_SUCCESS)
            return rc;


    }
    break;
#endif     // CC_PolicyCounterTimer == YES
#if defined CC_PolicyCommandCode && CC_PolicyCommandCode == YES                  // based on Part 4
    case TPM_CC_PolicyCommandCode:
    {
        // Get a buffer for input parameters (uses function from MemoryLib.c)
        PolicyCommandCode_In *in_params = (PolicyCommandCode_In *) MemoryGetActionInputBuffer(sizeof(PolicyCommandCode_In));

        // No buffer for output parameters required

        // Get handle 0 (policySession) from handles array
        in_params->policySession = handles[0];

        rc = TPM_CC_Unmarshal(&in_params->code, &parmBufferStart, parmBufferSize);
        if(rc != TPM_RC_SUCCESS)
            return rc + RC_PolicyCommandCode_code;

        if(*parmBufferSize != 0)
            return TPM_RC_SIZE;

        // Call to the action routine for TPM2_PolicyCommandCode
        rc = TPM2_PolicyCommandCode(in_params);

        // Check the return code of action routine for TPM2_PolicyCommandCode
        if(rc != TPM_RC_SUCCESS)
            return rc;


    }
    break;
#endif     // CC_PolicyCommandCode == YES
#if defined CC_PolicyPhysicalPresence && CC_PolicyPhysicalPresence == YES                  // based on Part 4
    case TPM_CC_PolicyPhysicalPresence:
    {
        // Get a buffer for input parameters (uses function from MemoryLib.c)
        PolicyPhysicalPresence_In *in_params = (PolicyPhysicalPresence_In *) MemoryGetActionInputBuffer(sizeof(PolicyPhysicalPresence_In));

        // No buffer for output parameters required

        // Get handle 0 (policySession) from handles array
        in_params->policySession = handles[0];


        if(*parmBufferSize != 0)
            return TPM_RC_SIZE;

        // Call to the action routine for TPM2_PolicyPhysicalPresence
        rc = TPM2_PolicyPhysicalPresence(in_params);

        // Check the return code of action routine for TPM2_PolicyPhysicalPresence
        if(rc != TPM_RC_SUCCESS)
            return rc;


    }
    break;
#endif     // CC_PolicyPhysicalPresence == YES
#if defined CC_PolicyCpHash && CC_PolicyCpHash == YES                  // based on Part 4
    case TPM_CC_PolicyCpHash:
    {
        // Get a buffer for input parameters (uses function from MemoryLib.c)
        PolicyCpHash_In *in_params = (PolicyCpHash_In *) MemoryGetActionInputBuffer(sizeof(PolicyCpHash_In));

        // No buffer for output parameters required

        // Get handle 0 (policySession) from handles array
        in_params->policySession = handles[0];

        rc = TPM2B_DIGEST_Unmarshal(&in_params->cpHashA, &parmBufferStart, parmBufferSize);
        if(rc != TPM_RC_SUCCESS)
            return rc + RC_PolicyCpHash_cpHashA;

        if(*parmBufferSize != 0)
            return TPM_RC_SIZE;

        // Call to the action routine for TPM2_PolicyCpHash
        rc = TPM2_PolicyCpHash(in_params);

        // Check the return code of action routine for TPM2_PolicyCpHash
        if(rc != TPM_RC_SUCCESS)
            return rc;


    }
    break;
#endif     // CC_PolicyCpHash == YES
#if defined CC_PolicyNameHash && CC_PolicyNameHash == YES                  // based on Part 4
    case TPM_CC_PolicyNameHash:
    {
        // Get a buffer for input parameters (uses function from MemoryLib.c)
        PolicyNameHash_In *in_params = (PolicyNameHash_In *) MemoryGetActionInputBuffer(sizeof(PolicyNameHash_In));

        // No buffer for output parameters required

        // Get handle 0 (policySession) from handles array
        in_params->policySession = handles[0];

        rc = TPM2B_DIGEST_Unmarshal(&in_params->nameHash, &parmBufferStart, parmBufferSize);
        if(rc != TPM_RC_SUCCESS)
            return rc + RC_PolicyNameHash_nameHash;

        if(*parmBufferSize != 0)
            return TPM_RC_SIZE;

        // Call to the action routine for TPM2_PolicyNameHash
        rc = TPM2_PolicyNameHash(in_params);

        // Check the return code of action routine for TPM2_PolicyNameHash
        if(rc != TPM_RC_SUCCESS)
            return rc;


    }
    break;
#endif     // CC_PolicyNameHash == YES
#if defined CC_PolicyDuplicationSelect && CC_PolicyDuplicationSelect == YES                  // based on Part 4
    case TPM_CC_PolicyDuplicationSelect:
    {
        // Get a buffer for input parameters (uses function from MemoryLib.c)
        PolicyDuplicationSelect_In *in_params = (PolicyDuplicationSelect_In *) MemoryGetActionInputBuffer(sizeof(PolicyDuplicationSelect_In));

        // No buffer for output parameters required

        // Get handle 0 (policySession) from handles array
        in_params->policySession = handles[0];

        rc = TPM2B_NAME_Unmarshal(&in_params->objectName, &parmBufferStart, parmBufferSize);
        if(rc != TPM_RC_SUCCESS)
            return rc + RC_PolicyDuplicationSelect_objectName;
        rc = TPM2B_NAME_Unmarshal(&in_params->newParentName, &parmBufferStart, parmBufferSize);
        if(rc != TPM_RC_SUCCESS)
            return rc + RC_PolicyDuplicationSelect_newParentName;
        rc = TPMI_YES_NO_Unmarshal(&in_params->includeObject, &parmBufferStart, parmBufferSize);
        if(rc != TPM_RC_SUCCESS)
            return rc + RC_PolicyDuplicationSelect_includeObject;

        if(*parmBufferSize != 0)
            return TPM_RC_SIZE;

        // Call to the action routine for TPM2_PolicyDuplicationSelect
        rc = TPM2_PolicyDuplicationSelect(in_params);

        // Check the return code of action routine for TPM2_PolicyDuplicationSelect
        if(rc != TPM_RC_SUCCESS)
            return rc;


    }
    break;
#endif     // CC_PolicyDuplicationSelect == YES
#if defined CC_PolicyAuthorize && CC_PolicyAuthorize == YES                  // based on Part 4
    case TPM_CC_PolicyAuthorize:
    {
        // Get a buffer for input parameters (uses function from MemoryLib.c)
        PolicyAuthorize_In *in_params = (PolicyAuthorize_In *) MemoryGetActionInputBuffer(sizeof(PolicyAuthorize_In));

        // No buffer for output parameters required

        // Get handle 0 (policySession) from handles array
        in_params->policySession = handles[0];

        rc = TPM2B_DIGEST_Unmarshal(&in_params->approvedPolicy, &parmBufferStart, parmBufferSize);
        if(rc != TPM_RC_SUCCESS)
            return rc + RC_PolicyAuthorize_approvedPolicy;
        rc = TPM2B_NONCE_Unmarshal(&in_params->policyRef, &parmBufferStart, parmBufferSize);
        if(rc != TPM_RC_SUCCESS)
            return rc + RC_PolicyAuthorize_policyRef;
        rc = TPM2B_NAME_Unmarshal(&in_params->keySign, &parmBufferStart, parmBufferSize);
        if(rc != TPM_RC_SUCCESS)
            return rc + RC_PolicyAuthorize_keySign;
        rc = TPMT_TK_VERIFIED_Unmarshal(&in_params->checkTicket, &parmBufferStart, parmBufferSize);
        if(rc != TPM_RC_SUCCESS)
            return rc + RC_PolicyAuthorize_checkTicket;

        if(*parmBufferSize != 0)
            return TPM_RC_SIZE;

        // Call to the action routine for TPM2_PolicyAuthorize
        rc = TPM2_PolicyAuthorize(in_params);

        // Check the return code of action routine for TPM2_PolicyAuthorize
        if(rc != TPM_RC_SUCCESS)
            return rc;


    }
    break;
#endif     // CC_PolicyAuthorize == YES
#if defined CC_PolicyAuthValue && CC_PolicyAuthValue == YES                  // based on Part 4
    case TPM_CC_PolicyAuthValue:
    {
        // Get a buffer for input parameters (uses function from MemoryLib.c)
        PolicyAuthValue_In *in_params = (PolicyAuthValue_In *) MemoryGetActionInputBuffer(sizeof(PolicyAuthValue_In));

        // No buffer for output parameters required

        // Get handle 0 (policySession) from handles array
        in_params->policySession = handles[0];


        if(*parmBufferSize != 0)
            return TPM_RC_SIZE;

        // Call to the action routine for TPM2_PolicyAuthValue
        rc = TPM2_PolicyAuthValue(in_params);

        // Check the return code of action routine for TPM2_PolicyAuthValue
        if(rc != TPM_RC_SUCCESS)
            return rc;


    }
    break;
#endif     // CC_PolicyAuthValue == YES
#if defined CC_PolicyPassword && CC_PolicyPassword == YES                  // based on Part 4
    case TPM_CC_PolicyPassword:
    {
        // Get a buffer for input parameters (uses function from MemoryLib.c)
        PolicyPassword_In *in_params = (PolicyPassword_In *) MemoryGetActionInputBuffer(sizeof(PolicyPassword_In));

        // No buffer for output parameters required

        // Get handle 0 (policySession) from handles array
        in_params->policySession = handles[0];


        if(*parmBufferSize != 0)
            return TPM_RC_SIZE;

        // Call to the action routine for TPM2_PolicyPassword
        rc = TPM2_PolicyPassword(in_params);

        // Check the return code of action routine for TPM2_PolicyPassword
        if(rc != TPM_RC_SUCCESS)
            return rc;


    }
    break;
#endif     // CC_PolicyPassword == YES
#if defined CC_PolicyGetDigest && CC_PolicyGetDigest == YES                  // based on Part 4
    case TPM_CC_PolicyGetDigest:
    {
        // Get a buffer for input parameters (uses function from MemoryLib.c)
        PolicyGetDigest_In *in_params = (PolicyGetDigest_In *) MemoryGetActionInputBuffer(sizeof(PolicyGetDigest_In));

        // Get a buffer for output parameters (uses function from MemoryLib.c)
        PolicyGetDigest_Out *out_params = (PolicyGetDigest_Out *) MemoryGetActionOutputBuffer(sizeof(PolicyGetDigest_Out));

        // Get handle 0 (policySession) from handles array
        in_params->policySession = handles[0];


        if(*parmBufferSize != 0)
            return TPM_RC_SIZE;

        // Call to the action routine for TPM2_PolicyGetDigest
        rc = TPM2_PolicyGetDigest(in_params, out_params);

        // Check the return code of action routine for TPM2_PolicyGetDigest
        if(rc != TPM_RC_SUCCESS)
            return rc;

        // Calculate size of PolicyGetDigest_Out
        size = sizeof(PolicyGetDigest_Out);

        // Marshal parameter 'policyDigest'
        *respParmSize += TPM2B_DIGEST_Marshal(&out_params->policyDigest, &buffer, &size);

    }
    break;
#endif     // CC_PolicyGetDigest == YES
#if defined CC_PolicyNvWritten && CC_PolicyNvWritten == YES                  // based on Part 4
    case TPM_CC_PolicyNvWritten:
    {
        // Get a buffer for input parameters (uses function from MemoryLib.c)
        PolicyNvWritten_In *in_params = (PolicyNvWritten_In *) MemoryGetActionInputBuffer(sizeof(PolicyNvWritten_In));

        // No buffer for output parameters required

        // Get handle 0 (policySession) from handles array
        in_params->policySession = handles[0];

        rc = TPMI_YES_NO_Unmarshal(&in_params->writtenSet, &parmBufferStart, parmBufferSize);
        if(rc != TPM_RC_SUCCESS)
            return rc + RC_PolicyNvWritten_writtenSet;

        if(*parmBufferSize != 0)
            return TPM_RC_SIZE;

        // Call to the action routine for TPM2_PolicyNvWritten
        rc = TPM2_PolicyNvWritten(in_params);

        // Check the return code of action routine for TPM2_PolicyNvWritten
        if(rc != TPM_RC_SUCCESS)
            return rc;


    }
    break;
#endif     // CC_PolicyNvWritten == YES
#if defined CC_CreatePrimary && CC_CreatePrimary == YES                  // based on Part 4
    case TPM_CC_CreatePrimary:
    {
        // Get a buffer for input parameters (uses function from MemoryLib.c)
        CreatePrimary_In *in_params = (CreatePrimary_In *) MemoryGetActionInputBuffer(sizeof(CreatePrimary_In));

        // Get a buffer for output parameters (uses function from MemoryLib.c)
        CreatePrimary_Out *out_params = (CreatePrimary_Out *) MemoryGetActionOutputBuffer(sizeof(CreatePrimary_Out));

        // Get handle 0 (primaryHandle) from handles array
        in_params->primaryHandle = handles[0];

        rc = TPM2B_SENSITIVE_CREATE_Unmarshal(&in_params->inSensitive, &parmBufferStart, parmBufferSize);
        if(rc != TPM_RC_SUCCESS)
            return rc + RC_CreatePrimary_inSensitive;
        rc = TPM2B_PUBLIC_Unmarshal(&in_params->inPublic, &parmBufferStart, parmBufferSize, FALSE);
        if(rc != TPM_RC_SUCCESS)
            return rc + RC_CreatePrimary_inPublic;
        rc = TPM2B_DATA_Unmarshal(&in_params->outsideInfo, &parmBufferStart, parmBufferSize);
        if(rc != TPM_RC_SUCCESS)
            return rc + RC_CreatePrimary_outsideInfo;
        rc = TPML_PCR_SELECTION_Unmarshal(&in_params->creationPCR, &parmBufferStart, parmBufferSize);
        if(rc != TPM_RC_SUCCESS)
            return rc + RC_CreatePrimary_creationPCR;

        if(*parmBufferSize != 0)
            return TPM_RC_SIZE;

        // Call to the action routine for TPM2_CreatePrimary
        rc = TPM2_CreatePrimary(in_params, out_params);

        // Check the return code of action routine for TPM2_CreatePrimary
        if(rc != TPM_RC_SUCCESS)
            return rc;

        // Calculate size of CreatePrimary_Out
        size = sizeof(CreatePrimary_Out);

        // Marshal handle 'objectHandle'
        *responseHandleSize += TPM_HANDLE_Marshal(&out_params->objectHandle, &responseHandlePtr, &size);
        // Marshal parameter 'outPublic'
        *respParmSize += TPM2B_PUBLIC_Marshal(&out_params->outPublic, &buffer, &size);
        // Marshal parameter 'creationData'
        *respParmSize += TPM2B_CREATION_DATA_Marshal(&out_params->creationData, &buffer, &size);
        // Marshal parameter 'creationHash'
        *respParmSize += TPM2B_DIGEST_Marshal(&out_params->creationHash, &buffer, &size);
        // Marshal parameter 'creationTicket'
        *respParmSize += TPMT_TK_CREATION_Marshal(&out_params->creationTicket, &buffer, &size);
        // Marshal parameter 'name'
        *respParmSize += TPM2B_NAME_Marshal(&out_params->name, &buffer, &size);

    }
    break;
#endif     // CC_CreatePrimary == YES
#if defined CC_HierarchyControl && CC_HierarchyControl == YES                  // based on Part 4
    case TPM_CC_HierarchyControl:
    {
        // Get a buffer for input parameters (uses function from MemoryLib.c)
        HierarchyControl_In *in_params = (HierarchyControl_In *) MemoryGetActionInputBuffer(sizeof(HierarchyControl_In));

        // No buffer for output parameters required

        // Get handle 0 (authHandle) from handles array
        in_params->authHandle = handles[0];

        rc = TPMI_RH_ENABLES_Unmarshal(&in_params->enable, &parmBufferStart, parmBufferSize, FALSE);
        if(rc != TPM_RC_SUCCESS)
            return rc + RC_HierarchyControl_enable;
        rc = TPMI_YES_NO_Unmarshal(&in_params->state, &parmBufferStart, parmBufferSize);
        if(rc != TPM_RC_SUCCESS)
            return rc + RC_HierarchyControl_state;

        if(*parmBufferSize != 0)
            return TPM_RC_SIZE;

        // Call to the action routine for TPM2_HierarchyControl
        rc = TPM2_HierarchyControl(in_params);

        // Check the return code of action routine for TPM2_HierarchyControl
        if(rc != TPM_RC_SUCCESS)
            return rc;


    }
    break;
#endif     // CC_HierarchyControl == YES
#if defined CC_SetPrimaryPolicy && CC_SetPrimaryPolicy == YES                  // based on Part 4
    case TPM_CC_SetPrimaryPolicy:
    {
        // Get a buffer for input parameters (uses function from MemoryLib.c)
        SetPrimaryPolicy_In *in_params = (SetPrimaryPolicy_In *) MemoryGetActionInputBuffer(sizeof(SetPrimaryPolicy_In));

        // No buffer for output parameters required

        // Get handle 0 (authHandle) from handles array
        in_params->authHandle = handles[0];

        rc = TPM2B_DIGEST_Unmarshal(&in_params->authPolicy, &parmBufferStart, parmBufferSize);
        if(rc != TPM_RC_SUCCESS)
            return rc + RC_SetPrimaryPolicy_authPolicy;
        rc = TPMI_ALG_HASH_Unmarshal(&in_params->hashAlg, &parmBufferStart, parmBufferSize, TRUE);
        if(rc != TPM_RC_SUCCESS)
            return rc + RC_SetPrimaryPolicy_hashAlg;

        if(*parmBufferSize != 0)
            return TPM_RC_SIZE;

        // Call to the action routine for TPM2_SetPrimaryPolicy
        rc = TPM2_SetPrimaryPolicy(in_params);

        // Check the return code of action routine for TPM2_SetPrimaryPolicy
        if(rc != TPM_RC_SUCCESS)
            return rc;


    }
    break;
#endif     // CC_SetPrimaryPolicy == YES
#if defined CC_ChangePPS && CC_ChangePPS == YES                  // based on Part 4
    case TPM_CC_ChangePPS:
    {
        // Get a buffer for input parameters (uses function from MemoryLib.c)
        ChangePPS_In *in_params = (ChangePPS_In *) MemoryGetActionInputBuffer(sizeof(ChangePPS_In));

        // No buffer for output parameters required

        // Get handle 0 (authHandle) from handles array
        in_params->authHandle = handles[0];


        if(*parmBufferSize != 0)
            return TPM_RC_SIZE;

        // Call to the action routine for TPM2_ChangePPS
        rc = TPM2_ChangePPS(in_params);

        // Check the return code of action routine for TPM2_ChangePPS
        if(rc != TPM_RC_SUCCESS)
            return rc;


    }
    break;
#endif     // CC_ChangePPS == YES
#if defined CC_ChangeEPS && CC_ChangeEPS == YES                  // based on Part 4
    case TPM_CC_ChangeEPS:
    {
        // Get a buffer for input parameters (uses function from MemoryLib.c)
        ChangeEPS_In *in_params = (ChangeEPS_In *) MemoryGetActionInputBuffer(sizeof(ChangeEPS_In));

        // No buffer for output parameters required

        // Get handle 0 (authHandle) from handles array
        in_params->authHandle = handles[0];


        if(*parmBufferSize != 0)
            return TPM_RC_SIZE;

        // Call to the action routine for TPM2_ChangeEPS
        rc = TPM2_ChangeEPS(in_params);

        // Check the return code of action routine for TPM2_ChangeEPS
        if(rc != TPM_RC_SUCCESS)
            return rc;


    }
    break;
#endif     // CC_ChangeEPS == YES
#if defined CC_Clear && CC_Clear == YES                  // based on Part 4
    case TPM_CC_Clear:
    {
        // Get a buffer for input parameters (uses function from MemoryLib.c)
        Clear_In *in_params = (Clear_In *) MemoryGetActionInputBuffer(sizeof(Clear_In));

        // No buffer for output parameters required

        // Get handle 0 (authHandle) from handles array
        in_params->authHandle = handles[0];


        if(*parmBufferSize != 0)
            return TPM_RC_SIZE;

        // Call to the action routine for TPM2_Clear
        rc = TPM2_Clear(in_params);

        // Check the return code of action routine for TPM2_Clear
        if(rc != TPM_RC_SUCCESS)
            return rc;


    }
    break;
#endif     // CC_Clear == YES
#if defined CC_ClearControl && CC_ClearControl == YES                  // based on Part 4
    case TPM_CC_ClearControl:
    {
        // Get a buffer for input parameters (uses function from MemoryLib.c)
        ClearControl_In *in_params = (ClearControl_In *) MemoryGetActionInputBuffer(sizeof(ClearControl_In));

        // No buffer for output parameters required

        // Get handle 0 (auth) from handles array
        in_params->auth = handles[0];

        rc = TPMI_YES_NO_Unmarshal(&in_params->disable, &parmBufferStart, parmBufferSize);
        if(rc != TPM_RC_SUCCESS)
            return rc + RC_ClearControl_disable;

        if(*parmBufferSize != 0)
            return TPM_RC_SIZE;

        // Call to the action routine for TPM2_ClearControl
        rc = TPM2_ClearControl(in_params);

        // Check the return code of action routine for TPM2_ClearControl
        if(rc != TPM_RC_SUCCESS)
            return rc;


    }
    break;
#endif     // CC_ClearControl == YES
#if defined CC_HierarchyChangeAuth && CC_HierarchyChangeAuth == YES                  // based on Part 4
    case TPM_CC_HierarchyChangeAuth:
    {
        // Get a buffer for input parameters (uses function from MemoryLib.c)
        HierarchyChangeAuth_In *in_params = (HierarchyChangeAuth_In *) MemoryGetActionInputBuffer(sizeof(HierarchyChangeAuth_In));

        // No buffer for output parameters required

        // Get handle 0 (authHandle) from handles array
        in_params->authHandle = handles[0];

        rc = TPM2B_AUTH_Unmarshal(&in_params->newAuth, &parmBufferStart, parmBufferSize);
        if(rc != TPM_RC_SUCCESS)
            return rc + RC_HierarchyChangeAuth_newAuth;

        if(*parmBufferSize != 0)
            return TPM_RC_SIZE;

        // Call to the action routine for TPM2_HierarchyChangeAuth
        rc = TPM2_HierarchyChangeAuth(in_params);

        // Check the return code of action routine for TPM2_HierarchyChangeAuth
        if(rc != TPM_RC_SUCCESS)
            return rc;


    }
    break;
#endif     // CC_HierarchyChangeAuth == YES
#if defined CC_DictionaryAttackLockReset && CC_DictionaryAttackLockReset == YES                  // based on Part 4
    case TPM_CC_DictionaryAttackLockReset:
    {
        // Get a buffer for input parameters (uses function from MemoryLib.c)
        DictionaryAttackLockReset_In *in_params = (DictionaryAttackLockReset_In *) MemoryGetActionInputBuffer(sizeof(DictionaryAttackLockReset_In));

        // No buffer for output parameters required

        // Get handle 0 (lockHandle) from handles array
        in_params->lockHandle = handles[0];


        if(*parmBufferSize != 0)
            return TPM_RC_SIZE;

        // Call to the action routine for TPM2_DictionaryAttackLockReset
        rc = TPM2_DictionaryAttackLockReset(in_params);

        // Check the return code of action routine for TPM2_DictionaryAttackLockReset
        if(rc != TPM_RC_SUCCESS)
            return rc;


    }
    break;
#endif     // CC_DictionaryAttackLockReset == YES
#if defined CC_DictionaryAttackParameters && CC_DictionaryAttackParameters == YES                  // based on Part 4
    case TPM_CC_DictionaryAttackParameters:
    {
        // Get a buffer for input parameters (uses function from MemoryLib.c)
        DictionaryAttackParameters_In *in_params = (DictionaryAttackParameters_In *) MemoryGetActionInputBuffer(sizeof(DictionaryAttackParameters_In));

        // No buffer for output parameters required

        // Get handle 0 (lockHandle) from handles array
        in_params->lockHandle = handles[0];

        rc = UINT32_Unmarshal(&in_params->newMaxTries, &parmBufferStart, parmBufferSize);
        if(rc != TPM_RC_SUCCESS)
            return rc + RC_DictionaryAttackParameters_newMaxTries;
        rc = UINT32_Unmarshal(&in_params->newRecoveryTime, &parmBufferStart, parmBufferSize);
        if(rc != TPM_RC_SUCCESS)
            return rc + RC_DictionaryAttackParameters_newRecoveryTime;
        rc = UINT32_Unmarshal(&in_params->lockoutRecovery, &parmBufferStart, parmBufferSize);
        if(rc != TPM_RC_SUCCESS)
            return rc + RC_DictionaryAttackParameters_lockoutRecovery;

        if(*parmBufferSize != 0)
            return TPM_RC_SIZE;

        // Call to the action routine for TPM2_DictionaryAttackParameters
        rc = TPM2_DictionaryAttackParameters(in_params);

        // Check the return code of action routine for TPM2_DictionaryAttackParameters
        if(rc != TPM_RC_SUCCESS)
            return rc;


    }
    break;
#endif     // CC_DictionaryAttackParameters == YES
#if defined CC_PP_Commands && CC_PP_Commands == YES                  // based on Part 4
    case TPM_CC_PP_Commands:
    {
        // Get a buffer for input parameters (uses function from MemoryLib.c)
        PP_Commands_In *in_params = (PP_Commands_In *) MemoryGetActionInputBuffer(sizeof(PP_Commands_In));

        // No buffer for output parameters required

        // Get handle 0 (auth) from handles array
        in_params->auth = handles[0];

        rc = TPML_CC_Unmarshal(&in_params->setList, &parmBufferStart, parmBufferSize);
        if(rc != TPM_RC_SUCCESS)
            return rc + RC_PP_Commands_setList;
        rc = TPML_CC_Unmarshal(&in_params->clearList, &parmBufferStart, parmBufferSize);
        if(rc != TPM_RC_SUCCESS)
            return rc + RC_PP_Commands_clearList;

        if(*parmBufferSize != 0)
            return TPM_RC_SIZE;

        // Call to the action routine for TPM2_PP_Commands
        rc = TPM2_PP_Commands(in_params);

        // Check the return code of action routine for TPM2_PP_Commands
        if(rc != TPM_RC_SUCCESS)
            return rc;


    }
    break;
#endif     // CC_PP_Commands == YES
#if defined CC_SetAlgorithmSet && CC_SetAlgorithmSet == YES                  // based on Part 4
    case TPM_CC_SetAlgorithmSet:
    {
        // Get a buffer for input parameters (uses function from MemoryLib.c)
        SetAlgorithmSet_In *in_params = (SetAlgorithmSet_In *) MemoryGetActionInputBuffer(sizeof(SetAlgorithmSet_In));

        // No buffer for output parameters required

        // Get handle 0 (authHandle) from handles array
        in_params->authHandle = handles[0];

        rc = UINT32_Unmarshal(&in_params->algorithmSet, &parmBufferStart, parmBufferSize);
        if(rc != TPM_RC_SUCCESS)
            return rc + RC_SetAlgorithmSet_algorithmSet;

        if(*parmBufferSize != 0)
            return TPM_RC_SIZE;

        // Call to the action routine for TPM2_SetAlgorithmSet
        rc = TPM2_SetAlgorithmSet(in_params);

        // Check the return code of action routine for TPM2_SetAlgorithmSet
        if(rc != TPM_RC_SUCCESS)
            return rc;


    }
    break;
#endif     // CC_SetAlgorithmSet == YES
#if defined CC_FieldUpgradeStart && CC_FieldUpgradeStart == YES                  // based on Part 4
    case TPM_CC_FieldUpgradeStart:
    {
        // Get a buffer for input parameters (uses function from MemoryLib.c)
        FieldUpgradeStart_In *in_params = (FieldUpgradeStart_In *) MemoryGetActionInputBuffer(sizeof(FieldUpgradeStart_In));

        // No buffer for output parameters required

        // Get handle 0 (authorization) from handles array
        in_params->authorization = handles[0];
        // Get handle 1 (keyHandle) from handles array
        in_params->keyHandle = handles[1];

        rc = TPM2B_DIGEST_Unmarshal(&in_params->fuDigest, &parmBufferStart, parmBufferSize);
        if(rc != TPM_RC_SUCCESS)
            return rc + RC_FieldUpgradeStart_fuDigest;
        rc = TPMT_SIGNATURE_Unmarshal(&in_params->manifestSignature, &parmBufferStart, parmBufferSize, FALSE);
        if(rc != TPM_RC_SUCCESS)
            return rc + RC_FieldUpgradeStart_manifestSignature;

        if(*parmBufferSize != 0)
            return TPM_RC_SIZE;

        // Call to the action routine for TPM2_FieldUpgradeStart
        rc = TPM2_FieldUpgradeStart(in_params);

        // Check the return code of action routine for TPM2_FieldUpgradeStart
        if(rc != TPM_RC_SUCCESS)
            return rc;


    }
    break;
#endif     // CC_FieldUpgradeStart == YES
#if defined CC_FieldUpgradeData && CC_FieldUpgradeData == YES                  // based on Part 4
    case TPM_CC_FieldUpgradeData:
    {
        // Get a buffer for input parameters (uses function from MemoryLib.c)
        FieldUpgradeData_In *in_params = (FieldUpgradeData_In *) MemoryGetActionInputBuffer(sizeof(FieldUpgradeData_In));

        // Get a buffer for output parameters (uses function from MemoryLib.c)
        FieldUpgradeData_Out *out_params = (FieldUpgradeData_Out *) MemoryGetActionOutputBuffer(sizeof(FieldUpgradeData_Out));

        // No handles required
        rc = TPM2B_MAX_BUFFER_Unmarshal(&in_params->fuData, &parmBufferStart, parmBufferSize);
        if(rc != TPM_RC_SUCCESS)
            return rc + RC_FieldUpgradeData_fuData;

        if(*parmBufferSize != 0)
            return TPM_RC_SIZE;

        // Call to the action routine for TPM2_FieldUpgradeData
        rc = TPM2_FieldUpgradeData(in_params, out_params);

        // Check the return code of action routine for TPM2_FieldUpgradeData
        if(rc != TPM_RC_SUCCESS)
            return rc;

        // Calculate size of FieldUpgradeData_Out
        size = sizeof(FieldUpgradeData_Out);

        // Marshal parameter 'nextDigest'
        *respParmSize += TPMT_HA_Marshal(&out_params->nextDigest, &buffer, &size);
        // Marshal parameter 'firstDigest'
        *respParmSize += TPMT_HA_Marshal(&out_params->firstDigest, &buffer, &size);

    }
    break;
#endif     // CC_FieldUpgradeData == YES
#if defined CC_FirmwareRead && CC_FirmwareRead == YES                  // based on Part 4
    case TPM_CC_FirmwareRead:
    {
        // Get a buffer for input parameters (uses function from MemoryLib.c)
        FirmwareRead_In *in_params = (FirmwareRead_In *) MemoryGetActionInputBuffer(sizeof(FirmwareRead_In));

        // Get a buffer for output parameters (uses function from MemoryLib.c)
        FirmwareRead_Out *out_params = (FirmwareRead_Out *) MemoryGetActionOutputBuffer(sizeof(FirmwareRead_Out));

        // No handles required
        rc = UINT32_Unmarshal(&in_params->sequenceNumber, &parmBufferStart, parmBufferSize);
        if(rc != TPM_RC_SUCCESS)
            return rc + RC_FirmwareRead_sequenceNumber;

        if(*parmBufferSize != 0)
            return TPM_RC_SIZE;

        // Call to the action routine for TPM2_FirmwareRead
        rc = TPM2_FirmwareRead(in_params, out_params);

        // Check the return code of action routine for TPM2_FirmwareRead
        if(rc != TPM_RC_SUCCESS)
            return rc;

        // Calculate size of FirmwareRead_Out
        size = sizeof(FirmwareRead_Out);

        // Marshal parameter 'fuData'
        *respParmSize += TPM2B_MAX_BUFFER_Marshal(&out_params->fuData, &buffer, &size);

    }
    break;
#endif     // CC_FirmwareRead == YES
#if defined CC_ContextSave && CC_ContextSave == YES                  // based on Part 4
    case TPM_CC_ContextSave:
    {
        // Get a buffer for input parameters (uses function from MemoryLib.c)
        ContextSave_In *in_params = (ContextSave_In *) MemoryGetActionInputBuffer(sizeof(ContextSave_In));

        // Get a buffer for output parameters (uses function from MemoryLib.c)
        ContextSave_Out *out_params = (ContextSave_Out *) MemoryGetActionOutputBuffer(sizeof(ContextSave_Out));

        // Get handle 0 (saveHandle) from handles array
        in_params->saveHandle = handles[0];


        if(*parmBufferSize != 0)
            return TPM_RC_SIZE;

        // Call to the action routine for TPM2_ContextSave
        rc = TPM2_ContextSave(in_params, out_params);

        // Check the return code of action routine for TPM2_ContextSave
        if(rc != TPM_RC_SUCCESS)
            return rc;

        // Calculate size of ContextSave_Out
        size = sizeof(ContextSave_Out);

        // Marshal parameter 'context'
        *respParmSize += TPMS_CONTEXT_Marshal(&out_params->context, &buffer, &size);

    }
    break;
#endif     // CC_ContextSave == YES
#if defined CC_ContextLoad && CC_ContextLoad == YES                  // based on Part 4
    case TPM_CC_ContextLoad:
    {
        // Get a buffer for input parameters (uses function from MemoryLib.c)
        ContextLoad_In *in_params = (ContextLoad_In *) MemoryGetActionInputBuffer(sizeof(ContextLoad_In));

        // Get a buffer for output parameters (uses function from MemoryLib.c)
        ContextLoad_Out *out_params = (ContextLoad_Out *) MemoryGetActionOutputBuffer(sizeof(ContextLoad_Out));

        // No handles required
        rc = TPMS_CONTEXT_Unmarshal(&in_params->context, &parmBufferStart, parmBufferSize);
        if(rc != TPM_RC_SUCCESS)
            return rc + RC_ContextLoad_context;

        if(*parmBufferSize != 0)
            return TPM_RC_SIZE;

        // Call to the action routine for TPM2_ContextLoad
        rc = TPM2_ContextLoad(in_params, out_params);

        // Check the return code of action routine for TPM2_ContextLoad
        if(rc != TPM_RC_SUCCESS)
            return rc;

        // Calculate size of ContextLoad_Out
        size = sizeof(ContextLoad_Out);

        // Marshal handle 'loadedHandle'
        *responseHandleSize += TPMI_DH_CONTEXT_Marshal(&out_params->loadedHandle, &responseHandlePtr, &size);

    }
    break;
#endif     // CC_ContextLoad == YES
#if defined CC_FlushContext && CC_FlushContext == YES                  // based on Part 4
    case TPM_CC_FlushContext:
    {
        // Get a buffer for input parameters (uses function from MemoryLib.c)
        FlushContext_In *in_params = (FlushContext_In *) MemoryGetActionInputBuffer(sizeof(FlushContext_In));

        // No buffer for output parameters required

        // No handles required
        rc = TPMI_DH_CONTEXT_Unmarshal(&in_params->flushHandle, &parmBufferStart, parmBufferSize);
        if(rc != TPM_RC_SUCCESS)
            return rc + RC_FlushContext_flushHandle;

        if(*parmBufferSize != 0)
            return TPM_RC_SIZE;

        // Call to the action routine for TPM2_FlushContext
        rc = TPM2_FlushContext(in_params);

        // Check the return code of action routine for TPM2_FlushContext
        if(rc != TPM_RC_SUCCESS)
            return rc;


    }
    break;
#endif     // CC_FlushContext == YES
#if defined CC_EvictControl && CC_EvictControl == YES                  // based on Part 4
    case TPM_CC_EvictControl:
    {
        // Get a buffer for input parameters (uses function from MemoryLib.c)
        EvictControl_In *in_params = (EvictControl_In *) MemoryGetActionInputBuffer(sizeof(EvictControl_In));

        // No buffer for output parameters required

        // Get handle 0 (auth) from handles array
        in_params->auth = handles[0];
        // Get handle 1 (objectHandle) from handles array
        in_params->objectHandle = handles[1];

        rc = TPMI_DH_PERSISTENT_Unmarshal(&in_params->persistentHandle, &parmBufferStart, parmBufferSize);
        if(rc != TPM_RC_SUCCESS)
            return rc + RC_EvictControl_persistentHandle;

        if(*parmBufferSize != 0)
            return TPM_RC_SIZE;

        // Call to the action routine for TPM2_EvictControl
        rc = TPM2_EvictControl(in_params);

        // Check the return code of action routine for TPM2_EvictControl
        if(rc != TPM_RC_SUCCESS)
            return rc;


    }
    break;
#endif     // CC_EvictControl == YES
#if defined CC_ReadClock && CC_ReadClock == YES                  // based on Part 4
    case TPM_CC_ReadClock:
    {
        // No buffer for input parameters required

        // Get a buffer for output parameters (uses function from MemoryLib.c)
        ReadClock_Out *out_params = (ReadClock_Out *) MemoryGetActionOutputBuffer(sizeof(ReadClock_Out));

        // No handles required

        if(*parmBufferSize != 0)
            return TPM_RC_SIZE;

        // Call to the action routine for TPM2_ReadClock
        rc = TPM2_ReadClock(out_params);

        // Check the return code of action routine for TPM2_ReadClock
        if(rc != TPM_RC_SUCCESS)
            return rc;

        // Calculate size of ReadClock_Out
        size = sizeof(ReadClock_Out);

        // Marshal parameter 'currentTime'
        *respParmSize += TPMS_TIME_INFO_Marshal(&out_params->currentTime, &buffer, &size);

    }
    break;
#endif     // CC_ReadClock == YES
#if defined CC_ClockSet && CC_ClockSet == YES                  // based on Part 4
    case TPM_CC_ClockSet:
    {
        // Get a buffer for input parameters (uses function from MemoryLib.c)
        ClockSet_In *in_params = (ClockSet_In *) MemoryGetActionInputBuffer(sizeof(ClockSet_In));

        // No buffer for output parameters required

        // Get handle 0 (auth) from handles array
        in_params->auth = handles[0];

        rc = UINT64_Unmarshal(&in_params->newTime, &parmBufferStart, parmBufferSize);
        if(rc != TPM_RC_SUCCESS)
            return rc + RC_ClockSet_newTime;

        if(*parmBufferSize != 0)
            return TPM_RC_SIZE;

        // Call to the action routine for TPM2_ClockSet
        rc = TPM2_ClockSet(in_params);

        // Check the return code of action routine for TPM2_ClockSet
        if(rc != TPM_RC_SUCCESS)
            return rc;


    }
    break;
#endif     // CC_ClockSet == YES
#if defined CC_ClockRateAdjust && CC_ClockRateAdjust == YES                  // based on Part 4
    case TPM_CC_ClockRateAdjust:
    {
        // Get a buffer for input parameters (uses function from MemoryLib.c)
        ClockRateAdjust_In *in_params = (ClockRateAdjust_In *) MemoryGetActionInputBuffer(sizeof(ClockRateAdjust_In));

        // No buffer for output parameters required

        // Get handle 0 (auth) from handles array
        in_params->auth = handles[0];

        rc = TPM_CLOCK_ADJUST_Unmarshal(&in_params->rateAdjust, &parmBufferStart, parmBufferSize);
        if(rc != TPM_RC_SUCCESS)
            return rc + RC_ClockRateAdjust_rateAdjust;

        if(*parmBufferSize != 0)
            return TPM_RC_SIZE;

        // Call to the action routine for TPM2_ClockRateAdjust
        rc = TPM2_ClockRateAdjust(in_params);

        // Check the return code of action routine for TPM2_ClockRateAdjust
        if(rc != TPM_RC_SUCCESS)
            return rc;


    }
    break;
#endif     // CC_ClockRateAdjust == YES
#if defined CC_GetCapability && CC_GetCapability == YES                  // based on Part 4
    case TPM_CC_GetCapability:
    {
        // Get a buffer for input parameters (uses function from MemoryLib.c)
        GetCapability_In *in_params = (GetCapability_In *) MemoryGetActionInputBuffer(sizeof(GetCapability_In));

        // Get a buffer for output parameters (uses function from MemoryLib.c)
        GetCapability_Out *out_params = (GetCapability_Out *) MemoryGetActionOutputBuffer(sizeof(GetCapability_Out));

        // No handles required
        rc = TPM_CAP_Unmarshal(&in_params->capability, &parmBufferStart, parmBufferSize);
        if(rc != TPM_RC_SUCCESS)
            return rc + RC_GetCapability_capability;
        rc = UINT32_Unmarshal(&in_params->property, &parmBufferStart, parmBufferSize);
        if(rc != TPM_RC_SUCCESS)
            return rc + RC_GetCapability_property;
        rc = UINT32_Unmarshal(&in_params->propertyCount, &parmBufferStart, parmBufferSize);
        if(rc != TPM_RC_SUCCESS)
            return rc + RC_GetCapability_propertyCount;

        if(*parmBufferSize != 0)
            return TPM_RC_SIZE;

        // Call to the action routine for TPM2_GetCapability
        rc = TPM2_GetCapability(in_params, out_params);

        // Check the return code of action routine for TPM2_GetCapability
        if(rc != TPM_RC_SUCCESS)
            return rc;

        // Calculate size of GetCapability_Out
        size = sizeof(GetCapability_Out);

        // Marshal parameter 'moreData'
        *respParmSize += TPMI_YES_NO_Marshal(&out_params->moreData, &buffer, &size);
        // Marshal parameter 'capabilityData'
        *respParmSize += TPMS_CAPABILITY_DATA_Marshal(&out_params->capabilityData, &buffer, &size);

    }
    break;
#endif     // CC_GetCapability == YES
#if defined CC_TestParms && CC_TestParms == YES                  // based on Part 4
    case TPM_CC_TestParms:
    {
        // Get a buffer for input parameters (uses function from MemoryLib.c)
        TestParms_In *in_params = (TestParms_In *) MemoryGetActionInputBuffer(sizeof(TestParms_In));

        // No buffer for output parameters required

        // No handles required
        rc = TPMT_PUBLIC_PARMS_Unmarshal(&in_params->parameters, &parmBufferStart, parmBufferSize);
        if(rc != TPM_RC_SUCCESS)
            return rc + RC_TestParms_parameters;

        if(*parmBufferSize != 0)
            return TPM_RC_SIZE;

        // Call to the action routine for TPM2_TestParms
        rc = TPM2_TestParms(in_params);

        // Check the return code of action routine for TPM2_TestParms
        if(rc != TPM_RC_SUCCESS)
            return rc;


    }
    break;
#endif     // CC_TestParms == YES
#if defined CC_NV_DefineSpace && CC_NV_DefineSpace == YES                  // based on Part 4
    case TPM_CC_NV_DefineSpace:
    {
        // Get a buffer for input parameters (uses function from MemoryLib.c)
        NV_DefineSpace_In *in_params = (NV_DefineSpace_In *) MemoryGetActionInputBuffer(sizeof(NV_DefineSpace_In));

        // No buffer for output parameters required

        // Get handle 0 (authHandle) from handles array
        in_params->authHandle = handles[0];

        rc = TPM2B_AUTH_Unmarshal(&in_params->auth, &parmBufferStart, parmBufferSize);
        if(rc != TPM_RC_SUCCESS)
            return rc + RC_NV_DefineSpace_auth;
        rc = TPM2B_NV_PUBLIC_Unmarshal(&in_params->publicInfo, &parmBufferStart, parmBufferSize);
        if(rc != TPM_RC_SUCCESS)
            return rc + RC_NV_DefineSpace_publicInfo;

        if(*parmBufferSize != 0)
            return TPM_RC_SIZE;

        // Call to the action routine for TPM2_NV_DefineSpace
        rc = TPM2_NV_DefineSpace(in_params);

        // Check the return code of action routine for TPM2_NV_DefineSpace
        if(rc != TPM_RC_SUCCESS)
            return rc;


    }
    break;
#endif     // CC_NV_DefineSpace == YES
#if defined CC_NV_UndefineSpace && CC_NV_UndefineSpace == YES                  // based on Part 4
    case TPM_CC_NV_UndefineSpace:
    {
        // Get a buffer for input parameters (uses function from MemoryLib.c)
        NV_UndefineSpace_In *in_params = (NV_UndefineSpace_In *) MemoryGetActionInputBuffer(sizeof(NV_UndefineSpace_In));

        // No buffer for output parameters required

        // Get handle 0 (authHandle) from handles array
        in_params->authHandle = handles[0];
        // Get handle 1 (nvIndex) from handles array
        in_params->nvIndex = handles[1];


        if(*parmBufferSize != 0)
            return TPM_RC_SIZE;

        // Call to the action routine for TPM2_NV_UndefineSpace
        rc = TPM2_NV_UndefineSpace(in_params);

        // Check the return code of action routine for TPM2_NV_UndefineSpace
        if(rc != TPM_RC_SUCCESS)
            return rc;


    }
    break;
#endif     // CC_NV_UndefineSpace == YES
#if defined CC_NV_UndefineSpaceSpecial && CC_NV_UndefineSpaceSpecial == YES                  // based on Part 4
    case TPM_CC_NV_UndefineSpaceSpecial:
    {
        // Get a buffer for input parameters (uses function from MemoryLib.c)
        NV_UndefineSpaceSpecial_In *in_params = (NV_UndefineSpaceSpecial_In *) MemoryGetActionInputBuffer(sizeof(NV_UndefineSpaceSpecial_In));

        // No buffer for output parameters required

        // Get handle 0 (nvIndex) from handles array
        in_params->nvIndex = handles[0];
        // Get handle 1 (platform) from handles array
        in_params->platform = handles[1];


        if(*parmBufferSize != 0)
            return TPM_RC_SIZE;

        // Call to the action routine for TPM2_NV_UndefineSpaceSpecial
        rc = TPM2_NV_UndefineSpaceSpecial(in_params);

        // Check the return code of action routine for TPM2_NV_UndefineSpaceSpecial
        if(rc != TPM_RC_SUCCESS)
            return rc;


    }
    break;
#endif     // CC_NV_UndefineSpaceSpecial == YES
#if defined CC_NV_ReadPublic && CC_NV_ReadPublic == YES                  // based on Part 4
    case TPM_CC_NV_ReadPublic:
    {
        // Get a buffer for input parameters (uses function from MemoryLib.c)
        NV_ReadPublic_In *in_params = (NV_ReadPublic_In *) MemoryGetActionInputBuffer(sizeof(NV_ReadPublic_In));

        // Get a buffer for output parameters (uses function from MemoryLib.c)
        NV_ReadPublic_Out *out_params = (NV_ReadPublic_Out *) MemoryGetActionOutputBuffer(sizeof(NV_ReadPublic_Out));

        // Get handle 0 (nvIndex) from handles array
        in_params->nvIndex = handles[0];


        if(*parmBufferSize != 0)
            return TPM_RC_SIZE;

        // Call to the action routine for TPM2_NV_ReadPublic
        rc = TPM2_NV_ReadPublic(in_params, out_params);

        // Check the return code of action routine for TPM2_NV_ReadPublic
        if(rc != TPM_RC_SUCCESS)
            return rc;

        // Calculate size of NV_ReadPublic_Out
        size = sizeof(NV_ReadPublic_Out);

        // Marshal parameter 'nvPublic'
        *respParmSize += TPM2B_NV_PUBLIC_Marshal(&out_params->nvPublic, &buffer, &size);
        // Marshal parameter 'nvName'
        *respParmSize += TPM2B_NAME_Marshal(&out_params->nvName, &buffer, &size);

    }
    break;
#endif     // CC_NV_ReadPublic == YES
#if defined CC_NV_Write && CC_NV_Write == YES                  // based on Part 4
    case TPM_CC_NV_Write:
    {
        // Get a buffer for input parameters (uses function from MemoryLib.c)
        NV_Write_In *in_params = (NV_Write_In *) MemoryGetActionInputBuffer(sizeof(NV_Write_In));

        // No buffer for output parameters required

        // Get handle 0 (authHandle) from handles array
        in_params->authHandle = handles[0];
        // Get handle 1 (nvIndex) from handles array
        in_params->nvIndex = handles[1];

        rc = TPM2B_MAX_NV_BUFFER_Unmarshal(&in_params->data, &parmBufferStart, parmBufferSize);
        if(rc != TPM_RC_SUCCESS)
            return rc + RC_NV_Write_data;
        rc = UINT16_Unmarshal(&in_params->offset, &parmBufferStart, parmBufferSize);
        if(rc != TPM_RC_SUCCESS)
            return rc + RC_NV_Write_offset;

        if(*parmBufferSize != 0)
            return TPM_RC_SIZE;

        // Call to the action routine for TPM2_NV_Write
        rc = TPM2_NV_Write(in_params);

        // Check the return code of action routine for TPM2_NV_Write
        if(rc != TPM_RC_SUCCESS)
            return rc;


    }
    break;
#endif     // CC_NV_Write == YES
#if defined CC_NV_Increment && CC_NV_Increment == YES                  // based on Part 4
    case TPM_CC_NV_Increment:
    {
        // Get a buffer for input parameters (uses function from MemoryLib.c)
        NV_Increment_In *in_params = (NV_Increment_In *) MemoryGetActionInputBuffer(sizeof(NV_Increment_In));

        // No buffer for output parameters required

        // Get handle 0 (authHandle) from handles array
        in_params->authHandle = handles[0];
        // Get handle 1 (nvIndex) from handles array
        in_params->nvIndex = handles[1];


        if(*parmBufferSize != 0)
            return TPM_RC_SIZE;

        // Call to the action routine for TPM2_NV_Increment
        rc = TPM2_NV_Increment(in_params);

        // Check the return code of action routine for TPM2_NV_Increment
        if(rc != TPM_RC_SUCCESS)
            return rc;


    }
    break;
#endif     // CC_NV_Increment == YES
#if defined CC_NV_Extend && CC_NV_Extend == YES                  // based on Part 4
    case TPM_CC_NV_Extend:
    {
        // Get a buffer for input parameters (uses function from MemoryLib.c)
        NV_Extend_In *in_params = (NV_Extend_In *) MemoryGetActionInputBuffer(sizeof(NV_Extend_In));

        // No buffer for output parameters required

        // Get handle 0 (authHandle) from handles array
        in_params->authHandle = handles[0];
        // Get handle 1 (nvIndex) from handles array
        in_params->nvIndex = handles[1];

        rc = TPM2B_MAX_NV_BUFFER_Unmarshal(&in_params->data, &parmBufferStart, parmBufferSize);
        if(rc != TPM_RC_SUCCESS)
            return rc + RC_NV_Extend_data;

        if(*parmBufferSize != 0)
            return TPM_RC_SIZE;

        // Call to the action routine for TPM2_NV_Extend
        rc = TPM2_NV_Extend(in_params);

        // Check the return code of action routine for TPM2_NV_Extend
        if(rc != TPM_RC_SUCCESS)
            return rc;


    }
    break;
#endif     // CC_NV_Extend == YES
#if defined CC_NV_SetBits && CC_NV_SetBits == YES                  // based on Part 4
    case TPM_CC_NV_SetBits:
    {
        // Get a buffer for input parameters (uses function from MemoryLib.c)
        NV_SetBits_In *in_params = (NV_SetBits_In *) MemoryGetActionInputBuffer(sizeof(NV_SetBits_In));

        // No buffer for output parameters required

        // Get handle 0 (authHandle) from handles array
        in_params->authHandle = handles[0];
        // Get handle 1 (nvIndex) from handles array
        in_params->nvIndex = handles[1];

        rc = UINT64_Unmarshal(&in_params->bits, &parmBufferStart, parmBufferSize);
        if(rc != TPM_RC_SUCCESS)
            return rc + RC_NV_SetBits_bits;

        if(*parmBufferSize != 0)
            return TPM_RC_SIZE;

        // Call to the action routine for TPM2_NV_SetBits
        rc = TPM2_NV_SetBits(in_params);

        // Check the return code of action routine for TPM2_NV_SetBits
        if(rc != TPM_RC_SUCCESS)
            return rc;


    }
    break;
#endif     // CC_NV_SetBits == YES
#if defined CC_NV_WriteLock && CC_NV_WriteLock == YES                  // based on Part 4
    case TPM_CC_NV_WriteLock:
    {
        // Get a buffer for input parameters (uses function from MemoryLib.c)
        NV_WriteLock_In *in_params = (NV_WriteLock_In *) MemoryGetActionInputBuffer(sizeof(NV_WriteLock_In));

        // No buffer for output parameters required

        // Get handle 0 (authHandle) from handles array
        in_params->authHandle = handles[0];
        // Get handle 1 (nvIndex) from handles array
        in_params->nvIndex = handles[1];


        if(*parmBufferSize != 0)
            return TPM_RC_SIZE;

        // Call to the action routine for TPM2_NV_WriteLock
        rc = TPM2_NV_WriteLock(in_params);

        // Check the return code of action routine for TPM2_NV_WriteLock
        if(rc != TPM_RC_SUCCESS)
            return rc;


    }
    break;
#endif     // CC_NV_WriteLock == YES
#if defined CC_NV_GlobalWriteLock && CC_NV_GlobalWriteLock == YES                  // based on Part 4
    case TPM_CC_NV_GlobalWriteLock:
    {
        // Get a buffer for input parameters (uses function from MemoryLib.c)
        NV_GlobalWriteLock_In *in_params = (NV_GlobalWriteLock_In *) MemoryGetActionInputBuffer(sizeof(NV_GlobalWriteLock_In));

        // No buffer for output parameters required

        // Get handle 0 (authHandle) from handles array
        in_params->authHandle = handles[0];


        if(*parmBufferSize != 0)
            return TPM_RC_SIZE;

        // Call to the action routine for TPM2_NV_GlobalWriteLock
        rc = TPM2_NV_GlobalWriteLock(in_params);

        // Check the return code of action routine for TPM2_NV_GlobalWriteLock
        if(rc != TPM_RC_SUCCESS)
            return rc;


    }
    break;
#endif     // CC_NV_GlobalWriteLock == YES
#if defined CC_NV_Read && CC_NV_Read == YES                  // based on Part 4
    case TPM_CC_NV_Read:
    {
        // Get a buffer for input parameters (uses function from MemoryLib.c)
        NV_Read_In *in_params = (NV_Read_In *) MemoryGetActionInputBuffer(sizeof(NV_Read_In));

        // Get a buffer for output parameters (uses function from MemoryLib.c)
        NV_Read_Out *out_params = (NV_Read_Out *) MemoryGetActionOutputBuffer(sizeof(NV_Read_Out));

        // Get handle 0 (authHandle) from handles array
        in_params->authHandle = handles[0];
        // Get handle 1 (nvIndex) from handles array
        in_params->nvIndex = handles[1];

        rc = UINT16_Unmarshal(&in_params->size, &parmBufferStart, parmBufferSize);
        if(rc != TPM_RC_SUCCESS)
            return rc + RC_NV_Read_size;
        rc = UINT16_Unmarshal(&in_params->offset, &parmBufferStart, parmBufferSize);
        if(rc != TPM_RC_SUCCESS)
            return rc + RC_NV_Read_offset;

        if(*parmBufferSize != 0)
            return TPM_RC_SIZE;

        // Call to the action routine for TPM2_NV_Read
        rc = TPM2_NV_Read(in_params, out_params);

        // Check the return code of action routine for TPM2_NV_Read
        if(rc != TPM_RC_SUCCESS)
            return rc;

        // Calculate size of NV_Read_Out
        size = sizeof(NV_Read_Out);

        // Marshal parameter 'data'
        *respParmSize += TPM2B_MAX_NV_BUFFER_Marshal(&out_params->data, &buffer, &size);

    }
    break;
#endif     // CC_NV_Read == YES
#if defined CC_NV_ReadLock && CC_NV_ReadLock == YES                  // based on Part 4
    case TPM_CC_NV_ReadLock:
    {
        // Get a buffer for input parameters (uses function from MemoryLib.c)
        NV_ReadLock_In *in_params = (NV_ReadLock_In *) MemoryGetActionInputBuffer(sizeof(NV_ReadLock_In));

        // No buffer for output parameters required

        // Get handle 0 (authHandle) from handles array
        in_params->authHandle = handles[0];
        // Get handle 1 (nvIndex) from handles array
        in_params->nvIndex = handles[1];


        if(*parmBufferSize != 0)
            return TPM_RC_SIZE;

        // Call to the action routine for TPM2_NV_ReadLock
        rc = TPM2_NV_ReadLock(in_params);

        // Check the return code of action routine for TPM2_NV_ReadLock
        if(rc != TPM_RC_SUCCESS)
            return rc;


    }
    break;
#endif     // CC_NV_ReadLock == YES
#if defined CC_NV_ChangeAuth && CC_NV_ChangeAuth == YES                  // based on Part 4
    case TPM_CC_NV_ChangeAuth:
    {
        // Get a buffer for input parameters (uses function from MemoryLib.c)
        NV_ChangeAuth_In *in_params = (NV_ChangeAuth_In *) MemoryGetActionInputBuffer(sizeof(NV_ChangeAuth_In));

        // No buffer for output parameters required

        // Get handle 0 (nvIndex) from handles array
        in_params->nvIndex = handles[0];

        rc = TPM2B_AUTH_Unmarshal(&in_params->newAuth, &parmBufferStart, parmBufferSize);
        if(rc != TPM_RC_SUCCESS)
            return rc + RC_NV_ChangeAuth_newAuth;

        if(*parmBufferSize != 0)
            return TPM_RC_SIZE;

        // Call to the action routine for TPM2_NV_ChangeAuth
        rc = TPM2_NV_ChangeAuth(in_params);

        // Check the return code of action routine for TPM2_NV_ChangeAuth
        if(rc != TPM_RC_SUCCESS)
            return rc;


    }
    break;
#endif     // CC_NV_ChangeAuth == YES
#if defined CC_NV_Certify && CC_NV_Certify == YES                  // based on Part 4
    case TPM_CC_NV_Certify:
    {
        // Get a buffer for input parameters (uses function from MemoryLib.c)
        NV_Certify_In *in_params = (NV_Certify_In *) MemoryGetActionInputBuffer(sizeof(NV_Certify_In));

        // Get a buffer for output parameters (uses function from MemoryLib.c)
        NV_Certify_Out *out_params = (NV_Certify_Out *) MemoryGetActionOutputBuffer(sizeof(NV_Certify_Out));

        // Get handle 0 (signHandle) from handles array
        in_params->signHandle = handles[0];
        // Get handle 1 (authHandle) from handles array
        in_params->authHandle = handles[1];
        // Get handle 2 (nvIndex) from handles array
        in_params->nvIndex = handles[2];

        rc = TPM2B_DATA_Unmarshal(&in_params->qualifyingData, &parmBufferStart, parmBufferSize);
        if(rc != TPM_RC_SUCCESS)
            return rc + RC_NV_Certify_qualifyingData;
        rc = TPMT_SIG_SCHEME_Unmarshal(&in_params->inScheme, &parmBufferStart, parmBufferSize, TRUE);
        if(rc != TPM_RC_SUCCESS)
            return rc + RC_NV_Certify_inScheme;
        rc = UINT16_Unmarshal(&in_params->size, &parmBufferStart, parmBufferSize);
        if(rc != TPM_RC_SUCCESS)
            return rc + RC_NV_Certify_size;
        rc = UINT16_Unmarshal(&in_params->offset, &parmBufferStart, parmBufferSize);
        if(rc != TPM_RC_SUCCESS)
            return rc + RC_NV_Certify_offset;

        if(*parmBufferSize != 0)
            return TPM_RC_SIZE;

        // Call to the action routine for TPM2_NV_Certify
        rc = TPM2_NV_Certify(in_params, out_params);

        // Check the return code of action routine for TPM2_NV_Certify
        if(rc != TPM_RC_SUCCESS)
            return rc;

        // Calculate size of NV_Certify_Out
        size = sizeof(NV_Certify_Out);

        // Marshal parameter 'certifyInfo'
        *respParmSize += TPM2B_ATTEST_Marshal(&out_params->certifyInfo, &buffer, &size);
        // Marshal parameter 'signature'
        *respParmSize += TPMT_SIGNATURE_Marshal(&out_params->signature, &buffer, &size);

    }
    break;
#endif     // CC_NV_Certify == YES

    default:
        pAssert(FALSE);
        break;
    }

    if(respParamSizePtr != NULL)
    {
        UINT32_Marshal(respParmSize, &respParamSizePtr, NULL);      // marshal local variable into OUT parameter
    }

    return rc;
}

#endif      //% TABLE_DRIVEN_DISPATCH                               // Spec. Version 01.19+
