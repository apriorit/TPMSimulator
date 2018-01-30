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

// 9.4.1 Introduction
// This file contains the functions for testing various command properties.
// 9.4.2 Includes and Defines
#include "Tpm.h"
#include "InternalRoutines.h"
typedef UINT16 ATTRIBUTE_TYPE;
#include "CommandAttributeData.c"
AUTH_ROLE
CommandAuthRole(
    TPM_CC commandCode,                 // IN: command code
    UINT32 handleIndex                  // IN: handle index (zero based)
)
{
    if(handleIndex > 1)
        return AUTH_NONE;
    if(handleIndex == 0) {
        ATTRIBUTE_TYPE properties = s_commandAttributes[commandCode - TPM_CC_FIRST];
        if(properties & HANDLE_1_USER) return AUTH_USER;
        if(properties & HANDLE_1_ADMIN) return AUTH_ADMIN;
        if(properties & HANDLE_1_DUP) return AUTH_DUP;
        return AUTH_NONE;
    }
    if(s_commandAttributes[commandCode - TPM_CC_FIRST] & HANDLE_2_USER) return AUTH_USER;
    return AUTH_NONE;
}
BOOL
CommandIsImplemented(
    TPM_CC commandCode           // IN: command code
)
{
    if(commandCode < TPM_CC_FIRST || commandCode > TPM_CC_LAST)
        return FALSE;
    if((s_commandAttributes[commandCode - TPM_CC_FIRST] & IS_IMPLEMENTED))
        return TRUE;
    else
        return FALSE;
}
TPMA_CC
CommandGetAttribute(
    TPM_CC commandCode           // IN: command code
)
{
    UINT32 size = sizeof(s_ccAttr)           / sizeof(s_ccAttr[0]);
    UINT32 i;
    for(i = 0; i < size; i++) {
        if(s_ccAttr[i].commandIndex == (UINT16) commandCode)
            return s_ccAttr[i];
    }

    // This function should be called in the way that the command code
    // attribute is available.
    FAIL(FATAL_ERROR_INTERNAL);
}
int
EncryptSize(
    TPM_CC commandCode           // IN: commandCode
)
{
    COMMAND_ATTRIBUTES ca = s_commandAttributes[commandCode - TPM_CC_FIRST];
    if(ca & ENCRYPT_2)
        return 2;
    if(ca & ENCRYPT_4)
        return 4;
    return 0;
}
int
DecryptSize(
    TPM_CC commandCode  // IN: commandCode
)
{
    COMMAND_ATTRIBUTES ca = s_commandAttributes[commandCode - TPM_CC_FIRST];

    if(ca & DECRYPT_2)
        return 2;
    if(ca & DECRYPT_4)
        return 4;
    return 0;
}
BOOL
IsSessionAllowed(
    TPM_CC commandCode  // IN: the command to be checked
)
{
    if(s_commandAttributes[commandCode - TPM_CC_FIRST] & NO_SESSIONS)
        return FALSE;
    else
        return TRUE;
}
BOOL
IsHandleInResponse(
    TPM_CC commandCode
)
{
    if(s_commandAttributes[commandCode - TPM_CC_FIRST] & R_HANDLE)
        return TRUE;
    else
        return FALSE;
}
BOOL
IsWriteOperation(
    TPM_CC command                  // IN: Command to check
)
{
    switch (command)
    {
    case TPM_CC_NV_Write:
    case TPM_CC_NV_Increment:
    case TPM_CC_NV_SetBits:
    case TPM_CC_NV_Extend:
    // Nv write lock counts as a write operation for authorization purposes.
    // We check to see if the NV is write locked before we do the authorization
    // If it is locked, we fail the command early.
    case TPM_CC_NV_WriteLock:
        return TRUE;
    default:
        break;
    }
    return FALSE;
}
BOOL
IsReadOperation(
    TPM_CC command                  // IN: Command to check
)
{
    switch (command)
    {
    case TPM_CC_NV_Read:
    case TPM_CC_PolicyNV:
    case TPM_CC_NV_Certify:
    // Nv read lock counts as a read operation for authorization purposes.
    // We check to see if the NV is read locked before we do the authorization
    // If it is locked, we fail the command early.
    case TPM_CC_NV_ReadLock:
        return TRUE;
    default:
        break;
    }
    return FALSE;
}
TPMI_YES_NO
CommandCapGetCCList(
    TPM_CC commandCode,                 // IN: start command code
    UINT32 count,                       // IN: maximum count for number of entries in
    // 'commandList'
    TPML_CCA *commandList                    // OUT: list of TPMA_CC
)
{
    TPMI_YES_NO more = NO;
    UINT32 i;

    // initialize output handle list count
    commandList->count = 0;

    // The maximum count of commands that may be return is MAX_CAP_CC.
    if(count > MAX_CAP_CC) count = MAX_CAP_CC;

    // If the command code is smaller than TPM_CC_FIRST, start from TPM_CC_FIRST
    if(commandCode < TPM_CC_FIRST) commandCode = TPM_CC_FIRST;

    // Collect command attributes
    for(i = commandCode; i <= TPM_CC_LAST; i++)
    {
        if(CommandIsImplemented(i))
        {
            if(commandList->count < count)
            {
                // If the list is not full, add the attributes for this command.
                commandList->commandAttributes[commandList->count]
                    = CommandGetAttribute(i);
                commandList->count++;
            }
            else
            {
                // If the list is full but there are more commands to report,
                // indicate this and return.
                more = YES;
                break;
            }
        }
    }
    return more;
}
