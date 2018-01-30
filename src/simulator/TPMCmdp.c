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

// D.4.1. Description
// This file contains the functions that process the commands received on the control port or the command
// port of the simulator. The control port is used to allow simulation of hardware events
// (such as,
// _TPM_Hash_Start()) to test the simulated TPM's reaction to those events. This improves code coverage
// of the testing.
// D.4.2. Includes and Data Definitions
#define _SWAP_H                 // Preclude inclusion of unnecessary simulator header
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <setjmp.h>
#include "bool.h"
#include "Platform.h"
#include "ExecCommand_fp.h"
#include "Manufacture_fp.h"
#include "DRTM_fp.h"
#include "_TPM_Init_fp.h"
#include "TpmFail_fp.h"

// CHANGE START
#if defined(_Win32) || defined(WIN32)
#include <windows.h>
#else
#define SOCKET int
#endif
// CHANGE END

#include "TpmTcpProtocol.h"
static BOOL s_isPowerOn = FALSE;
void
_rpc__Signal_PowerOn(
    BOOL isReset
)
{
    // if power is on and this is not a call to do TPM reset then return
    if(s_isPowerOn && !isReset)
        return;

    // If this is a reset but power is not on, then return
    if(isReset && !s_isPowerOn)
        return;

    // Pass power on signal to platform
    if(isReset)
        _plat__Signal_Reset();
    else
        _plat__Signal_PowerOn();

    // Pass power on signal to TPM
    _TPM_Init();

    // Set state as power on
    s_isPowerOn = TRUE;
}
void
_rpc__Signal_PowerOff(
    void
)
{
    if(!s_isPowerOn) return;

    // Pass power off signal to platform
    _plat__Signal_PowerOff();

    s_isPowerOn = FALSE;

    return;
}
void
_rpc__ForceFailureMode(
    void
)
{
    SetForceFailureMode();
}
void
_rpc__Signal_PhysicalPresenceOn(
    void
)
{
    // If TPM is power off, reject this signal
    if(!s_isPowerOn) return;

    // Pass physical presence on to platform
    _plat__Signal_PhysicalPresenceOn();

    return;
}
void
_rpc__Signal_PhysicalPresenceOff(
    void
)
{
    // If TPM is power off, reject this signal
    if(!s_isPowerOn) return;

    // Pass physical presence off to platform
    _plat__Signal_PhysicalPresenceOff();

    return;
}
void
_rpc__Signal_Hash_Start(
    void
)
{
    // If TPM is power off, reject this signal
    if(!s_isPowerOn) return;

    // Pass _TPM_Hash_Start signal to TPM
    Signal_Hash_Start();
    return;
}
void
_rpc__Signal_Hash_Data(
    _IN_BUFFER input
)
{
    // If TPM is power off, reject this signal
    if(!s_isPowerOn) return;

    // Pass _TPM_Hash_Data signal to TPM
    Signal_Hash_Data(input.BufferSize, input.Buffer);
    return;
}
void
_rpc__Signal_HashEnd(
    void
)
{
    // If TPM is power off, reject this signal
    if(!s_isPowerOn) return;

    // Pass _TPM_HashEnd signal to TPM
    Signal_Hash_End();
    return;
}
void
_rpc__Send_Command(
    unsigned char locality,
    _IN_BUFFER request,
    _OUT_BUFFER *response
)
{
    // If TPM is power off, reject any commands.
    if(!s_isPowerOn) {
        response->BufferSize = 0;
        return;
    }
    // Set the locality of the command so that it doesn't change during the command
    _plat__LocalitySet(locality);
    // Do implementation-specific command dispatch
    ExecuteCommand(request.BufferSize, request.Buffer,
                   &response->BufferSize, &response->Buffer);
    return;

}
void
_rpc__Signal_CancelOn(
    void
)
{
    // If TPM is power off, reject this signal
    if(!s_isPowerOn) return;

    // Set the platform canceling flag.
    _plat__SetCancel();

    return;
}
void
_rpc__Signal_CancelOff(
    void
)
{
    // If TPM is power off, reject this signal
    if(!s_isPowerOn) return;

    // Set the platform canceling flag.
    _plat__ClearCancel();

    return;
}
void
_rpc__Signal_NvOn(
    void
)
{
    // If TPM is power off, reject this signal
    if(!s_isPowerOn) return;

    _plat__SetNvAvail();
    return;
}
void
_rpc__Signal_NvOff(
    void
)
{
    // If TPM is power off, reject this signal
    if(!s_isPowerOn) return;

    _plat__ClearNvAvail();
    return;
}
void
_rpc__Shutdown(
    void
)
{
#if defined(_Win32) || defined(WIN32)
    RPC_STATUS status;
#endif

    // Stop TPM
    TPM_TearDown();

#if defined(_Win32) || defined(WIN32)
    status = RpcMgmtStopServerListening(NULL);
    if (status != RPC_S_OK)
    {
        printf_s("RpcMgmtStopServerListening returned: 0x%x\n", status);
        exit(status);
    }

    status = RpcServerUnregisterIf(NULL, NULL, FALSE);
    if (status != RPC_S_OK)
    {
        printf_s("RpcServerUnregisterIf returned 0x%x\n", status);
        exit(status);
    }
#endif
}
