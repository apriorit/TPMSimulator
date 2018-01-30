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
#include "HierarchyControl_fp.h"
#ifdef TPM_CC_HierarchyControl                // Conditional expansion of this file

// M e
// TPM_RC_AUTH_TYPE authHandle is not applicable to hierarchy in its current state

TPM_RC
TPM2_HierarchyControl(
    HierarchyControl_In *in                        // IN: input parameter list
)
{
    TPM_RC result;
    BOOL select = (in->state == YES);
    BOOL *selected = NULL;

// Input Validation
    switch(in->enable)
    {
    // Platform hierarchy has to be disabled by platform auth
    // If the platform hierarchy has already been disabled, only a reboot
    // can enable it again
    case TPM_RH_PLATFORM:
    case TPM_RH_PLATFORM_NV:
        if(in->authHandle != TPM_RH_PLATFORM)
            return TPM_RC_AUTH_TYPE;
        break;

    // ShEnable may be disabled if PlatformAuth/PlatformPolicy or
    // OwnerAuth/OwnerPolicy is provided. If ShEnable is disabled, then it
    // may only be enabled if PlatformAuth/PlatformPolicy is provided.
    case TPM_RH_OWNER:
        if( in->authHandle != TPM_RH_PLATFORM
                && in->authHandle != TPM_RH_OWNER)
            return TPM_RC_AUTH_TYPE;
        if( gc.shEnable == FALSE && in->state == YES
                && in->authHandle != TPM_RH_PLATFORM)
            return TPM_RC_AUTH_TYPE;
        break;

    // EhEnable may be disabled if either PlatformAuth/PlatformPolicy or
    // EndosementAuth/EndorsementPolicy is provided. If EhEnable is disabled,
    // then it may only be enabled if PlatformAuth/PlatformPolicy is
    // provided.
    case TPM_RH_ENDORSEMENT:
        if( in->authHandle != TPM_RH_PLATFORM
                && in->authHandle != TPM_RH_ENDORSEMENT)
            return TPM_RC_AUTH_TYPE;
        if( gc.ehEnable == FALSE && in->state == YES
                && in->authHandle != TPM_RH_PLATFORM)
            return TPM_RC_AUTH_TYPE;
        break;
    default:
        pAssert(FALSE);
        break;
    }

// Internal Data Update

    // Enable or disable the selected hierarchy
    // Note: the authorization processing for this command may keep these
    // command actions from being executed. For example, if phEnable is
    // CLEAR, then platformAuth cannot be used for authorization. This
    // means that would not be possible to use platformAuth to change the
    // state of phEnable from CLEAR to SET.
    // If it is decided that platformPolicy can still be used when phEnable
    // is CLEAR, then this code could SET phEnable when proper platform
    // policy is provided.
    switch(in->enable)
    {
    case TPM_RH_OWNER:
        selected = &gc.shEnable;
        break;
    case TPM_RH_ENDORSEMENT:
        selected = &gc.ehEnable;
        break;
    case TPM_RH_PLATFORM:
        selected = &g_phEnable;
        break;
    case TPM_RH_PLATFORM_NV:
        selected = &gc.phEnableNV;
        break;
    default:
        pAssert(FALSE);
        break;
    }
    if(selected != NULL && *selected != select)
    {
        // Before changing the internal state, make sure that NV is available.
        // Only need to update NV if changing the orderly state
        if(gp.orderlyState != SHUTDOWN_NONE)
        {
            // The command needs NV update. Check if NV is available.
            // A TPM_RC_NV_UNAVAILABLE or TPM_RC_NV_RATE error may be returned at
            // this point
            result = NvIsAvailable();
            if(result != TPM_RC_SUCCESS)
                return result;
        }
        // state is changing and NV is available so modify
        *selected = select;
        // If a hierarchy was just disabled, flush it
        if(select == CLEAR && in->enable != TPM_RH_PLATFORM_NV)
            // Flush hierarchy
            ObjectFlushHierarchy(in->enable);

        // orderly state should be cleared because of the update to state clear data
        // This gets processed in ExecuteCommand() on the way out.
        g_clearOrderly = TRUE;
    }
    return TPM_RC_SUCCESS;
}
#endif // CC_HierarchyControl
