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
#include "NV_WriteLock_fp.h"
#ifdef TPM_CC_NV_WriteLock             // Conditional expansion of this file
#include "NV_spt_fp.h"

// M e
// TPM_RC_ATTRIBUTES neither TPMA_NV_WRITEDEFINE nor
// TPMA_NV_WRITE_STCLEAR is SET in Index referenced by
// nvIndex
// TPM_RC_NV_AUTHORIZATION the authorization was valid but the authorizing entity (authHandle) is
// not allowed to write to the Index referenced by nvIndex

TPM_RC
TPM2_NV_WriteLock(
    NV_WriteLock_In *in                   // IN: input parameter list
)
{
    TPM_RC result;
    NV_INDEX nvIndex;

// Input Validation:

    // Common write access checks, a TPM_RC_NV_AUTHORIZATION or TPM_RC_NV_LOCKED
    // error may be returned at this point
    result = NvWriteAccessChecks(in->authHandle, in->nvIndex);
    if(result != TPM_RC_SUCCESS)
    {
        if(result == TPM_RC_NV_AUTHORIZATION)
            return TPM_RC_NV_AUTHORIZATION;
        // If write access failed because the index is already locked, then it is
        // no error.
        return TPM_RC_SUCCESS;
    }

    // Get NV index info
    NvGetIndexInfo(in->nvIndex, &nvIndex);

    // if neither TPMA_NV_WRITEDEFINE nor TPMA_NV_WRITE_STCLEAR is set, the index
    // can not be write-locked
    if( nvIndex.publicArea.attributes.TPMA_NV_WRITEDEFINE == CLEAR
            && nvIndex.publicArea.attributes.TPMA_NV_WRITE_STCLEAR == CLEAR)
        return TPM_RC_ATTRIBUTES + RC_NV_WriteLock_nvIndex;

// Internal Data Update

    // The command needs NV update. Check if NV is available.
    // A TPM_RC_NV_UNAVAILABLE or TPM_RC_NV_RATE error may be returned at
    // this point
    result = NvIsAvailable();
    if(result != TPM_RC_SUCCESS)
        return result;

    // Set the WRITELOCK attribute.
    // Note: if TPMA_NV_WRITELOCKED were already SET, then the write access check
    // above would have failed and this code isn't executed.
    nvIndex.publicArea.attributes.TPMA_NV_WRITELOCKED = SET;

    // Write index info back
    NvWriteIndexInfo(in->nvIndex, &nvIndex);

    return TPM_RC_SUCCESS;
}
#endif // CC_NV_WriteLock
