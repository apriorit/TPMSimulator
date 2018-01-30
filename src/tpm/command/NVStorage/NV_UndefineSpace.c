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
#include "NV_UndefineSpace_fp.h"
#ifdef TPM_CC_NV_UndefineSpace               // Conditional expansion of this file

// M e
// TPM_RC_ATTRIBUTES TPMA_NV_POLICY_DELETE is SET in the Index referenced by
// nvIndex so this command may not be used to delete this Index (see
// TPM2_NV_UndefineSpaceSpecial())
// TPM_RC_NV_AUTHORIZATION attempt to use ownerAuth to delete an index created by the platform

TPM_RC
TPM2_NV_UndefineSpace(
    NV_UndefineSpace_In *in                      // IN: input parameter list
)
{
    TPM_RC result;
    NV_INDEX nvIndex;

    // The command needs NV update. Check if NV is available.
    // A TPM_RC_NV_UNAVAILABLE or TPM_RC_NV_RATE error may be returned at
    // this point
    result = NvIsAvailable();
    if(result != TPM_RC_SUCCESS) return result;

// Input Validation

    // Get NV index info
    NvGetIndexInfo(in->nvIndex, &nvIndex);

    // This command can't be used to delete an index with TPMA_NV_POLICY_DELETE SET
    if(SET == nvIndex.publicArea.attributes.TPMA_NV_POLICY_DELETE)
        return TPM_RC_ATTRIBUTES + RC_NV_UndefineSpace_nvIndex;

    // The owner may only delete an index that was defined with ownerAuth. The
    // platform may delete an index that was created with either auth.
    if( in->authHandle == TPM_RH_OWNER
            && nvIndex.publicArea.attributes.TPMA_NV_PLATFORMCREATE == SET)
        return TPM_RC_NV_AUTHORIZATION;

// Internal Data Update

    // Call implementation dependent internal routine to delete NV index
    NvDeleteEntity(in->nvIndex);

    return TPM_RC_SUCCESS;
}
#endif // CC_NV_UndefineSpace
