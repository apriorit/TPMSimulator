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
#include "NV_Read_fp.h"
#ifdef TPM_CC_NV_Read           // Conditional expansion of this file
#include "NV_spt_fp.h"

// M e
// TPM_RC_NV_AUTHORIZATION the authorization was valid but the authorizing entity (authHandle) is
// not allowed to read from the Index referenced by nvIndex
// TPM_RC_NV_LOCKED the Index referenced by nvIndex is read locked
// TPM_RC_NV_RANGE read range defined by size and offset is outside the range of the
// Index referenced by nvIndex
// TPM_RC_NV_UNINITIALIZED the Index referenced by nvIndex has not been initialized (written)

TPM_RC
TPM2_NV_Read(
    NV_Read_In *in,            // IN: input parameter list
    NV_Read_Out *out            // OUT: output parameter list
)
{
    NV_INDEX nvIndex;
    TPM_RC result;

// Input Validation

    // Get NV index info
    NvGetIndexInfo(in->nvIndex, &nvIndex);

    // Common read access checks. NvReadAccessChecks() returns
    // TPM_RC_NV_AUTHORIZATION, TPM_RC_NV_LOCKED, or TPM_RC_NV_UNINITIALIZED
    // error may be returned at this point
    result = NvReadAccessChecks(in->authHandle, in->nvIndex);
    if(result != TPM_RC_SUCCESS)
        return result;

    // Too much data
    if((in->size + in->offset) > nvIndex.publicArea.dataSize)
        return TPM_RC_NV_RANGE;

// Command Output

    // Set the return size
    out->data.t.size = in->size;
    // Perform the read
    NvGetIndexData(in->nvIndex, &nvIndex, in->offset, in->size, out->data.t.buffer);

    return TPM_RC_SUCCESS;
}
#endif // CC_NV_Read
