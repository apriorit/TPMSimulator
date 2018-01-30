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
#include "NV_Write_fp.h"
#ifdef TPM_CC_NV_Write             // Conditional expansion of this file
#include "NV_spt_fp.h"

// M e
// TPM_RC_ATTRIBUTES Index referenced by nvIndex has either TPMA_NV_BITS,
// TPMA_NV_COUNTER, or TPMA_NV_EVENT attribute SET
// TPM_RC_NV_AUTHORIZATION the authorization was valid but the authorizing entity (authHandle) is
// not allowed to write to the Index referenced by nvIndex
// TPM_RC_NV_LOCKED Index referenced by nvIndex is write locked
// TPM_RC_NV_RANGE if TPMA_NV_WRITEALL is SET then the write is not the size of the
// Index referenced by nvIndex; otherwise, the write extends beyond the
// limits of the Index

TPM_RC
TPM2_NV_Write(
    NV_Write_In *in                     // IN: input parameter list
)
{
    NV_INDEX nvIndex;
    TPM_RC result;

// Input Validation

    // Get NV index info
    NvGetIndexInfo(in->nvIndex, &nvIndex);

    // common access checks. NvWrtieAccessChecks() may return
    // TPM_RC_NV_AUTHORIZATION or TPM_RC_NV_LOCKED
    result = NvWriteAccessChecks(in->authHandle, in->nvIndex);
    if(result != TPM_RC_SUCCESS)
        return result;

    // Bits index, extend index or counter index may not be updated by
    // TPM2_NV_Write
    if( nvIndex.publicArea.attributes.TPMA_NV_COUNTER == SET
            || nvIndex.publicArea.attributes.TPMA_NV_BITS == SET
            || nvIndex.publicArea.attributes.TPMA_NV_EXTEND == SET)
        return TPM_RC_ATTRIBUTES;

    // Too much data
    if((in->data.t.size + in->offset) > nvIndex.publicArea.dataSize)
        return TPM_RC_NV_RANGE;

    // If this index requires a full sized write, make sure that input range is
    // full sized
    if( nvIndex.publicArea.attributes.TPMA_NV_WRITEALL == SET
            && in->data.t.size < nvIndex.publicArea.dataSize)
        return TPM_RC_NV_RANGE;

// Internal Data Update

    // Perform the write. This called routine will SET the TPMA_NV_WRITTEN
    // attribute if it has not already been SET. If NV isn't available, an error
    // will be returned.
    return NvWriteIndexData(in->nvIndex, &nvIndex, in->offset,
                            in->data.t.size, in->data.t.buffer);

}
#endif // CC_NV_Write
