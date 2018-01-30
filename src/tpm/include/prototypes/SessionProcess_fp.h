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

#ifndef _SESSIONPROCESS_FP_H_
#define _SESSIONPROCESS_FP_H_

BOOL
IsDAExempted(
    TPM_HANDLE handle            // IN: entity handle
);

#ifdef TPM_CC_GetCommandAuditDigest
#endif
TPM_RC
ParseSessionBuffer(
    TPM_CC commandCode,                     // IN: Command code
    UINT32 handleNum,                       // IN: number of element in handle array
    TPM_HANDLE handles[],                       // IN: array of handle
    BYTE *sessionBufferStart,                 // IN: start of session buffer
    UINT32 sessionBufferSize,               // IN: size of session buffer
    BYTE *parmBufferStart,                    // IN: start of parameter buffer
    UINT32 parmBufferSize                   // IN: size of parameter buffer
);

TPM_RC
CheckAuthNoSession(
    TPM_CC commandCode,                // IN: Command Code
    UINT32 handleNum,                  // IN: number of handles in command
    TPM_HANDLE handles[],                  // IN: array of handle
    BYTE *parmBufferStart,               // IN: start of parameter buffer
    UINT32 parmBufferSize              // IN: size of parameter buffer
);

#ifdef TPM_CC_GetCommandAuditDigest
#endif
void
BuildResponseSession(
    TPM_ST tag,                      // IN: tag
    TPM_CC commandCode,              // IN: commandCode
    UINT32 resHandleSize,            // IN: size of response handle buffer
    UINT32 resParmSize,              // IN: size of response parameter buffer
    UINT32 *resSessionSize           // OUT: response session area
);

void
SessionRemoveAssociationToHandle(
    TPM_HANDLE           handle
    );
#endif  // _SESSIONPROCESS_FP_H_
