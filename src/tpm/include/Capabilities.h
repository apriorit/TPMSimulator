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

#ifndef _CAPABILITIES_H
#define _CAPABILITIES_H
/*
The size of the MAX_CAP_DATA was changed due to detected problems in interaction between simulator and WIndows 2012 R2
system components.
MAX_CAP_DATA is the buffer for data returned by TPM_CC_GetCapability command. The maximum size of a whole data which
expected by the system is 1KB including TPM header and response header specific for the certain command. So, to avoid
the overflow of returned data buffer, we should decrease the maximum size of the buffer which contains payload of
TPM_CC_GetCapability response.
Here are the meanings of the sizes to which the resulting value decreases:
MAX_CAP_DATA = MAX_CAP_BUFFER (1KB) - command tag (0x8001 or 0x8002) - command code (32 bit 0x17a) - size of the
payload (size of the next data in buffer) - TPM_CC_GetCapability command header - capability handles count.
*/
#define MAX_CAP_DATA (MAX_CAP_BUFFER-sizeof(TPMI_ST_COMMAND_TAG)-sizeof(TPM_CC)-sizeof(UINT32)-sizeof(TPM_CAP)-sizeof(UINT32))
#define MAX_CAP_ALGS (ALG_LAST_VALUE - ALG_FIRST_VALUE + 1)
#define MAX_CAP_HANDLES (MAX_CAP_DATA/sizeof(TPM_HANDLE))
#define MAX_CAP_CC ((TPM_CC_LAST - TPM_CC_FIRST) + 1)
#define MAX_TPM_PROPERTIES (MAX_CAP_DATA/sizeof(TPMS_TAGGED_PROPERTY))
#define MAX_PCR_PROPERTIES (MAX_CAP_DATA/sizeof(TPMS_TAGGED_PCR_SELECT))
#define MAX_ECC_CURVES (MAX_CAP_DATA/sizeof(TPM_ECC_CURVE))
#endif
