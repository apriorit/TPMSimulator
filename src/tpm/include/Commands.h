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

#ifndef _COMMANDS_H_
#define _COMMANDS_H_

#include "Startup_fp.h"
#include "Shutdown_fp.h"
#include "SelfTest_fp.h"
#include "IncrementalSelfTest_fp.h"
#include "GetTestResult_fp.h"
#include "StartAuthSession_fp.h"
#include "PolicyRestart_fp.h"
#include "Create_fp.h"
#include "Load_fp.h"
#include "LoadExternal_fp.h"
#include "ReadPublic_fp.h"
#include "ActivateCredential_fp.h"
#include "MakeCredential_fp.h"
#include "Unseal_fp.h"
#include "ObjectChangeAuth_fp.h"
#include "Duplicate_fp.h"
#include "Rewrap_fp.h"
#include "Import_fp.h"
#include "RSA_Encrypt_fp.h"
#include "RSA_Decrypt_fp.h"
#include "ECDH_KeyGen_fp.h"
#include "ECDH_ZGen_fp.h"
#include "ECC_Parameters_fp.h"
#include "ZGen_2Phase_fp.h"
#include "EncryptDecrypt_fp.h"
#include "Hash_fp.h"
#include "HMAC_fp.h"
#include "GetRandom_fp.h"
#include "StirRandom_fp.h"
#include "HMAC_Start_fp.h"
#include "HashSequenceStart_fp.h"
#include "SequenceUpdate_fp.h"
#include "SequenceComplete_fp.h"
#include "EventSequenceComplete_fp.h"
#include "Certify_fp.h"
#include "CertifyCreation_fp.h"
#include "Quote_fp.h"
#include "GetSessionAuditDigest_fp.h"
#include "GetCommandAuditDigest_fp.h"
#include "GetTime_fp.h"
#include "Commit_fp.h"
#include "EC_Ephemeral_fp.h"
#include "VerifySignature_fp.h"
#include "Sign_fp.h"
#include "SetCommandCodeAuditStatus_fp.h"
#include "PCR_Extend_fp.h"
#include "PCR_Event_fp.h"
#include "PCR_Read_fp.h"
#include "PCR_Allocate_fp.h"
#include "PCR_SetAuthPolicy_fp.h"
#include "PCR_SetAuthValue_fp.h"
#include "PCR_Reset_fp.h"
#include "PolicySigned_fp.h"
#include "PolicySecret_fp.h"
#include "PolicyTicket_fp.h"
#include "PolicyOR_fp.h"
#include "PolicyPCR_fp.h"
#include "PolicyLocality_fp.h"
#include "PolicyNV_fp.h"
#include "PolicyCounterTimer_fp.h"
#include "PolicyCommandCode_fp.h"
#include "PolicyPhysicalPresence_fp.h"
#include "PolicyCpHash_fp.h"
#include "PolicyNameHash_fp.h"
#include "PolicyDuplicationSelect_fp.h"
#include "PolicyAuthorize_fp.h"
#include "PolicyAuthValue_fp.h"
#include "PolicyPassword_fp.h"
#include "PolicyGetDigest_fp.h"
#include "PolicyNvWritten_fp.h"
#include "CreatePrimary_fp.h"
#include "HierarchyControl_fp.h"
#include "SetPrimaryPolicy_fp.h"
#include "ChangePPS_fp.h"
#include "ChangeEPS_fp.h"
#include "Clear_fp.h"
#include "ClearControl_fp.h"
#include "HierarchyChangeAuth_fp.h"
#include "DictionaryAttackLockReset_fp.h"
#include "DictionaryAttackParameters_fp.h"
#include "PP_Commands_fp.h"
#include "SetAlgorithmSet_fp.h"
#include "FieldUpgradeStart_fp.h"
#include "FieldUpgradeData_fp.h"
#include "FirmwareRead_fp.h"
#include "ContextSave_fp.h"
#include "ContextLoad_fp.h"
#include "FlushContext_fp.h"
#include "EvictControl_fp.h"
#include "ReadClock_fp.h"
#include "ClockSet_fp.h"
#include "ClockRateAdjust_fp.h"
#include "GetCapability_fp.h"
#include "TestParms_fp.h"
#include "NV_DefineSpace_fp.h"
#include "NV_UndefineSpace_fp.h"
#include "NV_UndefineSpaceSpecial_fp.h"
#include "NV_ReadPublic_fp.h"
#include "NV_Write_fp.h"
#include "NV_Increment_fp.h"
#include "NV_Extend_fp.h"
#include "NV_SetBits_fp.h"
#include "NV_WriteLock_fp.h"
#include "NV_GlobalWriteLock_fp.h"
#include "NV_Read_fp.h"
#include "NV_ReadLock_fp.h"
#include "NV_ChangeAuth_fp.h"
#include "NV_Certify_fp.h"
#endif  // _COMMANDS_H_
