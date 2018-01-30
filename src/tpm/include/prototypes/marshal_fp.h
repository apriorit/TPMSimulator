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
/*     Any marks and brands contained herein are the property of their respective owners.                         */
/*                                                                                                                */
/******************************************************************************************************************/

#ifndef _MARSHAL_FP_H
#define _MARSHAL_FP_H


// Table 2:3 - Definition of Base Types (TypedefTable)
TPM_RC
UINT8_Unmarshal(UINT8 *target, BYTE **buffer, INT32 *size);
UINT16
UINT8_Marshal(UINT8 *source, BYTE **buffer, INT32 *size);


#define BYTE_Unmarshal(target, buffer, size) \
 UINT8_Unmarshal((UINT8 *)(target), buffer, size)
#define BYTE_Marshal(source, buffer, size) \
 UINT8_Marshal((UINT8 *)(source), buffer, size)


#define INT8_Unmarshal(target, buffer, size) \
 UINT8_Unmarshal((UINT8 *)(target), buffer, size)
#define INT8_Marshal(source, buffer, size) \
 UINT8_Marshal((UINT8 *)(source), buffer, size)


TPM_RC
UINT16_Unmarshal(UINT16 *target, BYTE **buffer, INT32 *size);
UINT16
UINT16_Marshal(UINT16 *source, BYTE **buffer, INT32 *size);


#define INT16_Unmarshal(target, buffer, size) \
 UINT16_Unmarshal((UINT16 *)(target), buffer, size)
#define INT16_Marshal(source, buffer, size) \
 UINT16_Marshal((UINT16 *)(source), buffer, size)


TPM_RC
UINT32_Unmarshal(UINT32 *target, BYTE **buffer, INT32 *size);
UINT16
UINT32_Marshal(UINT32 *source, BYTE **buffer, INT32 *size);


#define INT32_Unmarshal(target, buffer, size) \
 UINT32_Unmarshal((UINT32 *)(target), buffer, size)
#define INT32_Marshal(source, buffer, size) \
 UINT32_Marshal((UINT32 *)(source), buffer, size)


TPM_RC
UINT64_Unmarshal(UINT64 *target, BYTE **buffer, INT32 *size);
UINT16
UINT64_Marshal(UINT64 *source, BYTE **buffer, INT32 *size);


#define INT64_Unmarshal(target, buffer, size) \
 UINT64_Unmarshal((UINT64 *)(target), buffer, size)
#define INT64_Marshal(source, buffer, size) \
 UINT64_Marshal((UINT64 *)(source), buffer, size)



// Table 2:5 - Definition of Types for Documentation Clarity (TypedefTable)
#define TPM_ALGORITHM_ID_Unmarshal(target, buffer, size) \
 UINT32_Unmarshal((UINT32 *)(target), buffer, size)
#define TPM_ALGORITHM_ID_Marshal(source, buffer, size) \
 UINT32_Marshal((UINT32 *)(source), buffer, size)


#define TPM_MODIFIER_INDICATOR_Unmarshal(target, buffer, size) \
 UINT32_Unmarshal((UINT32 *)(target), buffer, size)
#define TPM_MODIFIER_INDICATOR_Marshal(source, buffer, size) \
 UINT32_Marshal((UINT32 *)(source), buffer, size)


#define TPM_AUTHORIZATION_SIZE_Unmarshal(target, buffer, size) \
 UINT32_Unmarshal((UINT32 *)(target), buffer, size)
#define TPM_AUTHORIZATION_SIZE_Marshal(source, buffer, size) \
 UINT32_Marshal((UINT32 *)(source), buffer, size)


#define TPM_PARAMETER_SIZE_Unmarshal(target, buffer, size) \
 UINT32_Unmarshal((UINT32 *)(target), buffer, size)
#define TPM_PARAMETER_SIZE_Marshal(source, buffer, size) \
 UINT32_Marshal((UINT32 *)(source), buffer, size)


#define TPM_KEY_SIZE_Unmarshal(target, buffer, size) \
 UINT16_Unmarshal((UINT16 *)(target), buffer, size)
#define TPM_KEY_SIZE_Marshal(source, buffer, size) \
 UINT16_Marshal((UINT16 *)(source), buffer, size)


#define TPM_KEY_BITS_Unmarshal(target, buffer, size) \
 UINT16_Unmarshal((UINT16 *)(target), buffer, size)
#define TPM_KEY_BITS_Marshal(source, buffer, size) \
 UINT16_Marshal((UINT16 *)(source), buffer, size)



// Table 2:6 - Definition of (UINT32) TPM_SPEC Constants (EnumTable)
// TPM_SPEC_Unmarshal not required
// TPM_SPEC_Marshal not required

// Table 2:7 - Definition of (UINT32) TPM_GENERATED Constants (EnumTable)
// TPM_GENERATED_Unmarshal not required
#define TPM_GENERATED_Marshal(source, buffer, size) \
 UINT32_Marshal((UINT32 *)(source), buffer, size)


// Table 2:9 - Definition of (UINT16) TPM_ALG_ID Constants (EnumTable)
#define TPM_ALG_ID_Unmarshal(target, buffer, size) \
 UINT16_Unmarshal((UINT16 *)(target), buffer, size)
#define TPM_ALG_ID_Marshal(source, buffer, size) \
 UINT16_Marshal((UINT16 *)(source), buffer, size)


// Table 2:10 - Definition of (UINT16) {ECC} TPM_ECC_CURVE Constants (EnumTable)
#ifdef TPM_ALG_ECC
#define TPM_ECC_CURVE_Unmarshal(target, buffer, size) \
 UINT16_Unmarshal((UINT16 *)(target), buffer, size)
#define TPM_ECC_CURVE_Marshal(source, buffer, size) \
 UINT16_Marshal((UINT16 *)(source), buffer, size)

#endif // TPM_ALG_ECC


// Table 2:13 - Definition of (UINT32) TPM_CC Constants (EnumTable)
#define TPM_CC_Unmarshal(target, buffer, size) \
 UINT32_Unmarshal((UINT32 *)(target), buffer, size)
#define TPM_CC_Marshal(source, buffer, size) \
 UINT32_Marshal((UINT32 *)(source), buffer, size)


// Table 2:17 - Definition of (UINT32) TPM_RC Constants (EnumTable)
// TPM_RC_Unmarshal not required
#define TPM_RC_Marshal(source, buffer, size) \
 UINT32_Marshal((UINT32 *)(source), buffer, size)


// Table 2:18 - Definition of (INT8) TPM_CLOCK_ADJUST Constants (EnumTable)
TPM_RC
TPM_CLOCK_ADJUST_Unmarshal(TPM_CLOCK_ADJUST *target, BYTE **buffer, INT32 *size);
// TPM_CLOCK_ADJUST_Marshal not required

// Table 2:19 - Definition of (UINT16) TPM_EO Constants (EnumTable)
TPM_RC
TPM_EO_Unmarshal(TPM_EO *target, BYTE **buffer, INT32 *size);
#define TPM_EO_Marshal(source, buffer, size) \
 UINT16_Marshal((UINT16 *)(source), buffer, size)


// Table 2:20 - Definition of (UINT16) TPM_ST Constants (EnumTable)
#define TPM_ST_Unmarshal(target, buffer, size) \
 UINT16_Unmarshal((UINT16 *)(target), buffer, size)
#define TPM_ST_Marshal(source, buffer, size) \
 UINT16_Marshal((UINT16 *)(source), buffer, size)


// Table 2:21 - Definition of (UINT16) TPM_SU Constants (EnumTable)
TPM_RC
TPM_SU_Unmarshal(TPM_SU *target, BYTE **buffer, INT32 *size);
// TPM_SU_Marshal not required

// Table 2:22 - Definition of (UINT8) TPM_SE Constants (EnumTable)
TPM_RC
TPM_SE_Unmarshal(TPM_SE *target, BYTE **buffer, INT32 *size);
// TPM_SE_Marshal not required

// Table 2:23 - Definition of (UINT32) TPM_CAP Constants (EnumTable)
TPM_RC
TPM_CAP_Unmarshal(TPM_CAP *target, BYTE **buffer, INT32 *size);
#define TPM_CAP_Marshal(source, buffer, size) \
 UINT32_Marshal((UINT32 *)(source), buffer, size)


// Table 2:24 - Definition of (UINT32) TPM_PT Constants (EnumTable)
#define TPM_PT_Unmarshal(target, buffer, size) \
 UINT32_Unmarshal((UINT32 *)(target), buffer, size)
#define TPM_PT_Marshal(source, buffer, size) \
 UINT32_Marshal((UINT32 *)(source), buffer, size)


// Table 2:25 - Definition of (UINT32) TPM_PT_PCR Constants (EnumTable)
#define TPM_PT_PCR_Unmarshal(target, buffer, size) \
 UINT32_Unmarshal((UINT32 *)(target), buffer, size)
#define TPM_PT_PCR_Marshal(source, buffer, size) \
 UINT32_Marshal((UINT32 *)(source), buffer, size)


// Table 2:26 - Definition of (UINT32) TPM_PS Constants (EnumTable)
// TPM_PS_Unmarshal not required
#define TPM_PS_Marshal(source, buffer, size) \
 UINT32_Marshal((UINT32 *)(source), buffer, size)


// Table 2:27 - Definition of Types for Handles (TypedefTable)
#define TPM_HANDLE_Unmarshal(target, buffer, size) \
 UINT32_Unmarshal((UINT32 *)(target), buffer, size)
#define TPM_HANDLE_Marshal(source, buffer, size) \
 UINT32_Marshal((UINT32 *)(source), buffer, size)



// Table 2:28 - Definition of (UINT8) TPM_HT Constants (EnumTable)
// TPM_HT_Unmarshal not required
// TPM_HT_Marshal not required

// Table 2:29 - Definition of (TPM_HANDLE) TPM_RH Constants (EnumTable)

// Table 2:30 - Definition of (TPM_HANDLE) TPM_HC Constants (EnumTable)

// Table 2:31 - Definition of (UINT32) TPMA_ALGORITHM Bits (BitsTable)
TPM_RC
TPMA_ALGORITHM_Unmarshal(TPMA_ALGORITHM *target, BYTE **buffer, INT32 *size);
#define TPMA_ALGORITHM_Marshal(source, buffer, size) \
 UINT32_Marshal((UINT32 *)(source), buffer, size)


// Table 2:32 - Definition of (UINT32) TPMA_OBJECT Bits (BitsTable)
TPM_RC
TPMA_OBJECT_Unmarshal(TPMA_OBJECT *target, BYTE **buffer, INT32 *size);
#define TPMA_OBJECT_Marshal(source, buffer, size) \
 UINT32_Marshal((UINT32 *)(source), buffer, size)


// Table 2:33 - Definition of (UINT8) TPMA_SESSION Bits (BitsTable)
TPM_RC
TPMA_SESSION_Unmarshal(TPMA_SESSION *target, BYTE **buffer, INT32 *size);
#define TPMA_SESSION_Marshal(source, buffer, size) \
 UINT8_Marshal((UINT8 *)(source), buffer, size)


// Table 2:34 - Definition of (UINT8) TPMA_LOCALITY Bits (BitsTable)
#define TPMA_LOCALITY_Unmarshal(target, buffer, size) \
 UINT8_Unmarshal((UINT8 *)(target), buffer, size)
#define TPMA_LOCALITY_Marshal(source, buffer, size) \
 UINT8_Marshal((UINT8 *)(source), buffer, size)


// Table 2:35 - Definition of (UINT32) TPMA_PERMANENT Bits (BitsTable)
TPM_RC
TPMA_PERMANENT_Unmarshal(TPMA_PERMANENT *target, BYTE **buffer, INT32 *size);
#define TPMA_PERMANENT_Marshal(source, buffer, size) \
 UINT32_Marshal((UINT32 *)(source), buffer, size)


// Table 2:36 - Definition of (UINT32) TPMA_STARTUP_CLEAR Bits (BitsTable)
TPM_RC
TPMA_STARTUP_CLEAR_Unmarshal(TPMA_STARTUP_CLEAR *target, BYTE **buffer, INT32 *size);
#define TPMA_STARTUP_CLEAR_Marshal(source, buffer, size) \
 UINT32_Marshal((UINT32 *)(source), buffer, size)


// Table 2:37 - Definition of (UINT32) TPMA_MEMORY Bits (BitsTable)
TPM_RC
TPMA_MEMORY_Unmarshal(TPMA_MEMORY *target, BYTE **buffer, INT32 *size);
#define TPMA_MEMORY_Marshal(source, buffer, size) \
 UINT32_Marshal((UINT32 *)(source), buffer, size)


// Table 2:38 - Definition of (TPM_CC) TPMA_CC Bits (BitsTable)
TPM_RC
TPMA_CC_Unmarshal(TPMA_CC *target, BYTE **buffer, INT32 *size);
#define TPMA_CC_Marshal(source, buffer, size) \
 TPM_CC_Marshal((TPM_CC *)(source), buffer, size)


// Table 2:39 - Definition of (BYTE) TPMI_YES_NO Type (InterfaceTable)
TPM_RC
TPMI_YES_NO_Unmarshal(TPMI_YES_NO *target, BYTE **buffer, INT32 *size);
#define TPMI_YES_NO_Marshal(source, buffer, size) \
 BYTE_Marshal((BYTE *)(source), buffer, size)


// Table 2:40 - Definition of (TPM_HANDLE) TPMI_DH_OBJECT Type (InterfaceTable)
TPM_RC
TPMI_DH_OBJECT_Unmarshal(TPMI_DH_OBJECT *target, BYTE **buffer, INT32 *size, BOOL allowNull);
#define TPMI_DH_OBJECT_Marshal(source, buffer, size) \
 TPM_HANDLE_Marshal((TPM_HANDLE *)(source), buffer, size)


// Table 2:41 - Definition of (TPM_HANDLE) TPMI_DH_PERSISTENT Type (InterfaceTable)
TPM_RC
TPMI_DH_PERSISTENT_Unmarshal(TPMI_DH_PERSISTENT *target, BYTE **buffer, INT32 *size);
#define TPMI_DH_PERSISTENT_Marshal(source, buffer, size) \
 TPM_HANDLE_Marshal((TPM_HANDLE *)(source), buffer, size)


// Table 2:42 - Definition of (TPM_HANDLE) TPMI_DH_ENTITY Type (InterfaceTable)
TPM_RC
TPMI_DH_ENTITY_Unmarshal(TPMI_DH_ENTITY *target, BYTE **buffer, INT32 *size, BOOL allowNull);

// Table 2:43 - Definition of (TPM_HANDLE) TPMI_DH_PCR Type (InterfaceTable)
TPM_RC
TPMI_DH_PCR_Unmarshal(TPMI_DH_PCR *target, BYTE **buffer, INT32 *size, BOOL allowNull);

// Table 2:44 - Definition of (TPM_HANDLE) TPMI_SH_AUTH_SESSION Type (InterfaceTable)
TPM_RC
TPMI_SH_AUTH_SESSION_Unmarshal(TPMI_SH_AUTH_SESSION *target, BYTE **buffer, INT32 *size, BOOL allowNull);
#define TPMI_SH_AUTH_SESSION_Marshal(source, buffer, size) \
 TPM_HANDLE_Marshal((TPM_HANDLE *)(source), buffer, size)


// Table 2:45 - Definition of (TPM_HANDLE) TPMI_SH_HMAC Type (InterfaceTable)
TPM_RC
TPMI_SH_HMAC_Unmarshal(TPMI_SH_HMAC *target, BYTE **buffer, INT32 *size);
#define TPMI_SH_HMAC_Marshal(source, buffer, size) \
 TPM_HANDLE_Marshal((TPM_HANDLE *)(source), buffer, size)


// Table 2:46 - Definition of (TPM_HANDLE) TPMI_SH_POLICY Type (InterfaceTable)
TPM_RC
TPMI_SH_POLICY_Unmarshal(TPMI_SH_POLICY *target, BYTE **buffer, INT32 *size);
#define TPMI_SH_POLICY_Marshal(source, buffer, size) \
 TPM_HANDLE_Marshal((TPM_HANDLE *)(source), buffer, size)


// Table 2:47 - Definition of (TPM_HANDLE) TPMI_DH_CONTEXT Type (InterfaceTable)
TPM_RC
TPMI_DH_CONTEXT_Unmarshal(TPMI_DH_CONTEXT *target, BYTE **buffer, INT32 *size);
#define TPMI_DH_CONTEXT_Marshal(source, buffer, size) \
 TPM_HANDLE_Marshal((TPM_HANDLE *)(source), buffer, size)


// Table 2:48 - Definition of (TPM_HANDLE) TPMI_RH_HIERARCHY Type (InterfaceTable)
TPM_RC
TPMI_RH_HIERARCHY_Unmarshal(TPMI_RH_HIERARCHY *target, BYTE **buffer, INT32 *size, BOOL allowNull);
#define TPMI_RH_HIERARCHY_Marshal(source, buffer, size) \
 TPM_HANDLE_Marshal((TPM_HANDLE *)(source), buffer, size)


// Table 2:49 - Definition of (TPM_HANDLE) TPMI_RH_ENABLES Type (InterfaceTable)
TPM_RC
TPMI_RH_ENABLES_Unmarshal(TPMI_RH_ENABLES *target, BYTE **buffer, INT32 *size, BOOL allowNull);
#define TPMI_RH_ENABLES_Marshal(source, buffer, size) \
 TPM_HANDLE_Marshal((TPM_HANDLE *)(source), buffer, size)


// Table 2:50 - Definition of (TPM_HANDLE) TPMI_RH_HIERARCHY_AUTH Type (InterfaceTable)
TPM_RC
TPMI_RH_HIERARCHY_AUTH_Unmarshal(TPMI_RH_HIERARCHY_AUTH *target, BYTE **buffer, INT32 *size);

// Table 2:51 - Definition of (TPM_HANDLE) TPMI_RH_PLATFORM Type (InterfaceTable)
TPM_RC
TPMI_RH_PLATFORM_Unmarshal(TPMI_RH_PLATFORM *target, BYTE **buffer, INT32 *size);

// Table 2:52 - Definition of (TPM_HANDLE) TPMI_RH_OWNER Type (InterfaceTable)
TPM_RC
TPMI_RH_OWNER_Unmarshal(TPMI_RH_OWNER *target, BYTE **buffer, INT32 *size, BOOL allowNull);

// Table 2:53 - Definition of (TPM_HANDLE) TPMI_RH_ENDORSEMENT Type (InterfaceTable)
TPM_RC
TPMI_RH_ENDORSEMENT_Unmarshal(TPMI_RH_ENDORSEMENT *target, BYTE **buffer, INT32 *size, BOOL allowNull);

// Table 2:54 - Definition of (TPM_HANDLE) TPMI_RH_PROVISION Type (InterfaceTable)
TPM_RC
TPMI_RH_PROVISION_Unmarshal(TPMI_RH_PROVISION *target, BYTE **buffer, INT32 *size);

// Table 2:55 - Definition of (TPM_HANDLE) TPMI_RH_CLEAR Type (InterfaceTable)
TPM_RC
TPMI_RH_CLEAR_Unmarshal(TPMI_RH_CLEAR *target, BYTE **buffer, INT32 *size);

// Table 2:56 - Definition of (TPM_HANDLE) TPMI_RH_NV_AUTH Type (InterfaceTable)
TPM_RC
TPMI_RH_NV_AUTH_Unmarshal(TPMI_RH_NV_AUTH *target, BYTE **buffer, INT32 *size);

// Table 2:57 - Definition of (TPM_HANDLE) TPMI_RH_LOCKOUT Type (InterfaceTable)
TPM_RC
TPMI_RH_LOCKOUT_Unmarshal(TPMI_RH_LOCKOUT *target, BYTE **buffer, INT32 *size);

// Table 2:58 - Definition of (TPM_HANDLE) TPMI_RH_NV_INDEX Type (InterfaceTable)
TPM_RC
TPMI_RH_NV_INDEX_Unmarshal(TPMI_RH_NV_INDEX *target, BYTE **buffer, INT32 *size);
#define TPMI_RH_NV_INDEX_Marshal(source, buffer, size) \
 TPM_HANDLE_Marshal((TPM_HANDLE *)(source), buffer, size)


// Table 2:59 - Definition of (TPM_ALG_ID) TPMI_ALG_HASH Type (InterfaceTable)
TPM_RC
TPMI_ALG_HASH_Unmarshal(TPMI_ALG_HASH *target, BYTE **buffer, INT32 *size, BOOL allowNull);
#define TPMI_ALG_HASH_Marshal(source, buffer, size) \
 TPM_ALG_ID_Marshal((TPM_ALG_ID *)(source), buffer, size)


// Table 2:60 - Definition of (TPM_ALG_ID) TPMI_ALG_ASYM Type (InterfaceTable)
TPM_RC
TPMI_ALG_ASYM_Unmarshal(TPMI_ALG_ASYM *target, BYTE **buffer, INT32 *size, BOOL allowNull);
#define TPMI_ALG_ASYM_Marshal(source, buffer, size) \
 TPM_ALG_ID_Marshal((TPM_ALG_ID *)(source), buffer, size)


// Table 2:61 - Definition of (TPM_ALG_ID) TPMI_ALG_SYM Type (InterfaceTable)
TPM_RC
TPMI_ALG_SYM_Unmarshal(TPMI_ALG_SYM *target, BYTE **buffer, INT32 *size, BOOL allowNull);
#define TPMI_ALG_SYM_Marshal(source, buffer, size) \
 TPM_ALG_ID_Marshal((TPM_ALG_ID *)(source), buffer, size)


// Table 2:62 - Definition of (TPM_ALG_ID) TPMI_ALG_SYM_OBJECT Type (InterfaceTable)
TPM_RC
TPMI_ALG_SYM_OBJECT_Unmarshal(TPMI_ALG_SYM_OBJECT *target, BYTE **buffer, INT32 *size, BOOL allowNull);
#define TPMI_ALG_SYM_OBJECT_Marshal(source, buffer, size) \
 TPM_ALG_ID_Marshal((TPM_ALG_ID *)(source), buffer, size)


// Table 2:63 - Definition of (TPM_ALG_ID) TPMI_ALG_SYM_MODE Type (InterfaceTable)
TPM_RC
TPMI_ALG_SYM_MODE_Unmarshal(TPMI_ALG_SYM_MODE *target, BYTE **buffer, INT32 *size, BOOL allowNull);
#define TPMI_ALG_SYM_MODE_Marshal(source, buffer, size) \
 TPM_ALG_ID_Marshal((TPM_ALG_ID *)(source), buffer, size)


// Table 2:64 - Definition of (TPM_ALG_ID) TPMI_ALG_KDF Type (InterfaceTable)
TPM_RC
TPMI_ALG_KDF_Unmarshal(TPMI_ALG_KDF *target, BYTE **buffer, INT32 *size, BOOL allowNull);
#define TPMI_ALG_KDF_Marshal(source, buffer, size) \
 TPM_ALG_ID_Marshal((TPM_ALG_ID *)(source), buffer, size)


// Table 2:65 - Definition of (TPM_ALG_ID) TPMI_ALG_SIG_SCHEME Type (InterfaceTable)
TPM_RC
TPMI_ALG_SIG_SCHEME_Unmarshal(TPMI_ALG_SIG_SCHEME *target, BYTE **buffer, INT32 *size, BOOL allowNull);
#define TPMI_ALG_SIG_SCHEME_Marshal(source, buffer, size) \
 TPM_ALG_ID_Marshal((TPM_ALG_ID *)(source), buffer, size)


// Table 2:66 - Definition of (TPM_ALG_ID){ECC} TPMI_ECC_KEY_EXCHANGE Type (InterfaceTable)
#ifdef TPM_ALG_ECC
TPM_RC
TPMI_ECC_KEY_EXCHANGE_Unmarshal(TPMI_ECC_KEY_EXCHANGE *target, BYTE **buffer, INT32 *size, BOOL allowNull);
#define TPMI_ECC_KEY_EXCHANGE_Marshal(source, buffer, size) \
 TPM_ALG_ID_Marshal((TPM_ALG_ID *)(source), buffer, size)

#endif // TPM_ALG_ECC


// Table 2:67 - Definition of (TPM_ST) TPMI_ST_COMMAND_TAG Type (InterfaceTable)
TPM_RC
TPMI_ST_COMMAND_TAG_Unmarshal(TPMI_ST_COMMAND_TAG *target, BYTE **buffer, INT32 *size);
#define TPMI_ST_COMMAND_TAG_Marshal(source, buffer, size) \
 TPM_ST_Marshal((TPM_ST *)(source), buffer, size)

TPM_RC
TPMS_EMPTY_Unmarshal(TPMS_EMPTY *target, BYTE **buffer, INT32 *size);
UINT16
TPMS_EMPTY_Marshal(TPMS_EMPTY *source, BYTE **buffer, INT32 *size);


// Table 2:69 - Definition of TPMS_ALGORITHM_DESCRIPTION Structure (StructureTable)
// TPMS_ALGORITHM_DESCRIPTION_Unmarshal not required
UINT16
TPMS_ALGORITHM_DESCRIPTION_Marshal(TPMS_ALGORITHM_DESCRIPTION *source, BYTE **buffer, INT32 *size);


// Table 2:70 - Definition of TPMU_HA Union (UnionTable)
TPM_RC
TPMU_HA_Unmarshal(TPMU_HA *target, BYTE **buffer, INT32 *size, UINT32 selector);
UINT16
TPMU_HA_Marshal(TPMU_HA *source, BYTE **buffer, INT32 *size, UINT32 selector);


// Table 2:71 - Definition of TPMT_HA Structure (StructureTable)
TPM_RC
TPMT_HA_Unmarshal(TPMT_HA *target, BYTE **buffer, INT32 *size, BOOL allowNull);
UINT16
TPMT_HA_Marshal(TPMT_HA *source, BYTE **buffer, INT32 *size);


// Table 2:72 - Definition of TPM2B_DIGEST Structure (StructureTable)
TPM_RC
TPM2B_DIGEST_Unmarshal(TPM2B_DIGEST *target, BYTE **buffer, INT32 *size);
UINT16
TPM2B_DIGEST_Marshal(TPM2B_DIGEST *source, BYTE **buffer, INT32 *size);


// Table 2:73 - Definition of TPM2B_DATA Structure (StructureTable)
TPM_RC
TPM2B_DATA_Unmarshal(TPM2B_DATA *target, BYTE **buffer, INT32 *size);
UINT16
TPM2B_DATA_Marshal(TPM2B_DATA *source, BYTE **buffer, INT32 *size);


// Table 2:74 - Definition of Types for TPM2B_NONCE (TypedefTable)
#define TPM2B_NONCE_Unmarshal(target, buffer, size) \
 TPM2B_DIGEST_Unmarshal((TPM2B_DIGEST *)(target), buffer, size)
#define TPM2B_NONCE_Marshal(source, buffer, size) \
 TPM2B_DIGEST_Marshal((TPM2B_DIGEST *)(source), buffer, size)



// Table 2:75 - Definition of Types for TPM2B_AUTH (TypedefTable)
#define TPM2B_AUTH_Unmarshal(target, buffer, size) \
 TPM2B_DIGEST_Unmarshal((TPM2B_DIGEST *)(target), buffer, size)
#define TPM2B_AUTH_Marshal(source, buffer, size) \
 TPM2B_DIGEST_Marshal((TPM2B_DIGEST *)(source), buffer, size)



// Table 2:76 - Definition of Types for TPM2B_OPERAND (TypedefTable)
#define TPM2B_OPERAND_Unmarshal(target, buffer, size) \
 TPM2B_DIGEST_Unmarshal((TPM2B_DIGEST *)(target), buffer, size)
#define TPM2B_OPERAND_Marshal(source, buffer, size) \
 TPM2B_DIGEST_Marshal((TPM2B_DIGEST *)(source), buffer, size)



// Table 2:77 - Definition of TPM2B_EVENT Structure (StructureTable)
TPM_RC
TPM2B_EVENT_Unmarshal(TPM2B_EVENT *target, BYTE **buffer, INT32 *size);
UINT16
TPM2B_EVENT_Marshal(TPM2B_EVENT *source, BYTE **buffer, INT32 *size);


// Table 2:78 - Definition of TPM2B_MAX_BUFFER Structure (StructureTable)
TPM_RC
TPM2B_MAX_BUFFER_Unmarshal(TPM2B_MAX_BUFFER *target, BYTE **buffer, INT32 *size);
UINT16
TPM2B_MAX_BUFFER_Marshal(TPM2B_MAX_BUFFER *source, BYTE **buffer, INT32 *size);


// Table 2:79 - Definition of TPM2B_MAX_NV_BUFFER Structure (StructureTable)
TPM_RC
TPM2B_MAX_NV_BUFFER_Unmarshal(TPM2B_MAX_NV_BUFFER *target, BYTE **buffer, INT32 *size);
UINT16
TPM2B_MAX_NV_BUFFER_Marshal(TPM2B_MAX_NV_BUFFER *source, BYTE **buffer, INT32 *size);


// Table 2:80 - Definition of TPM2B_TIMEOUT Structure (StructureTable)
TPM_RC
TPM2B_TIMEOUT_Unmarshal(TPM2B_TIMEOUT *target, BYTE **buffer, INT32 *size);
UINT16
TPM2B_TIMEOUT_Marshal(TPM2B_TIMEOUT *source, BYTE **buffer, INT32 *size);


// Table 2:81 - Definition of TPM2B_IV Structure (StructureTable)
TPM_RC
TPM2B_IV_Unmarshal(TPM2B_IV *target, BYTE **buffer, INT32 *size);
UINT16
TPM2B_IV_Marshal(TPM2B_IV *source, BYTE **buffer, INT32 *size);


// Table 2:82 - Definition of TPMU_NAME Union (UnionTable)
// TPMU_NAME_Unmarshal not required
// TPMU_NAME_Marshal not required

// Table 2:83 - Definition of TPM2B_NAME Structure (StructureTable)
TPM_RC
TPM2B_NAME_Unmarshal(TPM2B_NAME *target, BYTE **buffer, INT32 *size);
UINT16
TPM2B_NAME_Marshal(TPM2B_NAME *source, BYTE **buffer, INT32 *size);


// Table 2:84 - Definition of TPMS_PCR_SELECT Structure (StructureTable)
TPM_RC
TPMS_PCR_SELECT_Unmarshal(TPMS_PCR_SELECT *target, BYTE **buffer, INT32 *size);
UINT16
TPMS_PCR_SELECT_Marshal(TPMS_PCR_SELECT *source, BYTE **buffer, INT32 *size);


// Table 2:85 - Definition of TPMS_PCR_SELECTION Structure (StructureTable)
TPM_RC
TPMS_PCR_SELECTION_Unmarshal(TPMS_PCR_SELECTION *target, BYTE **buffer, INT32 *size);
UINT16
TPMS_PCR_SELECTION_Marshal(TPMS_PCR_SELECTION *source, BYTE **buffer, INT32 *size);


// Table 2:88 - Definition of TPMT_TK_CREATION Structure (StructureTable)
TPM_RC
TPMT_TK_CREATION_Unmarshal(TPMT_TK_CREATION *target, BYTE **buffer, INT32 *size);
UINT16
TPMT_TK_CREATION_Marshal(TPMT_TK_CREATION *source, BYTE **buffer, INT32 *size);


// Table 2:89 - Definition of TPMT_TK_VERIFIED Structure (StructureTable)
TPM_RC
TPMT_TK_VERIFIED_Unmarshal(TPMT_TK_VERIFIED *target, BYTE **buffer, INT32 *size);
UINT16
TPMT_TK_VERIFIED_Marshal(TPMT_TK_VERIFIED *source, BYTE **buffer, INT32 *size);


// Table 2:90 - Definition of TPMT_TK_AUTH Structure (StructureTable)
TPM_RC
TPMT_TK_AUTH_Unmarshal(TPMT_TK_AUTH *target, BYTE **buffer, INT32 *size);
UINT16
TPMT_TK_AUTH_Marshal(TPMT_TK_AUTH *source, BYTE **buffer, INT32 *size);


// Table 2:91 - Definition of TPMT_TK_HASHCHECK Structure (StructureTable)
TPM_RC
TPMT_TK_HASHCHECK_Unmarshal(TPMT_TK_HASHCHECK *target, BYTE **buffer, INT32 *size);
UINT16
TPMT_TK_HASHCHECK_Marshal(TPMT_TK_HASHCHECK *source, BYTE **buffer, INT32 *size);


// Table 2:92 - Definition of TPMS_ALG_PROPERTY Structure (StructureTable)
// TPMS_ALG_PROPERTY_Unmarshal not required
UINT16
TPMS_ALG_PROPERTY_Marshal(TPMS_ALG_PROPERTY *source, BYTE **buffer, INT32 *size);


// Table 2:93 - Definition of TPMS_TAGGED_PROPERTY Structure (StructureTable)
// TPMS_TAGGED_PROPERTY_Unmarshal not required
UINT16
TPMS_TAGGED_PROPERTY_Marshal(TPMS_TAGGED_PROPERTY *source, BYTE **buffer, INT32 *size);


// Table 2:94 - Definition of TPMS_TAGGED_PCR_SELECT Structure (StructureTable)
// TPMS_TAGGED_PCR_SELECT_Unmarshal not required
UINT16
TPMS_TAGGED_PCR_SELECT_Marshal(TPMS_TAGGED_PCR_SELECT *source, BYTE **buffer, INT32 *size);


// Table 2:95 - Definition of TPML_CC Structure (StructureTable)
TPM_RC
TPML_CC_Unmarshal(TPML_CC *target, BYTE **buffer, INT32 *size);
UINT16
TPML_CC_Marshal(TPML_CC *source, BYTE **buffer, INT32 *size);


// Table 2:96 - Definition of TPML_CCA Structure (StructureTable)
// TPML_CCA_Unmarshal not required
UINT16
TPML_CCA_Marshal(TPML_CCA *source, BYTE **buffer, INT32 *size);


// Table 2:97 - Definition of TPML_ALG Structure (StructureTable)
TPM_RC
TPML_ALG_Unmarshal(TPML_ALG *target, BYTE **buffer, INT32 *size);
UINT16
TPML_ALG_Marshal(TPML_ALG *source, BYTE **buffer, INT32 *size);


// Table 2:98 - Definition of TPML_HANDLE Structure (StructureTable)
// TPML_HANDLE_Unmarshal not required
UINT16
TPML_HANDLE_Marshal(TPML_HANDLE *source, BYTE **buffer, INT32 *size);


// Table 2:99 - Definition of TPML_DIGEST Structure (StructureTable)
TPM_RC
TPML_DIGEST_Unmarshal(TPML_DIGEST *target, BYTE **buffer, INT32 *size);
UINT16
TPML_DIGEST_Marshal(TPML_DIGEST *source, BYTE **buffer, INT32 *size);


// Table 2:100 - Definition of TPML_DIGEST_VALUES Structure (StructureTable)
TPM_RC
TPML_DIGEST_VALUES_Unmarshal(TPML_DIGEST_VALUES *target, BYTE **buffer, INT32 *size);
UINT16
TPML_DIGEST_VALUES_Marshal(TPML_DIGEST_VALUES *source, BYTE **buffer, INT32 *size);


// Table 2:101 - Definition of TPM2B_DIGEST_VALUES Structure (StructureTable)
TPM_RC
TPM2B_DIGEST_VALUES_Unmarshal(TPM2B_DIGEST_VALUES *target, BYTE **buffer, INT32 *size);
UINT16
TPM2B_DIGEST_VALUES_Marshal(TPM2B_DIGEST_VALUES *source, BYTE **buffer, INT32 *size);


// Table 2:102 - Definition of TPML_PCR_SELECTION Structure (StructureTable)
TPM_RC
TPML_PCR_SELECTION_Unmarshal(TPML_PCR_SELECTION *target, BYTE **buffer, INT32 *size);
UINT16
TPML_PCR_SELECTION_Marshal(TPML_PCR_SELECTION *source, BYTE **buffer, INT32 *size);


// Table 2:103 - Definition of TPML_ALG_PROPERTY Structure (StructureTable)
// TPML_ALG_PROPERTY_Unmarshal not required
UINT16
TPML_ALG_PROPERTY_Marshal(TPML_ALG_PROPERTY *source, BYTE **buffer, INT32 *size);


// Table 2:104 - Definition of TPML_TAGGED_TPM_PROPERTY Structure (StructureTable)
// TPML_TAGGED_TPM_PROPERTY_Unmarshal not required
UINT16
TPML_TAGGED_TPM_PROPERTY_Marshal(TPML_TAGGED_TPM_PROPERTY *source, BYTE **buffer, INT32 *size);


// Table 2:105 - Definition of TPML_TAGGED_PCR_PROPERTY Structure (StructureTable)
// TPML_TAGGED_PCR_PROPERTY_Unmarshal not required
UINT16
TPML_TAGGED_PCR_PROPERTY_Marshal(TPML_TAGGED_PCR_PROPERTY *source, BYTE **buffer, INT32 *size);


// Table 2:106 - Definition of {ECC} TPML_ECC_CURVE Structure (StructureTable)
#ifdef TPM_ALG_ECC
// TPML_ECC_CURVE_Unmarshal not required
UINT16
TPML_ECC_CURVE_Marshal(TPML_ECC_CURVE *source, BYTE **buffer, INT32 *size);

#endif // TPM_ALG_ECC


// Table 2:107 - Definition of TPMU_CAPABILITIES Union (UnionTable)
// TPMU_CAPABILITIES_Unmarshal not required
UINT16
TPMU_CAPABILITIES_Marshal(TPMU_CAPABILITIES *source, BYTE **buffer, INT32 *size, UINT32 selector);


// Table 2:108 - Definition of TPMS_CAPABILITY_DATA Structure (StructureTable)
// TPMS_CAPABILITY_DATA_Unmarshal not required
UINT16
TPMS_CAPABILITY_DATA_Marshal(TPMS_CAPABILITY_DATA *source, BYTE **buffer, INT32 *size);


// Table 2:109 - Definition of TPMS_CLOCK_INFO Structure (StructureTable)
TPM_RC
TPMS_CLOCK_INFO_Unmarshal(TPMS_CLOCK_INFO *target, BYTE **buffer, INT32 *size);
UINT16
TPMS_CLOCK_INFO_Marshal(TPMS_CLOCK_INFO *source, BYTE **buffer, INT32 *size);


// Table 2:110 - Definition of TPMS_TIME_INFO Structure (StructureTable)
TPM_RC
TPMS_TIME_INFO_Unmarshal(TPMS_TIME_INFO *target, BYTE **buffer, INT32 *size);
UINT16
TPMS_TIME_INFO_Marshal(TPMS_TIME_INFO *source, BYTE **buffer, INT32 *size);


// Table 2:111 - Definition of TPMS_TIME_ATTEST_INFO Structure (StructureTable)
// TPMS_TIME_ATTEST_INFO_Unmarshal not required
UINT16
TPMS_TIME_ATTEST_INFO_Marshal(TPMS_TIME_ATTEST_INFO *source, BYTE **buffer, INT32 *size);


// Table 2:112 - Definition of TPMS_CERTIFY_INFO Structure (StructureTable)
// TPMS_CERTIFY_INFO_Unmarshal not required
UINT16
TPMS_CERTIFY_INFO_Marshal(TPMS_CERTIFY_INFO *source, BYTE **buffer, INT32 *size);


// Table 2:113 - Definition of TPMS_QUOTE_INFO Structure (StructureTable)
// TPMS_QUOTE_INFO_Unmarshal not required
UINT16
TPMS_QUOTE_INFO_Marshal(TPMS_QUOTE_INFO *source, BYTE **buffer, INT32 *size);


// Table 2:114 - Definition of TPMS_COMMAND_AUDIT_INFO Structure (StructureTable)
// TPMS_COMMAND_AUDIT_INFO_Unmarshal not required
UINT16
TPMS_COMMAND_AUDIT_INFO_Marshal(TPMS_COMMAND_AUDIT_INFO *source, BYTE **buffer, INT32 *size);


// Table 2:115 - Definition of TPMS_SESSION_AUDIT_INFO Structure (StructureTable)
// TPMS_SESSION_AUDIT_INFO_Unmarshal not required
UINT16
TPMS_SESSION_AUDIT_INFO_Marshal(TPMS_SESSION_AUDIT_INFO *source, BYTE **buffer, INT32 *size);


// Table 2:116 - Definition of TPMS_CREATION_INFO Structure (StructureTable)
// TPMS_CREATION_INFO_Unmarshal not required
UINT16
TPMS_CREATION_INFO_Marshal(TPMS_CREATION_INFO *source, BYTE **buffer, INT32 *size);


// Table 2:117 - Definition of TPMS_NV_CERTIFY_INFO Structure (StructureTable)
// TPMS_NV_CERTIFY_INFO_Unmarshal not required
UINT16
TPMS_NV_CERTIFY_INFO_Marshal(TPMS_NV_CERTIFY_INFO *source, BYTE **buffer, INT32 *size);


// Table 2:118 - Definition of (TPM_ST) TPMI_ST_ATTEST Type (InterfaceTable)
#define TPMI_ST_ATTEST_Marshal(source, buffer, size) \
 TPM_ST_Marshal((TPM_ST *)(source), buffer, size)


// Table 2:119 - Definition of TPMU_ATTEST Union (UnionTable)
// TPMU_ATTEST_Unmarshal not required
UINT16
TPMU_ATTEST_Marshal(TPMU_ATTEST *source, BYTE **buffer, INT32 *size, UINT32 selector);


// Table 2:120 - Definition of TPMS_ATTEST Structure (StructureTable)
// TPMS_ATTEST_Unmarshal not required
UINT16
TPMS_ATTEST_Marshal(TPMS_ATTEST *source, BYTE **buffer, INT32 *size);


// Table 2:121 - Definition of TPM2B_ATTEST Structure (StructureTable)
// TPM2B_ATTEST_Unmarshal not required
UINT16
TPM2B_ATTEST_Marshal(TPM2B_ATTEST *source, BYTE **buffer, INT32 *size);


// Table 2:122 - Definition of TPMS_AUTH_COMMAND Structure (StructureTable)
TPM_RC
TPMS_AUTH_COMMAND_Unmarshal(TPMS_AUTH_COMMAND *target, BYTE **buffer, INT32 *size);
// TPMS_AUTH_COMMAND_Marshal not required

// Table 2:123 - Definition of TPMS_AUTH_RESPONSE Structure (StructureTable)
// TPMS_AUTH_RESPONSE_Unmarshal not required
UINT16
TPMS_AUTH_RESPONSE_Marshal(TPMS_AUTH_RESPONSE *source, BYTE **buffer, INT32 *size);


// Table 2:124 - Definition of {!ALG.S} (TPM_KEY_BITS) TPMI_!ALG.S_KEY_BITS Type (InterfaceTable)
// Table 2:124 - Definition of TPMI_AES_KEY_BITS Type (InterfaceTable)
#ifdef TPM_ALG_AES
TPM_RC
TPMI_AES_KEY_BITS_Unmarshal(TPMI_AES_KEY_BITS *target, BYTE **buffer, INT32 *size);
#define TPMI_AES_KEY_BITS_Marshal(source, buffer, size) \
 TPM_KEY_BITS_Marshal((TPM_KEY_BITS *)(source), buffer, size)

#endif // TPM_ALG_AES

// Table 2:124 - Definition of TPMI_SM4_KEY_BITS Type (InterfaceTable)
#ifdef TPM_ALG_SM4
TPM_RC
TPMI_SM4_KEY_BITS_Unmarshal(TPMI_SM4_KEY_BITS *target, BYTE **buffer, INT32 *size);
#define TPMI_SM4_KEY_BITS_Marshal(source, buffer, size) \
 TPM_KEY_BITS_Marshal((TPM_KEY_BITS *)(source), buffer, size)

#endif // TPM_ALG_SM4

// Table 2:124 - Definition of TPMI_CAMELLIA_KEY_BITS Type (InterfaceTable)
#ifdef TPM_ALG_CAMELLIA
TPM_RC
TPMI_CAMELLIA_KEY_BITS_Unmarshal(TPMI_CAMELLIA_KEY_BITS *target, BYTE **buffer, INT32 *size);
#define TPMI_CAMELLIA_KEY_BITS_Marshal(source, buffer, size) \
 TPM_KEY_BITS_Marshal((TPM_KEY_BITS *)(source), buffer, size)

#endif // TPM_ALG_CAMELLIA


// Table 2:125 - Definition of TPMU_SYM_KEY_BITS Union (UnionTable)
TPM_RC
TPMU_SYM_KEY_BITS_Unmarshal(TPMU_SYM_KEY_BITS *target, BYTE **buffer, INT32 *size, UINT32 selector);
UINT16
TPMU_SYM_KEY_BITS_Marshal(TPMU_SYM_KEY_BITS *source, BYTE **buffer, INT32 *size, UINT32 selector);


// Table 2:126 - Definition of TPMU_SYM_MODE Union (UnionTable)
TPM_RC
TPMU_SYM_MODE_Unmarshal(TPMU_SYM_MODE *target, BYTE **buffer, INT32 *size, UINT32 selector);
UINT16
TPMU_SYM_MODE_Marshal(TPMU_SYM_MODE *source, BYTE **buffer, INT32 *size, UINT32 selector);


// Table 2:128 - Definition of TPMT_SYM_DEF Structure (StructureTable)
TPM_RC
TPMT_SYM_DEF_Unmarshal(TPMT_SYM_DEF *target, BYTE **buffer, INT32 *size, BOOL allowNull);
UINT16
TPMT_SYM_DEF_Marshal(TPMT_SYM_DEF *source, BYTE **buffer, INT32 *size);


// Table 2:129 - Definition of TPMT_SYM_DEF_OBJECT Structure (StructureTable)
TPM_RC
TPMT_SYM_DEF_OBJECT_Unmarshal(TPMT_SYM_DEF_OBJECT *target, BYTE **buffer, INT32 *size, BOOL allowNull);
UINT16
TPMT_SYM_DEF_OBJECT_Marshal(TPMT_SYM_DEF_OBJECT *source, BYTE **buffer, INT32 *size);


// Table 2:130 - Definition of TPM2B_SYM_KEY Structure (StructureTable)
TPM_RC
TPM2B_SYM_KEY_Unmarshal(TPM2B_SYM_KEY *target, BYTE **buffer, INT32 *size);
UINT16
TPM2B_SYM_KEY_Marshal(TPM2B_SYM_KEY *source, BYTE **buffer, INT32 *size);


// Table 2:131 - Definition of TPMS_SYMCIPHER_PARMS Structure (StructureTable)
#define TPMS_SYMCIPHER_PARMS_Unmarshal(target, buffer, size) \
 TPMT_SYM_DEF_OBJECT_Unmarshal((TPMT_SYM_DEF_OBJECT *)&((target)->sym), buffer, size, 0)
#define TPMS_SYMCIPHER_PARMS_Marshal(source, buffer, size) \
 TPMT_SYM_DEF_OBJECT_Marshal((TPMT_SYM_DEF_OBJECT *)&((source)->sym), buffer, size)


// Table 2:132 - Definition of TPM2B_SENSITIVE_DATA Structure (StructureTable)
TPM_RC
TPM2B_SENSITIVE_DATA_Unmarshal(TPM2B_SENSITIVE_DATA *target, BYTE **buffer, INT32 *size);
UINT16
TPM2B_SENSITIVE_DATA_Marshal(TPM2B_SENSITIVE_DATA *source, BYTE **buffer, INT32 *size);


// Table 2:133 - Definition of TPMS_SENSITIVE_CREATE Structure (StructureTable)
TPM_RC
TPMS_SENSITIVE_CREATE_Unmarshal(TPMS_SENSITIVE_CREATE *target, BYTE **buffer, INT32 *size);
// TPMS_SENSITIVE_CREATE_Marshal not required

// Table 2:134 - Definition of TPM2B_SENSITIVE_CREATE Structure (StructureTable)
TPM_RC
TPM2B_SENSITIVE_CREATE_Unmarshal(TPM2B_SENSITIVE_CREATE *target, BYTE **buffer, INT32 *size);
// TPM2B_SENSITIVE_CREATE_Marshal not required

// Table 2:135 - Definition of TPMS_SCHEME_HASH Structure (StructureTable)
#define TPMS_SCHEME_HASH_Unmarshal(target, buffer, size) \
 TPMI_ALG_HASH_Unmarshal((TPMI_ALG_HASH *)&((target)->hashAlg), buffer, size, 0)
#define TPMS_SCHEME_HASH_Marshal(source, buffer, size) \
 TPMI_ALG_HASH_Marshal((TPMI_ALG_HASH *)&((source)->hashAlg), buffer, size)


// Table 2:136 - Definition of {ECC} TPMS_SCHEME_ECDAA Structure (StructureTable)
#ifdef TPM_ALG_ECC
TPM_RC
TPMS_SCHEME_ECDAA_Unmarshal(TPMS_SCHEME_ECDAA *target, BYTE **buffer, INT32 *size);
UINT16
TPMS_SCHEME_ECDAA_Marshal(TPMS_SCHEME_ECDAA *source, BYTE **buffer, INT32 *size);

#endif // TPM_ALG_ECC


// Table 2:137 - Definition of (TPM_ALG_ID) TPMI_ALG_KEYEDHASH_SCHEME Type (InterfaceTable)
TPM_RC
TPMI_ALG_KEYEDHASH_SCHEME_Unmarshal(TPMI_ALG_KEYEDHASH_SCHEME *target, BYTE **buffer, INT32 *size, BOOL allowNull);
#define TPMI_ALG_KEYEDHASH_SCHEME_Marshal(source, buffer, size) \
 TPM_ALG_ID_Marshal((TPM_ALG_ID *)(source), buffer, size)


// Table 2:138 - Definition of Types for HMAC_SIG_SCHEME (TypedefTable)
#define TPMS_SCHEME_HMAC_Unmarshal(target, buffer, size) \
 TPMS_SCHEME_HASH_Unmarshal((TPMS_SCHEME_HASH *)(target), buffer, size)
#define TPMS_SCHEME_HMAC_Marshal(source, buffer, size) \
 TPMS_SCHEME_HASH_Marshal((TPMS_SCHEME_HASH *)(source), buffer, size)



// Table 2:139 - Definition of TPMS_SCHEME_XOR Structure (StructureTable)
TPM_RC
TPMS_SCHEME_XOR_Unmarshal(TPMS_SCHEME_XOR *target, BYTE **buffer, INT32 *size, BOOL allowNull);
UINT16
TPMS_SCHEME_XOR_Marshal(TPMS_SCHEME_XOR *source, BYTE **buffer, INT32 *size);


// Table 2:140 - Definition of TPMU_SCHEME_KEYEDHASH Union (UnionTable)
TPM_RC
TPMU_SCHEME_KEYEDHASH_Unmarshal(TPMU_SCHEME_KEYEDHASH *target, BYTE **buffer, INT32 *size, UINT32 selector);
UINT16
TPMU_SCHEME_KEYEDHASH_Marshal(TPMU_SCHEME_KEYEDHASH *source, BYTE **buffer, INT32 *size, UINT32 selector);


// Table 2:141 - Definition of TPMT_KEYEDHASH_SCHEME Structure (StructureTable)
TPM_RC
TPMT_KEYEDHASH_SCHEME_Unmarshal(TPMT_KEYEDHASH_SCHEME *target, BYTE **buffer, INT32 *size, BOOL allowNull);
UINT16
TPMT_KEYEDHASH_SCHEME_Marshal(TPMT_KEYEDHASH_SCHEME *source, BYTE **buffer, INT32 *size);


// Table 2:142 - Definition of {RSA} Types for RSA Signature Schemes (TypedefTable)
#ifdef TPM_ALG_RSA
#define TPMS_SIG_SCHEME_RSASSA_Unmarshal(target, buffer, size) \
 TPMS_SCHEME_HASH_Unmarshal((TPMS_SCHEME_HASH *)(target), buffer, size)
#define TPMS_SIG_SCHEME_RSASSA_Marshal(source, buffer, size) \
 TPMS_SCHEME_HASH_Marshal((TPMS_SCHEME_HASH *)(source), buffer, size)

#endif // TPM_ALG_RSA


#ifdef TPM_ALG_RSA
#define TPMS_SIG_SCHEME_RSAPSS_Unmarshal(target, buffer, size) \
 TPMS_SCHEME_HASH_Unmarshal((TPMS_SCHEME_HASH *)(target), buffer, size)
#define TPMS_SIG_SCHEME_RSAPSS_Marshal(source, buffer, size) \
 TPMS_SCHEME_HASH_Marshal((TPMS_SCHEME_HASH *)(source), buffer, size)

#endif // TPM_ALG_RSA



// Table 2:143 - Definition of {ECC} Types for ECC Signature Schemes (TypedefTable)
#ifdef TPM_ALG_ECC
#define TPMS_SIG_SCHEME_ECDSA_Unmarshal(target, buffer, size) \
 TPMS_SCHEME_HASH_Unmarshal((TPMS_SCHEME_HASH *)(target), buffer, size)
#define TPMS_SIG_SCHEME_ECDSA_Marshal(source, buffer, size) \
 TPMS_SCHEME_HASH_Marshal((TPMS_SCHEME_HASH *)(source), buffer, size)

#endif // TPM_ALG_ECC


#ifdef TPM_ALG_ECC
#define TPMS_SIG_SCHEME_SM2_Unmarshal(target, buffer, size) \
 TPMS_SCHEME_HASH_Unmarshal((TPMS_SCHEME_HASH *)(target), buffer, size)
#define TPMS_SIG_SCHEME_SM2_Marshal(source, buffer, size) \
 TPMS_SCHEME_HASH_Marshal((TPMS_SCHEME_HASH *)(source), buffer, size)

#endif // TPM_ALG_ECC


#ifdef TPM_ALG_ECC
#define TPMS_SIG_SCHEME_ECSCHNORR_Unmarshal(target, buffer, size) \
 TPMS_SCHEME_HASH_Unmarshal((TPMS_SCHEME_HASH *)(target), buffer, size)
#define TPMS_SIG_SCHEME_ECSCHNORR_Marshal(source, buffer, size) \
 TPMS_SCHEME_HASH_Marshal((TPMS_SCHEME_HASH *)(source), buffer, size)

#endif // TPM_ALG_ECC


#ifdef TPM_ALG_ECC
#define TPMS_SIG_SCHEME_ECDAA_Unmarshal(target, buffer, size) \
 TPMS_SCHEME_ECDAA_Unmarshal((TPMS_SCHEME_ECDAA *)(target), buffer, size)
#define TPMS_SIG_SCHEME_ECDAA_Marshal(source, buffer, size) \
 TPMS_SCHEME_ECDAA_Marshal((TPMS_SCHEME_ECDAA *)(source), buffer, size)

#endif // TPM_ALG_ECC



// Table 2:144 - Definition of TPMU_SIG_SCHEME Union (UnionTable)
TPM_RC
TPMU_SIG_SCHEME_Unmarshal(TPMU_SIG_SCHEME *target, BYTE **buffer, INT32 *size, UINT32 selector);
UINT16
TPMU_SIG_SCHEME_Marshal(TPMU_SIG_SCHEME *source, BYTE **buffer, INT32 *size, UINT32 selector);


// Table 2:145 - Definition of TPMT_SIG_SCHEME Structure (StructureTable)
TPM_RC
TPMT_SIG_SCHEME_Unmarshal(TPMT_SIG_SCHEME *target, BYTE **buffer, INT32 *size, BOOL allowNull);
UINT16
TPMT_SIG_SCHEME_Marshal(TPMT_SIG_SCHEME *source, BYTE **buffer, INT32 *size);


// Table 2:146 - Definition of Types for {RSA} Encryption Schemes (TypedefTable)
#ifdef TPM_ALG_RSA
#define TPMS_ENC_SCHEME_OAEP_Unmarshal(target, buffer, size) \
 TPMS_SCHEME_HASH_Unmarshal((TPMS_SCHEME_HASH *)(target), buffer, size)
#define TPMS_ENC_SCHEME_OAEP_Marshal(source, buffer, size) \
 TPMS_SCHEME_HASH_Marshal((TPMS_SCHEME_HASH *)(source), buffer, size)

#endif // TPM_ALG_RSA


#ifdef TPM_ALG_RSA
#define TPMS_ENC_SCHEME_RSAES_Unmarshal(target, buffer, size) \
 TPMS_EMPTY_Unmarshal((TPMS_EMPTY *)(target), buffer, size)
#define TPMS_ENC_SCHEME_RSAES_Marshal(source, buffer, size) \
 TPMS_EMPTY_Marshal((TPMS_EMPTY *)(source), buffer, size)

#endif // TPM_ALG_RSA



// Table 2:147 - Definition of Types for {ECC} ECC Key Exchange (TypedefTable)
#ifdef TPM_ALG_ECC
#define TPMS_KEY_SCHEME_ECDH_Unmarshal(target, buffer, size) \
 TPMS_SCHEME_HASH_Unmarshal((TPMS_SCHEME_HASH *)(target), buffer, size)
#define TPMS_KEY_SCHEME_ECDH_Marshal(source, buffer, size) \
 TPMS_SCHEME_HASH_Marshal((TPMS_SCHEME_HASH *)(source), buffer, size)

#endif // TPM_ALG_ECC


#ifdef TPM_ALG_ECC
#define TPMS_KEY_SCHEME_ECMQV_Unmarshal(target, buffer, size) \
 TPMS_SCHEME_HASH_Unmarshal((TPMS_SCHEME_HASH *)(target), buffer, size)
#define TPMS_KEY_SCHEME_ECMQV_Marshal(source, buffer, size) \
 TPMS_SCHEME_HASH_Marshal((TPMS_SCHEME_HASH *)(source), buffer, size)

#endif // TPM_ALG_ECC



// Table 2:148 - Definition of Types for KDF Schemes (TypedefTable)
#define TPMS_SCHEME_MGF1_Unmarshal(target, buffer, size) \
 TPMS_SCHEME_HASH_Unmarshal((TPMS_SCHEME_HASH *)(target), buffer, size)
#define TPMS_SCHEME_MGF1_Marshal(source, buffer, size) \
 TPMS_SCHEME_HASH_Marshal((TPMS_SCHEME_HASH *)(source), buffer, size)


#define TPMS_SCHEME_KDF1_SP800_56A_Unmarshal(target, buffer, size) \
 TPMS_SCHEME_HASH_Unmarshal((TPMS_SCHEME_HASH *)(target), buffer, size)
#define TPMS_SCHEME_KDF1_SP800_56A_Marshal(source, buffer, size) \
 TPMS_SCHEME_HASH_Marshal((TPMS_SCHEME_HASH *)(source), buffer, size)


#define TPMS_SCHEME_KDF2_Unmarshal(target, buffer, size) \
 TPMS_SCHEME_HASH_Unmarshal((TPMS_SCHEME_HASH *)(target), buffer, size)
#define TPMS_SCHEME_KDF2_Marshal(source, buffer, size) \
 TPMS_SCHEME_HASH_Marshal((TPMS_SCHEME_HASH *)(source), buffer, size)


#define TPMS_SCHEME_KDF1_SP800_108_Unmarshal(target, buffer, size) \
 TPMS_SCHEME_HASH_Unmarshal((TPMS_SCHEME_HASH *)(target), buffer, size)
#define TPMS_SCHEME_KDF1_SP800_108_Marshal(source, buffer, size) \
 TPMS_SCHEME_HASH_Marshal((TPMS_SCHEME_HASH *)(source), buffer, size)



// Table 2:149 - Definition of TPMU_KDF_SCHEME Union (UnionTable)
TPM_RC
TPMU_KDF_SCHEME_Unmarshal(TPMU_KDF_SCHEME *target, BYTE **buffer, INT32 *size, UINT32 selector);
UINT16
TPMU_KDF_SCHEME_Marshal(TPMU_KDF_SCHEME *source, BYTE **buffer, INT32 *size, UINT32 selector);


// Table 2:150 - Definition of TPMT_KDF_SCHEME Structure (StructureTable)
TPM_RC
TPMT_KDF_SCHEME_Unmarshal(TPMT_KDF_SCHEME *target, BYTE **buffer, INT32 *size, BOOL allowNull);
UINT16
TPMT_KDF_SCHEME_Marshal(TPMT_KDF_SCHEME *source, BYTE **buffer, INT32 *size);


// Table 2:151 - Definition of (TPM_ALG_ID) TPMI_ALG_ASYM_SCHEME Type (InterfaceTable)

// Table 2:152 - Definition of TPMU_ASYM_SCHEME Union (UnionTable)
TPM_RC
TPMU_ASYM_SCHEME_Unmarshal(TPMU_ASYM_SCHEME *target, BYTE **buffer, INT32 *size, UINT32 selector);
UINT16
TPMU_ASYM_SCHEME_Marshal(TPMU_ASYM_SCHEME *source, BYTE **buffer, INT32 *size, UINT32 selector);


// Table 2:153 - Definition of TPMT_ASYM_SCHEME Structure (StructureTable)
// TPMT_ASYM_SCHEME_Unmarshal not required
// TPMT_ASYM_SCHEME_Marshal not required

// Table 2:154 - Definition of (TPM_ALG_ID) {RSA} TPMI_ALG_RSA_SCHEME Type (InterfaceTable)
#ifdef TPM_ALG_RSA
TPM_RC
TPMI_ALG_RSA_SCHEME_Unmarshal(TPMI_ALG_RSA_SCHEME *target, BYTE **buffer, INT32 *size, BOOL allowNull);
#define TPMI_ALG_RSA_SCHEME_Marshal(source, buffer, size) \
 TPM_ALG_ID_Marshal((TPM_ALG_ID *)(source), buffer, size)

#endif // TPM_ALG_RSA


// Table 2:155 - Definition of {RSA} TPMT_RSA_SCHEME Structure (StructureTable)
#ifdef TPM_ALG_RSA
TPM_RC
TPMT_RSA_SCHEME_Unmarshal(TPMT_RSA_SCHEME *target, BYTE **buffer, INT32 *size, BOOL allowNull);
UINT16
TPMT_RSA_SCHEME_Marshal(TPMT_RSA_SCHEME *source, BYTE **buffer, INT32 *size);

#endif // TPM_ALG_RSA


// Table 2:156 - Definition of (TPM_ALG_ID) {RSA} TPMI_ALG_RSA_DECRYPT Type (InterfaceTable)
#ifdef TPM_ALG_RSA
TPM_RC
TPMI_ALG_RSA_DECRYPT_Unmarshal(TPMI_ALG_RSA_DECRYPT *target, BYTE **buffer, INT32 *size, BOOL allowNull);
#define TPMI_ALG_RSA_DECRYPT_Marshal(source, buffer, size) \
 TPM_ALG_ID_Marshal((TPM_ALG_ID *)(source), buffer, size)

#endif // TPM_ALG_RSA


// Table 2:157 - Definition of {RSA} TPMT_RSA_DECRYPT Structure (StructureTable)
#ifdef TPM_ALG_RSA
TPM_RC
TPMT_RSA_DECRYPT_Unmarshal(TPMT_RSA_DECRYPT *target, BYTE **buffer, INT32 *size, BOOL allowNull);
UINT16
TPMT_RSA_DECRYPT_Marshal(TPMT_RSA_DECRYPT *source, BYTE **buffer, INT32 *size);

#endif // TPM_ALG_RSA


// Table 2:158 - Definition of {RSA} TPM2B_PUBLIC_KEY_RSA Structure (StructureTable)
#ifdef TPM_ALG_RSA
TPM_RC
TPM2B_PUBLIC_KEY_RSA_Unmarshal(TPM2B_PUBLIC_KEY_RSA *target, BYTE **buffer, INT32 *size);
UINT16
TPM2B_PUBLIC_KEY_RSA_Marshal(TPM2B_PUBLIC_KEY_RSA *source, BYTE **buffer, INT32 *size);

#endif // TPM_ALG_RSA


// Table 2:159 - Definition of {RSA} (TPM_KEY_BITS) TPMI_RSA_KEY_BITS Type (InterfaceTable)
#ifdef TPM_ALG_RSA
TPM_RC
TPMI_RSA_KEY_BITS_Unmarshal(TPMI_RSA_KEY_BITS *target, BYTE **buffer, INT32 *size);
#define TPMI_RSA_KEY_BITS_Marshal(source, buffer, size) \
 TPM_KEY_BITS_Marshal((TPM_KEY_BITS *)(source), buffer, size)

#endif // TPM_ALG_RSA


// Table 2:160 - Definition of {RSA} TPM2B_PRIVATE_KEY_RSA Structure (StructureTable)
#ifdef TPM_ALG_RSA
TPM_RC
TPM2B_PRIVATE_KEY_RSA_Unmarshal(TPM2B_PRIVATE_KEY_RSA *target, BYTE **buffer, INT32 *size);
UINT16
TPM2B_PRIVATE_KEY_RSA_Marshal(TPM2B_PRIVATE_KEY_RSA *source, BYTE **buffer, INT32 *size);

#endif // TPM_ALG_RSA


// Table 2:161 - Definition of {ECC} TPM2B_ECC_PARAMETER Structure (StructureTable)
#ifdef TPM_ALG_ECC
TPM_RC
TPM2B_ECC_PARAMETER_Unmarshal(TPM2B_ECC_PARAMETER *target, BYTE **buffer, INT32 *size);
UINT16
TPM2B_ECC_PARAMETER_Marshal(TPM2B_ECC_PARAMETER *source, BYTE **buffer, INT32 *size);

#endif // TPM_ALG_ECC


// Table 2:162 - Definition of {ECC} TPMS_ECC_POINT Structure (StructureTable)
#ifdef TPM_ALG_ECC
TPM_RC
TPMS_ECC_POINT_Unmarshal(TPMS_ECC_POINT *target, BYTE **buffer, INT32 *size);
UINT16
TPMS_ECC_POINT_Marshal(TPMS_ECC_POINT *source, BYTE **buffer, INT32 *size);

#endif // TPM_ALG_ECC


// Table 2:163 - Definition of {ECC} TPM2B_ECC_POINT Structure (StructureTable)
#ifdef TPM_ALG_ECC
TPM_RC
TPM2B_ECC_POINT_Unmarshal(TPM2B_ECC_POINT *target, BYTE **buffer, INT32 *size);
UINT16
TPM2B_ECC_POINT_Marshal(TPM2B_ECC_POINT *source, BYTE **buffer, INT32 *size);

#endif // TPM_ALG_ECC


// Table 2:164 - Definition of (TPM_ALG_ID) {ECC} TPMI_ALG_ECC_SCHEME Type (InterfaceTable)
#ifdef TPM_ALG_ECC
TPM_RC
TPMI_ALG_ECC_SCHEME_Unmarshal(TPMI_ALG_ECC_SCHEME *target, BYTE **buffer, INT32 *size, BOOL allowNull);
#define TPMI_ALG_ECC_SCHEME_Marshal(source, buffer, size) \
 TPM_ALG_ID_Marshal((TPM_ALG_ID *)(source), buffer, size)

#endif // TPM_ALG_ECC


// Table 2:165 - Definition of {ECC} (TPM_ECC_CURVE) TPMI_ECC_CURVE Type (InterfaceTable)
#ifdef TPM_ALG_ECC
TPM_RC
TPMI_ECC_CURVE_Unmarshal(TPMI_ECC_CURVE *target, BYTE **buffer, INT32 *size);
#define TPMI_ECC_CURVE_Marshal(source, buffer, size) \
 TPM_ECC_CURVE_Marshal((TPM_ECC_CURVE *)(source), buffer, size)

#endif // TPM_ALG_ECC


// Table 2:166 - Definition of (TPMT_SIG_SCHEME) {ECC} TPMT_ECC_SCHEME Structure (StructureTable)
#ifdef TPM_ALG_ECC
TPM_RC
TPMT_ECC_SCHEME_Unmarshal(TPMT_ECC_SCHEME *target, BYTE **buffer, INT32 *size, BOOL allowNull);
UINT16
TPMT_ECC_SCHEME_Marshal(TPMT_ECC_SCHEME *source, BYTE **buffer, INT32 *size);

#endif // TPM_ALG_ECC


// Table 2:167 - Definition of {ECC} TPMS_ALGORITHM_DETAIL_ECC Structure (StructureTable)
#ifdef TPM_ALG_ECC
// TPMS_ALGORITHM_DETAIL_ECC_Unmarshal not required
UINT16
TPMS_ALGORITHM_DETAIL_ECC_Marshal(TPMS_ALGORITHM_DETAIL_ECC *source, BYTE **buffer, INT32 *size);

#endif // TPM_ALG_ECC


// Table 2:168 - Definition of {RSA} TPMS_SIGNATURE_RSA Structure (StructureTable)
#ifdef TPM_ALG_RSA
TPM_RC
TPMS_SIGNATURE_RSA_Unmarshal(TPMS_SIGNATURE_RSA *target, BYTE **buffer, INT32 *size);
UINT16
TPMS_SIGNATURE_RSA_Marshal(TPMS_SIGNATURE_RSA *source, BYTE **buffer, INT32 *size);

#endif // TPM_ALG_RSA


// Table 2:169 - Definition of Types for {RSA} Signature (TypedefTable)
#ifdef TPM_ALG_RSA
#define TPMS_SIGNATURE_RSASSA_Unmarshal(target, buffer, size) \
 TPMS_SIGNATURE_RSA_Unmarshal((TPMS_SIGNATURE_RSA *)(target), buffer, size)
#define TPMS_SIGNATURE_RSASSA_Marshal(source, buffer, size) \
 TPMS_SIGNATURE_RSA_Marshal((TPMS_SIGNATURE_RSA *)(source), buffer, size)

#endif // TPM_ALG_RSA


#ifdef TPM_ALG_RSA
#define TPMS_SIGNATURE_RSAPSS_Unmarshal(target, buffer, size) \
 TPMS_SIGNATURE_RSA_Unmarshal((TPMS_SIGNATURE_RSA *)(target), buffer, size)
#define TPMS_SIGNATURE_RSAPSS_Marshal(source, buffer, size) \
 TPMS_SIGNATURE_RSA_Marshal((TPMS_SIGNATURE_RSA *)(source), buffer, size)

#endif // TPM_ALG_RSA



// Table 2:170 - Definition of {ECC} TPMS_SIGNATURE_ECC Structure (StructureTable)
#ifdef TPM_ALG_ECC
TPM_RC
TPMS_SIGNATURE_ECC_Unmarshal(TPMS_SIGNATURE_ECC *target, BYTE **buffer, INT32 *size);
UINT16
TPMS_SIGNATURE_ECC_Marshal(TPMS_SIGNATURE_ECC *source, BYTE **buffer, INT32 *size);

#endif // TPM_ALG_ECC


// Table 2:171 - Definition of Types for {ECC} TPMS_SIGNATUE_ECC (TypedefTable)
#ifdef TPM_ALG_ECC
#define TPMS_SIGNATURE_ECDSA_Unmarshal(target, buffer, size) \
 TPMS_SIGNATURE_ECC_Unmarshal((TPMS_SIGNATURE_ECC *)(target), buffer, size)
#define TPMS_SIGNATURE_ECDSA_Marshal(source, buffer, size) \
 TPMS_SIGNATURE_ECC_Marshal((TPMS_SIGNATURE_ECC *)(source), buffer, size)

#endif // TPM_ALG_ECC


#ifdef TPM_ALG_ECC
#define TPMS_SIGNATURE_SM2_Unmarshal(target, buffer, size) \
 TPMS_SIGNATURE_ECC_Unmarshal((TPMS_SIGNATURE_ECC *)(target), buffer, size)
#define TPMS_SIGNATURE_SM2_Marshal(source, buffer, size) \
 TPMS_SIGNATURE_ECC_Marshal((TPMS_SIGNATURE_ECC *)(source), buffer, size)

#endif // TPM_ALG_ECC


#ifdef TPM_ALG_ECC
#define TPMS_SIGNATURE_ECSCHNORR_Unmarshal(target, buffer, size) \
 TPMS_SIGNATURE_ECC_Unmarshal((TPMS_SIGNATURE_ECC *)(target), buffer, size)
#define TPMS_SIGNATURE_ECSCHNORR_Marshal(source, buffer, size) \
 TPMS_SIGNATURE_ECC_Marshal((TPMS_SIGNATURE_ECC *)(source), buffer, size)

#endif // TPM_ALG_ECC


#ifdef TPM_ALG_ECC
#define TPMS_SIGNATURE_ECDAA_Unmarshal(target, buffer, size) \
 TPMS_SIGNATURE_ECC_Unmarshal((TPMS_SIGNATURE_ECC *)(target), buffer, size)
#define TPMS_SIGNATURE_ECDAA_Marshal(source, buffer, size) \
 TPMS_SIGNATURE_ECC_Marshal((TPMS_SIGNATURE_ECC *)(source), buffer, size)

#endif // TPM_ALG_ECC



// Table 2:172 - Definition of TPMU_SIGNATURE Union (UnionTable)
TPM_RC
TPMU_SIGNATURE_Unmarshal(TPMU_SIGNATURE *target, BYTE **buffer, INT32 *size, UINT32 selector);
UINT16
TPMU_SIGNATURE_Marshal(TPMU_SIGNATURE *source, BYTE **buffer, INT32 *size, UINT32 selector);


// Table 2:173 - Definition of TPMT_SIGNATURE Structure (StructureTable)
TPM_RC
TPMT_SIGNATURE_Unmarshal(TPMT_SIGNATURE *target, BYTE **buffer, INT32 *size, BOOL allowNull);
UINT16
TPMT_SIGNATURE_Marshal(TPMT_SIGNATURE *source, BYTE **buffer, INT32 *size);


// Table 2:174 - Definition of TPMU_ENCRYPTED_SECRET Union (UnionTable)
// TPMU_ENCRYPTED_SECRET_Unmarshal not required
// TPMU_ENCRYPTED_SECRET_Marshal not required

// Table 2:175 - Definition of TPM2B_ENCRYPTED_SECRET Structure (StructureTable)
TPM_RC
TPM2B_ENCRYPTED_SECRET_Unmarshal(TPM2B_ENCRYPTED_SECRET *target, BYTE **buffer, INT32 *size);
UINT16
TPM2B_ENCRYPTED_SECRET_Marshal(TPM2B_ENCRYPTED_SECRET *source, BYTE **buffer, INT32 *size);


// Table 2:176 - Definition of (TPM_ALG_ID) TPMI_ALG_PUBLIC Type (InterfaceTable)
TPM_RC
TPMI_ALG_PUBLIC_Unmarshal(TPMI_ALG_PUBLIC *target, BYTE **buffer, INT32 *size);
#define TPMI_ALG_PUBLIC_Marshal(source, buffer, size) \
 TPM_ALG_ID_Marshal((TPM_ALG_ID *)(source), buffer, size)


// Table 2:177 - Definition of TPMU_PUBLIC_ID Union (UnionTable)
TPM_RC
TPMU_PUBLIC_ID_Unmarshal(TPMU_PUBLIC_ID *target, BYTE **buffer, INT32 *size, UINT32 selector);
UINT16
TPMU_PUBLIC_ID_Marshal(TPMU_PUBLIC_ID *source, BYTE **buffer, INT32 *size, UINT32 selector);


// Table 2:178 - Definition of TPMS_KEYEDHASH_PARMS Structure (StructureTable)
#define TPMS_KEYEDHASH_PARMS_Unmarshal(target, buffer, size) \
 TPMT_KEYEDHASH_SCHEME_Unmarshal((TPMT_KEYEDHASH_SCHEME *)&((target)->scheme), buffer, size, 1)
#define TPMS_KEYEDHASH_PARMS_Marshal(source, buffer, size) \
 TPMT_KEYEDHASH_SCHEME_Marshal((TPMT_KEYEDHASH_SCHEME *)&((source)->scheme), buffer, size)


// Table 2:179 - Definition of TPMS_ASYM_PARMS Structure (StructureTable)
// TPMS_ASYM_PARMS_Unmarshal not required
// TPMS_ASYM_PARMS_Marshal not required

// Table 2:180 - Definition of {RSA} TPMS_RSA_PARMS Structure (StructureTable)
#ifdef TPM_ALG_RSA
TPM_RC
TPMS_RSA_PARMS_Unmarshal(TPMS_RSA_PARMS *target, BYTE **buffer, INT32 *size);
UINT16
TPMS_RSA_PARMS_Marshal(TPMS_RSA_PARMS *source, BYTE **buffer, INT32 *size);

#endif // TPM_ALG_RSA


// Table 2:181 - Definition of {ECC} TPMS_ECC_PARMS Structure (StructureTable)
#ifdef TPM_ALG_ECC
TPM_RC
TPMS_ECC_PARMS_Unmarshal(TPMS_ECC_PARMS *target, BYTE **buffer, INT32 *size);
UINT16
TPMS_ECC_PARMS_Marshal(TPMS_ECC_PARMS *source, BYTE **buffer, INT32 *size);

#endif // TPM_ALG_ECC


// Table 2:182 - Definition of TPMU_PUBLIC_PARMS Union (UnionTable)
TPM_RC
TPMU_PUBLIC_PARMS_Unmarshal(TPMU_PUBLIC_PARMS *target, BYTE **buffer, INT32 *size, UINT32 selector);
UINT16
TPMU_PUBLIC_PARMS_Marshal(TPMU_PUBLIC_PARMS *source, BYTE **buffer, INT32 *size, UINT32 selector);


// Table 2:183 - Definition of TPMT_PUBLIC_PARMS Structure (StructureTable)
TPM_RC
TPMT_PUBLIC_PARMS_Unmarshal(TPMT_PUBLIC_PARMS *target, BYTE **buffer, INT32 *size);
UINT16
TPMT_PUBLIC_PARMS_Marshal(TPMT_PUBLIC_PARMS *source, BYTE **buffer, INT32 *size);


// Table 2:184 - Definition of TPMT_PUBLIC Structure (StructureTable)
TPM_RC
TPMT_PUBLIC_Unmarshal(TPMT_PUBLIC *target, BYTE **buffer, INT32 *size, BOOL allowNull);
UINT16
TPMT_PUBLIC_Marshal(TPMT_PUBLIC *source, BYTE **buffer, INT32 *size);


// Table 2:185 - Definition of TPM2B_PUBLIC Structure (StructureTable)
TPM_RC
TPM2B_PUBLIC_Unmarshal(TPM2B_PUBLIC *target, BYTE **buffer, INT32 *size, BOOL allowNull);
UINT16
TPM2B_PUBLIC_Marshal(TPM2B_PUBLIC *source, BYTE **buffer, INT32 *size);


// Table 2:186 - Definition of TPM2B_PRIVATE_VENDOR_SPECIFIC Structure (StructureTable)
// TPM2B_PRIVATE_VENDOR_SPECIFIC_Unmarshal not required
// TPM2B_PRIVATE_VENDOR_SPECIFIC_Marshal not required

// Table 2:187 - Definition of TPMU_SENSITIVE_COMPOSITE Union (UnionTable)
TPM_RC
TPMU_SENSITIVE_COMPOSITE_Unmarshal(TPMU_SENSITIVE_COMPOSITE *target, BYTE **buffer, INT32 *size, UINT32 selector);
UINT16
TPMU_SENSITIVE_COMPOSITE_Marshal(TPMU_SENSITIVE_COMPOSITE *source, BYTE **buffer, INT32 *size, UINT32 selector);


// Table 2:188 - Definition of TPMT_SENSITIVE Structure (StructureTable)
TPM_RC
TPMT_SENSITIVE_Unmarshal(TPMT_SENSITIVE *target, BYTE **buffer, INT32 *size);
UINT16
TPMT_SENSITIVE_Marshal(TPMT_SENSITIVE *source, BYTE **buffer, INT32 *size);


// Table 2:189 - Definition of TPM2B_SENSITIVE Structure (StructureTable)
TPM_RC
TPM2B_SENSITIVE_Unmarshal(TPM2B_SENSITIVE *target, BYTE **buffer, INT32 *size);
UINT16
TPM2B_SENSITIVE_Marshal(TPM2B_SENSITIVE *source, BYTE **buffer, INT32 *size);


// Table 2:190 - Definition of _PRIVATE Structure (StructureTable)
// _PRIVATE_Unmarshal not required
// _PRIVATE_Marshal not required

// Table 2:191 - Definition of TPM2B_PRIVATE Structure (StructureTable)
TPM_RC
TPM2B_PRIVATE_Unmarshal(TPM2B_PRIVATE *target, BYTE **buffer, INT32 *size);
UINT16
TPM2B_PRIVATE_Marshal(TPM2B_PRIVATE *source, BYTE **buffer, INT32 *size);


// Table 2:192 - Definition of _ID_OBJECT Structure (StructureTable)
// _ID_OBJECT_Unmarshal not required
// _ID_OBJECT_Marshal not required

// Table 2:193 - Definition of TPM2B_ID_OBJECT Structure (StructureTable)
TPM_RC
TPM2B_ID_OBJECT_Unmarshal(TPM2B_ID_OBJECT *target, BYTE **buffer, INT32 *size);
UINT16
TPM2B_ID_OBJECT_Marshal(TPM2B_ID_OBJECT *source, BYTE **buffer, INT32 *size);


// Table 2:194 - Definition of (UINT32) TPM_NV_INDEX Bits (BitsTable)
#define TPM_NV_INDEX_Unmarshal(target, buffer, size) \
 UINT32_Unmarshal((UINT32 *)(target), buffer, size)
#define TPM_NV_INDEX_Marshal(source, buffer, size) \
 UINT32_Marshal((UINT32 *)(source), buffer, size)


// Table 2:195 - Definition of (UINT32) TPMA_NV Bits (BitsTable)
TPM_RC
TPMA_NV_Unmarshal(TPMA_NV *target, BYTE **buffer, INT32 *size);
#define TPMA_NV_Marshal(source, buffer, size) \
 UINT32_Marshal((UINT32 *)(source), buffer, size)


// Table 2:196 - Definition of TPMS_NV_PUBLIC Structure (StructureTable)
TPM_RC
TPMS_NV_PUBLIC_Unmarshal(TPMS_NV_PUBLIC *target, BYTE **buffer, INT32 *size);
UINT16
TPMS_NV_PUBLIC_Marshal(TPMS_NV_PUBLIC *source, BYTE **buffer, INT32 *size);


// Table 2:197 - Definition of TPM2B_NV_PUBLIC Structure (StructureTable)
TPM_RC
TPM2B_NV_PUBLIC_Unmarshal(TPM2B_NV_PUBLIC *target, BYTE **buffer, INT32 *size);
UINT16
TPM2B_NV_PUBLIC_Marshal(TPM2B_NV_PUBLIC *source, BYTE **buffer, INT32 *size);


// Table 2:198 - Definition of TPM2B_CONTEXT_SENSITIVE Structure (StructureTable)
TPM_RC
TPM2B_CONTEXT_SENSITIVE_Unmarshal(TPM2B_CONTEXT_SENSITIVE *target, BYTE **buffer, INT32 *size);
UINT16
TPM2B_CONTEXT_SENSITIVE_Marshal(TPM2B_CONTEXT_SENSITIVE *source, BYTE **buffer, INT32 *size);


// Table 2:199 - Definition of TPMS_CONTEXT_DATA Structure (StructureTable)
TPM_RC
TPMS_CONTEXT_DATA_Unmarshal(TPMS_CONTEXT_DATA *target, BYTE **buffer, INT32 *size);
UINT16
TPMS_CONTEXT_DATA_Marshal(TPMS_CONTEXT_DATA *source, BYTE **buffer, INT32 *size);


// Table 2:200 - Definition of TPM2B_CONTEXT_DATA Structure (StructureTable)
TPM_RC
TPM2B_CONTEXT_DATA_Unmarshal(TPM2B_CONTEXT_DATA *target, BYTE **buffer, INT32 *size);
UINT16
TPM2B_CONTEXT_DATA_Marshal(TPM2B_CONTEXT_DATA *source, BYTE **buffer, INT32 *size);


// Table 2:201 - Definition of TPMS_CONTEXT Structure (StructureTable)
TPM_RC
TPMS_CONTEXT_Unmarshal(TPMS_CONTEXT *target, BYTE **buffer, INT32 *size);
UINT16
TPMS_CONTEXT_Marshal(TPMS_CONTEXT *source, BYTE **buffer, INT32 *size);


// Table 2:203 - Definition of TPMS_CREATION_DATA Structure (StructureTable)
// TPMS_CREATION_DATA_Unmarshal not required
UINT16
TPMS_CREATION_DATA_Marshal(TPMS_CREATION_DATA *source, BYTE **buffer, INT32 *size);


// Table 2:204 - Definition of TPM2B_CREATION_DATA Structure (StructureTable)
// TPM2B_CREATION_DATA_Unmarshal not required
UINT16
TPM2B_CREATION_DATA_Marshal(TPM2B_CREATION_DATA *source, BYTE **buffer, INT32 *size);

// Array Marshal/Unmarshal for TPM2B_DIGEST
TPM_RC
TPM2B_DIGEST_Array_Unmarshal(TPM2B_DIGEST *target, BYTE **buffer, INT32 *size, INT32 count);
UINT16
TPM2B_DIGEST_Array_Marshal(TPM2B_DIGEST *source, BYTE **buffer, INT32 *size, INT32 count);

// Array Marshal/Unmarshal for TPMS_TAGGED_PCR_SELECT
// TPMS_TAGGED_PCR_SELECT_Array_Unmarshal not required
UINT16
TPMS_TAGGED_PCR_SELECT_Array_Marshal(TPMS_TAGGED_PCR_SELECT *source, BYTE **buffer, INT32 *size, INT32 count);

// Array Marshal/Unmarshal for TPMS_PCR_SELECTION
TPM_RC
TPMS_PCR_SELECTION_Array_Unmarshal(TPMS_PCR_SELECTION *target, BYTE **buffer, INT32 *size, INT32 count);
UINT16
TPMS_PCR_SELECTION_Array_Marshal(TPMS_PCR_SELECTION *source, BYTE **buffer, INT32 *size, INT32 count);

// Array Marshal/Unmarshal for TPM_ALG_ID
TPM_RC
TPM_ALG_ID_Array_Unmarshal(TPM_ALG_ID *target, BYTE **buffer, INT32 *size, INT32 count);
UINT16
TPM_ALG_ID_Array_Marshal(TPM_ALG_ID *source, BYTE **buffer, INT32 *size, INT32 count);

// Array Marshal/Unmarshal for TPM_CC
TPM_RC
TPM_CC_Array_Unmarshal(TPM_CC *target, BYTE **buffer, INT32 *size, INT32 count);
UINT16
TPM_CC_Array_Marshal(TPM_CC *source, BYTE **buffer, INT32 *size, INT32 count);

// Array Marshal/Unmarshal for TPMT_HA
TPM_RC
TPMT_HA_Array_Unmarshal(TPMT_HA *target, BYTE **buffer, INT32 *size, BOOL allowNull, INT32 count);
UINT16
TPMT_HA_Array_Marshal(TPMT_HA *source, BYTE **buffer, INT32 *size, INT32 count);

// Array Marshal/Unmarshal for TPM_ECC_CURVE
#ifdef TPM_ALG_ECC
// TPM_ECC_CURVE_Array_Unmarshal not required
UINT16
TPM_ECC_CURVE_Array_Marshal(TPM_ECC_CURVE *source, BYTE **buffer, INT32 *size, INT32 count);

#endif // TPM_ALG_ECC

// Array Marshal/Unmarshal for TPMS_ALG_PROPERTY
// TPMS_ALG_PROPERTY_Array_Unmarshal not required
UINT16
TPMS_ALG_PROPERTY_Array_Marshal(TPMS_ALG_PROPERTY *source, BYTE **buffer, INT32 *size, INT32 count);

// Array Marshal/Unmarshal for TPMA_CC
// TPMA_CC_Array_Unmarshal not required
UINT16
TPMA_CC_Array_Marshal(TPMA_CC *source, BYTE **buffer, INT32 *size, INT32 count);

// Array Marshal/Unmarshal for TPMS_TAGGED_PROPERTY
// TPMS_TAGGED_PROPERTY_Array_Unmarshal not required
UINT16
TPMS_TAGGED_PROPERTY_Array_Marshal(TPMS_TAGGED_PROPERTY *source, BYTE **buffer, INT32 *size, INT32 count);

// Array Marshal/Unmarshal for BYTE
TPM_RC
BYTE_Array_Unmarshal(BYTE *target, BYTE **buffer, INT32 *size, INT32 count);
UINT16
BYTE_Array_Marshal(BYTE *source, BYTE **buffer, INT32 *size, INT32 count);

// Array Marshal/Unmarshal for TPM_HANDLE
// TPM_HANDLE_Array_Unmarshal not required
UINT16
TPM_HANDLE_Array_Marshal(TPM_HANDLE *source, BYTE **buffer, INT32 *size, INT32 count);

#endif // _MARSHAL_FP_H