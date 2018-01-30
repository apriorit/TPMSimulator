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

// 8.3.1 Introduction
// This file contains the functions used for managing and accessing the hierarchy-related values.
// 8.3.2 Includes
#include "InternalRoutines.h"
void
HierarchyPreInstall_Init(
    void
)
{
    // Allow lockout clear command
    gp.disableClear = FALSE;

    // Initialize Primary Seeds
    gp.EPSeed.t.size = PRIMARY_SEED_SIZE;
    CryptGenerateRandom(PRIMARY_SEED_SIZE, gp.EPSeed.t.buffer);
    gp.SPSeed.t.size = PRIMARY_SEED_SIZE;
    CryptGenerateRandom(PRIMARY_SEED_SIZE, gp.SPSeed.t.buffer);
    gp.PPSeed.t.size = PRIMARY_SEED_SIZE;
    CryptGenerateRandom(PRIMARY_SEED_SIZE, gp.PPSeed.t.buffer);

    // Initialize owner, endorsement and lockout auth
    gp.ownerAuth.t.size = 0;
    gp.endorsementAuth.t.size = 0;
    gp.lockoutAuth.t.size = 0;

    // Initialize owner, endorsement, and lockout policy
    gp.ownerAlg = TPM_ALG_NULL;
    gp.ownerPolicy.t.size = 0;
    gp.endorsementAlg = TPM_ALG_NULL;
    gp.endorsementPolicy.t.size = 0;
    gp.lockoutAlg = TPM_ALG_NULL;
    gp.lockoutPolicy.t.size = 0;

    // Initialize ehProof, shProof and phProof
    gp.phProof.t.size = PROOF_SIZE;
    gp.shProof.t.size = PROOF_SIZE;
    gp.ehProof.t.size = PROOF_SIZE;
    CryptGenerateRandom(gp.phProof.t.size, gp.phProof.t.buffer);
    CryptGenerateRandom(gp.shProof.t.size, gp.shProof.t.buffer);
    CryptGenerateRandom(gp.ehProof.t.size, gp.ehProof.t.buffer);

    // Write hierarchy data to NV
    NvWriteReserved(NV_DISABLE_CLEAR, &gp.disableClear);
    NvWriteReserved(NV_EP_SEED, &gp.EPSeed);
    NvWriteReserved(NV_SP_SEED, &gp.SPSeed);
    NvWriteReserved(NV_PP_SEED, &gp.PPSeed);
    NvWriteReserved(NV_OWNER_AUTH, &gp.ownerAuth);
    NvWriteReserved(NV_ENDORSEMENT_AUTH, &gp.endorsementAuth);
    NvWriteReserved(NV_LOCKOUT_AUTH, &gp.lockoutAuth);
    NvWriteReserved(NV_OWNER_ALG, &gp.ownerAlg);
    NvWriteReserved(NV_OWNER_POLICY, &gp.ownerPolicy);
    NvWriteReserved(NV_ENDORSEMENT_ALG, &gp.endorsementAlg);
    NvWriteReserved(NV_ENDORSEMENT_POLICY, &gp.endorsementPolicy);
    NvWriteReserved(NV_LOCKOUT_ALG, &gp.lockoutAlg);
    NvWriteReserved(NV_LOCKOUT_POLICY, &gp.lockoutPolicy);
    NvWriteReserved(NV_PH_PROOF, &gp.phProof);
    NvWriteReserved(NV_SH_PROOF, &gp.shProof);
    NvWriteReserved(NV_EH_PROOF, &gp.ehProof);

    return;
}
void
HierarchyStartup(
    STARTUP_TYPE type                       // IN: start up type
)
{
    // phEnable is SET on any startup
    g_phEnable = TRUE;

    // Reset platformAuth, platformPolicy; enable SH and EH at TPM_RESET and
    // TPM_RESTART
    if(type != SU_RESUME)
    {
        gc.platformAuth.t.size = 0;
        gc.platformPolicy.t.size = 0;

        // enable the storage and endorsement hierarchies and the platformNV
        gc.shEnable = gc.ehEnable = gc.phEnableNV = TRUE;
    }

    // nullProof and nullSeed are updated at every TPM_RESET
    if(type == SU_RESET)
    {
        gr.nullProof.t.size = PROOF_SIZE;
        CryptGenerateRandom(gr.nullProof.t.size,
                            gr.nullProof.t.buffer);
        gr.nullSeed.t.size = PRIMARY_SEED_SIZE;
        CryptGenerateRandom(PRIMARY_SEED_SIZE, gr.nullSeed.t.buffer);
    }

    return;
}
TPM2B_AUTH *
HierarchyGetProof(
    TPMI_RH_HIERARCHY hierarchy        // IN: hierarchy constant
)
{
    TPM2B_AUTH *auth = NULL;

    switch(hierarchy)
    {
    case TPM_RH_PLATFORM:
        // phProof for TPM_RH_PLATFORM
        auth = &gp.phProof;
        break;
    case TPM_RH_ENDORSEMENT:
        // ehProof for TPM_RH_ENDORSEMENT
        auth = &gp.ehProof;
        break;
    case TPM_RH_OWNER:
        // shProof for TPM_RH_OWNER
        auth = &gp.shProof;
        break;
    case TPM_RH_NULL:
        // nullProof for TPM_RH_NULL
        auth = &gr.nullProof;
        break;
    default:
        pAssert(FALSE);
        break;
    }
    return auth;

}
TPM2B_SEED *
HierarchyGetPrimarySeed(
    TPMI_RH_HIERARCHY hierarchy        // IN: hierarchy
)
{
    TPM2B_SEED *seed = NULL;
    switch(hierarchy)
    {
    case TPM_RH_PLATFORM:
        seed = &gp.PPSeed;
        break;
    case TPM_RH_OWNER:
        seed = &gp.SPSeed;
        break;
    case TPM_RH_ENDORSEMENT:
        seed = &gp.EPSeed;
        break;
    case TPM_RH_NULL:
        return &gr.nullSeed;
    default:
        pAssert(FALSE);
        break;
    }
    return seed;
}
BOOL
HierarchyIsEnabled(
    TPMI_RH_HIERARCHY hierarchy        // IN: hierarchy
)
{
    BOOL enabled = FALSE;

    switch(hierarchy)
    {
    case TPM_RH_PLATFORM:
        enabled = g_phEnable;
        break;
    case TPM_RH_OWNER:
        enabled = gc.shEnable;
        break;
    case TPM_RH_ENDORSEMENT:
        enabled = gc.ehEnable;
        break;
    case TPM_RH_NULL:
        enabled = TRUE;
        break;
    default:
        pAssert(FALSE);
        break;
    }
    return enabled;
}
