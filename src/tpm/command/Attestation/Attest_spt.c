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

// 7.2.1 Includes
#include "InternalRoutines.h"
#include "Attest_spt_fp.h"

// M e
// TPM_RC_KEY key referenced by signHandle is not a signing key
// TPM_RC_SCHEME both scheme and key's default scheme are empty; or scheme is
// empty while key's default scheme requires explicit input scheme (split
// signing); or non-empty default key scheme differs from scheme

TPM_RC
FillInAttestInfo(
    TPMI_DH_OBJECT signHandle,             // IN: handle of signing object
    TPMT_SIG_SCHEME *scheme,                // IN/OUT: scheme to be used for signing
    TPM2B_DATA *data,                  // IN: qualifying data
    TPMS_ATTEST *attest                 // OUT: attest structure
)
{
    TPM_RC result;
    TPMI_RH_HIERARCHY signHierarhcy;

    result = CryptSelectSignScheme(signHandle, scheme);
    if(result != TPM_RC_SUCCESS)
        return result;

    // Magic number
    attest->magic = TPM_GENERATED_VALUE;

    if(signHandle == TPM_RH_NULL)
    {
        BYTE *buffer;
        // For null sign handle, the QN is TPM_RH_NULL
        buffer = attest->qualifiedSigner.t.name;
        attest->qualifiedSigner.t.size =
            TPM_HANDLE_Marshal(&signHandle, &buffer, NULL);
    }
    else
    {
        // Certifying object qualified name
        // if the scheme is anonymous, this is an empty buffer
        if(CryptIsSchemeAnonymous(scheme->scheme))
            attest->qualifiedSigner.t.size = 0;
        else
            ObjectGetQualifiedName(signHandle, &attest->qualifiedSigner);
    }

    // current clock in plain text
    TimeFillInfo(&attest->clockInfo);

    // Firmware version in plain text
    attest->firmwareVersion = ((UINT64) gp.firmwareV1 << (sizeof(UINT32) * 8));
    attest->firmwareVersion += gp.firmwareV2;

    // Get the hierarchy of sign object. For NULL sign handle, the hierarchy
    // will be TPM_RH_NULL
    signHierarhcy = EntityGetHierarchy(signHandle);
    if(signHierarhcy != TPM_RH_PLATFORM && signHierarhcy != TPM_RH_ENDORSEMENT)
    {
        // For sign object is not in platform or endorsement hierarchy,
        // obfuscate the clock and firmwereVersion information
        UINT64 obfuscation[2];
        TPMI_ALG_HASH hashAlg;

        // Get hash algorithm
        if(signHandle == TPM_RH_NULL || signHandle == TPM_RH_OWNER)
        {
            hashAlg = CONTEXT_INTEGRITY_HASH_ALG;
        }
        else
        {
            OBJECT *signObject = NULL;
            signObject = ObjectGet(signHandle);
            hashAlg = signObject->publicArea.nameAlg;
        }
        KDFa(hashAlg, &gp.shProof.b, "OBFUSCATE",
             &attest->qualifiedSigner.b, NULL, 128, (BYTE *)&obfuscation[0], NULL);

        // Obfuscate data
        attest->firmwareVersion += obfuscation[0];
        attest->clockInfo.resetCount += (UINT32)(obfuscation[1] >> 32);
        attest->clockInfo.restartCount += (UINT32)obfuscation[1];
    }

    // External data
    if(CryptIsSchemeAnonymous(scheme->scheme))
        attest->extraData.t.size = 0;
    else
    {
        // If we move the data to the attestation structure, then we will not use
        // it in the signing operation except as part of the signed data
        attest->extraData = *data;
        data->t.size = 0;
    }

    return TPM_RC_SUCCESS;
}

// E r
// M e
// TPM_RC_ATTRIBUTES
// TPM_RC_SCHEME
// TPM_RC_VALUE



TPM_RC
SignAttestInfo(
    TPMI_DH_OBJECT signHandle,                     // IN: handle of sign object
    TPMT_SIG_SCHEME *scheme,                        // IN: sign scheme
    TPMS_ATTEST *certifyInfo,                   // IN: the data to be signed
    TPM2B_DATA *qualifyingData,                // IN: extra data for the signing proce
    TPM2B_ATTEST *attest,                        // OUT: marshaled attest blob to be
    // signed
    TPMT_SIGNATURE *signature                      // OUT: signature
)
{
    TPM_RC result;
    TPMI_ALG_HASH hashAlg;
    BYTE *buffer;
    HASH_STATE hashState;
    TPM2B_DIGEST digest;

    // Marshal TPMS_ATTEST structure for hash
    buffer = attest->t.attestationData;
    attest->t.size = TPMS_ATTEST_Marshal(certifyInfo, &buffer, NULL);

    if(signHandle == TPM_RH_NULL)
    {
        signature->sigAlg = TPM_ALG_NULL;
    }
    else
    {
        // Attestation command may cause the orderlyState to be cleared due to
        // the reporting of clock info. If this is the case, check if NV is
        // available first
        if(gp.orderlyState != SHUTDOWN_NONE)
        {
            // The command needs NV update. Check if NV is available.
            // A TPM_RC_NV_UNAVAILABLE or TPM_RC_NV_RATE error may be returned at
            // this point
            result = NvIsAvailable();
            if(result != TPM_RC_SUCCESS)
                return result;
        }

        // Compute hash
        hashAlg = scheme->details.any.hashAlg;
        digest.t.size = CryptStartHash(hashAlg, &hashState);
        CryptUpdateDigest(&hashState, attest->t.size, attest->t.attestationData);
        CryptCompleteHash2B(&hashState, &digest.b);

        // If there is qualifying data, need to rehash the the data
        // hash(qualifyingData || hash(attestationData))
        if(qualifyingData->t.size != 0)
        {
            CryptStartHash(hashAlg, &hashState);
            CryptUpdateDigest(&hashState,
                              qualifyingData->t.size,
                              qualifyingData->t.buffer);
            CryptUpdateDigest(&hashState, digest.t.size, digest.t.buffer);
            CryptCompleteHash2B(&hashState, &digest.b);
        }

        // Sign the hash. A TPM_RC_VALUE, TPM_RC_SCHEME, or
        // TPM_RC_ATTRIBUTES error may be returned at this point
        return CryptSign(signHandle,
                         scheme,
                         &digest,
                         signature);
    }

    return TPM_RC_SUCCESS;
}
