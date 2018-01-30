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

// 10.4.1 Introduction
// The functions in this file are designed to support self-test of cryptographic functions in the TPM. The TPM
// allows the user to decide whether to run self-test on a demand basis or to run all the self-tests before
// proceeding.
// The self-tests are controlled by a set of bit vectors. The g_untestedDecryptionAlgorithms vector has a bit
// for each decryption algorithm that needs to be tested and g_untestedEncryptionAlgorithms has a bit for
// each encryption algorithm that needs to be tested. Before an algorithm is used, the appropriate vector is
// checked (indexed using the algorithm ID). If the bit is SET, then the test function should be called.
#include "Global.h"
#include "CryptoEngine.h"
#include "InternalRoutines.h"
#include "AlgorithmCap_fp.h"
static TPM_RC
CryptRunSelfTests(
    ALGORITHM_VECTOR *toTest                // IN: the vector of the algorithms to test
)
{
    TPM_ALG_ID alg;

    // For each of the algorithms that are in the toTestVecor, need to run a
    // test
    for(alg = TPM_ALG_FIRST; alg <= TPM_ALG_LAST; alg++)
    {
        if(TEST_BIT(alg, *toTest))
        {
            TPM_RC result = CryptTestAlgorithm(alg, toTest);
            if(result != TPM_RC_SUCCESS)
                return result;
        }
    }
    return TPM_RC_SUCCESS;
}

// M e
// TPM_RC_CANCELED if the command is canceled

LIB_EXPORT
TPM_RC
CryptSelfTest(
    TPMI_YES_NO fullTest                 // IN: if full test is required
)
{
    if(g_forceFailureMode)
        FAIL(FATAL_ERROR_FORCED);

    // If the caller requested a full test, then reset the to test vector so that
    // all the tests will be run
    if(fullTest == YES)
    {
        MemoryCopy(g_toTest,
                   g_implementedAlgorithms,
                   sizeof(g_toTest), sizeof(g_toTest));
    }
    return CryptRunSelfTests(&g_toTest);
}

// M e
// TPM_RC_CANCELED processing of this command was canceled
// TPM_RC_TESTING if toTest list is not empty
// TPM_RC_VALUE an algorithm in the toTest list is not implemented

TPM_RC
CryptIncrementalSelfTest(
    TPML_ALG *toTest,                      // IN: list of algorithms to be tested
    TPML_ALG *toDoList                     // OUT: list of algorithms needing test
)
{
    ALGORITHM_VECTOR toTestVector = {0};
    TPM_ALG_ID alg;
    UINT32 i;

    pAssert(toTest != NULL && toDoList != NULL);
    if(toTest->count > 0)
    {
        // Transcribe the toTest list into the toTestVector
        for(i = 0; i < toTest->count; i++)
        {
            TPM_ALG_ID alg = toTest->algorithms[i];

            // make sure that the algorithm value is not out of range
            if((alg > TPM_ALG_LAST) || !TEST_BIT(alg, g_implementedAlgorithms))
                return TPM_RC_VALUE;
            SET_BIT(alg, toTestVector);
        }
        // Run the test
        if(CryptRunSelfTests(&toTestVector) == TPM_RC_CANCELED)
            return TPM_RC_CANCELED;
    }
    // Fill in the toDoList with the algorithms that are still untested
    toDoList->count = 0;

    for(alg = TPM_ALG_FIRST;
            toDoList->count < MAX_ALG_LIST_SIZE && alg <= TPM_ALG_LAST;
            alg++)
    {
        if(TEST_BIT(alg, g_toTest))
            toDoList->algorithms[toDoList->count++] = alg;
    }
    return TPM_RC_SUCCESS;
}
void
CryptInitializeToTest(
    void
)
{
    MemoryCopy(g_toTest,
               g_implementedAlgorithms,
               sizeof(g_toTest),
               sizeof(g_toTest));
    // Setting the algorithm to null causes the test function to just clear
    // out any algorithms for which there is no test.
    CryptTestAlgorithm(TPM_ALG_ERROR, &g_toTest);

    return;
}

// E r
// M e

// TPM_RC_SUCCESS

// TPM_RC_CANCELED


LIB_EXPORT
TPM_RC
CryptTestAlgorithm(
    TPM_ALG_ID alg,
    ALGORITHM_VECTOR *toTest
)
{
    TPM_RC result = TPM_RC_SUCCESS;
#ifdef SELF_TEST
    // This is the function prototype for TestAlgorithms(). It is here and not
    // in a _fp.h file to avoid a compiler error when SELF_TEST is not defined and
    // AlgorithmTexts.c is not part of the build.
    TPM_RC TestAlgorithm(TPM_ALG_ID alg, ALGORITHM_VECTOR *toTest);
    result = TestAlgorithm(alg, toTest);
#else
    // If this is an attempt to determine the algorithms for which there is a
    // self test, pretend that all of them do. We do that by not clearing any
    // of the algorithm bits. When/if this function is called to run tests, it
    // will over report. This can be changed so that any call to check on which
    // algorithms have tests, 'toTest' can be cleared.
    if(alg != TPM_ALG_ERROR)
    {
        CLEAR_BIT(alg, g_toTest);
        if(toTest != NULL)
            CLEAR_BIT(alg, *toTest);
    }
#endif
    return result;
}
