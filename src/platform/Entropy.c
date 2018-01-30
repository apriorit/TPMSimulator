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

// C.4.1. Includes
#define _CRT_RAND_S
#include <stdlib.h>
#include <stdint.h>
#include <memory.h>
#include "TpmBuildSwitches.h"
 
#if defined(_Win32) || defined(WIN32)
#else
// Quick and dirty
#include <stdio.h>
int32_t rand_s(uint32_t* rndNum) {
    FILE *fp;
    if (fp = fopen("/dev/urandom", "r")) {
        fread(rndNum, sizeof(char), 1, fp);
        fclose(fp);
        return 0;
    }
    return -1;
}
#endif

extern uint32_t lastEntropy;
extern int firstValue;
LIB_EXPORT int32_t
_plat__GetEntropy(
    unsigned char *entropy,              // output buffer
    uint32_t amount                 // amount requested
)
{
    uint32_t rndNum;
    int OK = 1;

    if(amount == 0)
    {
        firstValue = 1;
        return 0;
    }

    // Only provide entropy 32 bits at a time to test the ability
    // of the caller to deal with partial results.
    OK = rand_s(&rndNum) == 0;
    if(OK)
    {
        if(firstValue)
            firstValue = 0;
        else
            OK = (rndNum != lastEntropy);
    }
    if(OK)
    {
        lastEntropy = rndNum;
        if(amount > sizeof(rndNum))
            amount = sizeof(rndNum);
        memcpy(entropy, &rndNum, amount);
    }
    return (OK) ? (int32_t)amount : -1;
}
