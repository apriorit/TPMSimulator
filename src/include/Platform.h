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

#ifndef PLATFORM_H
#define PLATFORM_H
#include "bool.h"
#include "stdint.h"
#include "TpmError.h"
#include "TpmBuildSwitches.h"
#define UNREFERENCED(a) ((void)(a))
LIB_EXPORT int
_plat__Signal_PowerOn(void);
LIB_EXPORT int
_plat__Signal_Reset(void);
LIB_EXPORT BOOL
_plat__WasPowerLost(BOOL clear);
LIB_EXPORT void
_plat__Signal_PowerOff(void);
LIB_EXPORT BOOL
_plat__PhysicalPresenceAsserted(void);
LIB_EXPORT void
_plat__Signal_PhysicalPresenceOn(void);
LIB_EXPORT void
_plat__Signal_PhysicalPresenceOff(void);
LIB_EXPORT BOOL
_plat__IsCanceled(void);
LIB_EXPORT void
_plat__SetCancel(void);
LIB_EXPORT void
_plat__ClearCancel( void);
LIB_EXPORT void
_plat__NvErrors(
    BOOL recoverable,
    BOOL unrecoverable
);
LIB_EXPORT int
_plat__NVEnable(
    void *platParameter                          // IN: platform specific parameters
);
LIB_EXPORT void
_plat__NVDisable(void);
LIB_EXPORT int
_plat__IsNvAvailable(void);
LIB_EXPORT int
_plat__NvCommit(void);
LIB_EXPORT void
_plat__NvMemoryRead(
    unsigned int startOffset,           // IN: read start
    unsigned int size,                  // IN: size of bytes to read
    void *data                  // OUT: data buffer
);
LIB_EXPORT BOOL
_plat__NvIsDifferent(
    unsigned int startOffset,           // IN: read start
    unsigned int size,                  // IN: size of bytes to compare
    void *data                  // IN: data buffer
);
LIB_EXPORT void
_plat__NvMemoryWrite(
    unsigned int startOffset,           // IN: read start
    unsigned int size,                  // IN: size of bytes to read
    void *data                  // OUT: data buffer
);
LIB_EXPORT void
_plat__NvMemoryMove(
    unsigned int sourceOffset,          // IN: source offset
    unsigned int destOffset,            // IN: destination offset
    unsigned int size                   // IN: size of data being moved
);
LIB_EXPORT void
_plat__SetNvAvail(void);
LIB_EXPORT void
_plat__ClearNvAvail(void);
LIB_EXPORT unsigned char
_plat__LocalityGet(void);
LIB_EXPORT void
_plat__LocalitySet(
    unsigned char locality
);
LIB_EXPORT int
_plat__IsRsaKeyCacheEnabled(
    void
);
#define CLOCK_NOMINAL 30000
#define CLOCK_ADJUST_COARSE 300
#define CLOCK_ADJUST_MEDIUM 30
#define CLOCK_ADJUST_FINE 1
#define CLOCK_ADJUST_LIMIT 5000
LIB_EXPORT void
_plat__ClockReset(void);
LIB_EXPORT unsigned long long
_plat__ClockTimeFromStart(
    void
);
LIB_EXPORT unsigned long long
_plat__ClockTimeElapsed(void);
LIB_EXPORT void
_plat__ClockAdjustRate(
    int adjust               // IN: the adjust number. It could be
    // positive or negative
);
LIB_EXPORT int32_t
_plat__GetEntropy(
    unsigned char *entropy,                // output buffer
    uint32_t amount                   // amount requested
);
#endif
