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

// 8.9.1 Introduction
// This file contains the functions relating to the TPM's time functions including the interface to
// the
// implementation-specific time functions.
// 8.9.2 Includes
#include "InternalRoutines.h"
#include "Platform.h"
void
TimePowerOn(
    void
)
{
    TPM_SU orderlyShutDown;

    // Read orderly data info from NV memory
    NvReadReserved(NV_ORDERLY_DATA, &go);

    // Read orderly shut down state flag
    NvReadReserved(NV_ORDERLY, &orderlyShutDown);

    // If the previous cycle is orderly shut down, the value of the safe bit
    // the same as previously saved. Otherwise, it is not safe.
    if(orderlyShutDown == SHUTDOWN_NONE)
        go.clockSafe= NO;
    else
        go.clockSafe = YES;

    // Set the initial state of the DRBG
    CryptDrbgGetPutState(PUT_STATE);

    // Clear time since TPM power on
    g_time = 0;

    return;
}
void
TimeStartup(
    STARTUP_TYPE type                    // IN: start up type
)
{
    if(type == SU_RESUME)
    {
        // Resume sequence
        gr.restartCount++;
    }
    else
    {
        if(type == SU_RESTART)
        {
            // Hibernate sequence
            gr.clearCount++;
            gr.restartCount++;
        }
        else
        {
            // Reset sequence
            // Increase resetCount
            gp.resetCount++;

            // Write resetCount to NV
            NvWriteReserved(NV_RESET_COUNT, &gp.resetCount);
            gp.totalResetCount++;

            // We do not expect the total reset counter overflow during the life
            // time of TPM. if it ever happens, TPM will be put to failure mode
            // and there is no way to recover it.
            // The reason that there is no recovery is that we don't increment
            // the NV totalResetCount when incrementing would make it 0. When the
            // TPM starts up again, the old value of totalResetCount will be read
            // and we will get right back to here with the increment failing.
            if(gp.totalResetCount == 0)
                FAIL(FATAL_ERROR_INTERNAL);

            // Write total reset counter to NV
            NvWriteReserved(NV_TOTAL_RESET_COUNT, &gp.totalResetCount);

            // Reset restartCount
            gr.restartCount = 0;
        }
    }

    return;
}
void
TimeUpdateToCurrent(
    void
)
{
    UINT64 oldClock;
    UINT64 elapsed;
#define CLOCK_UPDATE_MASK ((1ULL << NV_CLOCK_UPDATE_INTERVAL)- 1)

    // Can't update time during the dark interval or when rate limiting.
    if(NvIsAvailable() != TPM_RC_SUCCESS)
        return;

    // Save the old clock value
    oldClock = go.clock;

    // Update the time info to current
    elapsed = _plat__ClockTimeElapsed();
    go.clock += elapsed;
    g_time += elapsed;

    // Check to see if the update has caused a need for an nvClock update
    // CLOCK_UPDATE_MASK is measured by second, while the value in go.clock is
    // recorded by millisecond. Align the clock value to second before the bit
    // operations
    if( ((go.clock/1000) | CLOCK_UPDATE_MASK)
            > ((oldClock/1000) | CLOCK_UPDATE_MASK))
    {
        // Going to update the time state so the safe flag
        // should be set
        go.clockSafe = YES;

        // Get the DRBG state before updating orderly data
        CryptDrbgGetPutState(GET_STATE);

        NvWriteReserved(NV_ORDERLY_DATA, &go);
    }

    // Call self healing logic for dictionary attack parameters
    DASelfHeal();

    return;
}
void
TimeSetAdjustRate(
    TPM_CLOCK_ADJUST adjust            // IN: adjust constant
)
{
    switch(adjust)
    {
    case TPM_CLOCK_COARSE_SLOWER:
        _plat__ClockAdjustRate(CLOCK_ADJUST_COARSE);
        break;
    case TPM_CLOCK_COARSE_FASTER:
        _plat__ClockAdjustRate(-CLOCK_ADJUST_COARSE);
        break;
    case TPM_CLOCK_MEDIUM_SLOWER:
        _plat__ClockAdjustRate(CLOCK_ADJUST_MEDIUM);
        break;
    case TPM_CLOCK_MEDIUM_FASTER:
        _plat__ClockAdjustRate(-CLOCK_ADJUST_MEDIUM);
        break;
    case TPM_CLOCK_FINE_SLOWER:
        _plat__ClockAdjustRate(CLOCK_ADJUST_FINE);
        break;
    case TPM_CLOCK_FINE_FASTER:
        _plat__ClockAdjustRate(-CLOCK_ADJUST_FINE);
        break;
    case TPM_CLOCK_NO_CHANGE:
        break;
    default:
        pAssert(FALSE);
        break;
    }

    return;
}

// E r
// M e
// TPM_RC_RANGE

TPM_RC
TimeGetRange(
    UINT16 offset,                  // IN: offset in TPMS_TIME_INFO
    UINT16 size,                    // IN: size of data
    TIME_INFO *dataBuffer              // OUT: result buffer
)
{
    TPMS_TIME_INFO timeInfo;
    UINT16 infoSize;
    BYTE infoData[sizeof(TPMS_TIME_INFO)];
    BYTE *buffer;

    // Fill TPMS_TIME_INFO structure
    timeInfo.time = g_time;
    TimeFillInfo(&timeInfo.clockInfo);

    // Marshal TPMS_TIME_INFO to canonical form
    buffer = infoData;
    infoSize = TPMS_TIME_INFO_Marshal(&timeInfo, &buffer, NULL);

    // Check if the input range is valid
    if(offset + size > infoSize) return TPM_RC_RANGE;

    // Copy info data to output buffer
    MemoryCopy(dataBuffer, infoData + offset, size, sizeof(TIME_INFO));

    return TPM_RC_SUCCESS;
}
void
TimeFillInfo(
    TPMS_CLOCK_INFO *clockInfo
)
{
    clockInfo->clock = go.clock;
    clockInfo->resetCount = gp.resetCount;
    clockInfo->restartCount = gr.restartCount;

    // If NV is not available, clock stopped advancing and the value reported is
    // not "safe".
    if(NvIsAvailable() == TPM_RC_SUCCESS)
        clockInfo->safe = go.clockSafe;
    else
        clockInfo->safe = NO;

    return;
}
