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

// 8.4.1 Introduction
// The NV memory is divided into two area: dynamic space for user defined NV Indices and evict objects,
// and reserved space for TPM persistent and state save data.
// 8.4.2 Includes, Defines and Data Definitions
#define NV_C
#include "InternalRoutines.h"
#include <Platform.h>
typedef UINT32 NV_ITER;            // type of a NV iterator
#define NV_ITER_INIT 0xFFFFFFFF          // initial value to start an
// iterator
void
NvCheckState(void)
{
    int func_return;

    func_return = _plat__IsNvAvailable();
    if(func_return == 0)
    {
        s_NvStatus = TPM_RC_SUCCESS;
    }
    else if(func_return == 1)
    {
        s_NvStatus = TPM_RC_NV_UNAVAILABLE;
    }
    else
    {
        s_NvStatus = TPM_RC_NV_RATE;
    }

    return;
}

// M e
// TPM_RC_SUCCESS NV is available
// TPM_RC_NV_RATE NV is unavailable because of rate limit
// TPM_RC_NV_UNAVAILABLE NV is inaccessible

TPM_RC
NvIsAvailable(
    void
)
{
    return s_NvStatus;
}
BOOL
NvCommit(
    void
)
{
    BOOL success = (_plat__NvCommit() == 0);
    return success;
}
static UINT64
NvReadMaxCount(
    void
)
{
    UINT64 countValue;
    _plat__NvMemoryRead(s_maxCountAddr, sizeof(UINT64), &countValue);
    return countValue;
}
static void
NvWriteMaxCount(
    UINT64 maxCount
)
{
    _plat__NvMemoryWrite(s_maxCountAddr, sizeof(UINT64), &maxCount);
    return;
}
static UINT32
NvNext(
    NV_ITER *iter
)
{
    NV_ITER currentIter;

    // If iterator is at the beginning of list
    if(*iter == NV_ITER_INIT)
    {
        // Initialize iterator
        *iter = s_evictNvStart;
    }

    // If iterator reaches the end of NV space, or iterator indicates list end
    if(*iter + sizeof(UINT32) > s_evictNvEnd || *iter == 0)
        return 0;

    // Save the current iter offset
    currentIter = *iter;

    // Adjust iter pointer pointing to next entity
    // Read pointer value
    _plat__NvMemoryRead(*iter, sizeof(UINT32), iter);

    if(*iter == 0) return 0;

    return currentIter + sizeof(UINT32);                     // entity stores after the pointer
}
static UINT32
NvGetEnd(
    void
)
{
    NV_ITER iter = NV_ITER_INIT;
    UINT32 endAddr = s_evictNvStart;
    UINT32 currentAddr;

    while((currentAddr = NvNext(&iter)) != 0)
        endAddr = currentAddr;

    if(endAddr != s_evictNvStart)
    {
        // Read offset
        endAddr -= sizeof(UINT32);
        _plat__NvMemoryRead(endAddr, sizeof(UINT32), &endAddr);
    }

    return endAddr;
}
static UINT32
NvGetFreeByte(
    void
)
{
    return s_evictNvEnd - NvGetEnd();
}
static UINT32
NvGetEvictObjectSize(
    void
)
{
    return sizeof(TPM_HANDLE) + sizeof(OBJECT) + sizeof(UINT32);
}
static UINT32
NvGetCounterSize(
    void
)
{
    // It takes an offset field, a handle and the sizeof(NV_INDEX) and
    // sizeof(UINT64) for counter data
    return sizeof(TPM_HANDLE) + sizeof(NV_INDEX) + sizeof(UINT64) + sizeof(UINT32);
}
static BOOL
NvTestSpace(
    UINT32 size,                         // IN: size of the entity to be added
    BOOL isIndex                       // IN: TRUE if the entity is an index
)
{
    UINT32 remainByte = NvGetFreeByte();

    // For NV Index, need to make sure that we do not allocate and Index if this
    // would mean that the TPM cannot allocate the minimum number of evict
    // objects.
    if(isIndex)
    {
        // Get the number of persistent objects allocated
        UINT32 persistentNum = NvCapGetPersistentNumber();

        // If we have not allocated the requisite number of evict objects, then we
        // need to reserve space for them.
        // NOTE: some of this is not written as simply as it might seem because
        // the values are all unsigned and subtracting needs to be done carefully
        // so that an underflow doesn't cause problems.
        if(persistentNum < MIN_EVICT_OBJECTS)
        {
            UINT32 needed = (MIN_EVICT_OBJECTS - persistentNum)
                            * NvGetEvictObjectSize();
            if(needed > remainByte)
                remainByte = 0;
            else
                remainByte -= needed;
        }
        // if the requisite number of evict objects have been allocated then
        // no need to reserve additional space
    }
    // This checks for the size of the value being added plus the index value.
    // NOTE: This does not check to see if the end marker can be placed in
    // memory because the end marker will not be written if it will not fit.
    return (size + sizeof(UINT32) <= remainByte);
}
static void
NvAdd(
    UINT32 totalSize,                   // IN: total size needed for this entity For
    // evict object, totalSize is the same as
    // bufferSize. For NV Index, totalSize is
    // bufferSize plus index data size
    UINT32 bufferSize,                  // IN: size of initial buffer
    BYTE *entity                         // IN: initial buffer
)
{
    UINT32 endAddr;
    UINT32 nextAddr;
    UINT32 listEnd = 0;

    // Get the end of data list
    endAddr = NvGetEnd();

    // Calculate the value of next pointer, which is the size of a pointer +
    // the entity data size
    nextAddr = endAddr + sizeof(UINT32) + totalSize;

    // Write next pointer
    _plat__NvMemoryWrite(endAddr, sizeof(UINT32), &nextAddr);

    // Write entity data
    _plat__NvMemoryWrite(endAddr + sizeof(UINT32), bufferSize, entity);

    // Write the end of list if it is not going to exceed the NV space
    if(nextAddr + sizeof(UINT32) <= s_evictNvEnd)
        _plat__NvMemoryWrite(nextAddr, sizeof(UINT32), &listEnd);

    // Set the flag so that NV changes are committed before the command completes.
    g_updateNV = TRUE;
}
static void
NvDelete(
    UINT32 entityAddr                   // IN: address of entity to be deleted
)
{
    UINT32 next;
    UINT32 entrySize;
    UINT32 entryAddr = entityAddr - sizeof(UINT32);
    UINT32 listEnd = 0;

    // Get the offset of the next entry.
    _plat__NvMemoryRead(entryAddr, sizeof(UINT32), &next);

    // The size of this entry is the difference between the current entry and the
    // next entry.
    entrySize = next - entryAddr;

    // Move each entry after the current one to fill the freed space.
    // Stop when we have reached the end of all the indexes. There are two
    // ways to detect the end of the list. The first is to notice that there
    // is no room for anything else because we are at the end of NV. The other
    // indication is that we find an end marker.

    // The loop condition checks for the end of NV.
    while(next + sizeof(UINT32) <= s_evictNvEnd)
    {
        UINT32 size, oldAddr, newAddr;

        // Now check for the end marker
        _plat__NvMemoryRead(next, sizeof(UINT32), &oldAddr);
        if(oldAddr == 0)
            break;

        size = oldAddr - next;

        // Move entry
        _plat__NvMemoryMove(next, next - entrySize, size);

        // Update forward link
        newAddr = oldAddr - entrySize;
        _plat__NvMemoryWrite(next - entrySize, sizeof(UINT32), &newAddr);
        next = oldAddr;
    }
    // Mark the end of list
    _plat__NvMemoryWrite(next - entrySize, sizeof(UINT32), &listEnd);

    // Set the flag so that NV changes are committed before the command completes.
    g_updateNV = TRUE;
}
static BOOL
NvTestRAMSpace(
    UINT32 size                           // IN: size of the data to be added to RAM
)
{
    BOOL success = ( s_ramIndexSize
                     + size
                     + sizeof(TPM_HANDLE) + sizeof(UINT32)
                     <= RAM_INDEX_SPACE);
    return success;
}
static UINT32
NvGetRAMIndexOffset(
    TPMI_RH_NV_INDEX handle                   // IN: NV handle
)
{
    UINT32 currAddr = 0;

    while(currAddr < s_ramIndexSize)
    {
        TPMI_RH_NV_INDEX currHandle;
        UINT32 currSize;
        currHandle = * (TPM_HANDLE *) &s_ramIndex[currAddr + sizeof(UINT32)];

        // Found a match
        if(currHandle == handle)

            // data buffer follows the handle and size field
            break;

        currSize = * (UINT32 *) &s_ramIndex[currAddr];
        currAddr += sizeof(UINT32) + currSize;
    }

    // We assume the index data is existing in RAM space
    pAssert(currAddr < s_ramIndexSize);
    return currAddr + sizeof(TPMI_RH_NV_INDEX) + sizeof(UINT32);
}
static void
NvAddRAM(
    TPMI_RH_NV_INDEX handle,                  // IN: NV handle
    UINT32 size                     // IN: size of data
)
{
    // Add data space at the end of reserved RAM buffer
    * (UINT32 *) &s_ramIndex[s_ramIndexSize] = size + sizeof(TPMI_RH_NV_INDEX);
    * (TPMI_RH_NV_INDEX *) &s_ramIndex[s_ramIndexSize + sizeof(UINT32)] = handle;
    s_ramIndexSize += sizeof(UINT32) + sizeof(TPMI_RH_NV_INDEX) + size;

    pAssert(s_ramIndexSize <= RAM_INDEX_SPACE);

    // Update NV version of s_ramIndexSize
    _plat__NvMemoryWrite(s_ramIndexSizeAddr, sizeof(UINT32), &s_ramIndexSize);

    // Write reserved RAM space to NV to reflect the newly added NV Index
    _plat__NvMemoryWrite(s_ramIndexAddr, RAM_INDEX_SPACE, s_ramIndex);

    return;
}
static void
NvDeleteRAM(
    TPMI_RH_NV_INDEX handle                        // IN: NV handle
)
{
    UINT32 nodeOffset;
    UINT32 nextNode;
    UINT32 size;

    nodeOffset = NvGetRAMIndexOffset(handle);

    // Move the pointer back to get the size field of this node
    nodeOffset -= sizeof(UINT32) + sizeof(TPMI_RH_NV_INDEX);

    // Get node size
    size = * (UINT32 *) &s_ramIndex[nodeOffset];

    // Get the offset of next node
    nextNode = nodeOffset + sizeof(UINT32) + size;

    // Move data
    MemoryMove(s_ramIndex + nodeOffset, s_ramIndex + nextNode,
               s_ramIndexSize - nextNode, s_ramIndexSize - nextNode);

    // Update RAM size
    s_ramIndexSize -= size + sizeof(UINT32);

    // Update NV version of s_ramIndexSize
    _plat__NvMemoryWrite(s_ramIndexSizeAddr, sizeof(UINT32), &s_ramIndexSize);

    // Write reserved RAM space to NV to reflect the newly delete NV Index
    _plat__NvMemoryWrite(s_ramIndexAddr, RAM_INDEX_SPACE, s_ramIndex);

    return;
}
static void
NvInitStatic(
    void
)
{
    UINT16 i;
    UINT32 reservedAddr;

    s_reservedSize[NV_DISABLE_CLEAR] = sizeof(gp.disableClear);
    s_reservedSize[NV_OWNER_ALG] = sizeof(gp.ownerAlg);
    s_reservedSize[NV_ENDORSEMENT_ALG] = sizeof(gp.endorsementAlg);
    s_reservedSize[NV_LOCKOUT_ALG] = sizeof(gp.lockoutAlg);
    s_reservedSize[NV_OWNER_POLICY] = sizeof(gp.ownerPolicy);
    s_reservedSize[NV_ENDORSEMENT_POLICY] = sizeof(gp.endorsementPolicy);
    s_reservedSize[NV_LOCKOUT_POLICY] = sizeof(gp.lockoutPolicy);
    s_reservedSize[NV_OWNER_AUTH] = sizeof(gp.ownerAuth);
    s_reservedSize[NV_ENDORSEMENT_AUTH] = sizeof(gp.endorsementAuth);
    s_reservedSize[NV_LOCKOUT_AUTH] = sizeof(gp.lockoutAuth);
    s_reservedSize[NV_EP_SEED] = sizeof(gp.EPSeed);
    s_reservedSize[NV_SP_SEED] = sizeof(gp.SPSeed);
    s_reservedSize[NV_PP_SEED] = sizeof(gp.PPSeed);
    s_reservedSize[NV_PH_PROOF] = sizeof(gp.phProof);
    s_reservedSize[NV_SH_PROOF] = sizeof(gp.shProof);
    s_reservedSize[NV_EH_PROOF] = sizeof(gp.ehProof);
    s_reservedSize[NV_TOTAL_RESET_COUNT] = sizeof(gp.totalResetCount);
    s_reservedSize[NV_RESET_COUNT] = sizeof(gp.resetCount);
    s_reservedSize[NV_PCR_POLICIES] = sizeof(gp.pcrPolicies);
    s_reservedSize[NV_PCR_ALLOCATED] = sizeof(gp.pcrAllocated);
    s_reservedSize[NV_PP_LIST] = sizeof(gp.ppList);
    s_reservedSize[NV_FAILED_TRIES] = sizeof(gp.failedTries);
    s_reservedSize[NV_MAX_TRIES] = sizeof(gp.maxTries);
    s_reservedSize[NV_RECOVERY_TIME] = sizeof(gp.recoveryTime);
    s_reservedSize[NV_LOCKOUT_RECOVERY] = sizeof(gp.lockoutRecovery);
    s_reservedSize[NV_LOCKOUT_AUTH_ENABLED] = sizeof(gp.lockOutAuthEnabled);
    s_reservedSize[NV_ORDERLY] = sizeof(gp.orderlyState);
    s_reservedSize[NV_AUDIT_COMMANDS] = sizeof(gp.auditComands);
    s_reservedSize[NV_AUDIT_HASH_ALG] = sizeof(gp.auditHashAlg);
    s_reservedSize[NV_AUDIT_COUNTER] = sizeof(gp.auditCounter);
    s_reservedSize[NV_ALGORITHM_SET] = sizeof(gp.algorithmSet);
    s_reservedSize[NV_FIRMWARE_V1] = sizeof(gp.firmwareV1);
    s_reservedSize[NV_FIRMWARE_V2] = sizeof(gp.firmwareV2);
    s_reservedSize[NV_ORDERLY_DATA] = sizeof(go);
    s_reservedSize[NV_STATE_CLEAR] = sizeof(gc);
    s_reservedSize[NV_STATE_RESET] = sizeof(gr);

    // Initialize reserved data address. In this implementation, reserved data
    // is stored at the start of NV memory
    reservedAddr = 0;
    for(i = 0; i < NV_RESERVE_LAST; i++)
    {
        s_reservedAddr[i] = reservedAddr;
        reservedAddr += s_reservedSize[i];
    }

    // Initialize auxiliary variable space for index/evict implementation.
    // Auxiliary variables are stored after reserved data area
    // RAM index copy starts at the beginning
    s_ramIndexSizeAddr = reservedAddr;
    s_ramIndexAddr = s_ramIndexSizeAddr + sizeof(UINT32);

    // Maximum counter value
    s_maxCountAddr = s_ramIndexAddr + RAM_INDEX_SPACE;

    // dynamic memory start
    s_evictNvStart = s_maxCountAddr + sizeof(UINT64);

    // dynamic memory ends at the end of NV memory
    s_evictNvEnd = NV_MEMORY_SIZE;

    return;
}
void
NvInit(
    void
)
{
    UINT32 nullPointer = 0;
    UINT64 zeroCounter = 0;

    // Initialize static variables
    NvInitStatic();

    // Initialize RAM index space as unused
    _plat__NvMemoryWrite(s_ramIndexSizeAddr, sizeof(UINT32), &nullPointer);

    // Initialize max counter value to 0
    _plat__NvMemoryWrite(s_maxCountAddr, sizeof(UINT64), &zeroCounter);

    // Initialize the next offset of the first entry in evict/index list to 0
    _plat__NvMemoryWrite(s_evictNvStart, sizeof(TPM_HANDLE), &nullPointer);

    return;

}
void
NvReadReserved(
    NV_RESERVE type,                // IN: type of reserved data
    void *buffer                 // OUT: buffer receives the data.
)
{
    // Input type should be valid
    pAssert(type >= 0 && type < NV_RESERVE_LAST);

    _plat__NvMemoryRead(s_reservedAddr[type], s_reservedSize[type], buffer);
    return;
}
void
NvWriteReserved(
    NV_RESERVE type,              // IN: type of reserved data
    void *buffer               // IN: data buffer
)
{
    // Input type should be valid
    pAssert(type >= 0 && type < NV_RESERVE_LAST);

    _plat__NvMemoryWrite(s_reservedAddr[type], s_reservedSize[type], buffer);

    // Set the flag that a NV write happens
    g_updateNV = TRUE;
    return;
}
void
NvReadPersistent(
    void
)
{
    // Hierarchy persistent data
    NvReadReserved(NV_DISABLE_CLEAR, &gp.disableClear);
    NvReadReserved(NV_OWNER_ALG, &gp.ownerAlg);
    NvReadReserved(NV_ENDORSEMENT_ALG, &gp.endorsementAlg);
    NvReadReserved(NV_LOCKOUT_ALG, &gp.lockoutAlg);
    NvReadReserved(NV_OWNER_POLICY, &gp.ownerPolicy);
    NvReadReserved(NV_ENDORSEMENT_POLICY, &gp.endorsementPolicy);
    NvReadReserved(NV_LOCKOUT_POLICY, &gp.lockoutPolicy);
    NvReadReserved(NV_OWNER_AUTH, &gp.ownerAuth);
    NvReadReserved(NV_ENDORSEMENT_AUTH, &gp.endorsementAuth);
    NvReadReserved(NV_LOCKOUT_AUTH, &gp.lockoutAuth);
    NvReadReserved(NV_EP_SEED, &gp.EPSeed);
    NvReadReserved(NV_SP_SEED, &gp.SPSeed);
    NvReadReserved(NV_PP_SEED, &gp.PPSeed);
    NvReadReserved(NV_PH_PROOF, &gp.phProof);
    NvReadReserved(NV_SH_PROOF, &gp.shProof);
    NvReadReserved(NV_EH_PROOF, &gp.ehProof);

    // Time persistent data
    NvReadReserved(NV_TOTAL_RESET_COUNT, &gp.totalResetCount);
    NvReadReserved(NV_RESET_COUNT, &gp.resetCount);

    // PCR persistent data
    NvReadReserved(NV_PCR_POLICIES, &gp.pcrPolicies);
    NvReadReserved(NV_PCR_ALLOCATED, &gp.pcrAllocated);

    // Physical Presence persistent data
    NvReadReserved(NV_PP_LIST, &gp.ppList);

    // Dictionary attack values persistent data
    NvReadReserved(NV_FAILED_TRIES, &gp.failedTries);
    NvReadReserved(NV_MAX_TRIES, &gp.maxTries);
    NvReadReserved(NV_RECOVERY_TIME, &gp.recoveryTime);
    NvReadReserved(NV_LOCKOUT_RECOVERY, &gp.lockoutRecovery);
    NvReadReserved(NV_LOCKOUT_AUTH_ENABLED, &gp.lockOutAuthEnabled);

    // Orderly State persistent data
    NvReadReserved(NV_ORDERLY, &gp.orderlyState);

    // Command audit values persistent data
    NvReadReserved(NV_AUDIT_COMMANDS, &gp.auditComands);
    NvReadReserved(NV_AUDIT_HASH_ALG, &gp.auditHashAlg);
    NvReadReserved(NV_AUDIT_COUNTER, &gp.auditCounter);

    // Algorithm selection persistent data
    NvReadReserved(NV_ALGORITHM_SET, &gp.algorithmSet);

    // Firmware version persistent data
    NvReadReserved(NV_FIRMWARE_V1, &gp.firmwareV1);
    NvReadReserved(NV_FIRMWARE_V2, &gp.firmwareV2);

    return;
}
BOOL
NvIsPlatformPersistentHandle(
    TPM_HANDLE handle             // IN: handle
)
{
    return (handle >= PLATFORM_PERSISTENT && handle <= PERSISTENT_LAST);
}
BOOL
NvIsOwnerPersistentHandle(
    TPM_HANDLE handle             // IN: handle
)
{
    return (handle >= PERSISTENT_FIRST && handle < PLATFORM_PERSISTENT);
}
static UINT32
NvNextIndex(
    NV_ITER *iter
)
{
    UINT32 addr;
    TPM_HANDLE handle;

    while((addr = NvNext(iter)) != 0)
    {
        // Read handle
        _plat__NvMemoryRead(addr, sizeof(TPM_HANDLE), &handle);
        if(HandleGetType(handle) == TPM_HT_NV_INDEX)
            return addr;
    }

    pAssert(addr == 0);
    return addr;
}
static UINT32
NvNextEvict(
    NV_ITER *iter
)
{
    UINT32 addr;
    TPM_HANDLE handle;

    while((addr = NvNext(iter)) != 0)
    {
        // Read handle
        _plat__NvMemoryRead(addr, sizeof(TPM_HANDLE), &handle);
        if(HandleGetType(handle) == TPM_HT_PERSISTENT)
            return addr;
    }

    pAssert(addr == 0);
    return addr;
}
static UINT32
NvFindHandle(
    TPM_HANDLE handle
)
{
    UINT32 addr;
    NV_ITER iter = NV_ITER_INIT;

    while((addr = NvNext(&iter)) != 0)
    {
        TPM_HANDLE entityHandle;
        // Read handle
        _plat__NvMemoryRead(addr, sizeof(TPM_HANDLE), &entityHandle);
        if(entityHandle == handle)
            return addr;
    }

    pAssert(addr == 0);
    return addr;
}
BOOL
NvPowerOn(
    void
)
{
    int nvError = 0;
    // If power was lost, need to re-establish the RAM data that is loaded from
    // NV and initialize the static variables
    if(_plat__WasPowerLost(TRUE))
    {
        if((nvError = _plat__NVEnable(0)) < 0)
            FAIL(FATAL_ERROR_NV_UNRECOVERABLE);

        NvInitStatic();
    }

    return nvError == 0;
}
void
NvStateSave(
    void
)
{
    // Write RAM backed NV Index info to NV
    // No need to save s_ramIndexSize because we save it to NV whenever it is
    // updated.
    _plat__NvMemoryWrite(s_ramIndexAddr, RAM_INDEX_SPACE, s_ramIndex);

    // Set the flag so that an NV write happens before the command completes.
    g_updateNV = TRUE;

    return;
}
void
NvEntityStartup(
    STARTUP_TYPE type                   // IN: start up type
)
{
    NV_ITER iter = NV_ITER_INIT;
    UINT32 currentAddr;                     // offset points to the current entity

    // Restore RAM index data
    _plat__NvMemoryRead(s_ramIndexSizeAddr, sizeof(UINT32), &s_ramIndexSize);
    _plat__NvMemoryRead(s_ramIndexAddr, RAM_INDEX_SPACE, s_ramIndex);

    // If recovering from state save, do nothing
    if(type == SU_RESUME)
        return;

    // Iterate all the NV Index to clear the locks
    while((currentAddr = NvNextIndex(&iter)) != 0)
    {
        NV_INDEX nvIndex;
        UINT32 indexAddr;                              // NV address points to index info
        TPMA_NV attributes;

        indexAddr = currentAddr + sizeof(TPM_HANDLE);

        // Read NV Index info structure
        _plat__NvMemoryRead(indexAddr, sizeof(NV_INDEX), &nvIndex);
        attributes = nvIndex.publicArea.attributes;

        // Clear read/write lock
        if(attributes.TPMA_NV_READLOCKED == SET)
            attributes.TPMA_NV_READLOCKED = CLEAR;

        if( attributes.TPMA_NV_WRITELOCKED == SET
                && ( attributes.TPMA_NV_WRITTEN == CLEAR
                     || attributes.TPMA_NV_WRITEDEFINE == CLEAR
                   )
          )
            attributes.TPMA_NV_WRITELOCKED = CLEAR;

        // Reset NV data for TPMA_NV_CLEAR_STCLEAR
        if(attributes.TPMA_NV_CLEAR_STCLEAR == SET)
        {
            attributes.TPMA_NV_WRITTEN = CLEAR;
            attributes.TPMA_NV_WRITELOCKED = CLEAR;
        }

        // Reset NV data for orderly values that are not counters
        // NOTE: The function has already exited on a TPM Resume, so the only
        // things being processed are TPM Restart and TPM Reset
        if( type == SU_RESET
                && attributes.TPMA_NV_ORDERLY == SET
                && attributes.TPMA_NV_COUNTER == CLEAR
          )
            attributes.TPMA_NV_WRITTEN = CLEAR;

        // Write NV Index info back if it has changed
        if(*((UINT32 *)&attributes) != *((UINT32 *)&nvIndex.publicArea.attributes))
        {
            nvIndex.publicArea.attributes = attributes;
            _plat__NvMemoryWrite(indexAddr, sizeof(NV_INDEX), &nvIndex);

            // Set the flag that a NV write happens
            g_updateNV = TRUE;
        }
        // Set the lower bits in an orderly counter to 1 for a non-orderly startup
        if( g_prevOrderlyState == SHUTDOWN_NONE
                && attributes.TPMA_NV_WRITTEN == SET)
        {
            if( attributes.TPMA_NV_ORDERLY == SET
                    && attributes.TPMA_NV_COUNTER == SET)
            {
                TPMI_RH_NV_INDEX nvHandle;
                UINT64 counter;

                // Read NV handle
                _plat__NvMemoryRead(currentAddr, sizeof(TPM_HANDLE), &nvHandle);

                // Read the counter value saved to NV upon the last roll over.
                // Do not use RAM backed storage for this once.
                nvIndex.publicArea.attributes.TPMA_NV_ORDERLY = CLEAR;
                NvGetIntIndexData(nvHandle, &nvIndex, &counter);
                nvIndex.publicArea.attributes.TPMA_NV_ORDERLY = SET;

                // Set the lower bits of counter to 1's
                counter |= MAX_ORDERLY_COUNT;

                // Write back to RAM
                NvWriteIndexData(nvHandle, &nvIndex, 0, sizeof(counter), &counter);

                // No write to NV because an orderly shutdown will update the
                // counters.

            }
        }
    }

    return;

}
BOOL
NvIsUndefinedIndex(
    TPMI_RH_NV_INDEX handle               // IN: handle
)
{
    UINT32 entityAddr;                // offset points to the entity

    pAssert(HandleGetType(handle) == TPM_HT_NV_INDEX);

    // Find the address of index
    entityAddr = NvFindHandle(handle);

    // If handle is not found, return TPM_RC_SUCCESS
    if(entityAddr == 0)
        return TPM_RC_SUCCESS;

    // NV Index is defined
    return TPM_RC_NV_DEFINED;
}

// E r
// M e
// TPM_RC_HANDLE


// TPM_RC_NV_READLOCKED

// TPM_RC_NV_WRITELOCKED


TPM_RC
NvIndexIsAccessible(
    TPMI_RH_NV_INDEX handle,              // IN: handle
    TPM_CC commandCode          // IN: the command
)
{
    UINT32 entityAddr;          // offset points to the entity
    NV_INDEX nvIndex;             //

    pAssert(HandleGetType(handle) == TPM_HT_NV_INDEX);

    // Find the address of index
    entityAddr = NvFindHandle(handle);

    // If handle is not found, return TPM_RC_HANDLE
    if(entityAddr == 0)
        return TPM_RC_HANDLE;

    // Read NV Index info structure
    _plat__NvMemoryRead(entityAddr + sizeof(TPM_HANDLE), sizeof(NV_INDEX),
                        &nvIndex);

    if(gc.shEnable == FALSE || gc.phEnableNV == FALSE)
    {
        // if shEnable is CLEAR, an ownerCreate NV Index should not be
        // indicated as present
        if(nvIndex.publicArea.attributes.TPMA_NV_PLATFORMCREATE == CLEAR)
        {
            if(gc.shEnable == FALSE)
                return TPM_RC_HANDLE;
        }
        // if phEnableNV is CLEAR, a platform created Index should not
        // be visible
        else if(gc.phEnableNV == FALSE)
            return TPM_RC_HANDLE;
    }

    // If the Index is write locked and this is an NV Write operation...
    if( nvIndex.publicArea.attributes.TPMA_NV_WRITELOCKED
            && IsWriteOperation(commandCode))
    {
        // then return a locked indication unless the command is TPM2_NV_WriteLock
        if(commandCode != TPM_CC_NV_WriteLock)
            return TPM_RC_NV_LOCKED;
        return TPM_RC_SUCCESS;
    }
    // If the Index is read locked and this is an NV Read operation...
    if( nvIndex.publicArea.attributes.TPMA_NV_READLOCKED
            && IsReadOperation(commandCode))
    {
        // then return a locked indication unless the command is TPM2_NV_ReadLock
        if(commandCode != TPM_CC_NV_ReadLock)
            return TPM_RC_NV_LOCKED;
        return TPM_RC_SUCCESS;
    }

    // NV Index is accessible
    return TPM_RC_SUCCESS;
}
static BOOL
NvIsUndefinedEvictHandle(
    TPM_HANDLE handle                      // IN: handle
)
{
    UINT32 entityAddr;                 // offset points to the entity
    pAssert(HandleGetType(handle) == TPM_HT_PERSISTENT);

    // Find the address of evict object
    entityAddr = NvFindHandle(handle);

    // If handle is not found, return TRUE
    if(entityAddr == 0)
        return TRUE;
    else
        return FALSE;
}

// E r
// M e
// TPM_RC_HANDLE

TPM_RC
NvGetEvictObject(
    TPM_HANDLE handle,                 // IN: handle
    OBJECT *object                   // OUT: object data
)
{
    UINT32 entityAddr;                       // offset points to the entity
    TPM_RC result = TPM_RC_SUCCESS;

    pAssert(HandleGetType(handle) == TPM_HT_PERSISTENT);

    // Find the address of evict object
    entityAddr = NvFindHandle(handle);

    // If handle is not found, return an error
    if(entityAddr == 0)
        result = TPM_RC_HANDLE;
    else
        // Read evict object
        _plat__NvMemoryRead(entityAddr + sizeof(TPM_HANDLE),
                            sizeof(OBJECT),
                            object);

    // whether there is an error or not, make sure that the evict
    // status of the object is set so that the slot will get freed on exit
    object->attributes.evict = SET;

    return result;
}
void
NvGetIndexInfo(
    TPMI_RH_NV_INDEX handle,                     // IN: handle
    NV_INDEX *nvIndex                    // OUT: NV index structure
)
{
    UINT32 entityAddr;                 // offset points to the entity

    pAssert(HandleGetType(handle) == TPM_HT_NV_INDEX);

    // Find the address of NV index
    entityAddr = NvFindHandle(handle);
    pAssert(entityAddr != 0);

    // This implementation uses the default format so just
    // read the data in
    _plat__NvMemoryRead(entityAddr + sizeof(TPM_HANDLE), sizeof(NV_INDEX),
                        nvIndex);

    return;
}
UINT64
NvInitialCounter(
    void
)
{
    UINT64 maxCount;
    NV_ITER iter = NV_ITER_INIT;
    UINT32 currentAddr;

    // Read the maxCount value
    maxCount = NvReadMaxCount();

    // Iterate all existing counters
    while((currentAddr = NvNextIndex(&iter)) != 0)
    {
        TPMI_RH_NV_INDEX nvHandle;
        NV_INDEX nvIndex;

        // Read NV handle
        _plat__NvMemoryRead(currentAddr, sizeof(TPM_HANDLE), &nvHandle);

        // Get NV Index
        NvGetIndexInfo(nvHandle, &nvIndex);
        if( nvIndex.publicArea.attributes.TPMA_NV_COUNTER == SET
                && nvIndex.publicArea.attributes.TPMA_NV_WRITTEN == SET)
        {
            UINT64 countValue;
            // Read counter value
            NvGetIntIndexData(nvHandle, &nvIndex, &countValue);
            if(countValue > maxCount)
                maxCount = countValue;
        }
    }
    // Initialize the new counter value to be maxCount + 1
    // A counter is only initialized the first time it is written. The
    // way to write a counter is with TPM2_NV_INCREMENT(). Since the
    // "initial" value of a defined counter is the largest count value that
    // may have existed in this index previously, then the first use would
    // add one to that value.
    return maxCount;
}
void
NvGetIndexData(
    TPMI_RH_NV_INDEX handle,               // IN: handle
    NV_INDEX *nvIndex,              // IN: RAM image of index header
    UINT32 offset,               // IN: offset of NV data
    UINT16 size,                 // IN: size of NV data
    void *data                  // OUT: data buffer
)
{

    pAssert(nvIndex->publicArea.attributes.TPMA_NV_WRITTEN == SET);

    if( nvIndex->publicArea.attributes.TPMA_NV_BITS == SET
            || nvIndex->publicArea.attributes.TPMA_NV_COUNTER == SET)
    {
        // Read bit or counter data in canonical form
        UINT64 dataInInt;
        NvGetIntIndexData(handle, nvIndex, &dataInInt);
        UINT64_TO_BYTE_ARRAY(dataInInt, (BYTE *)data);
    }
    else
    {
        if(nvIndex->publicArea.attributes.TPMA_NV_ORDERLY == SET)
        {
            UINT32 ramAddr;

            // Get data from RAM buffer
            ramAddr = NvGetRAMIndexOffset(handle);
            MemoryCopy(data, s_ramIndex + ramAddr + offset, size, size);
        }
        else
        {
            UINT32 entityAddr;
            entityAddr = NvFindHandle(handle);
            // Get data from NV
            // Skip NV Index info, read data buffer
            entityAddr += sizeof(TPM_HANDLE) + sizeof(NV_INDEX) + offset;
            // Read the data
            _plat__NvMemoryRead(entityAddr, size, data);
        }
    }
    return;
}
void
NvGetIntIndexData(
    TPMI_RH_NV_INDEX handle,               // IN: handle
    NV_INDEX *nvIndex,              // IN: RAM image of NV Index header
    UINT64 *data                  // IN: UINT64 pointer for counter or bit
)
{
    // Validate that index has been written and is the right type
    pAssert( nvIndex->publicArea.attributes.TPMA_NV_WRITTEN == SET
             && ( nvIndex->publicArea.attributes.TPMA_NV_BITS == SET
                  || nvIndex->publicArea.attributes.TPMA_NV_COUNTER == SET
                )
           );

    // bit and counter value is store in native format for TPM CPU. So we directly
    // copy the contents of NV to output data buffer
    if(nvIndex->publicArea.attributes.TPMA_NV_ORDERLY == SET)
    {
        UINT32 ramAddr;

        // Get data from RAM buffer
        ramAddr = NvGetRAMIndexOffset(handle);
        MemoryCopy(data, s_ramIndex + ramAddr, sizeof(*data), sizeof(*data));
    }
    else
    {
        UINT32 entityAddr;
        entityAddr = NvFindHandle(handle);

        // Get data from NV
        // Skip NV Index info, read data buffer
        _plat__NvMemoryRead(
            entityAddr + sizeof(TPM_HANDLE) + sizeof(NV_INDEX),
            sizeof(UINT64), data);
    }

    return;
}

// E r
// M e
// TPM_RC_NV_RATE
// TPM_RC_NV_UNAVAILABLE

TPM_RC
NvWriteIndexInfo(
    TPMI_RH_NV_INDEX handle,                 // IN: handle
    NV_INDEX *nvIndex                // IN: NV Index info to be written
)
{
    UINT32 entryAddr;
    TPM_RC result;

    // Get the starting offset for the index in the RAM image of NV
    entryAddr = NvFindHandle(handle);
    pAssert(entryAddr != 0);

    // Step over the link value
    entryAddr = entryAddr + sizeof(TPM_HANDLE);

    // If the index data is actually changed, then a write to NV is required
    if(_plat__NvIsDifferent(entryAddr, sizeof(NV_INDEX),nvIndex))
    {
        // Make sure that NV is available
        result = NvIsAvailable();
        if(result != TPM_RC_SUCCESS)
            return result;
        _plat__NvMemoryWrite(entryAddr, sizeof(NV_INDEX), nvIndex);
        g_updateNV = TRUE;
    }
    return TPM_RC_SUCCESS;
}

// E r
// M e
// TPM_RC_NV_RATE
// TPM_RC_NV_UNAVAILABLE

TPM_RC
NvWriteIndexData(
    TPMI_RH_NV_INDEX handle,                  // IN: handle
    NV_INDEX *nvIndex,                 // IN: RAM copy of NV Index
    UINT32 offset,                  // IN: offset of NV data
    UINT32 size,                    // IN: size of NV data
    void *data                     // OUT: data buffer
)
{
    TPM_RC result;
    // Validate that write falls within range of the index
    pAssert(nvIndex->publicArea.dataSize >= offset + size);

    // Update TPMA_NV_WRITTEN bit if necessary
    if(nvIndex->publicArea.attributes.TPMA_NV_WRITTEN == CLEAR)
    {
        nvIndex->publicArea.attributes.TPMA_NV_WRITTEN = SET;
        result = NvWriteIndexInfo(handle, nvIndex);
        if(result != TPM_RC_SUCCESS)
            return result;
    }

    // Check to see if process for an orderly index is required.
    if(nvIndex->publicArea.attributes.TPMA_NV_ORDERLY == SET)
    {
        UINT32 ramAddr;

        // Write data to RAM buffer
        ramAddr = NvGetRAMIndexOffset(handle);
        MemoryCopy(s_ramIndex + ramAddr + offset, data, size,
                   sizeof(s_ramIndex) - ramAddr - offset);

        // NV update does not happen for orderly index. Have
        // to clear orderlyState to reflect that we have changed the
        // NV and an orderly shutdown is required. Only going to do this if we
        // are not processing a counter that has just rolled over
        if(g_updateNV == FALSE)
            g_clearOrderly = TRUE;
    }
    // Need to process this part if the Index isn't orderly or if it is
    // an orderly counter that just rolled over.
    if(g_updateNV || nvIndex->publicArea.attributes.TPMA_NV_ORDERLY == CLEAR)
    {
        // Processing for an index with TPMA_NV_ORDERLY CLEAR
        UINT32 entryAddr = NvFindHandle(handle);

        pAssert(entryAddr != 0);

        // Offset into the index to the first byte of the data to be written
        entryAddr += sizeof(TPM_HANDLE) + sizeof(NV_INDEX) + offset;

        // If the data is actually changed, then a write to NV is required
        if(_plat__NvIsDifferent(entryAddr, size, data))
        {
            // Make sure that NV is available
            result = NvIsAvailable();
            if(result != TPM_RC_SUCCESS)
                return result;
            _plat__NvMemoryWrite(entryAddr, size, data);
            g_updateNV = TRUE;
        }
    }
    return TPM_RC_SUCCESS;
}
UINT16
NvGetName(
    TPMI_RH_NV_INDEX handle,             // IN: handle of the index
    NAME *name                // OUT: name of the index
)
{
    UINT16 dataSize, digestSize;
    NV_INDEX nvIndex;
    BYTE marshalBuffer[sizeof(TPMS_NV_PUBLIC)];
    BYTE *buffer;
    HASH_STATE hashState;

    // Get NV public info
    NvGetIndexInfo(handle, &nvIndex);

    // Marshal public area
    buffer = marshalBuffer;
    dataSize = TPMS_NV_PUBLIC_Marshal(&nvIndex.publicArea, &buffer, NULL);

    // hash public area
    digestSize = CryptStartHash(nvIndex.publicArea.nameAlg, &hashState);
    CryptUpdateDigest(&hashState, dataSize, marshalBuffer);

    // Complete digest leaving room for the nameAlg
    CryptCompleteHash(&hashState, digestSize, &((BYTE *)name)[2]);

    // Include the nameAlg
    UINT16_TO_BYTE_ARRAY(nvIndex.publicArea.nameAlg, (BYTE *)name);
    return digestSize + 2;
}

// E r
// M e
// TPM_RC_NV_SPACE

TPM_RC
NvDefineIndex(
    TPMS_NV_PUBLIC *publicArea,                  // IN: A template for an area to create.
    TPM2B_AUTH *authValue                    // IN: The initial authorization value
)
{
    // The buffer to be written to NV memory
    BYTE nvBuffer[sizeof(TPM_HANDLE) + sizeof(NV_INDEX)];

    NV_INDEX *nvIndex;                           // a pointer to the NV_INDEX data in
    // nvBuffer
    UINT16 entrySize;                          // size of entry

    entrySize = sizeof(TPM_HANDLE) + sizeof(NV_INDEX) + publicArea->dataSize;

    // Check if we have enough space to create the NV Index
    // In this implementation, the only resource limitation is the available NV
    // space. Other implementation may have other limitation on counter or on
    // NV slot
    if(!NvTestSpace(entrySize, TRUE)) return TPM_RC_NV_SPACE;

    // if the index to be defined is RAM backed, check RAM space availability
    // as well
    if(publicArea->attributes.TPMA_NV_ORDERLY == SET
            && !NvTestRAMSpace(publicArea->dataSize))
        return TPM_RC_NV_SPACE;

    // Copy input value to nvBuffer
    // Copy handle
    * (TPM_HANDLE *) nvBuffer = publicArea->nvIndex;

    // Copy NV_INDEX
    nvIndex = (NV_INDEX *) (nvBuffer + sizeof(TPM_HANDLE));
    nvIndex->publicArea = *publicArea;
    nvIndex->authValue = *authValue;

    // Add index to NV memory
    NvAdd(entrySize, sizeof(TPM_HANDLE) + sizeof(NV_INDEX), nvBuffer);

    // If the data of NV Index is RAM backed, add the data area in RAM as well
    if(publicArea->attributes.TPMA_NV_ORDERLY == SET)
        NvAddRAM(publicArea->nvIndex, publicArea->dataSize);

    return TPM_RC_SUCCESS;
}

// E r
// M e
// TPM_RC_NV_HANDLE
// TPM_RC_NV_SPACE

TPM_RC
NvAddEvictObject(
    TPMI_DH_OBJECT evictHandle,                  // IN: new evict handle
    OBJECT *object                          // IN: object to be added
)
{
    // The buffer to be written to NV memory
    BYTE nvBuffer[sizeof(TPM_HANDLE) + sizeof(OBJECT)];

    OBJECT *nvObject;                              // a pointer to the OBJECT data in
    // nvBuffer
    UINT16 entrySize;                              // size of entry

    // evict handle type should match the object hierarchy
    pAssert( ( NvIsPlatformPersistentHandle(evictHandle)
               && object->attributes.ppsHierarchy == SET)
             || ( NvIsOwnerPersistentHandle(evictHandle)
                  && ( object->attributes.spsHierarchy == SET
                       || object->attributes.epsHierarchy == SET)));

    // An evict needs 4 bytes of handle + sizeof OBJECT
    entrySize = sizeof(TPM_HANDLE) + sizeof(OBJECT);

    // Check if we have enough space to add the evict object
    // An evict object needs 8 bytes in index table + sizeof OBJECT
    // In this implementation, the only resource limitation is the available NV
    // space. Other implementation may have other limitation on evict object
    // handle space
    if(!NvTestSpace(entrySize, FALSE)) return TPM_RC_NV_SPACE;

    // Allocate a new evict handle
    if(!NvIsUndefinedEvictHandle(evictHandle))
        return TPM_RC_NV_DEFINED;

    // Copy evict object to nvBuffer
    // Copy handle
    * (TPM_HANDLE *) nvBuffer = evictHandle;

    // Copy OBJECT
    nvObject = (OBJECT *) (nvBuffer + sizeof(TPM_HANDLE));
    *nvObject = *object;

    // Set evict attribute and handle
    nvObject->attributes.evict = SET;
    nvObject->evictHandle = evictHandle;

    // Add evict to NV memory
    NvAdd(entrySize, entrySize, nvBuffer);

    return TPM_RC_SUCCESS;

}
void
NvDeleteEntity(
    TPM_HANDLE handle                           // IN: handle of entity to be deleted
)
{
    UINT32 entityAddr;                         // pointer to entity

    entityAddr = NvFindHandle(handle);
    pAssert(entityAddr != 0);

    if(HandleGetType(handle) == TPM_HT_NV_INDEX)
    {
        NV_INDEX nvIndex;

        // Read the NV Index info
        _plat__NvMemoryRead(entityAddr + sizeof(TPM_HANDLE), sizeof(NV_INDEX),
                            &nvIndex);

        // If the entity to be deleted is a counter with the maximum counter
        // value, record it in NV memory
        if(nvIndex.publicArea.attributes.TPMA_NV_COUNTER == SET
                && nvIndex.publicArea.attributes.TPMA_NV_WRITTEN == SET)
        {
            UINT64 countValue;
            UINT64 maxCount;
            NvGetIntIndexData(handle, &nvIndex, &countValue);
            maxCount = NvReadMaxCount();
            if(countValue > maxCount)
                NvWriteMaxCount(countValue);
        }
        // If the NV Index is RAM back, delete the RAM data as well
        if(nvIndex.publicArea.attributes.TPMA_NV_ORDERLY == SET)
            NvDeleteRAM(handle);
    }
    NvDelete(entityAddr);

    return;

}
void
NvFlushHierarchy(
    TPMI_RH_HIERARCHY hierarchy                   // IN: hierarchy to be flushed.
)
{
    NV_ITER iter = NV_ITER_INIT;
    UINT32 currentAddr;

    while((currentAddr = NvNext(&iter)) != 0)
    {
        TPM_HANDLE entityHandle;

        // Read handle information.
        _plat__NvMemoryRead(currentAddr, sizeof(TPM_HANDLE), &entityHandle);

        if(HandleGetType(entityHandle) == TPM_HT_NV_INDEX)
        {
            // Handle NV Index
            NV_INDEX nvIndex;

            // If flush endorsement or platform hierarchy, no NV Index would be
            // flushed
            if(hierarchy == TPM_RH_ENDORSEMENT || hierarchy == TPM_RH_PLATFORM)
                continue;
            _plat__NvMemoryRead(currentAddr + sizeof(TPM_HANDLE),
                                sizeof(NV_INDEX), &nvIndex);

            // For storage hierarchy, flush OwnerCreated index
            if( nvIndex.publicArea.attributes.TPMA_NV_PLATFORMCREATE == CLEAR)
            {
                // Delete the NV Index
                NvDelete(currentAddr);

                // Re-iterate from beginning after a delete
                iter = NV_ITER_INIT;

                // If the NV Index is RAM back, delete the RAM data as well
                if(nvIndex.publicArea.attributes.TPMA_NV_ORDERLY == SET)
                    NvDeleteRAM(entityHandle);
            }
        }
        else if(HandleGetType(entityHandle) == TPM_HT_PERSISTENT)
        {
            OBJECT object;

            // Get evict object
            NvGetEvictObject(entityHandle, &object);

            // If the evict object belongs to the hierarchy to be flushed
            if( ( hierarchy == TPM_RH_PLATFORM
                    && object.attributes.ppsHierarchy == SET)
                    || ( hierarchy == TPM_RH_OWNER
                         && object.attributes.spsHierarchy == SET)
                    || ( hierarchy == TPM_RH_ENDORSEMENT
                         && object.attributes.epsHierarchy == SET)
              )
            {
                // Delete the evict object
                NvDelete(currentAddr);

                // Re-iterate from beginning after a delete
                iter = NV_ITER_INIT;
            }
        }
        else
        {
            pAssert(FALSE);
        }
    }

    return;
}
void
NvSetGlobalLock(
    void
)
{
    NV_ITER iter = NV_ITER_INIT;
    UINT32 currentAddr;

    // Check all Indices
    while((currentAddr = NvNextIndex(&iter)) != 0)
    {
        NV_INDEX nvIndex;

        // Read the index data
        _plat__NvMemoryRead(currentAddr + sizeof(TPM_HANDLE),
                            sizeof(NV_INDEX), &nvIndex);

        // See if it should be locked
        if(nvIndex.publicArea.attributes.TPMA_NV_GLOBALLOCK == SET)
        {

            // if so, lock it
            nvIndex.publicArea.attributes.TPMA_NV_WRITELOCKED = SET;

            _plat__NvMemoryWrite(currentAddr + sizeof(TPM_HANDLE),
                                 sizeof(NV_INDEX), &nvIndex);
            // Set the flag that a NV write happens
            g_updateNV = TRUE;
        }
    }

    return;

}
static void
InsertSort(
    TPML_HANDLE *handleList,              // IN/OUT: sorted handle list
    UINT32 count,                   // IN: maximum count in the handle list
    TPM_HANDLE entityHandle             // IN: handle to be inserted
)
{
    UINT32 i, j;
    UINT32 originalCount;

    // For a corner case that the maximum count is 0, do nothing
    if(count == 0) return;

    // For empty list, add the handle at the beginning and return
    if(handleList->count == 0)
    {
        handleList->handle[0] = entityHandle;
        handleList->count++;
        return;
    }

    // Check if the maximum of the list has been reached
    originalCount = handleList->count;
    if(originalCount < count)
        handleList->count++;

    // Insert the handle to the list
    for(i = 0; i < originalCount; i++)
    {
        if(handleList->handle[i] > entityHandle)
        {
            for(j = handleList->count - 1; j > i; j--)
            {
                handleList->handle[j] = handleList->handle[j-1];
            }
            break;
        }
    }

    // If a slot was found, insert the handle in this position
    if(i < originalCount || handleList->count > originalCount)
        handleList->handle[i] = entityHandle;

    return;
}
TPMI_YES_NO
NvCapGetPersistent(
    TPMI_DH_OBJECT handle,                        // IN: start handle
    UINT32 count,                         // IN: maximum number of returned handle
    TPML_HANDLE *handleList                    // OUT: list of handle
)
{
    TPMI_YES_NO more = NO;
    NV_ITER iter = NV_ITER_INIT;
    UINT32 currentAddr;

    pAssert(HandleGetType(handle) == TPM_HT_PERSISTENT);

    // Initialize output handle list
    handleList->count = 0;

    // The maximum count of handles we may return is MAX_CAP_HANDLES
    if(count > MAX_CAP_HANDLES) count = MAX_CAP_HANDLES;

    while((currentAddr = NvNextEvict(&iter)) != 0)
    {
        TPM_HANDLE entityHandle;

        // Read handle information.
        _plat__NvMemoryRead(currentAddr, sizeof(TPM_HANDLE), &entityHandle);

        // Ignore persistent handles that have values less than the input handle
        if(entityHandle < handle)
            continue;

        // if the handles in the list have reached the requested count, and there
        // are still handles need to be inserted, indicate that there are more.
        if(handleList->count == count)
            more = YES;

        // A handle with a value larger than start handle is a candidate
        // for return. Insert sort it to the return list. Insert sort algorithm
        // is chosen here for simplicity based on the assumption that the total
        // number of NV Indices is small. For an implementation that may allow
        // large number of NV Indices, a more efficient sorting algorithm may be
        // used here.
        InsertSort(handleList, count, entityHandle);

    }
    return more;
}
TPMI_YES_NO
NvCapGetIndex(
    TPMI_DH_OBJECT handle,                       // IN: start handle
    UINT32 count,                        // IN: maximum number of returned handle
    TPML_HANDLE *handleList                   // OUT: list of handle
)
{
    TPMI_YES_NO more = NO;
    NV_ITER iter = NV_ITER_INIT;
    UINT32 currentAddr;

    pAssert(HandleGetType(handle) == TPM_HT_NV_INDEX);

    // Initialize output handle list
    handleList->count = 0;

    // The maximum count of handles we may return is MAX_CAP_HANDLES
    if(count > MAX_CAP_HANDLES) count = MAX_CAP_HANDLES;

    while((currentAddr = NvNextIndex(&iter)) != 0)
    {
        TPM_HANDLE entityHandle;

        // Read handle information.
        _plat__NvMemoryRead(currentAddr, sizeof(TPM_HANDLE), &entityHandle);

        // Ignore index handles that have values less than the 'handle'
        if(entityHandle < handle)
            continue;

        // if the count of handles in the list has reached the requested count,
        // and there are still handles to report, set more.
        if(handleList->count == count)
            more = YES;

        // A handle with a value larger than start handle is a candidate
        // for return. Insert sort it to the return list. Insert sort algorithm
        // is chosen here for simplicity based on the assumption that the total
        // number of NV Indices is small. For an implementation that may allow
        // large number of NV Indices, a more efficient sorting algorithm may be
        // used here.
        InsertSort(handleList, count, entityHandle);
    }
    return more;
}
UINT32
NvCapGetIndexNumber(
    void
)
{
    UINT32 num = 0;
    NV_ITER iter = NV_ITER_INIT;

    while(NvNextIndex(&iter) != 0) num++;

    return num;
}
UINT32
NvCapGetPersistentNumber(
    void
)
{
    UINT32 num = 0;
    NV_ITER iter = NV_ITER_INIT;

    while(NvNextEvict(&iter) != 0) num++;

    return num;
}
UINT32
NvCapGetPersistentAvail(
    void
)
{
    UINT32 availSpace;
    UINT32 objectSpace;

    // Compute the available space in NV storage
    availSpace = NvGetFreeByte();

    // Get the space needed to add a persistent object to NV storage
    objectSpace = NvGetEvictObjectSize();

    return availSpace    / objectSpace;
}
UINT32
NvCapGetCounterNumber(
    void
)
{
    NV_ITER iter = NV_ITER_INIT;
    UINT32 currentAddr;
    UINT32 num = 0;

    while((currentAddr = NvNextIndex(&iter)) != 0)
    {
        NV_INDEX nvIndex;

        // Get NV Index info
        _plat__NvMemoryRead(currentAddr + sizeof(TPM_HANDLE),
                            sizeof(NV_INDEX), &nvIndex);
        if(nvIndex.publicArea.attributes.TPMA_NV_COUNTER == SET) num++;
    }

    return num;
}
UINT32
NvCapGetCounterAvail(
    void
)
{
    UINT32 availNVSpace;
    UINT32 availRAMSpace;
    UINT32 counterNVSpace;
    UINT32 counterRAMSpace;
    UINT32 persistentNum = NvCapGetPersistentNumber();

    // Get the available space in NV storage
    availNVSpace = NvGetFreeByte();

    if (persistentNum < MIN_EVICT_OBJECTS)
    {
        // Some space have to be reserved for evict object. Adjust availNVSpace.
        UINT32 reserved = (MIN_EVICT_OBJECTS - persistentNum)
                          * NvGetEvictObjectSize();
        if (reserved > availNVSpace)
            availNVSpace = 0;
        else
            availNVSpace -= reserved;
    }

    // Get the space needed to add a counter index to NV storage
    counterNVSpace = NvGetCounterSize();

    // Compute the available space in RAM
    availRAMSpace = RAM_INDEX_SPACE - s_ramIndexSize;

    // Compute the space needed to add a counter index to RAM storage
    // It takes an size field, a handle and sizeof(UINT64) for counter data
    counterRAMSpace = sizeof(UINT32) + sizeof(TPM_HANDLE) + sizeof(UINT64);

    // Return the min of counter number in NV and in RAM
    if(availNVSpace                 / counterNVSpace > availRAMSpace              / counterRAMSpace)
        return availRAMSpace                       / counterRAMSpace;
    else
        return availNVSpace             / counterNVSpace;
}
