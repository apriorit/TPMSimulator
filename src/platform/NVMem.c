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

// C.6.1. Introduction
// This file contains the NV read and write access methods. This implementation uses RAM/file and does
// not manage the RAM/file as NV blocks. The implementation may become more sophisticated over time.
// C.6.2. Includes
#include <memory.h>
#include <string.h>
#include "PlatformData.h"
#include "TpmError.h"
#include "assert.h"
LIB_EXPORT void
_plat__NvErrors(
    BOOL recoverable,
    BOOL unrecoverable
)
{
    s_NV_unrecoverable = unrecoverable;
    s_NV_recoverable = recoverable;
}
LIB_EXPORT int
_plat__NVEnable(
    void *platParameter        // IN: platform specific parameter
)
{
    (platParameter);                             // to keep compiler quiet
    // Start assuming everything is OK
    s_NV_unrecoverable = FALSE;
    s_NV_recoverable = FALSE;

#ifdef FILE_BACKED_NV

    if(s_NVFile != NULL) return 0;

    // Try to open an exist NVChip file for read/write
#if defined(_Win32) || defined(WIN32)
    if(0 != fopen_s(&s_NVFile, "NVChip", "r+b"))
        s_NVFile = NULL;
#else
    s_NVFile = fopen("/tmp/NVChip", "r+b");
#endif

    if(NULL != s_NVFile)
    {
        // See if the NVChip file is empty
        fseek(s_NVFile, 0, SEEK_END);
        if(0 == ftell(s_NVFile))
            s_NVFile = NULL;
    }

    if(s_NVFile == NULL)
    {
        // Initialize all the byte in the new file to 0
        memset(s_NV, 0, NV_MEMORY_SIZE);

        // If NVChip file does not exist, try to create it for read/write
#if defined(_Win32) || defined(WIN32)
        fopen_s(&s_NVFile, "NVChip", "w+b");
#else
        s_NVFile = fopen("/tmp/NVChip", "w+b");
#endif
        // Start initialize at the end of new file
        fseek(s_NVFile, 0, SEEK_END);
        // Write 0s to NVChip file
        fwrite(s_NV, 1, NV_MEMORY_SIZE, s_NVFile);
    }
    else
    {
        // If NVChip file exist, assume the size is correct
        fseek(s_NVFile, 0, SEEK_END);
        assert(ftell(s_NVFile) == NV_MEMORY_SIZE);
        // read NV file data to memory
        fseek(s_NVFile, 0, SEEK_SET);
        fread(s_NV, NV_MEMORY_SIZE, 1, s_NVFile);
    }
#endif
    // NV contents have been read and the error checks have been performed. For
    // simulation purposes, use the signaling interface to indicate if an error is
    // to be simulated and the type of the error.
    if(s_NV_unrecoverable)
        return -1;
    return s_NV_recoverable;
}
LIB_EXPORT void
_plat__NVDisable(
    void
)
{
#ifdef FILE_BACKED_NV

    assert(s_NVFile != NULL);
    // Close NV file
    fclose(s_NVFile);
    // Set file handle to NULL
    s_NVFile = NULL;

#endif

    return;
}
LIB_EXPORT int
_plat__IsNvAvailable(
    void
)
{
    // NV is not available if the TPM is in failure mode
    if(!s_NvIsAvailable)
        return 1;

#ifdef FILE_BACKED_NV
    if(s_NVFile == NULL)
        return 1;
#endif

    return 0;

}
LIB_EXPORT void
_plat__NvMemoryRead(
    unsigned int startOffset,    // IN: read start
    unsigned int size,           // IN: size of bytes to read
    void *data              // OUT: data buffer
)
{
    assert(startOffset + size <= NV_MEMORY_SIZE);

    // Copy data from RAM
    memcpy(data, &s_NV[startOffset], size);
    return;
}
LIB_EXPORT BOOL
_plat__NvIsDifferent(
    unsigned int startOffset,                // IN: read start
    unsigned int size,                       // IN: size of bytes to read
    void *data                       // IN: data buffer
)
{
    return (memcmp(&s_NV[startOffset], data, size) != 0);
}
LIB_EXPORT void
_plat__NvMemoryWrite(
    unsigned int startOffset,                // IN: write start
    unsigned int size,                       // IN: size of bytes to write
    void *data                       // OUT: data buffer
)
{
    assert(startOffset + size <= NV_MEMORY_SIZE);

    // Copy the data to the NV image
    memcpy(&s_NV[startOffset], data, size);
}
LIB_EXPORT void
_plat__NvMemoryMove(
    unsigned int sourceOffset,               // IN: source offset
    unsigned int destOffset,                 // IN: destination offset
    unsigned int size                        // IN: size of data being moved
)
{
    assert(sourceOffset + size <= NV_MEMORY_SIZE);
    assert(destOffset + size <= NV_MEMORY_SIZE);

    // Move data in RAM
    memmove(&s_NV[destOffset], &s_NV[sourceOffset], size);

    return;
}
LIB_EXPORT int
_plat__NvCommit(
    void
)
{
#ifdef FILE_BACKED_NV
    // If NV file is not available, return failure
    if(s_NVFile == NULL)
        return 1;

    // Write RAM data to NV
    fseek(s_NVFile, 0, SEEK_SET);
    fwrite(s_NV, 1, NV_MEMORY_SIZE, s_NVFile);
    return 0;
#else
    return 0;
#endif

}
LIB_EXPORT void
_plat__SetNvAvail(
    void
)
{
    s_NvIsAvailable = TRUE;
    return;
}
LIB_EXPORT void
_plat__ClearNvAvail(
    void
)
{
    s_NvIsAvailable = FALSE;
    return;
}
