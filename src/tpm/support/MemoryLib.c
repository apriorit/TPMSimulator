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

// 9.12.1 Description
// This file contains a set of miscellaneous memory manipulation routines. Many of the functions have the
// same semantics as functions defined in string.h. Those functions are not used in the TPM in order to
// avoid namespace contamination.
// 9.12.2 Includes and Data Definitions
#define MEMORY_LIB_C
#include "InternalRoutines.h"
LIB_EXPORT void
MemoryMove(
    void *destination,           // OUT: move destination
    const void *source,                // IN: move source
    UINT32 size,               // IN: number of octets to moved
    UINT32 dSize               // IN: size of the receive buffer
)
{
    const BYTE *p = (BYTE *)source;
    BYTE *q = (BYTE *)destination;

    if(destination == NULL || source == NULL)
        return;

    pAssert(size <= dSize);
    // if the destination buffer has a lower address than the
    // source, then moving bytes in ascending order is safe.
    dSize -= size;

    if (p>q || (p+size <= q))
    {
        while(size--)
            *q++ = *p++;
    }
    // If the destination buffer has a higher address than the
    // source, then move bytes from the end to the beginning.
    else if (p < q)
    {
        p += size;
        q += size;
        while (size--)
            *--q = *--p;
    }

    // If the source and destination address are the same, nothing to move.
    return;
}
//%#define MemoryCopy(destination, source, size, destSize) \
//% MemoryMove((destination), (source), (size), (destSize))
LIB_EXPORT BOOL
MemoryEqual(
    const void *buffer1,              // IN: compare buffer1
    const void *buffer2,              // IN: compare buffer2
    UINT32 size                   // IN: size of bytes being compared
)
{
    BOOL equal = TRUE;
    const BYTE *b1, *b2;

    b1 = (BYTE *)buffer1;
    b2 = (BYTE *)buffer2;

    // Compare all bytes so that there is no leakage of information
    // due to timing differences.
    for(; size > 0; size--)
        equal = (*b1++ == *b2++) && equal;

    return equal;
}
LIB_EXPORT INT16
MemoryCopy2B(
    TPM2B *dest,              // OUT: receiving TPM2B
    const TPM2B *source,            // IN: source TPM2B
    UINT16 dSize               // IN: size of the receiving buffer
)
{

    if(dest == NULL)
        return 0;
    if(source == NULL)
        dest->size = 0;
    else
    {
        dest->size = source->size;
        MemoryMove(dest->buffer, source->buffer, dest->size, dSize);
    }
    return dest->size;
}
LIB_EXPORT void
MemoryConcat2B(
    TPM2B *aInOut,            // IN/OUT: destination 2B
    TPM2B *bIn,               // IN: second 2B
    UINT16 aSize               // IN: The size of aInOut.buffer (max values for
    // aInOut.size)
)
{
    MemoryMove(&aInOut->buffer[aInOut->size],
               bIn->buffer,
               bIn->size,
               aSize - aInOut->size);
    aInOut->size = aInOut->size + bIn->size;
    return;
}
LIB_EXPORT BOOL
Memory2BEqual(
    const TPM2B *aIn,               // IN: compare value
    const TPM2B *bIn                // IN: compare value
)
{
    if(aIn->size != bIn->size)
        return FALSE;

    return MemoryEqual(aIn->buffer, bIn->buffer, aIn->size);
}
LIB_EXPORT void
MemorySet(
    void *destination,             // OUT: memory destination
    char value,                  // IN: fill value
    UINT32 size                    // IN: number of octets to fill
)
{
    char *p = (char *)destination;
    while (size--)
        *p++ = value;
    return;
}
BYTE *
MemoryGetActionInputBuffer(
    UINT32 size                    // Size, in bytes, required for the input
    // unmarshaling
)
{
    BYTE *buf = NULL;

    if(size > 0)
    {
        // In this implementation, a static buffer is set aside for action output.
        // Other implementations may apply additional optimization based on command
        // code or other factors.
        UINT32 *p = s_actionInputBuffer;
        buf = (BYTE *)p;
        pAssert(size < sizeof(s_actionInputBuffer));

        // size of an element in the buffer
#define SZ sizeof(s_actionInputBuffer[0])

        for(size = (size + SZ - 1)  / SZ; size > 0; size--)
            *p++ = 0;
#undef SZ
    }
    return buf;
}
void *
MemoryGetActionOutputBuffer(
    TPM_CC command            // Command that requires the buffer
)
{
    // In this implementation, a static buffer is set aside for action output.
    // Other implementations may apply additional optimization based on the command
    // code or other factors.
    command = 0;            // Unreferenced parameter
    return s_actionOutputBuffer;
}
BYTE *
MemoryGetResponseBuffer(
    TPM_CC command            // Command that requires the buffer
)
{
    // In this implementation, a static buffer is set aside for responses.
    // Other implementation may apply additional optimization based on the command
    // code or other factors.
    command = 0;            // Unreferenced parameter
    return s_responseBuffer;
}
UINT16
MemoryRemoveTrailingZeros (
    TPM2B_AUTH *auth              // IN/OUT: value to adjust
)
{
    BYTE *a = &auth->t.buffer[auth->t.size-1];
    for(; auth->t.size > 0; auth->t.size--)
    {
        if(*a--)
            break;
    }
    return auth->t.size;
}
