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

// D.3.1. Description
// This file contains the socket interface to a TPM simulator.
// D.3.2. Includes, Locals, Defines and Function Prototypes
#include <stdio.h>

// CHANGE START
#if defined(_Win32) || defined(WIN32)
#include <windows.h>
#include <winsock.h>
#else
#include "bool.h"
#include "TPM_Types.h"
#define SOCKET int
#define DWORD unsigned long
typedef void *LPVOID;
#define WINAPI
#define HANDLE UINT32
typedef union {   int i;   void* p; } INT_PTR;
#include <sys/types.h> 
#include <sys/socket.h>
#include <netinet/in.h>
#include <pthread.h>
#define closesocket(x) close(x)
#endif
// CHANGE END

#include "string.h"
#include <stdlib.h>
#include <stdint.h>
#include "TpmTcpProtocol.h"
BOOL ReadBytes(SOCKET s, char* buffer, int NumBytes);
BOOL ReadVarBytes(SOCKET s, char* buffer, UINT32* BytesReceived, int MaxLen);
BOOL WriteVarBytes(SOCKET s, char *buffer, int BytesToSend);
BOOL WriteBytes(SOCKET s, char* buffer, int NumBytes);
BOOL WriteUINT32(SOCKET s, UINT32 val);
#ifndef __IGNORE_STATE__
static UINT32 ServerVersion = 1;
#define MAX_BUFFER 1048576
char InputBuffer[MAX_BUFFER];                      //The input data buffer for the simulator.
char OutputBuffer[MAX_BUFFER];                     //The output data buffer for the simulator.
struct {
    UINT32 largestCommandSize;
    UINT32 largestCommand;
    UINT32 largestResponseSize;
    UINT32 largestResponse;
} CommandResponseSizes = {0};
#endif     // __IGNORE_STATE___
static int
CreateSocket(
    int PortNumber,
    SOCKET *listenSocket
)
{
#if defined(_Win32) || defined(WIN32)
    WSADATA wsaData;
#endif
    struct sockaddr_in MyAddress;

    int res;

#if defined(_Win32) || defined(WIN32)
    // Initialize Winsock
    res = WSAStartup(MAKEWORD(2,2), &wsaData);
    if (res != 0)
    {
        printf("WSAStartup failed with error: %d\n", res);
        return -1;
    }
#endif

    // create listening socket
    *listenSocket = socket(PF_INET, SOCK_STREAM, 0);
#if defined(_Win32) || defined(WIN32)
    if(INVALID_SOCKET == *listenSocket)
    {
        printf("Cannot create server listen socket. Error is 0x%x\n",
               WSAGetLastError());
        return -1;
    }
#else
    if (*listenSocket < 0)
    {
        printf("Cannot create server listen socket.\n");
        return -1;
    }
#endif

    // bind the listening socket to the specified port
#if defined(_Win32) || defined(WIN32)
    ZeroMemory(&MyAddress, sizeof(MyAddress));
#else
    bzero((char *) &MyAddress, sizeof(MyAddress));
#endif
    MyAddress.sin_port=htons((short) PortNumber);
    MyAddress.sin_family=AF_INET;

    res= bind(*listenSocket,(struct sockaddr*) &MyAddress,sizeof(MyAddress));
#if defined(_Win32) || defined(WIN32)
    if(res==SOCKET_ERROR)
    {
        printf("Bind error. Error is 0x%x\n", WSAGetLastError());
        return -1;
    };
#else
    if(res)
    {
        printf("Bind error.\n");
        return -1;
    };
#endif

    // listen/wait for server connections
    res= listen(*listenSocket,3);
#if defined(_Win32) || defined(WIN32)
    if(res==SOCKET_ERROR)
    {
        printf("Listen error. Error is 0x%x\n", WSAGetLastError());
        return -1;
    };
#else
    if (res)
    {
        printf("Listen error.\n");
        return -1;
    };
#endif

    return 0;
}
BOOL
PlatformServer(
    SOCKET s
)
{
    BOOL ok = TRUE;
    UINT32 length = 0;
    UINT32 Command;

    for(;;)
    {
        ok = ReadBytes(s, (char*) &Command, 4);
        // client disconnected (or other error). We stop processing this client
        // and return to our caller who can stop the server or listen for another
        // connection.
        if(!ok) return TRUE;
        Command = ntohl(Command);
        switch(Command)
        {
        case TPM_SIGNAL_POWER_ON:
            _rpc__Signal_PowerOn(FALSE);
            break;

        case TPM_SIGNAL_POWER_OFF:
            _rpc__Signal_PowerOff();
            break;

        case TPM_SIGNAL_RESET:
            _rpc__Signal_PowerOn(TRUE);
            break;

        case TPM_SIGNAL_PHYS_PRES_ON:
            _rpc__Signal_PhysicalPresenceOn();
            break;

        case TPM_SIGNAL_PHYS_PRES_OFF:
            _rpc__Signal_PhysicalPresenceOff();
            break;

        case TPM_SIGNAL_CANCEL_ON:
            _rpc__Signal_CancelOn();
            break;

        case TPM_SIGNAL_CANCEL_OFF:
            _rpc__Signal_CancelOff();
            break;

        case TPM_SIGNAL_NV_ON:
            _rpc__Signal_NvOn();
            break;

        case TPM_SIGNAL_NV_OFF:
            _rpc__Signal_NvOff();
            break;

        case TPM_SESSION_END:
            // Client signaled end-of-session
            return TRUE;

        case TPM_STOP:
            // Client requested the simulator to exit
            return FALSE;

        case TPM_TEST_FAILURE_MODE:
            _rpc__ForceFailureMode();
            break;

        case TPM_GET_COMMAND_RESPONSE_SIZES:
            ok = WriteVarBytes(s, (char *)&CommandResponseSizes,
                               sizeof(CommandResponseSizes));
            memset(&CommandResponseSizes, 0, sizeof(CommandResponseSizes));
            if(!ok)
                return TRUE;
            break;

        default:
            printf("Unrecognized platform interface command %d\n", Command);
            WriteUINT32(s, 1);
            return TRUE;
        }
        WriteUINT32(s,0);
    }
    return FALSE;
}
DWORD WINAPI
PlatformSvcRoutine(
    LPVOID port
)
{
#if defined(_Win32) || defined(WIN32)
    int PortNumber = (int)(INT_PTR) port;
#else
    int                  PortNumber = (int)(((INT_PTR) port).i);
#endif
    SOCKET listenSocket, serverSocket;
    struct sockaddr_in HerAddress;
    int res;
    int length;
    BOOL continueServing;

    res = CreateSocket(PortNumber, &listenSocket);
    if(res != 0)
    {
        printf("Create platform service socket fail\n");
        return res;
    }

    // Loop accepting connections one-by-one until we are killed or asked to stop
    // Note the platform service is single-threaded so we don't listen for a new
    // connection until the prior connection drops.
    do
    {
        printf("Platform server listening on port %d\n", PortNumber);

        // blocking accept
        length = sizeof(HerAddress);
        serverSocket = accept(listenSocket,
                              (struct sockaddr*) &HerAddress,
                              &length);
#if defined(_Win32) || defined(WIN32)
        if(serverSocket == SOCKET_ERROR)
        {
            printf("Accept error. Error is 0x%x\n", WSAGetLastError());
            return -1;
        };
#else
        if(serverSocket < 0)
        {
            printf("Accept error\n");
            return -1;
        };
#endif
        printf("Client accepted\n");

        // normal behavior on client disconnection is to wait for a new client
        // to connect
        continueServing = PlatformServer(serverSocket);
        closesocket(serverSocket);
    }
    while(continueServing);

    return 0;
}
int
PlatformSignalService(
    int PortNumber
)
{
    HANDLE hPlatformSvc;
    int ThreadId;
    int port = PortNumber;

    // Create service thread for platform signals
#if defined(_Win32) || defined(WIN32)
    hPlatformSvc = CreateThread(NULL, 0,
                                (LPTHREAD_START_ROUTINE)PlatformSvcRoutine,
                                (LPVOID) (INT_PTR) port, 0, (LPDWORD)&ThreadId);
    if(hPlatformSvc == NULL)
    {
        printf("Thread Creation failed\n");
        return -1;
    }
#else
	pthread_t thread;
    hPlatformSvc = pthread_create(  &thread, 
                                    NULL, 
									(void*) PlatformSvcRoutine,
									(LPVOID) ((INT_PTR) port).p);
    if(hPlatformSvc)
    {
       printf("Thread Creation failed\n");
       return -1;
    }

#endif

    return 0;
}
int
RegularCommandService(
    int PortNumber
)
{
    SOCKET listenSocket;
    SOCKET serverSocket;
    struct sockaddr_in HerAddress;

    int res, length;
    BOOL continueServing;

    res = CreateSocket(PortNumber, &listenSocket);
    if(res != 0)
    {
        printf("Create platform service socket fail\n");
        return res;
    }

    // Loop accepting connections one-by-one until we are killed or asked to stop
    // Note the TPM command service is single-threaded so we don't listen for
    // a new connection until the prior connection drops.
    do
    {
        printf("TPM command server listening on port %d\n", PortNumber);

        // blocking accept
        length = sizeof(HerAddress);
        serverSocket = accept(listenSocket,
                              (struct sockaddr*) &HerAddress,
                              &length);
#if defined(_Win32) || defined(WIN32)
        if(serverSocket ==SOCKET_ERROR)
        {
            printf("Accept error. Error is 0x%x\n", WSAGetLastError());
            return -1;
        };
#else
        if(serverSocket < 0)
        {
        	printf("Accept error\n");
        	return -1;
        };
#endif

        printf("Client accepted\n");

        // normal behavior on client disconnection is to wait for a new client
        // to connect
        continueServing = TpmServer(serverSocket);
        closesocket(serverSocket);
    }
    while(continueServing);

    return 0;
}
int
StartTcpServer(
    int PortNumber
)
{
    int res;

    // Start Platform Signal Processing Service
    res = PlatformSignalService(PortNumber+1);
    if (res != 0)
    {
        printf("PlatformSignalService failed\n");
        return res;
    }

    // Start Regular/DRTM TPM command service
    res = RegularCommandService(PortNumber);
    if (res != 0)
    {
        printf("RegularCommandService failed\n");
        return res;
    }

    return 0;
}
BOOL
ReadBytes(
    SOCKET s,
    char *buffer,
    int NumBytes
)
{
    int res;
    int numGot = 0;

    while(numGot<NumBytes)
    {
        res = recv(s, buffer+numGot, NumBytes-numGot, 0);
        if(res == -1)
        {
#if defined(_Win32) || defined(WIN32)
            printf("Receive error. Error is 0x%x\n", WSAGetLastError());
#else
            printf("Receive error\n");
#endif
            return FALSE;
        }
        if(res==0)
        {
            return FALSE;
        }
        numGot+=res;
    }
    return TRUE;
}
BOOL
WriteBytes(
    SOCKET s,
    char *buffer,
    int NumBytes
)
{
    int res;
    int numSent = 0;
    while(numSent<NumBytes)
    {
        res = send(s, buffer+numSent, NumBytes-numSent, 0);
        if(res == -1)
        {
#if defined(_Win32) || defined(WIN32)
            if(WSAGetLastError() == 0x2745)
            {
                printf("Client disconnected\n");
            }
            else
            {
                printf("Send error. Error is 0x%x\n", WSAGetLastError());
            }
#else
        	printf("Send error.\n");
#endif
            return FALSE;
        }
        numSent+=res;
    }
    return TRUE;
}
BOOL
WriteUINT32(
    SOCKET s,
    UINT32 val
)
{
    UINT32 netVal = htonl(val);
    return WriteBytes(s, (char*) &netVal, 4);
}
BOOL
ReadVarBytes(
    SOCKET s,
    char *buffer,
    UINT32 *BytesReceived,
    int MaxLen
)
{
    int length;
    BOOL res;

    res = ReadBytes(s, (char*) &length, 4);
    if(!res) return res;
    length = ntohl(length);
    *BytesReceived = length;
    if(length>MaxLen)
    {
        printf("Buffer too big. Client says %d\n", length);
        return FALSE;
    }
    if(length==0) return TRUE;
    res = ReadBytes(s, buffer, length);
    if(!res) return res;
    return TRUE;
}
BOOL
WriteVarBytes(
    SOCKET s,
    char *buffer,
    int BytesToSend
)
{
    UINT32 netLength = htonl(BytesToSend);
    BOOL res;

    res = WriteBytes(s, (char*) &netLength, 4);
    if(!res) return res;
    res = WriteBytes(s, buffer, BytesToSend);
    if(!res) return res;
    return TRUE;
}
BOOL
TpmServer(
    SOCKET s
)
{
    UINT32 length;
    UINT32 Command;
    BYTE locality;
    BOOL ok;
    int result;
    int clientVersion;
    _IN_BUFFER InBuffer;
    _OUT_BUFFER OutBuffer;

    for(;;)
    {
        ok = ReadBytes(s, (char*) &Command, 4);
        // client disconnected (or other error). We stop processing this client
        // and return to our caller who can stop the server or listen for another
        // connection.
        if(!ok)
            return TRUE;
        Command = ntohl(Command);
        switch(Command)
        {
        case TPM_SIGNAL_HASH_START:
            _rpc__Signal_Hash_Start();
            break;

        case TPM_SIGNAL_HASH_END:
            _rpc__Signal_HashEnd();
            break;

        case TPM_SIGNAL_HASH_DATA:
            ok = ReadVarBytes(s, InputBuffer, &length, MAX_BUFFER);
            if(!ok) return TRUE;
            InBuffer.Buffer = (BYTE*) InputBuffer;
            InBuffer.BufferSize = length;
            _rpc__Signal_Hash_Data(InBuffer);
            break;

        case TPM_SEND_COMMAND:
            ok = ReadBytes(s, (char*) &locality, 1);
            if(!ok)
                return TRUE;

            ok = ReadVarBytes(s, InputBuffer, &length, MAX_BUFFER);
            if(!ok)
                return TRUE;
            InBuffer.Buffer = (BYTE*) InputBuffer;
            InBuffer.BufferSize = length;
            OutBuffer.BufferSize = MAX_BUFFER;
            OutBuffer.Buffer = (_OUTPUT_BUFFER) OutputBuffer;
            // record the number of bytes in the command if it is the largest
            // we have seen so far.
            if(InBuffer.BufferSize > CommandResponseSizes.largestCommandSize)
            {
                CommandResponseSizes.largestCommandSize = InBuffer.BufferSize;
                memcpy(&CommandResponseSizes.largestCommand,
                       &InputBuffer[6], sizeof(UINT32));
            }

            _rpc__Send_Command(locality, InBuffer, &OutBuffer);
            // record the number of bytes in the response if it is the largest
            // we have seen so far.
            if(OutBuffer.BufferSize > CommandResponseSizes.largestResponseSize)
            {
                CommandResponseSizes.largestResponseSize
                    = OutBuffer.BufferSize;
                memcpy(&CommandResponseSizes.largestResponse,
                       &OutputBuffer[6], sizeof(UINT32));
            }
            ok = WriteVarBytes(s,
                               (char*) OutBuffer.Buffer,
                               OutBuffer.BufferSize);
            if(!ok)
                return TRUE;
            break;

        case TPM_REMOTE_HANDSHAKE:
            ok = ReadBytes(s, (char*)&clientVersion, 4);
            if(!ok)
                return TRUE;
            if( clientVersion == 0 )
            {
                printf("Unsupported client version (0).\n");
                return TRUE;
            }
            ok &= WriteUINT32(s, ServerVersion);
            ok &= WriteUINT32(s,
                              tpmInRawMode | tpmPlatformAvailable | tpmSupportsPP);
            break;

        case TPM_SET_ALTERNATIVE_RESULT:
            ok = ReadBytes(s, (char*)&result, 4);
            if(!ok)
                return TRUE;
            // Alternative result is not applicable to the simulator.
            break;

        case TPM_SESSION_END:
            // Client signaled end-of-session
            return TRUE;

        case TPM_STOP:
            // Client requested the simulator to exit
            return FALSE;
        default:
            printf("Unrecognized TPM interface command %d\n", Command);
            return TRUE;
        }
        ok = WriteUINT32(s,0);
        if(!ok)
            return TRUE;
    }
    return FALSE;
}
