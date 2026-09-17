/*
 * comms.c — user<->kernel port. The agent connects with
 * FilterConnectCommunicationPort(L"\\KutFltPort"). GET_STATUS is answered
 * synchronously; tamper events are pushed with FltSendMessage.
 */
#include "kutflt.h"
#include <ntstrsafe.h>

static NTSTATUS KutConnect(PFLT_PORT ClientPort, PVOID ServerCookie,
                            PVOID ConnectionContext, ULONG SizeOfContext,
                            PVOID *ConnectionCookie)
{
    UNREFERENCED_PARAMETER(ServerCookie);
    UNREFERENCED_PARAMETER(ConnectionContext);
    UNREFERENCED_PARAMETER(SizeOfContext);
    UNREFERENCED_PARAMETER(ConnectionCookie);
    g_Kut.ClientPort = ClientPort;
    /* Auto-protect the connecting agent's PID. */
    KutRegisterProtectedPid(PsGetCurrentProcessId());
    return STATUS_SUCCESS;
}

static VOID KutDisconnect(PVOID ConnectionCookie)
{
    UNREFERENCED_PARAMETER(ConnectionCookie);
    FltCloseClientPort(g_Kut.Filter, &g_Kut.ClientPort);
    g_Kut.ClientPort = NULL;
}

/* Request/response: agent -> kernel (FilterSendMessage). */
static NTSTATUS KutMessage(PVOID ConnectionCookie, PVOID InputBuffer,
                            ULONG InputBufferLength, PVOID OutputBuffer,
                            ULONG OutputBufferLength, PULONG ReturnOutputBufferLength)
{
    UNREFERENCED_PARAMETER(ConnectionCookie);
    *ReturnOutputBufferLength = 0;
    if (InputBufferLength < sizeof(KUTFLT_REQUEST)) return STATUS_INVALID_PARAMETER;

    KUTFLT_REQUEST req;
    RtlCopyMemory(&req, InputBuffer, sizeof(req));

    switch (req.Command) {
    case KutFltCmdGetStatus: {
        if (OutputBufferLength < sizeof(KUTFLT_STATUS)) return STATUS_BUFFER_TOO_SMALL;
        KUTFLT_STATUS st = { 0 };
        st.Version   = 1;
        st.Active    = (ULONG)g_Kut.Active;
        st.DeniedOps = (ULONGLONG)g_Kut.DeniedOps;
        RtlCopyMemory(OutputBuffer, &st, sizeof(st));
        *ReturnOutputBufferLength = sizeof(st);
        return STATUS_SUCCESS;
    }
    case KutFltCmdSetPolicy:
        KutRegisterProtectedPid(ULongToHandle(req.Arg));
        return STATUS_SUCCESS;
    case KutFltCmdPing:
        return STATUS_SUCCESS;
    default:
        return STATUS_INVALID_DEVICE_REQUEST;
    }
}

NTSTATUS KutCommsInit(PFLT_FILTER Filter)
{
    KutProtectInit();
    UNICODE_STRING name; RtlInitUnicodeString(&name, KUTFLT_PORT_NAME);

    PSECURITY_DESCRIPTOR sd = NULL;
    NTSTATUS status = FltBuildDefaultSecurityDescriptor(&sd, FLT_PORT_ALL_ACCESS);
    if (!NT_SUCCESS(status)) return status;

    OBJECT_ATTRIBUTES oa;
    InitializeObjectAttributes(&oa, &name,
        OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, sd);

    status = FltCreateCommunicationPort(Filter, &g_Kut.ServerPort, &oa, NULL,
        KutConnect, KutDisconnect, KutMessage, 1 /* max connections */);
    FltFreeSecurityDescriptor(sd);
    return status;
}

VOID KutCommsTeardown(VOID)
{
    if (g_Kut.ServerPort) { FltCloseCommunicationPort(g_Kut.ServerPort); g_Kut.ServerPort = NULL; }
}

/* Push a tamper event to the connected agent (best-effort, short timeout). */
VOID KutPushEvent(ULONG Kind, ULONG ActorPid, PCWSTR Target)
{
    if (g_Kut.ClientPort == NULL) return;
    KUTFLT_EVENT evt = { 0 };
    evt.Kind = Kind; evt.ActorPid = ActorPid;
    LARGE_INTEGER qpc = KeQueryPerformanceCounter(NULL);
    evt.TimestampQpc = (ULONGLONG)qpc.QuadPart;
    if (Target) RtlStringCchCopyW(evt.Target, RTL_NUMBER_OF(evt.Target), Target);

    LARGE_INTEGER timeout; timeout.QuadPart = -10 * 1000 * 100; /* 100ms relative */
    FltSendMessage(g_Kut.Filter, &g_Kut.ClientPort, &evt, sizeof(evt),
                   NULL, NULL, &timeout);
}
