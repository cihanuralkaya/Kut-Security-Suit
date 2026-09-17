/*
 * kutflt.h — internal declarations for the KUT tamper-protection MiniFilter.
 * SKELETON (see driver/kutflt/README.md): correctness of intent over exhaustive
 * completeness. Built by the WDK/EWDK only — never by the Go CI.
 */
#pragma once
#include <fltKernel.h>
#include <dontuse.h>
#include "..\inc\kutflt_ioctl.h"

#define KUTFLT_POOL_TAG 'tFmX'   /* 'XmFt' */

/* Registered filter altitude — PLACEHOLDER. A production altitude must be
 * requested from Microsoft (fsfcomm@microsoft.com; see README). 385200 is in the
 * FSFilter Anti-Virus range and is fine for DEV/test-signed builds only. */
#define KUTFLT_ALTITUDE L"385200"

/* Global driver state. */
typedef struct _KUTFLT_GLOBALS {
    PFLT_FILTER    Filter;        /* from FltRegisterFilter */
    PFLT_PORT      ServerPort;    /* FltCreateCommunicationPort server */
    PFLT_PORT      ClientPort;    /* single connected agent */
    PVOID          ObHandle;      /* ObRegisterCallbacks registration */
    volatile LONG  Active;
    volatile LONG64 DeniedOps;
} KUTFLT_GLOBALS;

extern KUTFLT_GLOBALS g_Kut;

/* protect.c — policy */
VOID    KutProtectInit(VOID);
BOOLEAN KutIsProtectedProcess(HANDLE Pid);
BOOLEAN KutIsProtectedImagePath(PCUNICODE_STRING Path);   /* agent/watchdog .exe */
BOOLEAN KutIsProtectedFilePath(PCUNICODE_STRING Path);    /* binary/config */
BOOLEAN KutIsProtectedRegistryPath(PCUNICODE_STRING Path);
VOID    KutRegisterProtectedPid(HANDLE Pid);

/* comms.c — communication port */
NTSTATUS KutCommsInit(PFLT_FILTER Filter);
VOID     KutCommsTeardown(VOID);
VOID     KutPushEvent(ULONG Kind, ULONG ActorPid, PCWSTR Target);

/* obcallbacks.c — process-kill protection */
NTSTATUS KutObInit(VOID);
VOID     KutObTeardown(VOID);
