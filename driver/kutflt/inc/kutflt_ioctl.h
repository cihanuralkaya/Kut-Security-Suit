/*
 * kutflt_ioctl.h — PUBLIC user<->kernel ABI for the KUT tamper-protection
 * MiniFilter driver (kutflt.sys). This is the ONLY header the Go agent mirrors
 * (see agent/internal/tamperprotect/driverclient_windows.go). Keep struct layouts
 * fixed-size and packed; the Go side hard-codes the layout.
 */
#pragma once

/* FltCreateCommunicationPort object name. Userland connects via
 * FilterConnectCommunicationPort(L"\\KutFltPort", ...). */
#define KUTFLT_PORT_NAME   L"\\KutFltPort"

/* Message opcodes: userland -> kernel (request/response). */
typedef enum _KUTFLT_CMD {
    KutFltCmdGetStatus = 1,   /* agent asks: are you loaded/active? counters? */
    KutFltCmdSetPolicy = 2,   /* agent pushes a protected PID */
    KutFltCmdPing      = 3,   /* liveness */
} KUTFLT_CMD;

#pragma pack(push, 1)

/* Request header sent by userland (FilterSendMessage input buffer). */
typedef struct _KUTFLT_REQUEST {
    unsigned long Command;      /* KUTFLT_CMD */
    unsigned long Arg;          /* command-specific (e.g. a PID to protect) */
} KUTFLT_REQUEST;

/* Status reply (FilterSendMessage output buffer for KutFltCmdGetStatus). */
typedef struct _KUTFLT_STATUS {
    unsigned long      Version;         /* driver ABI version */
    unsigned long      Active;          /* 1 = filtering active */
    unsigned long      ProtectedPids;   /* count of PIDs under Ob protection */
    unsigned long      ProtectedPaths;  /* count of protected file/registry paths */
    unsigned long long DeniedOps;       /* cumulative denied tamper operations */
} KUTFLT_STATUS;

/* Kernel -> userland pushed tamper event kinds. */
typedef enum _KUTFLT_EVENT_KIND {
    KutFltEvtProcessTerminateBlocked = 1,
    KutFltEvtHandleStripped          = 2,
    KutFltEvtFileWriteBlocked        = 3,
    KutFltEvtFileDeleteBlocked       = 4,
    KutFltEvtRegistryBlocked         = 5,
} KUTFLT_EVENT_KIND;

/* Kernel -> userland pushed tamper event (FilterGetMessage payload, follows the
 * FILTER_MESSAGE_HEADER that the filter manager prepends). */
typedef struct _KUTFLT_EVENT {
    unsigned long      Kind;            /* KUTFLT_EVENT_KIND */
    unsigned long      ActorPid;        /* process that attempted the tamper */
    unsigned long long TimestampQpc;    /* KeQueryPerformanceCounter at detection */
    unsigned short     Target[260];     /* null-terminated: path or "PID:<n>" (UTF-16) */
} KUTFLT_EVENT;

#pragma pack(pop)
