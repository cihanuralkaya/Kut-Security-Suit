/*
 * obcallbacks.c — block termination/injection of the agent & watchdog by
 * stripping dangerous rights from any handle another process tries to open to a
 * protected process (the standard "PPL-lite" technique via ObRegisterCallbacks).
 *
 * NOTE (production): ObRegisterCallbacks requires the driver image to be signed
 * with a cert whose EKU permits it; on non-test-signed systems the driver must be
 * WHQL/attestation-signed. On a test-signing VM it works. See README.
 */
#include "kutflt.h"

static OB_PREOP_CALLBACK_STATUS KutObPreOp(PVOID RegContext,
                                            POB_PRE_OPERATION_INFORMATION Info)
{
    UNREFERENCED_PARAMETER(RegContext);

    if (Info->KernelHandle) return OB_PREOP_SUCCESS;         /* trust kernel handles */
    if (Info->ObjectType != *PsProcessType) return OB_PREOP_SUCCESS;

    PEPROCESS target = (PEPROCESS)Info->Object;
    HANDLE targetPid = PsGetProcessId(target);
    HANDLE actorPid  = PsGetCurrentProcessId();

    if (actorPid == targetPid) return OB_PREOP_SUCCESS;      /* self-access allowed */
    if (!KutIsProtectedProcess(targetPid)) return OB_PREOP_SUCCESS;

    /* Strip the rights that let another process kill/suspend/inject the agent. */
    ACCESS_MASK strip = PROCESS_TERMINATE | PROCESS_VM_WRITE |
                        PROCESS_VM_OPERATION | PROCESS_CREATE_THREAD |
                        PROCESS_SUSPEND_RESUME;

    if (Info->Operation == OB_OPERATION_HANDLE_CREATE) {
        Info->Parameters->CreateHandleInformation.DesiredAccess &= ~strip;
    } else { /* OB_OPERATION_HANDLE_DUPLICATE */
        Info->Parameters->DuplicateHandleInformation.DesiredAccess &= ~strip;
    }
    InterlockedIncrement64(&g_Kut.DeniedOps);
    KutPushEvent(KutFltEvtHandleStripped, HandleToULong(actorPid), L"protected-process");
    return OB_PREOP_SUCCESS;
}

NTSTATUS KutObInit(VOID)
{
    OB_OPERATION_REGISTRATION op = { 0 };
    op.ObjectType = PsProcessType;
    op.Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
    op.PreOperation = KutObPreOp;
    op.PostOperation = NULL;

    OB_CALLBACK_REGISTRATION reg = { 0 };
    reg.Version = OB_FLT_REGISTRATION_VERSION;
    reg.OperationRegistrationCount = 1;
    RtlInitUnicodeString(&reg.Altitude, KUTFLT_ALTITUDE); /* placeholder altitude */
    reg.RegistrationContext = NULL;
    reg.OperationRegistration = &op;

    return ObRegisterCallbacks(&reg, &g_Kut.ObHandle);
}

VOID KutObTeardown(VOID)
{
    if (g_Kut.ObHandle) { ObUnRegisterCallbacks(g_Kut.ObHandle); g_Kut.ObHandle = NULL; }
}
