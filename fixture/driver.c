#include <ntddk.h>
C_ASSERT(FIELD_OFFSET(IRP, AssociatedIrp.SystemBuffer) == 0x18);
C_ASSERT(FIELD_OFFSET(IRP, Tail.Overlay.CurrentStackLocation) == 0xb8);
C_ASSERT(FIELD_OFFSET(DRIVER_OBJECT, MajorFunction) == 0x70);
C_ASSERT(FIELD_OFFSET(IO_STACK_LOCATION, Parameters.DeviceIoControl.OutputBufferLength) == 0x08);
C_ASSERT(FIELD_OFFSET(IO_STACK_LOCATION, Parameters.DeviceIoControl.InputBufferLength) == 0x10);
C_ASSERT(FIELD_OFFSET(IO_STACK_LOCATION, Parameters.DeviceIoControl.IoControlCode) == 0x18);

#define IOCTL_CHECKSUM CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_READ_ACCESS)
typedef ULONG (*CHECKSUM_CALLBACK)(const UCHAR *, ULONG);
static UNICODE_STRING LinkName = RTL_CONSTANT_STRING(L"\\DosDevices\\CallbackSurfaceFixture");

__declspec(noinline) ULONG Checksum(const UCHAR *bytes, ULONG count) {
    ULONG sum = 0;
    for (ULONG i = 0; i < count; ++i) sum += bytes[i];
    return sum;
}
#ifdef READONLY_CALLBACK
CHECKSUM_CALLBACK const volatile Callback = Checksum;
#else
CHECKSUM_CALLBACK volatile Callback = Checksum;
#endif

#ifdef HELPER_CALLBACK
__declspec(noinline) ULONG ForwardBuffer(const UCHAR *bytes, ULONG count) {
    return Callback(bytes, count);
}
#endif

static NTSTATUS Finish(PIRP irp, NTSTATUS status, ULONG_PTR information) {
    irp->IoStatus.Status = status;
    irp->IoStatus.Information = information;
    IoCompleteRequest(irp, IO_NO_INCREMENT);
    return status;
}
NTSTATUS CreateClose(PDEVICE_OBJECT device, PIRP irp) {
    UNREFERENCED_PARAMETER(device);
    return Finish(irp, STATUS_SUCCESS, 0);
}
NTSTATUS Reject(PDEVICE_OBJECT device, PIRP irp) {
    UNREFERENCED_PARAMETER(device);
    return Finish(irp, STATUS_INVALID_DEVICE_REQUEST, 0);
}
NTSTATUS DeviceControl(PDEVICE_OBJECT device, PIRP irp) {
    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(irp);
    UNREFERENCED_PARAMETER(device);
    if (stack->Parameters.DeviceIoControl.IoControlCode != IOCTL_CHECKSUM)
        return Finish(irp, STATUS_INVALID_DEVICE_REQUEST, 0);
    ULONG count = stack->Parameters.DeviceIoControl.InputBufferLength;
    if (count == 0 || count > 4096 ||
        stack->Parameters.DeviceIoControl.OutputBufferLength < sizeof(ULONG) ||
        irp->AssociatedIrp.SystemBuffer == NULL)
        return Finish(irp, STATUS_INVALID_PARAMETER, 0);
    /* Only a bounded checksum. No operation can change Callback. */
#ifdef UNRELATED_CALLBACK
    const UCHAR fixed[] = {1, 2, 3};
    ULONG sum = Callback(fixed, sizeof(fixed));
#else
#ifdef HELPER_CALLBACK
    ULONG sum = ForwardBuffer((const UCHAR *)irp->AssociatedIrp.SystemBuffer, count);
#else
    ULONG sum = Callback((const UCHAR *)irp->AssociatedIrp.SystemBuffer, count);
#endif
#endif
    *(ULONG *)irp->AssociatedIrp.SystemBuffer = sum;
    return Finish(irp, STATUS_SUCCESS, sizeof(ULONG));
}
void Unload(PDRIVER_OBJECT driver) {
    IoDeleteSymbolicLink(&LinkName);
    IoDeleteDevice(driver->DeviceObject);
}
NTSTATUS DriverEntry(PDRIVER_OBJECT driver, PUNICODE_STRING registry) {
    UNICODE_STRING name = RTL_CONSTANT_STRING(L"\\Device\\CallbackSurfaceFixture");
    PDEVICE_OBJECT device = NULL;
    UNREFERENCED_PARAMETER(registry);
    /* Named device security comes from a deployment INF; this fixture is for offline analysis. */
    NTSTATUS status = IoCreateDevice(driver, 0, &name, FILE_DEVICE_UNKNOWN,
                                    FILE_DEVICE_SECURE_OPEN, FALSE, &device);
    if (!NT_SUCCESS(status)) return status;
    for (ULONG i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; ++i) driver->MajorFunction[i] = Reject;
    driver->MajorFunction[IRP_MJ_CREATE] = CreateClose;
    driver->MajorFunction[IRP_MJ_CLOSE] = CreateClose;
#ifdef INTERNAL_ONLY
    driver->MajorFunction[IRP_MJ_INTERNAL_DEVICE_CONTROL] = DeviceControl;
#else
    driver->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DeviceControl;
#endif
    driver->DriverUnload = Unload;
    status = IoCreateSymbolicLink(&LinkName, &name);
    if (!NT_SUCCESS(status)) { IoDeleteDevice(device); return status; }
    device->Flags &= ~DO_DEVICE_INITIALIZING;
    return STATUS_SUCCESS;
}
