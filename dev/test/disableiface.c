#include <Windows.h>
#include <stdio.h>
#include <wchar.h>
#include <ntddndis.h>

#pragma comment(lib, "kernel32.lib")
#pragma comment(lib, "shell32.lib")


int main(int argc, wchar_t *argv[])
{   
    int cmdCount = 0;

    wchar_t *cmdList = CommandLineToArgvW(GetCommandLineW(), &cmdCount);
    wchar_t *subjectNICGUID = cmdList[1];

    fwprintf(__acrt_iob_func(0x1), L"GUID => %ls\n", subjectNICGUID);

    wchar_t devPath[MAX_PATH];

    int ret = 0;

    if ((ret = _snwprintf(devPath, MAX_PATH, L"\\\\.\\%s", subjectNICGUID)) != 0)
    {
        fwprintf(__acrt_iob_func(0x2), L"Error >> failed to cast device interface GUID to allocated virtual memory within VPF in current system process. Dismantling...");

        return -1;
    }

    // open the device
    HANDLE subjectHandle = CreateFileW(devPath, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);

    if (subjectHandle == INVALID_HANDLE_VALUE || subjectHandle == NULL)
    {
        fwprintf(__acrt_iob_func(0x2), L"Error >> failed to obtain a handle to the subjected device. Dismantling...\n");
    
        return -1;
    }

    // disable the NIC
    DWORD bytesRecv;
    DWORD ifacePrimerState = NdisMediaStateDisconnected;

    DWORD IOCTL_code = 0x12345678;

    // if (!DeviceIoControl(subjectHandle, IOCTL_code, &ifacePrimerState, sizeof(ifacePrimerState), NULL, &bytesRecv, NULL)) 
    {
        // brute force IOTCL codes against NIC
        // Do not finish open source. Post to Github.
    }

    return 0;
}