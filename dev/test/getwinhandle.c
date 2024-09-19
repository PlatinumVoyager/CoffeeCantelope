#include <Windows.h>
#include <TlHelp32.h>
#include <wchar.h>
#include <stdio.h>

#pragma comment(lib, "user32.lib")

DWORD GetWindowPid(HWND hwnd);
LPWSTR getProcSzExe(DWORD process_pid);
LPWSTR returnMsgBuffer(DWORD errorCode);

LPWSTR convertToLPWSTR(const char *str_target);
BOOL CALLBACK EnumWindowsProc(HWND hwnd, LPARAM lparam);

DWORD obj_count = 0;
LPWSTR szExeTarget;


DWORD GetWindowPid(HWND hwnd)
{
    DWORD winProcId;
    DWORD windowThreadId = 0;

    GetWindowThreadProcessId(hwnd, &winProcId);

    wprintf(
        "\tPROCESS INFORMATION\n"
        "\t-------------------"
        L"\n\t\tPID => %lu\n\t\tSZEXE => \"%s\"\n\n", 
            winProcId, getProcSzExe(winProcId)
    );

    HANDLE hProcessThread = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);

    if (hProcessThread == NULL || hProcessThread == INVALID_HANDLE_VALUE)
    {
        fwprintf(stderr, L"Error >> failed to call CreateToolhelp32Snapshot!\n");

        return (DWORD)-1;
    }

    THREADENTRY32 threadEntry32 = {0};

    // set static size
    threadEntry32.dwSize = sizeof(THREADENTRY32);

    int threadLimit = 10;

    // zero out
    int x = threadLimit - threadLimit;

    do
    {
        if (Thread32First(hProcessThread, &threadEntry32))
        {
            if (threadEntry32.th32OwnerProcessID == winProcId)
            {
                // associated windows?
                HWND hwndThread = GetAncestor(hwnd, GA_ROOTOWNER);

                if (hwndThread == hwnd)
                {
                    windowThreadId = threadEntry32.th32ThreadID;

                    break;
                }
            }

            x++;

            if (x == threadLimit)
            {
                break;
            }
        }
    
    } while (Thread32Next(hProcessThread, &threadEntry32)); 

    printf("ROOT WINDOW THREAD ID: %lu\n", windowThreadId);

    return (DWORD)1;
}


LPWSTR getProcSzExe(DWORD process_pid)
{
    PROCESSENTRY32 procEntry32 = {0};

    // set size params
    procEntry32.dwSize = sizeof(PROCESSENTRY32);

    // create temporary handle
    HANDLE tempSnapHandle = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (tempSnapHandle == INVALID_HANDLE_VALUE || tempSnapHandle == NULL)
    {
        DWORD error = GetLastError();

        fwprintf(L"Error >> failed with error: %s\n", returnMsgBuffer(error));

        return -1;
    }

    if (Process32First(tempSnapHandle, &procEntry32))
    {
        do 
        {
            if (procEntry32.th32ProcessID == process_pid)
            {
                LPWSTR processSz = convertToLPWSTR(procEntry32.szExeFile);

                return processSz;
            }
            else
            {
                continue;
            }

        } while (Process32Next(tempSnapHandle, &procEntry32));
    }

    return (LPWSTR)L"NONE\n";
}


BOOL CALLBACK EnumWindowsProc(HWND hwnd, LPARAM lparam)
{
    WCHAR className[256];
    WCHAR windowTitle[256];

    GetClassNameW(hwnd, className, sizeof(className));
    GetWindowTextW(hwnd, windowTitle, sizeof(windowTitle));
    
    obj_count++;

    printf("============= START WINDOW OBJECT #\033[93;1m%lu\033[0;m =============\n", obj_count);

    printf("\tWINDOW HANDLE:\n\t\t\033[90;1m%p\033[0;m\n\n", (void*)hwnd);
    wprintf(L"\tCLASS NAME:\n\t\t\033[92;1m%s\033[0;m\n\n", className);
    wprintf(L"\tWINDOW TITLE:\n\t\t\033[0;0m\"%s\"\033[0;m\n\n", windowTitle);

    if(GetWindowPid(hwnd) < (DWORD)1)
    {
        fwprintf(stderr, L"Error >> failed to call GetWindowPid!\n");

        return (VARIANT_BOOL)0;
    }

    printf("============= END WINDOW OBJECT #\033[93;1m%lu\033[0;m =============\n\n", obj_count);

    return (VARIANT_BOOL)-1;
}


int main(void)
{
    printf("Info (EnumWindows) => enumerating all top-level window applications...\n");
    printf("\nPress <ENTER> to commence...\n");

    getchar();

    BOOL init = EnumWindows(EnumWindowsProc, 0);

    switch (init)
    {
        case TRUE:
            break;
        
        case FALSE:
        {
            fwprintf(stderr, L"Error >> EnumWindows returned FALSE\n");

            return -1;
        }
    }

    return 0;
}


LPWSTR convertToLPWSTR(const char *str_target)
{
    /* conversion operations */
    int wideLen = MultiByteToWideChar(CP_ACP, 0, str_target, -1, NULL, 0);

    if (wideLen == 0)
    {
        return ((void *)0);
    }

    /* request to allocate memory in the heap within virtual page frame */
    LPWSTR wideStr = (LPWSTR) malloc(wideLen * sizeof(WCHAR));

    if (wideStr == NULL)
    {
        return ((void *)0);
    }

    if (MultiByteToWideChar(CP_ACP, 0, str_target, -1, wideStr, wideLen) == 0)
    {
        free(wideStr);

        return NULL;
    }

    return wideStr;
}


LPWSTR returnMsgBuffer(DWORD errorCode)
{
    LPWSTR msgBuffer = NULL;

    DWORD result = FormatMessageW
    (
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL,
        errorCode,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        (LPWSTR)&msgBuffer,
        0,
        NULL
    );

    return msgBuffer;
}