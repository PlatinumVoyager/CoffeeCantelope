#include <Windows.h>
#include <TlHelp32.h>

// non-main imports
#include <string.h>
#include <wchar.h>
#include <stdio.h>
#include <stdlib.h>

#include <processthreadsapi.h>

#pragma comment(lib, "user32.lib")

/* threadinspect.c requires administrative privileges to run successfully */

#define CODE_INT 0x0
#define CODE_ARRAY 0x1

DWORD globalPid;
LPWSTR processName;

BOOL CPUTypeCheck(void);

LPWSTR returnMsgBuffer(DWORD errorCode);
LPWSTR convertToLPWSTR(const char *str_target);
BOOL runthroughSystemProcess(int code_type, LPWSTR procName, DWORD user_pid);

BOOL CPUTypeCheck(void)
{
    HANDLE hProcess = OpenProcess(
        (STANDARD_RIGHTS_REQUIRED | PROCESS_QUERY_INFORMATION),
        (VARIANT_BOOL)0, 
        globalPid
    );

    BOOL addrSpaceSz;
    BOOL getProcessor = IsWow64Process(hProcess, &addrSpaceSz);

    switch (getProcessor)
    {
        case (VARIANT_BOOL)-1:
        {
            switch (addrSpaceSz)
            {
                case (VARIANT_BOOL)-1:
                {
                    printf("64 bit\n");

                    goto exit_jmp;
                }

                case (VARIANT_BOOL)0:
                {
                    printf("32 bit or other\n");

                    goto exit_jmp;
                }
            }
        }

        case (VARIANT_BOOL)0:
        {
            // failed, die.
            fwprintf(__acrt_iob_func(0x01), L"Error >> failed to call IsWow64Process within the current process virtual namespace.\n");

            return (VARIANT_BOOL)0;
        }

        default: // buggy behavior
            goto exit_jmp;
    }

    exit_jmp:
    {
        // true, then die.
        return (VARIANT_BOOL)-1;
    }

    return (VARIANT_BOOL)0;
}


BOOL runthroughSystemProcess(int code_type, LPWSTR procName, DWORD user_pid)
{
    int PRIMARY_FLAG = -1;

    switch (code_type)
    {
        // code integer (22093, 113, 0, etc)
        case CODE_INT:
        {
            // set flag to obtain PID from szexe
            PRIMARY_FLAG = 0;

            break;
        }

        // character string (notepad.exe, chrome.exe, etc)
        case CODE_ARRAY:
        {
            // set flag to 
            PRIMARY_FLAG = CODE_INT + 1;

            break;
        }

        default:
        {
            // nothing to do, leave PID to system (0)
            PRIMARY_FLAG = CODE_INT;

            break;
        }
    }

    HANDLE hSnapshot;

    hSnapshot = CreateToolhelp32Snapshot((TH32CS_SNAPPROCESS | TH32CS_SNAPTHREAD), (DWORD)0);

    if (hSnapshot == INVALID_HANDLE_VALUE)
    {
        DWORD error = GetLastError();

        fwprintf(stderr, L"Error (CreateToolhelp32Snapshot) >> %s\n", returnMsgBuffer(error));

        return (VARIANT_BOOL)0;
    }

    // create process entry and thread entry
    PROCESSENTRY32 processEntry32 = {0};
    THREADENTRY32 threadEntry32 = {0};

    processEntry32.dwSize = sizeof(PROCESSENTRY32);
    threadEntry32.dwSize = sizeof(THREADENTRY32);

    if (Process32First(hSnapshot, &processEntry32) && Thread32First(hSnapshot, &threadEntry32))
    {
        do 
        {
            switch (PRIMARY_FLAG)
            {
                GENERIC_BREAKPOINT:
                {
                    wprintf(
                        L"PROCESS: %s (PID=%lu)\nTHREAD_ID: %lu\nOWNER_PID: %lu\n", 
                            processName,
                            globalPid,
                            
                            // thread information
                            threadEntry32.th32ThreadID,
                            threadEntry32.th32OwnerProcessID
                    );

                    HANDLE hThread;
                    HANDLE hProcess;

                    DWORD threadID = threadEntry32.th32ThreadID;

                    hProcess = OpenProcess(PROCESS_SUSPEND_RESUME, FALSE, globalPid);

                    if (hProcess == NULL)
                    {
                        DWORD error = GetLastError();

                        fwprintf(stderr, L"Error (OpenProcess) >> %s\n", returnMsgBuffer(error));
                    }

                    hThread = OpenThread(THREAD_SUSPEND_RESUME | THREAD_QUERY_INFORMATION, FALSE, threadID);

                    if (hThread == NULL)
                    {
                        DWORD error = GetLastError();

                        fwprintf(stderr, L"Error (OpenThread) >> %s\n", returnMsgBuffer(error));
                    }

                    DWORD exitCode;

                    if (GetExitCodeThread(hThread, &exitCode))
                    {
                        switch (exitCode)
                        {
                            case STILL_ACTIVE:
                            {
                                printf("Thread is still active...\n");

                                break;
                            }

                            default:
                            {
                                printf("Thread exited with code %lu\n", exitCode);

                                break;
                            }
                        }
                    }

                    if (!CPUTypeCheck())
                    {
                        return (VARIANT_BOOL)0;
                    }

                    // enumerate all top level windows
                    // to obtain the window handle
                    // use windows handle to get thread ui thread id
                    // use id to suspend (freeze) the application

                    HWND hwndThread = GetAncestor(threadEntry32.th32ThreadID, GA_ROOTOWNER);

                    DWORD suspendThread;
                    char *thread_id = NULL;

                    // suspend the thread
                    suspendThread = SuspendThread(hThread);
                    
                    if (suspendThread == -1)
                    {
                        DWORD error = GetLastError();

                        fwprintf(stderr, L"Error (%hs) >> failed to suspend the remote thread (THREAD_ID=%lu)\nError >> %s\n", 
                            thread_id,
                            threadID,
                            returnMsgBuffer(error)
                        );
                    
                        return (VARIANT_BOOL)0;
                    }

                    SuspendThread(hThread);

                    if (suspendThread > 0)
                    {
                        printf("The thread is suspended. Resuming in 5 seconds...\n");
                        Sleep(5000);

                        ResumeThread(hThread);
                    }
                    else 
                    {
                        printf("The thread is not suspended...(%lu)\n", suspendThread);
                    }

                    CloseHandle(hThread);

                    goto CLOSE_HANDLE;
                }

                case CODE_INT:
                {
                    if (processEntry32.th32ProcessID == user_pid)
                    {
                        // PID exists on the system, reset to same value to verify that it is present
                        // within the PCB (Process Control Block)
                        globalPid = user_pid;

                        /* setup globally accessible process name */
                        processName = convertToLPWSTR(processEntry32.szExeFile);

                        goto GENERIC_BREAKPOINT;
                    }
                    else 
                    {
                        continue;
                    }
                }

                case CODE_ARRAY:
                {
                    LPWSTR targetProcName = convertToLPWSTR(processEntry32.szExeFile);
                    
                    if (wcscmp(procName, targetProcName) == 0)
                    {
                        globalPid = processEntry32.th32ProcessID;
                        processName = targetProcName;

                        goto GENERIC_BREAKPOINT;
                    }
                }
            }

        } while (Process32Next(hSnapshot, &processEntry32) && Thread32Next(hSnapshot, &threadEntry32));
    }

    CLOSE_HANDLE:

    CloseHandle(hSnapshot);

    return (VARIANT_BOOL)-1;
}


int main(int argc, char *argv[])
{
    int global_code = -1;

    DWORD user_pid;
    DWORD system_pid;

    LPWSTR user_pid_str;

    char *pid_str = NULL;

    if (!argv[1])
    {
        fwprintf(stderr, L"Error >> specify the process name or the correct process ID.\n");

        return -1;
    }

    if (isdigit((int) argv[1][0]))
    {
        global_code = CODE_INT;
        user_pid = (DWORD) atoi(argv[1]);
    }
    else 
    {
        global_code = CODE_ARRAY;
        pid_str = (char *) argv[1];

        user_pid_str = convertToLPWSTR(pid_str);
    }

    #define GTYPE_INT runthroughSystemProcess(global_code, 0, user_pid)
    #define GTYPE_ARRAY runthroughSystemProcess(global_code, user_pid_str, 0)

    switch (global_code)
    {
        case 0x0:
        {
            system_pid = GTYPE_INT;

            break;
        }

        case 0x1:
        {
            system_pid = GTYPE_ARRAY;

            break;
        }
    }

    switch (system_pid)
    {
        case TRUE:
            break;

        case FALSE:
        {
            fwprintf(stderr, L"Error >> failed to call secondary function after main()!\n");

            return -1;
        }
    }

    printf("Done.\n");

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