#include <Windows.h>
#include <stdio.h>

/* 
    Mock write up, no actual research was done prior to developing the source.
    A deeper dive into the specific CPU instruction set architecture (ISA) is needed
    before resuming the methods herein which attempt to emulate a basic trampoline method
    by hooking the function call pre-execution with a jmp instruction to another address
*/

// function pointer 
typedef BOOL(WINAPI *IsDebuggerPresentType)(void);

// original function pointer
IsDebuggerPresentType originalIsDebuggerPresent;

// custom IsDebuggerPresent
BOOL WINAPI IsDebuggerPresentM(void)
{
    // src
    wprintf(L"Modified (Hooked) Win32 API function: IsDebuggerPresent()\n");

    return TRUE;
}


// trampoline function
void __stdcall Trampoline(void)
{
    IsDebuggerPresentM();

    // originalIsDebuggerPresent();
}


BOOL setHook(void)
{
    // get the address of the original IsDebuggerPresent function
    originalIsDebuggerPresent = (IsDebuggerPresentType)GetProcAddress(GetModuleHandle("kernel32.dll"), "IsDebuggerPresent");

    void *trampoline = VirtualAlloc(NULL, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

    if (trampoline == NULL)
    {
        fwprintf(__acrt_iob_func(0x2), L"Error >> failed to allocate 1000 bytes of memory...\n");

        return (VARIANT_BOOL)0;
    }

    // replace the original function with jump to the trampoline
    DWORD oldProtect;

    if (!VirtualProtect(originalIsDebuggerPresent, sizeof(IsDebuggerPresentType), PAGE_EXECUTE_READWRITE, &oldProtect))
    {
        fwprintf(__acrt_iob_func(0x2), L"Error >> failed to change memory page permissions inside of the calling process\n");
    
        return (VARIANT_BOOL)0;
    }

    memcpy(trampoline, Trampoline, 4000);
    printf("++ (%d) memcpy...\n", __LINE__);

    *(void**)((char *)originalIsDebuggerPresent) = trampoline;

    if (!VirtualProtect(originalIsDebuggerPresent, sizeof(IsDebuggerPresentType), oldProtect, &oldProtect))
    {
        fwprintf(__acrt_iob_func(0x2), L"Error >> failed to switch to default memory page permissions inside of the calling process\n");
    
        return (VARIANT_BOOL)0;
    }

    return (VARIANT_BOOL)-1;
}


int main(void)
{
    BOOL hook = setHook();

    if (!hook)
    {
        fwprintf(__acrt_iob_func(0x2), L"Error >> failed to set function hook! Abort!\n");

        return -1;
    }

    printf("++ Set function hook...\n");

    BOOL debug = IsDebuggerPresent();

    switch (debug)
    {
        case TRUE:
        {
            wprintf(L"Info >> A debugger is currently active.\n");

            break;
        }

        case FALSE:
        {
            wprintf(L"Info >> No debugger currently active.\n");

            break;
        }
    }

    return 0;
}