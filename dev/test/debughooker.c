#include <Windows.h>
// #include <debugapi.h>

#include <stdio.h>

/*
    Need a custom windows header defining executable PEB (Portable Execution Block)
    structure whos member contains a field value (bit set) equivalent to that of which
    IsDebuggerPresent() calls internally, this subjugates the calling process as 
    low-sophistication, hence the function call can easily be flagged by automatic EDR's
*/

int main(void)
{
    BOOL debug = IsDebuggerPresent();

    wprintf(L"Press <ENTER> after memory modification...\n");
    getchar();

    switch (debug)
    {
        case (VARIANT_BOOL)-1:
        {
            wprintf(L"Debugger is present.\n");

            break;
        }

        case (VARIANT_BOOL)0:
        {
            wprintf(L"Debugger is not present.\n");

            break;
        }

        default:
            break;
    }

    return 0;
}