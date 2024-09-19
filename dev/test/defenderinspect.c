#include <Windows.h>
#include <Wscapi.h>
#include <stdio.h>

#pragma comment(lib, "wscapi.lib")

#define INTEGRAL_RATE_LIMIT 64

#define GET_CURRENT_MULTIPLIERS\
        current = current * 2;\
        *wscLoadAddress = *wscLoadAddress * 2;\

/* generic "keen-eye" overview of windows core security service monitoring */

BOOL enumerateWSCTargets(void);
BOOL startQueryInfoRoutines(DWORD wscProvider);

wchar_t *WSC_PROVIDERS[] = {
    L"WSC_FIREWALL",
    L"WSC_AUTOUPDATE",
    L"WSC_ANTIVIRUS",
    L"WSC_INTERNET",
    L"WSC_ACCOUNTCTRL",
    L"WSC_SERVICEPROV"
};

typedef enum _WSC_TARGETS 
{
    WSC_TARGET_FIREWALL = 0x1,          /* The aggregation of all firewalls for this computer. */
    WSC_TARGET_AUTOUPDATE = 0x2,        /* The automatic update settings for this computer. */
    WSC_TARGET_ANTIVIRUS = 0x4,         /* The aggregation of all antivirus products for this computer. */
    WSC_TARGET_INTERNET = 0x10,         /* The settings that restrict the access of web sites in each of the Internet zones for this computer. */
    WSC_TARGET_ACCOUNT_CONTROL = 0x20,  /* The User Account Control (UAC) settings for this computer. */
    WSC_TARGET_SERVICE = 0x40,          /* The running state of the WSC service on this computer. */   

} WSC_TARGETS;


BOOL startQueryInfoRoutines(DWORD wscProvider)
{
    HRESULT hRes;
    WSC_SECURITY_PROVIDER_HEALTH sPHealth;

    hRes = WscGetSecurityProviderHealth((DWORD)wscProvider, &sPHealth);

    if (((HRESULT)(hRes)) >= 0L)
    {
        switch (sPHealth)
        {
            case WSC_SECURITY_PROVIDER_HEALTH_GOOD:
            {
                fwprintf(__acrt_iob_func(0x1), L"INF (ISLOADED) >> \"The status of the security provider category is good and does not need user attention.\"\n\n");

                break;
            }

            case WSC_SECURITY_PROVIDER_HEALTH_NOTMONITORED:
            {
                fwprintf(__acrt_iob_func(0x1), L"INF >> \"The status of the security provider category is not monitored by WSC.\"\n\n");

                break;
            }

            case WSC_SECURITY_PROVIDER_HEALTH_POOR:
            {
                fwprintf(__acrt_iob_func(0x1), L"INF >> \"The status of the security provider category is poor and the computer may be at risk.\"\n\n");

                break;
            }

            case WSC_SECURITY_PROVIDER_HEALTH_SNOOZE:
            {
                fwprintf(__acrt_iob_func(0x1), L"INF >> \"The security provider category is in snooze state. Snooze indicates that WSC is not actively protecting the computer.\"\n\n");

                break;
            }

            default:
            {
                fwprintf(__acrt_iob_func(0x1), L"ERR >> Could not obtain any WSC security provider enumeration objects in memory. Abort.\n");

                return (VARIANT_BOOL)0;
            }   
        }
    }

    return (VARIANT_BOOL)-1;
}


BOOL enumerateWSCTargets(void)
{
    // create pointer to enum
    WSC_TARGETS wscEntry = WSC_TARGET_FIREWALL;
    WSC_TARGETS *wscLoadAddress = &wscEntry;

    DWORD count = 0;
    size_t prov_sz = sizeof(WSC_PROVIDERS) / sizeof(WSC_PROVIDERS[0]);

    for (DWORD current = 1; current <= (DWORD)(INTEGRAL_RATE_LIMIT + 1);)
    {
        if (current == (DWORD)0x8) /* no 8 bit value set */
        {
            GET_CURRENT_MULTIPLIERS

            goto LOOP_CONSTRUCT_END;
        }

        printf("================================================\n");

        wprintf(
            L"[+] Current virtual memory position >> 0x%p\n\tValue: 0x%ld\n\tProvider: %ls\n\n[*] Running generic WSC security check...\n\t", 
            wscLoadAddress, 
            *wscLoadAddress, 
            WSC_PROVIDERS[count]
        );

        if (!startQueryInfoRoutines((DWORD)*wscLoadAddress))
        {
            fwprintf(__acrt_iob_func(0x1), L"Error >> Could not start main function for WSC security profiling!\n");
        
            return (VARIANT_BOOL)0;
        }
        else 
        {   
            GET_CURRENT_MULTIPLIERS
        
            count++;

            if (count == prov_sz)
                break;
        }

        LOOP_CONSTRUCT_END:
        ;;
    }


    return (VARIANT_BOOL)-1;
}


int main(void)
{
    // init
    BOOL stage_query = enumerateWSCTargets();

    switch (stage_query)
    {
        case TRUE: break;
        case FALSE: return -1;
    }    

    return 0;
}