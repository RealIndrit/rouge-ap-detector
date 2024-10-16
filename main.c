#include <wchar.h>
#include <windows.h>
#include <wlanapi.h>
#include <getopt.h>
#include <stdio.h>

#define MAX_CLIENT 2 /// https://learn.microsoft.com/en-us/windows/win32/api/wlanapi/nf-wlanapi-wlanopenhandle

static struct option long_options[] =
        {
                {"ssid", required_argument, NULL, 's'},
                {"password", required_argument, NULL, 'p'},
                {"bss_type", required_argument, NULL, 'b'},
                {"expected", required_argument, NULL, 'e'}
        };

int main(int argc, char *argv[]) {
    int ch;
    char *ssid = NULL;
    BOOL password = FALSE;
    int bssType = 1;
    int expected = 1;

    if (argc != 9) {
        wprintf(L"Incorrect amount of arguments passed to function (%d)\n", argc);
        wprintf(L"Expected argument is: \n", argc);
        wprintf(L"\t-s (ssid): (string)\n");
        wprintf(L"\t-p (password): (y/n)\n");
        wprintf(L"\t-b (bss_type): (1/2/3)\n");
        wprintf(L"\t-e (expected): (int)\n");
        return 1;
    }

    while ((ch = getopt_long(argc, argv, "s:p:b:e:", long_options, NULL)) != -1)
    {
        switch (ch)
        {
            case 's':
                ssid = optarg;
                break;
            case 'p':
                if(strcmp(optarg, "Y") == 0 || strcmp(optarg, "y") == 0)
                    password = TRUE;
                if(strcmp(optarg, "N") == 0 || strcmp(optarg, "n") == 0)
                    password = FALSE;
                else
                    wprintf(L"Only allowed values are Y/y (yes) or N/n (no)");
                break;
            case 'b':
                bssType = strtol(optarg, NULL, 10); // or copy it if you want to
                break;
            case 'e':
                expected = strtol(optarg, NULL, 10); // or copy it if you want to
                break;
        }
    }

    HANDLE hClient = NULL;
    DWORD dwCurVersion = 0;
    DWORD dwResult = 0;
    int dwRetVal = 0;

    PWLAN_INTERFACE_INFO_LIST pIfList = NULL;
    PWLAN_INTERFACE_INFO pIfInfo = NULL;

    PWLAN_BSS_LIST pBssList = NULL;
    PWLAN_BSS_ENTRY pBssEntry = NULL;

    unsigned int i, j;

    // Open Handle
    dwResult = WlanOpenHandle(MAX_CLIENT, NULL, &dwCurVersion, &hClient);

    if (dwResult != ERROR_SUCCESS) {
        wprintf(L"WlanOpenHandle failed with error: %u\n", dwResult);
        dwRetVal = 1;
        goto cleanup;
    }

    // Get list of wlan interfaces reference
    dwResult = WlanEnumInterfaces(hClient, NULL, &pIfList);

    if (dwResult != ERROR_SUCCESS) {
        wprintf(L"WlanEnumInterfaces failed with error: %u\n", dwResult);
        dwRetVal = 1;
        goto cleanup;

    } else {
        for (i = 0; i < pIfList->dwNumberOfItems; i++) {
            pIfInfo = (WLAN_INTERFACE_INFO *) &pIfList->InterfaceInfo[i];

            // Flush buffers and populate with latest wifi scan data
            dwResult = WlanScan(hClient, &pIfInfo->InterfaceGuid, NULL, NULL, NULL);

            if (dwResult != ERROR_SUCCESS) {
                wprintf(L"WlanScan failed for interface: %u\n", i);
                dwRetVal = 1;
                goto cleanup;
            }


            wprintf(L"Interface Index: %d\n", i);
            wprintf(L"  InterfaceDescription: %ls\n", pIfInfo->strInterfaceDescription);

            DOT11_SSID target;
            strcpy(target.ucSSID, ssid);
            target.uSSIDLength = (ULONG) strlen(ssid);

            dwResult = WlanGetNetworkBssList(hClient,
                                             &pIfInfo->InterfaceGuid,
                                             &target,
                                             bssType,
                                             password,
                                             NULL,
                                             &pBssList);

            if (dwResult != ERROR_SUCCESS) {
                wprintf(L"WlanGetNetworkBssList failed with error: %u\n",
                        dwResult);
                dwRetVal = 1;

            } else {
                wprintf(L"Found %d SSIDs\n", pBssList->dwNumberOfItems);
                for (j = 0; j < pBssList->dwNumberOfItems; j++) {
                    pBssEntry = (WLAN_BSS_ENTRY *) &pBssList->wlanBssEntries[j];

                    if (pBssEntry->dot11Ssid.uSSIDLength > 0) {
                        wprintf(L"Ssid[%u]: %s\n", j, pBssEntry->dot11Ssid.ucSSID);
                    } else {
                        wprintf(L"Ssid[%u]: [HIDDEN]\n", j);
                    }


                    wprintf(L"  Bssid:  %02X:%02X:%02X:%02X:%02X:%02X\n",
                            pBssEntry->dot11Bssid[0],
                            pBssEntry->dot11Bssid[1],
                            pBssEntry->dot11Bssid[2],
                            pBssEntry->dot11Bssid[3],
                            pBssEntry->dot11Bssid[4],
                            pBssEntry->dot11Bssid[5]);
                    wprintf(L"  CenterFrequency:  %ul\n", pBssEntry->ulChCenterFrequency);
                    wprintf(L"  RSSI:  %ld \n", pBssEntry->lRssi);
                }
            }

            wprintf(L"\n");
            if(expected < pBssList->dwNumberOfItems) {
                wprintf(L"MitM THREAT SUSPECTED: \n");
                wprintf(L"  EXPECTED: %d\n", expected);
                wprintf(L"  FOUND: %d\n", pBssList->dwNumberOfItems);
            } else {
                wprintf(L"NO MitM FOUND for %s", ssid);
            }
        }
    }

    cleanup:
    {
        if (hClient != NULL) {
            WlanCloseHandle(hClient, NULL);
            hClient = NULL;
        }

        if (pIfList != NULL) {
            WlanFreeMemory(pIfList);
            pIfList = NULL;
        }

        if (pBssList != NULL) {
            WlanFreeMemory(pBssList);
            pBssList = NULL;
        }
    }

    return dwRetVal;
}
