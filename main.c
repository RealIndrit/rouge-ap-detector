#include <wchar.h>
#include <windows.h>
#include <wlanapi.h>

#define TARGET_SSID "TheCrib 5GHz" /// Name
#define TARGET_SECURITY TRUE /// HAS WAEP2 Security
#define TARGET_BSSTYPE 1 /// Infrastructre
#define TARGET_EXPECTED_RESPONSE 1 /// Only one AP should pop up

#define MAX_CLIENT 2 /// https://learn.microsoft.com/en-us/windows/win32/api/wlanapi/nf-wlanapi-wlanopenhandle

int main(void) {
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

//            WlanRegisterNotification(hClient, WLAN_NOTIFICATION_SOURCE_ACM, TRUE, )
            // Flush buffers and populate with latest wifi scan data
            dwResult = WlanScan(hClient, &pIfInfo->InterfaceGuid, NULL, NULL, NULL);

            if (dwResult != ERROR_SUCCESS) {
                wprintf(L"WlanScan failed for interface: %u\n", i);
                dwRetVal = 1;
                goto cleanup;
            }


            wprintf(L"Interface Index: %d\n", i);
            wprintf(L"  InterfaceDescription: %ls\n", pIfInfo->strInterfaceDescription);


            /**
             * pDot11Ssid IS NULL = ALL BSS ARE LISTED https://learn.microsoft.com/en-us/windows/win32/api/wlanapi/nf-wlanapi-wlangetnetworkbsslist
             * dot11BssType IGNORED https://learn.microsoft.com/en-us/windows/win32/nativewifi/dot11-bss-type
             * bSecurityEnabled IGNORED
             **/
            if(TARGET_SSID == NULL) {
                dwResult = WlanGetNetworkBssList(hClient,
                                                 &pIfInfo->InterfaceGuid,
                                                 NULL,
                                                 3,
                                                 TRUE,
                                                 NULL,
                                                 &pBssList);
            } else {
                DOT11_SSID target;
                strcpy(target.ucSSID, TARGET_SSID);
                target.uSSIDLength = (ULONG) strlen(TARGET_SSID);

                dwResult = WlanGetNetworkBssList(hClient,
                                                 &pIfInfo->InterfaceGuid,
                                                 &target,
                                                 TARGET_BSSTYPE,
                                                 TARGET_SECURITY,
                                                 NULL,
                                                 &pBssList);
            }

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
            if(TARGET_EXPECTED_RESPONSE > 0 && TARGET_EXPECTED_RESPONSE < pBssList->dwNumberOfItems) {
                wprintf(L"MitM THREAT SUSPECTED: \n");
                wprintf(L"  EXPECTED: %d\n", TARGET_EXPECTED_RESPONSE);
                wprintf(L"  FOUND: %d\n", pBssList->dwNumberOfItems);
            } else {
                wprintf(L"NO MitM FOUND for %s", TARGET_SSID);
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
