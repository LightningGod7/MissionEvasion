#pragma once
#include <Windows.h>
#include <memory>

#define BOOLIFY(x) !!(x)
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)

const unsigned int READ_WRITE_SIZE = 2048;

// Defining structs

//// NewPEInfo struct
typedef struct
{
    IMAGE_DOS_HEADER* pDosHeader;
    IMAGE_NT_HEADERS32* pNtHeaders32;
    IMAGE_NT_HEADERS64* pNtHeaders64;
    IMAGE_SECTION_HEADER* pSectionHeader;
    IMAGE_DATA_DIRECTORY* pRelocationTable;
    std::unique_ptr<BYTE[]> pFileData;
    ULONGLONG dwFileSize;
} NewPEInfo;

//// Relocation block struct
typedef struct BASE_RELOCATION_BLOCK {
    DWORD PageAddress;
    DWORD BlockSize;
} BASE_RELOCATION_BLOCK, * PBASE_RELOCATION_BLOCK;

//// Relocation Entry struct
typedef struct BASE_RELOCATION_ENTRY {
    WORD Offset : 12;
    WORD Type : 4;
} BASE_RELOCATION_ENTRY, * PBASE_RELOCATION_ENTRY;