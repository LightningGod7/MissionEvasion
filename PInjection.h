#pragma once

// Inject Source PE Header into Destination
bool WritePEHeader(
    bool is64Bit,
    const NewPEInfo& srcPEInfo,
    PROCESS_INFORMATION& destProcessInfo,
    LPVOID destImageBase,
    SIZE_T DestImageSize,
    DWORD ulSrcImageSize,
    DWORD dwSrcHeaderSize,
    SIZE_T& dwBytesWritten);

// Inject Source PE sections into Destination
bool WritePESections(
    HANDLE hDestProcess,
    LPVOID destImageBase,
    const BYTE* pFileData,
    WORD numberOfSections,
    IMAGE_DOS_HEADER* pDosHeader);

// Restore relocations in the destination process
bool PatchRelocations(
    bool is64Bit,
    NewPEInfo& srcPEInfo,
    PROCESS_INFORMATION& destProcessInfo,
    LPVOID destImageBase,
    ULONGLONG deltaImageBase,
    WORD wSrcNumberOfSections,
    SIZE_T& bytesRead);

// Patch section protections in the destination process
bool PatchSectionProtections(
    HANDLE hProcess,
    IMAGE_DOS_HEADER* pDosHeader,
    LPVOID destImageBase,
    const BYTE* pFileData,
    WORD numberOfSections,
    size_t imageSize);

// Main injection function
PROCESS_INFORMATION ProcessOverwriting(NewPEInfo& srcPEInfo,
    PROCESS_INFORMATION destProcessInfo,
    PVOID& destImageBase,
    SIZE_T DestImageSize);

PROCESS_INFORMATION ProcessHollowing(NewPEInfo& srcPEInfo,
    PROCESS_INFORMATION destProcessInfo,
    PVOID& destImageBase,
    SIZE_T DestImageSize);

// Resume the destination process
void ResumeDestProcess(
    const NewPEInfo& srcPEInfo,
    const PROCESS_INFORMATION& destProcessInfo,
    PVOID destImageBase);