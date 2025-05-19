#pragma once


enum class PEInputMode
{
    FromFile,
    FromRegistry,
    FromBuffer
};

//Declarations
NewPEInfo StorePEInMemory(
    PEInputMode mode,
    LPCSTR strPEPath = nullptr,      // Explicit default
    LPCSTR regKeyPath = nullptr,     // Explicit default
    LPCSTR regValuePrefix = nullptr,  // Explicit default
    const BYTE* pBuffer = nullptr,        // Explicit default
    SIZE_T bufferSize = 0                 // Explicit default
);
std::string getArch(const NewPEInfo& peInfo);
SIZE_T GetImageSize(const NewPEInfo& peInfo);
PROCESS_INFORMATION GetDestProcessInfo(LPCSTR strDestPath);
#pragma once  

#include "ntapi.h" // Ensure this header is included for PEB definition  

PEB GetPEBExternal(HANDLE hProc);
DWORD get_sec_protection(DWORD sectionCharacteristics);