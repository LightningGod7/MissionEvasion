
#pragma once

#include <windows.h>       // For HKEY, RegCreateKeyExA, etc.
#include <array>           // For std::array
#include <string>          // For std::string

// Constants (adjust READ_WRITE_SIZE as needed)
constexpr DWORD REG_RW_SIZE = 4096;  // Example default size

// Function Declarations (no definitions!)

// Opens/Creates a registry key
HKEY OpenRegKey(
    HKEY hRegPath,
    const char* const strKeyName,
    const bool bKeyCreated = true
);

// Writes binary data (B64 encoded) to a registry value
void WriteToRegKeyValue(
    const HKEY hKey,
    const char* const strValueName,
    const BYTE* pBytesOfFile,
    const DWORD dwSplitSize
);

// Reads binary data (B64 decoded) from a registry value
std::array<BYTE, REG_RW_SIZE> ReadRegKeyValue(
    const char* const strKeyName,
    const char* const strValueName,
    bool& bErrorOccured,
    bool& bReadStatus
);

// Helper functions (if used elsewhere, declare here)
extern std::string base64_encode(const BYTE* data, size_t length);  // Assuming these exist
extern std::string base64_decode(const std::string& encoded);