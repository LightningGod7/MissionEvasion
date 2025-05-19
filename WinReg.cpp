#pragma once

#include <array>
#include <cstdio>
#include <memory>
#include <string>
#include <vector>
#include <Windows.h>

#include "WinReg.h"
#include "base64.h"

HKEY OpenRegKey(HKEY hRegPath, const char* const strKeyName, const bool bKeyCreated)
{
    HKEY hKey = nullptr;
    DWORD dwResult;

    // CREATE THE REGISTRY KEY
    LONG lCreateKeyStatus = RegCreateKeyExA(
        hRegPath,
        strKeyName, 0, NULL, 0,
        KEY_READ | KEY_WRITE | KEY_CREATE_SUB_KEY,
        NULL, &hKey, &dwResult);

    // CHECK IF KEY CREATED SUCCESSFULLY
    if (lCreateKeyStatus != ERROR_SUCCESS)
    {
        fprintf(stderr, "Could not create key, ERROR: %X\n", lCreateKeyStatus);
        exit(-1);
    }

    // IF KEY WAS CREATED
    if (bKeyCreated && dwResult == REG_CREATED_NEW_KEY)
    {
        fprintf(stdout, "Created new registry key.\n");
    }
    // IF KEY ALREADY EXISTS
    else
    {
        fprintf(stdout, "Opened existing registry key.\n");
    }

    return hKey;
}

// To resolve the ambiguity, explicitly cast the arguments to match the correct overload of base64_encode.  
// Assuming base64_encode has overloads that accept (const BYTE*, size_t) or similar.  

void WriteToRegKeyValue(const HKEY hKey, const char* const strValueName, const BYTE* pBytesOfFile, const DWORD dwSplitSize)  
{  
   // Explicitly cast the arguments to resolve ambiguity.  
   std::string strEncodedFileData = base64_encode(pBytesOfFile, dwSplitSize);  

   // WRITE ENCODED FILE DATA TO REGISTRY KEY VALUE AS REG_SZ  
   LONG lWriteToRegStatus = RegSetValueExA(hKey, strValueName, 0, REG_SZ,  
       (const BYTE*)strEncodedFileData.c_str(),  
       strEncodedFileData.length());  

   // CHECK IF VALUE WAS WRITTEN  
   if (lWriteToRegStatus != ERROR_SUCCESS)  
   {  
       fprintf(stderr, "Could not write registry value. ERROR: %X\n",  
           lWriteToRegStatus);  
       exit(-1);  
   }  
}

std::array<BYTE, REG_RW_SIZE> ReadRegKeyValue(const char* const strKeyName,
    const char* const strValueName, bool& bErrorOccured, bool& bReadStatus)
{
    DWORD dwType = 0;

    // ACCOUNT FOR CHANGE IN SIZE
    const DWORD dwMaxReadSize = REG_RW_SIZE * 2;
    DWORD dwReadSize = dwMaxReadSize;

    char strEncodedFileData[REG_RW_SIZE * 2] = { 0 };

    //GET REGISTRY VALUE STRING
    LONG lGetRegValueStatus = RegGetValueA(HKEY_CURRENT_USER, strKeyName, strValueName,
        RRF_RT_REG_SZ, &dwType, strEncodedFileData, &dwReadSize);


    // CHECK IF COULD GET REGISTRY VALUE
    if (!bReadStatus)
    {
        if (lGetRegValueStatus != ERROR_SUCCESS)
        {
            fprintf(stderr, "Could not read registry value. Error = %X\n",
                lGetRegValueStatus);
            bErrorOccured = true;
        }
        if (dwType != REG_SZ || (dwReadSize == 0 || dwReadSize > dwMaxReadSize))
        {
            fprintf(stderr, "Did not correctly read back a string from the registry.\n");
            bErrorOccured = true;
        }
        else
        {
            bReadStatus = true;
        }

    }

    // CHECK IF REACHED END OF FILE
    else if (lGetRegValueStatus != ERROR_SUCCESS)
    {
        fprintf(stderr, "Successfully read to end of file\n",
            lGetRegValueStatus);
        bErrorOccured = true;
    }

    // INITIALIZE ARRAY TO HOLD DECODED FILE DATA
    std::array<BYTE, REG_RW_SIZE> pBytesOfFile = { 0 };

    //B64 DECODE FILE DATA
    std::string strDecoded = base64_decode(std::string(strEncodedFileData));

    //MEMCPY THE DECODED BYTES INTO THE ARRAY
    (void)memcpy(pBytesOfFile.data(), strDecoded.c_str(), strDecoded.size());



    return pBytesOfFile;
}
