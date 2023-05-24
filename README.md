# Fileless-Malware
Anti-Forensics Malware Evasion Techniques

1. Hiding exe files in registry
2. Process Hollowing

TO NOTE:
1. Should only be compiled as x86
2. All files selected should be 32-bit
3. Can only perform process hollowing between same application types (GUI TO GUI or Console to Console)
4. Example executable (MissionEvasion.exe) uses c:\windows\syswow64\notepad.exe for the dummy process. Check if you have this executable, otherwise you may specify another one (refer to point 2) by changing DUMMY_PROCESS_FILE_PATH in config.ini
5. Project was compiled with Visual Studio 2022

HOW TO USE:
1. Apply all your changes to config.ini
2. Compile FilelessMalware.cpp as x86 or simply run MissionEvasion.exe
3. enter 'e' to hide a file in registry
4. enter 'w' to inject PE image hidden in registry to a dummy exe of your choice (will only work if you have existing PE image in the registry key set in config.ini)


References:
https://www.ired.team/offensive-security/code-injection-process-injection/process-hollowing-and-pe-image-relocations
https://www.codereversing.com/archives/261
