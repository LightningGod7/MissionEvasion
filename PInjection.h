#pragma once


PROCESS_INFORMATION OverwriteProcess(NewPEInfo& peInfo, PROCESS_INFORMATION procInfo, void*& pBase, SIZE_T imageSize);

void ResumeDestProcess(const NewPEInfo& peInfo, const PROCESS_INFORMATION& procInfo, void* pBase);