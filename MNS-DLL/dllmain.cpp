// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"


//Thread IDS
DWORD tHeartbeat, tAntiDebug, tAntiAnalysis, tModuleScan, tMain;

//Thread handles
HANDLE hHeartbeat, hAntiDebug, hAntiAnalysis, hModuleScan, hMain;

//Runs the AntiDebug functions on the protected process
DWORD WINAPI AntiDebugThread() {
	HideThread(GetCurrentThread());

	while (1)
	{
		exec_check(&IsDebuggerPresentAPI, TEXT("Checking IsDebuggerPresent API "));
		exec_check(&IsDebuggerPresentPEB, TEXT("Checking PEB.BeingDebugged "));
		exec_check(&CheckRemoteDebuggerPresentAPI, TEXT("Checking CheckRemoteDebuggerPresent API "));
		exec_check(&NtGlobalFlag, TEXT("Checking PEB.NtGlobalFlag "));
		exec_check(&HeapFlags, TEXT("Checking ProcessHeap.Flags "));
		exec_check(&HeapForceFlags, TEXT("Checking ProcessHeap.ForceFlags "));
		exec_check(&LowFragmentationHeap, TEXT("Checking Low Fragmentation Heap"));
		exec_check(&WUDF_IsAnyDebuggerPresent, TEXT("Checking WudfIsAnyDebuggerPresent API "));
		exec_check(&WUDF_IsKernelDebuggerPresent, TEXT("Checking WudfIsKernelDebuggerPresent API "));
		exec_check(&WUDF_IsUserDebuggerPresent, TEXT("Checking WudfIsUserDebuggerPresent API "));
		exec_check(&CloseHandle_InvalideHandle, TEXT("Checking CloseHandle with an invalide handle "));
		exec_check(&OutputDebugStringAPI, TEXT("Checking OutputDebugString "));
		exec_check(&HardwareBreakpoints, TEXT("Checking Hardware Breakpoints "));
		exec_check(&SoftwareBreakpoints, TEXT("Checking Software Breakpoints "));
		exec_check(&MemoryBreakpoints_PageGuard, TEXT("Checking Memory Breakpoints PAGE GUARD "));
		exec_check(&CanOpenCsrss, TEXT("Checking SeDebugPrivilege "));
		exec_check(&SetHandleInformatiom_ProtectedHandle, TEXT("Checking CloseHandle protected handle trick  "));
		exec_check(&SharedUserData_KernelDebugger, TEXT("Checking SharedUserData->KdDebuggerEnabled  "));
		exec_check(&ProcessJob, TEXT("Checking if process is in a job  "));
		exec_check(&VirtualAlloc_WriteWatch_BufferOnly, TEXT("Checking VirtualAlloc write watch (buffer only) "));
		exec_check(&VirtualAlloc_WriteWatch_APICalls, TEXT("Checking VirtualAlloc write watch (API calls) "));
		exec_check(&VirtualAlloc_WriteWatch_IsDebuggerPresent, TEXT("Checking VirtualAlloc write watch (IsDebuggerPresent) "));
		exec_check(&VirtualAlloc_WriteWatch_CodeWrite, TEXT("Checking VirtualAlloc write watch (code write) "));
		exec_check(&PageExceptionBreakpointCheck, TEXT("Checking for page exception breakpoints "));
		exec_check(&ModuleBoundsHookCheck, TEXT("Checking for API hooks outside module bounds "));

		Sleep(5000);
	}
}

//Checks for analysis tools
DWORD WINAPI AntiAnalysisThread() {
	HideThread(GetCurrentThread());

	while (1)
	{
		analysis_tools_process();
		ScanWindows();
		Sleep(5000);
	}
}

//Checks for injected modules
DWORD WINAPI ModuleScanThread() {
	HideThread(GetCurrentThread());

	while (1)
	{
		print_category(TEXT("DLL Injection Detection"));
		exec_check(&ScanForModules_EnumProcessModulesEx_32bit, TEXT("Enumerating modules with EnumProcessModulesEx [32-bit] "));
		exec_check(&ScanForModules_EnumProcessModulesEx_64bit, TEXT("Enumerating modules with EnumProcessModulesEx [64-bit] "));
		exec_check(&ScanForModules_EnumProcessModulesEx_All, TEXT("Enumerating modules with EnumProcessModulesEx [ALL] "));
		exec_check(&ScanForModules_ToolHelp32, TEXT("Enumerating modules with ToolHelp32 "));
		exec_check(&ScanForModules_LdrEnumerateLoadedModules, TEXT("Enumerating the process LDR via LdrEnumerateLoadedModules "));
		exec_check(&ScanForModules_MemoryWalk_GMI, TEXT("Walking process memory with GetModuleInformation "));
		exec_check(&ScanForModules_MemoryWalk_Hidden, TEXT("Walking process memory for hidden modules "));

		Sleep(5000);
	}

}


DWORD WINAPI Main() {
	HideThread(GetCurrentThread());

	while (1) 
	{
		DWORD MNS_PID = GetProcessIdFromName(L"MNS-CONSOLE.exe");
		DWORD PARENT_PID = getParentProcessId();
		if (MNS_PID == PARENT_PID)
		{
			Sleep(200);
		}
		else
		{
			exit(0); // TODO: Make proper exit function to terminate all threads
		}
		
	}

}


BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
		case DLL_PROCESS_ATTACH:
			hAntiDebug = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)AntiDebugThread, NULL, 0, &tAntiDebug);
			hAntiAnalysis = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)AntiAnalysisThread, NULL, 0, &tAntiAnalysis);
			hModuleScan = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)ModuleScanThread, NULL, 0, &tModuleScan);
			hMain = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)Main, NULL, 0, &tMain);
			
		case DLL_THREAD_ATTACH:
		case DLL_THREAD_DETACH:
		case DLL_PROCESS_DETACH:
			break;
    }
    return TRUE;
}

