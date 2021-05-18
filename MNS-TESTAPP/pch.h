// pch.h: This is a precompiled header file.
// Files listed below are compiled only once, improving build performance for future builds.
// This also affects IntelliSense performance, including code completion and many code browsing features.
// However, files listed here are ALL re-compiled if any one of them is updated between builds.
// Do not add files here that you will be updating frequently as this negates the performance advantage.

#ifndef PCH_H
#define PCH_H

// add headers that you want to pre-compile here


#include <string>
#include <vector>

#include <Windows.h>
#include <winternl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <IPTypes.h>
#include <Iphlpapi.h>
#include <icmpapi.h>
#include <Psapi.h>
#include <Shlwapi.h>
#include <ShlObj.h>
#include <stdarg.h>
#include <strsafe.h>
#include <tchar.h>
#include <time.h>
#include <TlHelp32.h>
#include <Wbemidl.h>
#include <devguid.h>    // Device guids
#include <winioctl.h>	// IOCTL
#include <intrin.h>		// cpuid()
#include <locale.h>		// 64-bit wchar atoi
#include <powrprof.h>	// check_power_modes()
#include <SetupAPI.h>
#include <algorithm>
#include <cctype>
#include <slpublic.h> // SLIsGenuineLocal

#pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib, "Shlwapi.lib")
#pragma comment(lib, "Mpr.lib")
#pragma comment(lib, "Iphlpapi.lib")
#pragma comment(lib, "Shlwapi.lib")
#pragma comment(lib, "Psapi.lib")
#pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib, "Winmm.lib")
#pragma comment(lib, "setupapi.lib")
#pragma comment(lib, "powrprof.lib")
#pragma comment(lib, "Slwga.lib")

#include "Shared/Common.h"
#include "Shared/VersionHelpers.h"
#include "Shared/log.h"
#include "Shared/Utils.h"
#include "Shared/WinStructs.h"
#include "Shared/ApiTypeDefs.h"
#include "Shared/APIs.h"
#include "Shared/winapifamily.h"

/* AntiDebugs headers */
#include "AntiDebug/CheckRemoteDebuggerPresent.h"
#include "AntiDebug/IsDebuggerPresent.h"
#include "AntiDebug/BeingDebugged.h"
#include "AntiDebug/ProcessHeap_Flags.h"
#include "AntiDebug/ProcessHeap_ForceFlags.h"
#include "AntiDebug/NtGlobalFlag.h"
#include "AntiDebug/NtQueryInformationProcess_ProcessDebugPort.h"
#include "AntiDebug/NtQueryInformationProcess_ProcessDebugFlags.h"
#include "AntiDebug/NtQueryInformationProcess_ProcessDebugObject.h"
#include "AntiDebug/NtSetInformationThread_ThreadHideFromDebugger.h"
#include "AntiDebug/CloseHandle_InvalidHandle.h"
#include "AntiDebug/UnhandledExceptionFilter_Handler.h"
#include "AntiDebug/OutputDebugStringAPI.h"
#include "AntiDebug/HardwareBreakpoints.h"
#include "AntiDebug/SoftwareBreakpoints.h"
#include "AntiDebug/Interrupt_3.h"
#include "AntiDebug/TrapFlag.h"
#include "AntiDebug/MemoryBreakpoints_PageGuard.h"
#include "AntiDebug/ParentProcess.h"
#include "AntiDebug/SeDebugPrivilege.h"
#include "AntiDebug/NtQueryObject_ObjectInformation.h"
#include "AntiDebug/NtYieldExecution.h"
#include "AntiDebug/SetHandleInformation_API.h"
#include "AntiDebug/TLS_callbacks.h"
#include "AntiDebug/NtQuerySystemInformation_SystemKernelDebuggerInformation.h"
#include "AntiDebug/SharedUserData_KernelDebugger.h"
#include "AntiDebug/ProcessJob.h"
#include "AntiDebug/WriteWatch.h"
#include "AntiDebug/PageExceptionBreakpointCheck.h"
#include "AntiDebug/ModuleBoundsHookCheck.h"
#include "AntiDebug/ScanForModules.h"
#include "AntiDebug/WUDF_IsDebuggerPresent.h"
#include "AntiDebug/LowFragmentationHeap.h"
#include "AntiDebug/TestModeEnabled.h"


/* Anti dumping headers */
#include "AntiDump/ErasePEHeaderFromMemory.h"
#include "AntiDump/SizeOfImage.h"

/* Anti VM headers */
#include "AntiVM/VirtualBox.h"
#include "AntiVM/VMware.h"
#include "AntiVM/Wine.h"
#include "AntiVM/Generic.h"
#include "AntiVM/VirtualPC.h"
#include "AntiVM/QEMU.h"
#include "AntiVM/Xen.h"
#include "AntiVM/Parallels.h"
#include "AntiVM/Services.h"



/* Delay Execution */
#include "TimingAttacks/timing.h"

/* Anti-Analysis */
#include "AntiAnalysis/process.h"
#include "AntiAnalysis/WindowScanner.h"



#endif //PCH_H
