// al-khaser.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include "pch.h"

//Threads
DWORD tHeartbeat, tAntiDebug, tAntiAnalysis, tModuleScan;

//Mutex


//Runs the AntiDebug functions on the monitoring system
VOID AntiDebugThread() {
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
		exec_check(&NtQueryInformationProcess_ProcessDebugPort, TEXT("Checking NtQueryInformationProcess with ProcessDebugPort "));
		exec_check(&NtQueryInformationProcess_ProcessDebugFlags, TEXT("Checking NtQueryInformationProcess with ProcessDebugFlags "));
		exec_check(&NtQueryInformationProcess_ProcessDebugObject, TEXT("Checking NtQueryInformationProcess with ProcessDebugObject "));
		exec_check(&WUDF_IsAnyDebuggerPresent, TEXT("Checking WudfIsAnyDebuggerPresent API "));
		exec_check(&WUDF_IsKernelDebuggerPresent, TEXT("Checking WudfIsKernelDebuggerPresent API "));
		exec_check(&WUDF_IsUserDebuggerPresent, TEXT("Checking WudfIsUserDebuggerPresent API "));
		exec_check(&NtSetInformationThread_ThreadHideFromDebugger, TEXT("Checking NtSetInformationThread with ThreadHideFromDebugger "));
		exec_check(&CloseHandle_InvalideHandle, TEXT("Checking CloseHandle with an invalide handle "));
		//exec_check(&UnhandledExcepFilterTest, TEXT("Checking UnhandledExcepFilterTest "));
		exec_check(&OutputDebugStringAPI, TEXT("Checking OutputDebugString "));
		exec_check(&HardwareBreakpoints, TEXT("Checking Hardware Breakpoints "));
		exec_check(&SoftwareBreakpoints, TEXT("Checking Software Breakpoints "));
		exec_check(&Interrupt_0x2d, TEXT("Checking Interupt 0x2d "));
		exec_check(&Interrupt_3, TEXT("Checking Interupt 1 "));
		exec_check(&TrapFlag, TEXT("Checking trap flag"));
		exec_check(&MemoryBreakpoints_PageGuard, TEXT("Checking Memory Breakpoints PAGE GUARD "));
		exec_check(&IsParentExplorerExe, TEXT("Checking If Parent Process is explorer.exe "));
		exec_check(&CanOpenCsrss, TEXT("Checking SeDebugPrivilege "));
		exec_check(&NtQueryObject_ObjectTypeInformation, TEXT("Checking NtQueryObject with ObjectTypeInformation "));
		exec_check(&NtQueryObject_ObjectAllTypesInformation, TEXT("Checking NtQueryObject with ObjectAllTypesInformation "));
		exec_check(&NtYieldExecutionAPI, TEXT("Checking NtYieldExecution "));
		exec_check(&SetHandleInformatiom_ProtectedHandle, TEXT("Checking CloseHandle protected handle trick  "));
		exec_check(&NtQuerySystemInformation_SystemKernelDebuggerInformation, TEXT("Checking NtQuerySystemInformation with SystemKernelDebuggerInformation  "));
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
VOID AntiAnalysisThread() {
	HideThread(GetCurrentThread());

	while (1) 
	{
		analysis_tools_process();
		ScanWindows();
		Sleep(5000);
	}
}

//Checks for injected modules
VOID ModuleScanThread() {
	HideThread(GetCurrentThread());

	while (1)
	{
		print_category(TEXT("DLL Injection Detection"));
		exec_check(&ScanForModules_EnumProcessModulesEx_32bit, TEXT("Enumerating modules with EnumProcessModulesEx [32-bit] "));
		exec_check(&ScanForModules_EnumProcessModulesEx_64bit, TEXT("Enumerating modules with EnumProcessModulesEx [64-bit] "));
		exec_check(&ScanForModules_EnumProcessModulesEx_All, TEXT("Enumerating modules with EnumProcessModulesEx [ALL] "));
		exec_check(&ScanForModules_ToolHelp32, TEXT("Enumerating modules with ToolHelp32 "));
		exec_check(&ScanForModules_LdrEnumerateLoadedModules, TEXT("Enumerating the process LDR via LdrEnumerateLoadedModules "));
		exec_check(&ScanForModules_LDR_Direct, TEXT("Enumerating the process LDR directly "));
		exec_check(&ScanForModules_MemoryWalk_GMI, TEXT("Walking process memory with GetModuleInformation "));
		exec_check(&ScanForModules_MemoryWalk_Hidden, TEXT("Walking process memory for hidden modules "));

		Sleep(5000);
	}

}

//Runs the heartbeat thread - synchronized with the driver
VOID HeartbeatThread() {
	HideThread(GetCurrentThread());
	ULONG FOR1, FOR2, FOR3, FOR4, FOR5;
	while (1)
	{
		/*srand(time(0));
		FOR1 = Heartbeat::randNum(2, 63);
		FOR2 = Heartbeat::randNum(3, 34);
		FOR3 = Heartbeat::randNum(8, 45);
		FOR4 = Heartbeat::randNum(5, 67);
		FOR5 = Heartbeat::randNum(2, 12);

		if (DriverRequest::HEARTBEATMAINSTART_FORWARD_Function(FOR1, FOR2, FOR3, FOR4, FOR5))
		{
			KERNEL_HEARTBEAT_REQUEST RETURNED_HEARTBEAT_CREATEPROCESS = DriverRequest::HEARTBEATMAINSTART_RETURN_Function();


			if (RETURNED_HEARTBEAT_CREATEPROCESS.Encrypt1 == HeartbeatFormula::Formula1(FOR1))
			{
				if (RETURNED_HEARTBEAT_CREATEPROCESS.Encrypt2 == HeartbeatFormula::Formula2(FOR2))
				{
					if (RETURNED_HEARTBEAT_CREATEPROCESS.Encrypt3 == HeartbeatFormula::Formula3(FOR3))
					{
						if (RETURNED_HEARTBEAT_CREATEPROCESS.Encrypt4 == HeartbeatFormula::Formula4(FOR4))
						{
							if (RETURNED_HEARTBEAT_CREATEPROCESS.Encrypt5 == HeartbeatFormula::Formula5(FOR5))
							{
								KERNEL_HEARTBEAT_REQUEST RETURNED_HEARTBEAT_CREATEPROCESS_CREATEPROCESS = DriverRequest::HEARTBEATCREATEPROCESS_RETURN_Function();

								CHECK_CREATEPROCESS1 = HeartbeatFormula::Formula1(RETURNED_HEARTBEAT_CREATEPROCESS_CREATEPROCESS.Encrypt1);
								CHECK_CREATEPROCESS2 = HeartbeatFormula::Formula2(RETURNED_HEARTBEAT_CREATEPROCESS_CREATEPROCESS.Encrypt2);
								CHECK_CREATEPROCESS3 = HeartbeatFormula::Formula3(RETURNED_HEARTBEAT_CREATEPROCESS_CREATEPROCESS.Encrypt3);
								CHECK_CREATEPROCESS4 = HeartbeatFormula::Formula4(RETURNED_HEARTBEAT_CREATEPROCESS_CREATEPROCESS.Encrypt4);
								CHECK_CREATEPROCESS5 = HeartbeatFormula::Formula5(RETURNED_HEARTBEAT_CREATEPROCESS_CREATEPROCESS.Encrypt5);
								if (DriverRequest::HEARTBEATCREATEPROCESS_FORWARD_Function(CHECK_CREATEPROCESS1, CHECK_CREATEPROCESS2, CHECK_CREATEPROCESS3, CHECK_CREATEPROCESS4, CHECK_CREATEPROCESS5))
								{
									
									Sleep(400);
								}
								else
								{
									print_exit(L"Heartbeat System Failed");
									Sleep(3000);
									exit(1);
								}

							}
							else
							{
								print_exit(L"Heartbeat System Failed");
								Sleep(3000);
								exit(1);
							}
						}
						else
						{
							print_exit(L"Heartbeat System Failed");
							Sleep(3000);
							exit(1);
						}
					}
					else
					{
						print_exit(L"Heartbeat System Failed");
						Sleep(3000);
						exit(1);
					}
				}
				else
				{
					print_exit(L"Heartbeat System Failed");
					Sleep(3000);
					exit(1);
				}
			}
			else
			{
				print_exit(L"Heartbeat System Failed");
				Sleep(3000);
				exit(1);
			}
		}
		else
		{
			print_exit(L"Heartbeat System Failed");
			Sleep(3000);
			exit(1);
		}*/
		Sleep(100);
	}

}


VOID SandboxScan() {
	print_category(TEXT("Generic Sandboxe/VM Detection"));
	loaded_dlls();
	known_file_names();
	known_usernames();
	known_hostnames();
	other_known_sandbox_environment_checks();
	exec_check(&NumberOfProcessors, TEXT("Checking Number of processors in machine "));
	exec_check(&idt_trick, TEXT("Checking Interupt Descriptor Table location "));
	exec_check(&ldt_trick, TEXT("Checking Local Descriptor Table location "));
	exec_check(&gdt_trick, TEXT("Checking Global Descriptor Table location "));
	exec_check(&str_trick, TEXT("Checking Store Task Register "));
	exec_check(&number_cores_wmi, TEXT("Checking Number of cores in machine using WMI "));
	exec_check(&disk_size_wmi, TEXT("Checking hard disk size using WMI "));
	exec_check(&dizk_size_deviceiocontrol, TEXT("Checking hard disk size using DeviceIoControl "));
	exec_check(&setupdi_diskdrive, TEXT("Checking SetupDi_diskdrive "));
	exec_check(&mouse_movement, TEXT("Checking mouse movement "));
	exec_check(&lack_user_input, TEXT("Checking lack of user input "));
	exec_check(&memory_space, TEXT("Checking memory space using GlobalMemoryStatusEx "));
	exec_check(&disk_size_getdiskfreespace, TEXT("Checking disk size using GetDiskFreeSpaceEx "));
	exec_check(&cpuid_is_hypervisor, TEXT("Checking if CPU hypervisor field is set using cpuid(0x1)"));
	exec_check(&cpuid_hypervisor_vendor, TEXT("Checking hypervisor vendor using cpuid(0x40000000)"));
	//exec_check(&accelerated_sleep, TEXT("Check if time has been accelerated "));
	exec_check(&VMDriverServices, TEXT("VM Driver Services  "));
	exec_check(&serial_number_bios_wmi, TEXT("Checking SerialNumber from BIOS using WMI "));
	exec_check(&model_computer_system_wmi, TEXT("Checking Model from ComputerSystem using WMI "));
	exec_check(&manufacturer_computer_system_wmi, TEXT("Checking Manufacturer from ComputerSystem using WMI "));
	exec_check(&current_temperature_acpi_wmi, TEXT("Checking Current Temperature using WMI "));
	exec_check(&process_id_processor_wmi, TEXT("Checking ProcessId using WMI "));
	exec_check(&power_capabilities, TEXT("Checking power capabilities "));
	exec_check(&cpu_fan_wmi, TEXT("Checking CPU fan using WMI "));
	exec_check(&query_license_value, TEXT("Checking NtQueryLicenseValue with Kernel-VMDetection-Private "));
	exec_check(&cachememory_wmi, TEXT("Checking Win32_CacheMemory with WMI "));
	exec_check(&physicalmemory_wmi, TEXT("Checking Win32_PhysicalMemory with WMI "));
	exec_check(&memorydevice_wmi, TEXT("Checking Win32_MemoryDevice with WMI "));
	exec_check(&memoryarray_wmi, TEXT("Checking Win32_MemoryArray with WMI "));
	exec_check(&voltageprobe_wmi, TEXT("Checking Win32_VoltageProbe with WMI "));
	exec_check(&portconnector_wmi, TEXT("Checking Win32_PortConnector with WMI "));
	exec_check(&smbiosmemory_wmi, TEXT("Checking Win32_SMBIOSMemory with WMI "));
	exec_check(&perfctrs_thermalzoneinfo_wmi, TEXT("Checking ThermalZoneInfo performance counters with WMI "));
	exec_check(&cim_memory_wmi, TEXT("Checking CIM_Memory with WMI "));
	exec_check(&cim_sensor_wmi, TEXT("Checking CIM_Sensor with WMI "));
	exec_check(&cim_numericsensor_wmi, TEXT("Checking CIM_NumericSensor with WMI "));
	exec_check(&cim_temperaturesensor_wmi, TEXT("Checking CIM_TemperatureSensor with WMI "));
	exec_check(&cim_voltagesensor_wmi, TEXT("Checking CIM_VoltageSensor with WMI "));
	exec_check(&cim_physicalconnector_wmi, TEXT("Checking CIM_PhysicalConnector with WMI "));
	exec_check(&cim_slot_wmi, TEXT("Checking CIM_Slot with WMI "));
	exec_check(&pirated_windows, TEXT("Checking if Windows is Genuine "));
	exec_check(&registry_services_disk_enum, TEXT("Checking Services\\Disk\\Enum entries for VM strings "));
	exec_check(&registry_disk_enum, TEXT("Checking Enum\\IDE and Enum\\SCSI entries for VM strings "));

}

VOID VirtualMachineScan() {
	print_category(TEXT("Virtual Machine Scan"));
	vbox_reg_key_value();
	exec_check(&vbox_dir, TEXT("Checking VirtualBox Guest Additions directory "));
	vbox_files();
	vbox_reg_keys();
	exec_check(&vbox_check_mac, TEXT("Checking Mac Address start with 08:00:27 "));
	exec_check(&hybridanalysismacdetect, TEXT("Checking MAC address (Hybrid Analysis) "));
	vbox_devices();
	exec_check(&vbox_window_class, TEXT("Checking VBoxTrayToolWndClass / VBoxTrayToolWnd "));
	exec_check(&vbox_network_share, TEXT("Checking VirtualBox Shared Folders network provider "));
	vbox_processes();
	exec_check(&vbox_pnpentity_pcideviceid_wmi, TEXT("Checking Win32_PnPDevice DeviceId from WMI for VBox PCI device "));
	exec_check(&vbox_pnpentity_controllers_wmi, TEXT("Checking Win32_PnPDevice Name from WMI for VBox controller hardware "));
	exec_check(&vbox_pnpentity_vboxname_wmi, TEXT("Checking Win32_PnPDevice Name from WMI for VBOX names "));
	exec_check(&vbox_bus_wmi, TEXT("Checking Win32_Bus from WMI "));
	exec_check(&vbox_baseboard_wmi, TEXT("Checking Win32_BaseBoard from WMI "));
	exec_check(&vbox_mac_wmi, TEXT("Checking MAC address from WMI "));
	exec_check(&vbox_eventlogfile_wmi, TEXT("Checking NTEventLog from WMI "));
	exec_check(&vbox_firmware_SMBIOS, TEXT("Checking SMBIOS firmware  "));
	exec_check(&vbox_firmware_ACPI, TEXT("Checking ACPI tables  "));
	vmware_reg_key_value();
	vmware_reg_keys();
	vmware_files();
	vmware_mac();
	exec_check(&vmware_adapter_name, TEXT("Checking VMWare network adapter name "));
	vmware_devices();
	exec_check(&vmware_dir, TEXT("Checking VMWare directory "));
	exec_check(&vmware_firmware_SMBIOS, TEXT("Checking SMBIOS firmware  "));
	exec_check(&vmware_firmware_ACPI, TEXT("Checking ACPI tables  "));
	virtual_pc_process();
	virtual_pc_reg_keys();
	qemu_reg_key_value();
	qemu_processes();
	exec_check(&qemu_firmware_SMBIOS, TEXT("Checking SMBIOS firmware  "));
	exec_check(&qemu_firmware_ACPI, TEXT("Checking ACPI tables  "));
	xen_process();
	exec_check(&xen_check_mac, TEXT("Checking Mac Address start with 08:16:3E "));
	exec_check(&wine_exports, TEXT("Checking Wine via dll exports "));
	wine_reg_keys();
	parallels_process();
	exec_check(&parallels_check_mac, TEXT("Checking Mac Address start with 08:1C:42 "));

}

int main(void)
{
	print_category(TEXT("Initialisation"));
	API::Init();
	print_os();
	API::PrintAvailabilityReport();
	
	exec_check(IsTestModeEnabled, TEXT("Checking if Test Sign is Disabled"));

	if (IsElevated()) 
	{
		HideThread(GetCurrentThread());

		VirtualMachineScan();
		SandboxScan();

		ErasePEHeaderFromMemory(); // Dumping Prevention

		HANDLE hHeartbeat, hAntiDebug, hAntiAnalysis, hModuleScan;

		hAntiDebug = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)AntiDebugThread, NULL, 0, &tAntiDebug);
		hHeartbeat = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)HeartbeatThread, NULL, 0, &tHeartbeat);
		hAntiAnalysis = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)AntiAnalysisThread, NULL, 0, &tAntiAnalysis);
		hModuleScan = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)ModuleScanThread, NULL, 0, &tModuleScan);

		STARTUPINFO StartupInfo = { sizeof(StartupInfo) };
		PROCESS_INFORMATION ProcessInfo;
		
		if (CreateProcess(L"C:\\Users\\user\\Desktop\\SLIIT\\Research\\Implementation\\al-khaser-master\\Release\\MNS-TESTAPP.exe", NULL, NULL, NULL, TRUE, CREATE_NEW_CONSOLE, NULL, NULL, &StartupInfo, &ProcessInfo))
		{
			if (Injection(L"MNS-DLL.dll", ProcessInfo.dwProcessId))
			{
				while (1)
				{
					if (isProcessRunning(ProcessInfo.dwProcessId)) 
					{
						Sleep(200);
					}
					else 
					{
						print_exit(L"Protected Process not Running");
						exit(0); //TODO : Make proper exit function to terminate all threads
					}
				}
			}
		}
	}
	else 
	{ // When not run as admin
		TCHAR msg[256] = _T("Check if the program is executed as admin ");
		print_results(TRUE, msg);
	}

	getchar();
	return 0;
}

