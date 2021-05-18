#include "pch.h"
#include "Common.h"

DWORD Injection(PCWSTR pszLibFile, DWORD dwProcessId)
{
	// Calculate the number of bytes needed for the DLL's pathname
	DWORD dwSize = (lstrlenW(pszLibFile) + 1) * sizeof(wchar_t);
	// Get process handle passing in the process ID
	HANDLE hProcess = OpenProcess(
		PROCESS_QUERY_INFORMATION |
		PROCESS_CREATE_THREAD |
		PROCESS_VM_OPERATION |
		PROCESS_VM_WRITE,
		FALSE, dwProcessId);
	if (hProcess == NULL)
	{
		//wprintf(TEXT("[-] Error: Could not open process for PID (%d).\n"), dwProcessId);
		return(1);
	}

	// Allocate space in the remote process for the pathname
	LPVOID pszLibFileRemote = (PWSTR)VirtualAllocEx(hProcess, NULL, dwSize, MEM_COMMIT, PAGE_READWRITE);
	if (pszLibFileRemote == NULL)
	{
		//wprintf(TEXT("[-] Error: Could not allocate memory inside PID (%d).\n"), dwProcessId);
		return(1);
	}

	// Copy the DLL's pathname to the remote process address space
	DWORD n = WriteProcessMemory(hProcess, pszLibFileRemote, (PVOID)pszLibFile, dwSize, NULL);
	if (n == 0)
	{
		//wprintf(TEXT("[-] Error: Could not write any bytes into the PID [%d] address space.\n"), dwProcessId);
		return(1);
	}

	// Get the real address of LoadLibraryW in Kernel32.dll
	PTHREAD_START_ROUTINE pfnThreadRtn = (PTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandle(TEXT("Kernel32")), "LoadLibraryW");
	if (pfnThreadRtn == NULL)
	{
		//wprintf(TEXT("[-] Error: Could not find LoadLibraryA function inside kernel32.dll library.\n"));
		return(1);
	}

	// Create a remote thread that calls LoadLibraryW(DLLPathname)
	HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, pfnThreadRtn, pszLibFileRemote, 0, NULL);
	if (hThread == NULL)
	{
		//wprintf(TEXT("[-] Error: Could not create the Remote Thread.\n"));
		return(1);
	}
	else
	{

	}
	//wprintf(TEXT("[+] Success: DLL injected via CreateRemoteThread().\n"));

// Wait for the remote thread to terminate
	WaitForSingleObject(hThread, INFINITE);

	// Free the remote memory that contained the DLL's pathname and close Handles
	if (pszLibFileRemote != NULL)
		VirtualFreeEx(hProcess, pszLibFileRemote, 0, MEM_RELEASE);

	if (hThread != NULL)
		CloseHandle(hThread);

	if (hProcess != NULL)
		CloseHandle(hProcess);

}
VOID print_exit(const TCHAR* text) 
{
	HANDLE nStdHandle = GetStdHandle(STD_OUTPUT_HANDLE);

	SetConsoleTextAttribute(nStdHandle, 12);
	_tprintf(TEXT("Exiting --- [%s]\n"), text);
	SetConsoleTextAttribute(nStdHandle, 7);
}
VOID print_detected()
{
	/* Get handle to standard output */
	HANDLE nStdHandle = GetStdHandle(STD_OUTPUT_HANDLE);
	
	SetConsoleTextAttribute(nStdHandle, 12);
	_tprintf(TEXT("[ BAD  ]\n"));
	SetConsoleTextAttribute(nStdHandle, 7);
}

VOID print_not_detected()
{
	/* Get handle to standard output */
	HANDLE nStdHandle = GetStdHandle(STD_OUTPUT_HANDLE);
	
	SetConsoleTextAttribute(nStdHandle, 10);
	_tprintf(TEXT("[ GOOD ]\n"));
	SetConsoleTextAttribute(nStdHandle, 7);
}

VOID print_category(const TCHAR* text)
{
	/* Get handle to standard output */
	HANDLE nStdHandle = GetStdHandle(STD_OUTPUT_HANDLE);  
	CONSOLE_SCREEN_BUFFER_INFO ConsoleScreenBufferInfo;
	SecureZeroMemory(&ConsoleScreenBufferInfo, sizeof(CONSOLE_SCREEN_BUFFER_INFO));

	/* Save the original console color */
	GetConsoleScreenBufferInfo(nStdHandle, &ConsoleScreenBufferInfo);
	WORD OriginalColors = *(&ConsoleScreenBufferInfo.wAttributes);

	SetConsoleTextAttribute(nStdHandle, 13);
	_tprintf(TEXT("\n-------------------------[%s]-------------------------\n"), text);
	SetConsoleTextAttribute(nStdHandle, OriginalColors);
}

VOID _print_check_text(const TCHAR* szMsg)
{
	_tprintf(TEXT("[*] %s"), szMsg);

	/* align the result according to the length of the text */
	size_t spaces_to_padd = 95 - _tcslen(szMsg);
	while (spaces_to_padd > 0) {
		_tprintf(TEXT(" "));
		spaces_to_padd--;
	}
}

VOID _print_check_result(int result, const TCHAR* szMsg)
{
	
	if (result == TRUE) 
	{
		print_detected();
		TCHAR buffer[256] = _T("");
		_stprintf_s(buffer, sizeof(buffer) / sizeof(TCHAR), _T("[*] %s -> %d"), szMsg, result);
		LOG_PRINT(buffer);
	}
	else
		print_not_detected();

	/* log to file*/
	
}

VOID print_results(int result, TCHAR* szMsg)
{
	_print_check_text(szMsg);
	_print_check_result(result, szMsg);
}

// note: templated version of this function is in Common.h
VOID exec_check(int(*callback)(), const TCHAR* szMsg)
{

	/* Print the text to screen so we can see what's currently running */
	_print_check_text(szMsg);

	/* Call our check */
	int result = callback();

	/* Print / Log the result */
	if (szMsg)
		_print_check_result(result, szMsg);
}

VOID resize_console_window()
{
	// Change the window title:
	SetConsoleTitle(_T("MNS-CONSOLE"));

	// Get console window handle
	HWND wh = GetConsoleWindow();

	// Move window to required position
	MoveWindow(wh, 100, 100, 900, 900, TRUE);
}


VOID print_os()
{
	TCHAR szOS[MAX_PATH] = _T("");
	if (GetOSDisplayString(szOS))
	{
		//_tcscpy_s(szOS, MAX_PATH, szOS);
		_tprintf(_T("\n[*] You are running: %s\n"), szOS);
	}
}

VOID print_last_error(LPCTSTR lpszFunction)
{
	// Retrieve the system error message for the last-error code

	LPVOID lpMsgBuf;
	LPVOID lpDisplayBuf;
	DWORD dw = GetLastError();

	if (FormatMessage(
		FORMAT_MESSAGE_ALLOCATE_BUFFER |
		FORMAT_MESSAGE_FROM_SYSTEM |
		FORMAT_MESSAGE_IGNORE_INSERTS,
		NULL,
		dw,
		MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
		(LPTSTR)&lpMsgBuf,
		0, NULL) == 0)
	{
		//FormatMessage failed, return
		return;
	}

	// Display the error message and exit the process

	lpDisplayBuf = (LPVOID)LocalAlloc(LMEM_ZEROINIT,
		(lstrlen((LPCTSTR)lpMsgBuf) + lstrlen((LPCTSTR)lpszFunction) + 40) * sizeof(TCHAR));

	if (lpDisplayBuf) {

		StringCchPrintf((LPTSTR)lpDisplayBuf,
			LocalSize(lpDisplayBuf) / sizeof(TCHAR),
			TEXT("%s failed with error %u: %s"),
			lpszFunction, dw, lpMsgBuf);

		_tprintf((LPCTSTR)lpDisplayBuf);

		LocalFree(lpDisplayBuf);
	}
	LocalFree(lpMsgBuf);
}

WCHAR* ascii_to_wide_str(CHAR* lpMultiByteStr)
{

	/* Get the required size */
	INT iNumChars = MultiByteToWideChar(CP_ACP, 0, lpMultiByteStr, -1, NULL, 0);

	/* Allocate new wide string */

	SIZE_T Size = (1 + iNumChars) * sizeof(WCHAR);
	
	WCHAR *lpWideCharStr = reinterpret_cast<WCHAR*>(malloc(Size));

	if (lpWideCharStr) {
		SecureZeroMemory(lpWideCharStr, Size);
		/* Do the conversion */
		iNumChars = MultiByteToWideChar(CP_ACP, 0, lpMultiByteStr, -1, lpWideCharStr, iNumChars);
	}
	return lpWideCharStr;
}

CHAR* wide_str_to_multibyte (TCHAR* lpWideStr)
{
	errno_t status;
	int *pRetValue = NULL;
	CHAR *mbchar = NULL;
	size_t sizeInBytes = 0;
	
	status = wctomb_s(pRetValue, mbchar, sizeInBytes, *lpWideStr);
	return mbchar;
}

BOOL IsHexString(WCHAR* szStr) {
	std::wstring s(szStr);

	if (std::find_if(s.begin(), s.end(), [](wchar_t c) {return !std::isxdigit(static_cast<unsigned char>(c)); }) == s.end())
		return TRUE;
	else
		return FALSE;
}
