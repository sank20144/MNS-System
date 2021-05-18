#include "pch.h"
#include "WindowScanner.h"


WindowNamesClasses names[] = {
	// Class names
	{_T("PROCEXPL"), NULL},
	{_T("ProcessHacker"), NULL},
	{_T("PhTreeNew"), NULL},
	{_T("RegEdit_RegEdit"), NULL},
	{_T("0x150114 (1376532)"), NULL},
	{_T("SysListView32"), NULL},
	{_T("Tmb"), NULL},
	{_T("TformSettings"), NULL},
	{_T("Afx:400000:8:10011:0:20575"), NULL},
	{_T("TWildProxyMain"), NULL},
	{_T("TUserdefinedform"), NULL},
	{_T("TformAddressChange"), NULL},
	{_T("TMemoryBrowser"), NULL},
	{_T("TFoundCodeDialog"), NULL},

	//Window names
	{NULL, _T("HiDeToolz")},
	{NULL, _T("HideToolz")},
	{NULL, _T("Injector")},
	{NULL, _T("Olly Debugger")},
	{NULL, _T("The following opcodes accessed the selected address")},
	{NULL, _T("WPE PRO")},
	{NULL, _T("WPePro 0.9a")},
	{NULL, _T("WPePro 1.3")},
	{NULL, _T("ZhyperMu Packet Editor")},
	{NULL, _T("eXpLoRer")},
	{NULL, _T("rPE - rEdoX Packet Editor")},
	{NULL, _T("OllyDbg")},
	{NULL, _T("HxD")},
};

BOOL ScanWindow(WindowNamesClasses window)
{
	HWND Window = FindWindow(window.wClass, window.wWindow);
	if (Window > 0) 
		return TRUE;
	
	return FALSE;
}

VOID ScanWindows() 
{
	WORD iLength = sizeof(names) / sizeof(names[0]);
	for (int i = 0; i < iLength; i++)
	{
		TCHAR msg[256] = _T("");
		
		_stprintf_s(msg, sizeof(msg) / sizeof(TCHAR), _T("Checking window title/class: %s "), names[i].wClass == NULL ? names[i].wWindow : names[i].wClass);
		if (ScanWindow(names[i]))
			print_results(TRUE, msg);
		else
			print_results(FALSE, msg);
	}
}
