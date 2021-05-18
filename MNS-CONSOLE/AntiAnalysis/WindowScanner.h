#pragma once
struct WindowNamesClasses
{
	LPCTSTR wClass;
	LPCTSTR wWindow;
};

BOOL ScanWindow(WindowNamesClasses window);
VOID ScanWindows();

