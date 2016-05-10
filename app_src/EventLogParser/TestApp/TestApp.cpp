#include <Windows.h>
#include <stdio.h>
#include <wchar.h>
#include <winevt.h>

typedef int (__stdcall *MYPROC)(int, int);
typedef DWORD64 (__stdcall *PARSEEVENTLOG)(LPWSTR, LPWSTR, LPWSTR, LPWSTR, LPWSTR, LPWSTR, INT, INT);
typedef DWORD64 (__stdcall *GETLASTRECORD)(LPWSTR, LPWSTR, LPWSTR, LPWSTR, LPWSTR, INT);

int main() {
	HINSTANCE hModule = LoadLibrary( L"EventLogParser.dll" );
	DWORD64 lastRecord = 0;

	if( hModule == NULL ) {
		printf("Could not load EventLogParser.dll\n");
		return 1;
	}

	//PARSEEVENTLOG parseEventLog = (PARSEEVENTLOG) GetProcAddress( hModule, "ParseEventLog" );
	GETLASTRECORD getLastRecord = (GETLASTRECORD) GetProcAddress( hModule, "GetLatestEventLogRecord" );

	if( getLastRecord != NULL ) {
		lastRecord = getLastRecord(L"techupp.eyesurf.ca", L"", L"randy", L"Evergreen", L"Application", 1);
	} else {
		printf("Could not load the proc\n");
	}

	FreeLibrary( hModule );
}