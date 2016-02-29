#include <Windows.h>
#include <stdio.h>
#include <wchar.h>
#include <winevt.h>

typedef int (__stdcall *MYPROC)(int, int);
typedef DWORD (__stdcall *PARSEEVENTLOG)(LPWSTR, LPWSTR, LPWSTR, LPWSTR, LPWSTR, LPWSTR, INT, INT);

int main() {
	HINSTANCE hModule = LoadLibrary( L"EventLogParser.dll" );

	if( hModule == NULL ) {
		printf("Could not load EventLogParser.dll\n");
		return 1;
	}

	PARSEEVENTLOG parseEventLog = (PARSEEVENTLOG) GetProcAddress( hModule, "ParseEventLog" );

	if( parseEventLog != NULL ) {
		parseEventLog(L"yourserver", NULL, L"youruser", L"yourpassword", L"Application", NULL, 0, 1);
	} else {
		printf("Could not load the proc\n");
	}

	FreeLibrary( hModule );
}