#include <windows.h>
#include <stdio.h>
#include <tchar.h>
#include <winevt.h>
#include "rapidxml.hpp"

#pragma comment(lib, "wevtapi.lib")

#define CHUNK_SIZE 1

// Default log to use when no log name has been specified
#define DEFAULT_LOG L"Application"

// Default max/min record numbers to use when none have been specified
#define DEFAULT_MIN_RECORD 0
#define DEFAULT_MAX_RECORD 0xFFFFFFFF

// Pass to the "outputFormat" parameter of ParseLogInternal to determine  
// the output format
#define OUTPUT_FORMAT_JSON 0

// Pass to the "mode" parameter for ParseLogInternal to determine how it
// behaves
#define MODE_DEFAULT 0
#define MODE_FETCH_LAST_RECORD 1

// Debugging levels accepted through the "debug" parameter
#define DEBUG_NONE 0
#define DEBUG_L1 1
#define DEBUG_L2 2 

// Exports
extern "C" __declspec(dllexport) DWORD64 __stdcall ParseEventLog(LPWSTR, LPWSTR, LPWSTR, LPWSTR, LPWSTR, LPWSTR, INT, INT);
extern "C" __declspec(dllexport) DWORD64 __stdcall GetLatestEventLogRecord(LPWSTR, LPWSTR, LPWSTR, LPWSTR, LPWSTR, INT);

// Internal functions
DWORD64 ParseEventLogInternal(LPWSTR, LPWSTR, LPWSTR, LPWSTR, LPWSTR, LPWSTR, INT, INT, INT);
EVT_HANDLE CreateRemoteSession(LPWSTR, LPWSTR, LPWSTR, LPWSTR);
DWORD64 DumpEventInfo(EVT_HANDLE, EVT_HANDLE, INT, INT, INT);
LPWSTR GetEventMessageDescription(EVT_HANDLE, EVT_HANDLE);
DWORD64 ProcessResults(EVT_HANDLE, EVT_HANDLE, INT, INT, INT);
wchar_t *repl_wcs(const wchar_t*, const wchar_t*, const wchar_t*);
