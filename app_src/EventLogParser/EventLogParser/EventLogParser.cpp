#include <windows.h>
#include <wchar.h>
#include "EventLogParser.h"

/****
 * GetLatestEventLogRecord
 *
 * DESC:
 *     Gets the most recent event log record
 *
 * ARGS:
 *     server - IP or host to connect to
 *     domain - domain within the host (empty string for none)
 *     username - username within the domain
 *     password - password for above user
 *     logName - event log to open (default to "Application" if NULL)
 *     debug - set to 0 (none) 1 (basic) or 2 (verbose)
 *
 * RETURNS:
 *     Returns numeric value of the most recent event log record ID
 */
extern "C" __declspec(dllexport) DWORD __stdcall GetLatestEventLogRecord(LPWSTR server, LPWSTR domain, LPWSTR username, LPWSTR password, LPWSTR logName, INT debug) 
{
	return ParseEventLogInternal(server, domain, username, password, logName, L"LAST_RECORD", OUTPUT_FORMAT_JSON, debug, MODE_FETCH_LAST_RECORD);
}


/****
 * ParseEventLog
 *
 * DESC:
 *     Displays event log information to STDOUT
 *
 * ARGS:
 *     server - IP or host to connect to
 *     domain - domain within the host (empty string for none)
 *     username - username within the domain
 *     password - password for above user
 *     logName - event log to open (default to "Application" if NULL)
 *     query - XPath query to retrieve (see remarks)
 *     outputFormat - set to 0 (JSON) otherwise XML
 *     debug - set to 0 (none) 1 (basic) or 2 (verbose)
 *
 * REMARKS:
 *     The Windows Event log is structurally an XML document. You
 *     may therefore use XPath queries to retrieve the information 
 *     you want. Pre-defined XPath queries have been built into the
 *     supplementary Perl module. However, you are free to modify
 *     that module to include newer queries, based on your requirements
 *
 *     Note: As per previous discussions, output format is forced as
 *     JSON here. To re-allow XML, simply replace OUTPUT_FORMAT_JSON
 *     with outputFormat, in the line of code, below
 */
extern "C" __declspec(dllexport) DWORD __stdcall ParseEventLog(LPWSTR server, LPWSTR domain, LPWSTR username, LPWSTR password, LPWSTR logName, LPWSTR query, INT outputFormat, INT debug) 
{
	return ParseEventLogInternal(server, domain, username, password, logName, query, OUTPUT_FORMAT_JSON, debug, MODE_DEFAULT);
}


/****
 * ParseEventLogInternal
 *
 * DESC:
 *     Gets the most recent event log record
 *
 * ARGS:
 *     server - IP or host to connect to
 *     domain - domain within the host (empty string for none)
 *     username - username within the domain
 *     password - password for above user
 *     logName - event log to open (default to "Application" if NULL)
 *     query - XPath query to retrieve (see remarks)
 *     outputFormat - set to 0 (JSON) otherwise XML
 *     debug - set to 0 (none) 1 (basic) or 2 (verbose)
 *     mode - mode to run the parser (see remarks)
 *
 * REMARKS:
 *     XPath:
 * 
 *     The Windows Event log is structurally an XML document. You
 *     may therefore use XPath queries to retrieve the information 
 *     you want. Pre-defined XPath queries have been built into the
 *     supplementary Perl module. However, you are free to modify
 *     that module to include newer queries, based on your requirements
 *
 *     mode:
 *
 *     Can be set to either MODE_FETCH_LAST_RECORD or MODE_DEFAULT. The
 *     former will simply return the Event Log Record ID of the topmost
 *     (i.e. the latest) event record. The latter will do the actual
 *     processing of parsing an event log record to the screen.
 *
 *     Note: As per previous discussions, output format is forced as
 *     JSON here. To re-allow XML, simply replace OUTPUT_FORMAT_JSON
 *     with outputFormat, in the line of code, below
 */
DWORD ParseEventLogInternal(LPWSTR server, LPWSTR domain, LPWSTR username, LPWSTR password, LPWSTR logName, LPWSTR query, INT outputFormat, INT debug, INT mode) {	
	bool getLastRecord = false;
	DWORD result = 0;

	if( debug > DEBUG_L1 ) {
		wprintf(L"[ParseEventLogInternal]: Attempting to connect to '%s' on domain '%s' using %s:%s...\n", server, domain, username, password);
	}

	// If no domain was supplied
	if( wcslen(domain) == 0 ) {
		// Official MSDN specs request NULL instead of an empty string
		domain = NULL;

		if( debug >= DEBUG_L1 ) {
			wprintf(L"[ParseEventLogInternal]: Empty domain supplied. Default to NULL\n");
		}		
	}
		
	// If a blank query was supplied, assume no query (NULL)
	if( lstrlen(query) == 0 )
		query = NULL;

	// If the supplied query is our special token that retrieves the last record
	if( lstrcmpW( query, L"LAST_RECORD") == 0 ) {
		if( debug >= DEBUG_L1 ) {
			wprintf(L"[ParseEventLogInternal]: Mode is last record fetch\n");
		}

		// Flag the processing routine to only fetch the lastest record
		getLastRecord = true;

		// Force an empty query so that the last record is not affected by query filters
		// An empty query means it will get ALL records, in which case we are guaranteed
		// the latest record (i.e. the record ID we want) is the first to be retrieved
		query = NULL;
	} else {
		if( debug >= DEBUG_L1 ) {
			if( query == NULL ) {
				wprintf(L"[ParseEventLogInternal]: (no query specified)\n");
			} else {
				wprintf(L"[ParseEventLogInternal]: Using query: %s\n", query);
			}
		}
	}

	// Xreate a remote context to the external server
    EVT_HANDLE hRemote = CreateRemoteSession(server, domain, username, password);

    if (hRemote != NULL)
    {
		// NOTE: Reaching here does not mean the connection succeeded. It merely 
		// means that we successfully created the remote context

		if( debug >= DEBUG_L1 ) {
			wprintf(L"[ParseEventLogInternal]: Attempting to query the EventLog...\n\n", hRemote);
		}

		// Attempt to query event log in reverse chronological order (newest to oldest)
		EVT_HANDLE hResults = EvtQuery( hRemote, logName, query, EvtQueryChannelPath | EvtQueryReverseDirection);

		// If the query was successful
		if (hResults != NULL) 
		{
			// Process the first event found
			DumpEventInfo(hRemote, hResults, outputFormat, getLastRecord ? MODE_FETCH_LAST_RECORD : 0, debug);

			// Process subsequent events
			result = ProcessResults(hRemote, hResults, outputFormat, getLastRecord ? MODE_FETCH_LAST_RECORD : 0, debug);
		}
		else
		{
			// Query was not successful. Get the error code
			DWORD dwError = GetLastError();

			if (dwError == ERROR_EVT_CHANNEL_NOT_FOUND) 
			{
				fwprintf(stderr, L"[Error][ParseEventLog]: Could not open the '%s' log on this machine.\n", logName);
			}
			else if (dwError == ERROR_EVT_INVALID_QUERY)
			{
				// You can call the EvtGetExtendedStatus function to try to get 
				// additional information as to what is wrong with the query.
				fwprintf(stderr, L"[Error][ParseEventLog]: The specified search query is not valid.\n");
			}
			else
			{
				fwprintf(stderr, L"[Error][ParseEventLog]: Could not read event logs due to the following Windows error: %lu.\n", dwError);
			}
		}

		// Close the handle to the query we opened
		EvtClose(hRemote);
    }
	else 
	{
        fwprintf(stderr, L"[Error][ParseEventLog]: Failed to connect to remote computer. Error code is %d.\n", GetLastError());
	}

	return result;
}


/****
 * CreateRemoteSession
 *
 * DESC:
 *     Creates a remote context 
 *
 * ARGS:
 *     server - IP or host to connect to
 *     domain - domain within the host (empty string for none)
 *     username - username within the domain
 *     password - password for above user
 *
 * REMARKS:
 *     Set the domain, user, and password to NULL for current user
 *
 *     Note: This just creates the session context. A connection
 *     is not actually made until we attempt to use the context
 */
EVT_HANDLE CreateRemoteSession(LPWSTR server, LPWSTR domain, LPWSTR username, LPWSTR password)
{
    EVT_RPC_LOGIN rpcLogin;

	// Allocate required memory for our credentials buffer
    RtlZeroMemory(&rpcLogin, sizeof(EVT_RPC_LOGIN));

	// Initialize our credentials with the supplied machine, username and password
	rpcLogin.Domain = domain; 
	rpcLogin.User = username; 
    rpcLogin.Password = password; 
	rpcLogin.Server = server;
    rpcLogin.Flags = EvtRpcLoginAuthNegotiate; 

    // Create session context for remote machine
    EVT_HANDLE hRemote = EvtOpenSession(EvtRpcLogin, &rpcLogin, 0, 0);

	// Release memory used for our credentails buffer as it's no longer required
    SecureZeroMemory(&rpcLogin, sizeof(EVT_RPC_LOGIN));

	// Return the session context handle
    return hRemote;
}


/****
 * ProcessResults
 *
 * DESC:
 *     Creates a remote context 
 *
 * ARGS:
 *     hRemote - Remote session context
 *     hResults - An open set of results
 *     outputFormat - 0 for JSON, otherwise XML
 *     mode - last record vs dump results
 *     debug - set to 0 (none) 1 (basic) or 2 (verbose)
 */
DWORD ProcessResults(EVT_HANDLE hRemote, EVT_HANDLE hResults, int outputFormat, int mode, int debug)
{
    DWORD status = ERROR_SUCCESS;
    EVT_HANDLE hEvents[CHUNK_SIZE + 1];
    DWORD dwReturned = 0;
	BOOL completed = FALSE;	
	BOOL firstRecordCompleted = FALSE;

	// Print header information for our events
	if( outputFormat == OUTPUT_FORMAT_JSON ) {
		// Note: Marc requested this to be removed
		//wprintf(L"[");
	} else {
		wprintf(L"%s||%s||%s||%s||%s||%s||%s||%s\n\n", L"RecordID", L"EventID", L"Channel", L"Provider", L"Computer", L"TimeCreated", L"Task", L"Level");
	}

	// Begin an infinite loop, as we want to continue reading records as long as they are available.
	// The break-condition is a manual one at the bottom (i.e. no more records found)
    while (TRUE)
    {
        // Get a block of events from the result set.
        if (EvtNext(hResults, CHUNK_SIZE, hEvents, INFINITE, 0, &dwReturned))
        {
			// Cycle through all the events that we received
			for (DWORD i = 0; i < dwReturned; i++)
			{
				// Only print the separator characters once the first record is completed
				if( firstRecordCompleted )
					wprintf(L"||");

				// Extract event details and output the screen
				DWORD result = DumpEventInfo(hRemote, hEvents[i], outputFormat, mode, debug);
				
				// Set flag indicating first record is completed so that
				// the top of our loop knows to begin printing the separator character
				firstRecordCompleted = TRUE;

				// Close the handle to the current event, as we are done
				EvtClose(hEvents[i]);

				// Clear the event handle so our cleanup routine does not attempt to re-close
				hEvents[i] = NULL;

				// If currently in "last record" mode			
				if( mode == MODE_FETCH_LAST_RECORD ) {
					// We do not need to process anymore events
					// Recall that all we were looking for was the record ID of the most recent record
					// This should be stored in "status" as, this is the variable that's returned
					status = result;

					completed = true;

					break;
				}
			}
        }
		else 
		{
			// Call to retrieve events failed. Get the error code
			status = GetLastError();

			// If the error was the result of not having any more records
            if (status == ERROR_NO_MORE_ITEMS)
            {
				// Exit the loop. No more records to process
				completed = TRUE;
            }
			else 
			{
				// Otherwise, notify user of the error
                fwprintf(stderr, L"Failed to fetch next batch with following error: %lu\n", status);
			}
		}

		// Cycle through all records that we received
		// Recall that dwReturned contains the number of records received
		for (DWORD i = 0; i < dwReturned; i++)
		{
			// If the event isn't already closed
			if (hEvents[i] != NULL) 
			{
				// Close the event record
				EvtClose(hEvents[i]);
			}
		}

		// Exit the loop if required (i.e. we're done)
		if( completed )
			break;
	}

	// Add closing tag if this is JSON
	if( outputFormat == OUTPUT_FORMAT_JSON ) {
		// Marc requested this to be removed
		// wprintf(L"]");
	}

    return status;
}


/****
 * DumpEventInfo
 *
 * DESC:
 *     This function has two purposes depending on the mode. It will
 *     either (1) Print the contents of an event (if normal mode) or
 *     (2) return the latest record ID (if "last record" mode)
 *
 * ARGS:
 *     hRemote - Remote session context
 *     hResults - An open set of results
 *     outputFormat - 0 for JSON, otherwise XML
 *     mode - last record vs print results
 *     debug - set to 0 (none) 1 (basic) or 2 (verbose)
 *
 * REMARKS:
 */
DWORD DumpEventInfo(EVT_HANDLE hRemote, EVT_HANDLE hEvent, INT outputFormat, INT mode, INT debug)
{
    DWORD dwError = ERROR_SUCCESS;
    DWORD dwBufferSize = 0;
    DWORD dwBufferUsed = 0;
    DWORD dwPropertyCount = 0;
    LPWSTR pwsBuffer = NULL;
	rapidxml::xml_document<WCHAR> doc;

	if( debug >= DEBUG_L2 ) {
		wprintf(L"[DumpEventInfo]: Attempting to read event XML with no buffer\n" );
	}

    // Attempt to read the event as an XML string
	//
	// Note: We are expecting this call to fail, as we have NOT provided a buffer. Therefore
	// the purpose of this call is to fail, and have dwBufferUsed updated with required space	
    if (!EvtRender(NULL, hEvent, EvtRenderEventXml, dwBufferSize, pwsBuffer, &dwBufferUsed, &dwPropertyCount)) 
	{
		// Reading was NOT successful, as expected
		if( debug >= DEBUG_L2 ) {
			wprintf(L"[DumpEventInfo]: Required buffer space: %lu\n", dwBufferUsed );
		}

		// Get the error code
		dwError = GetLastError();

		if( debug >= DEBUG_L2 ) {
			wprintf(L"[DumpEventInfo]: Raw error code is: %lu\n", dwError );
		}

		// If call failed due to insufficient buffer (as we should expect)
        if (dwError == ERROR_INSUFFICIENT_BUFFER)
        {
			if( debug >= DEBUG_L2 ) {
				wprintf(L"[DumpEventInfo]: Last error code is insufficient buffer (as expecteted)\n" );
			}

			// Adjust the buffer size to the required amount as indicated by dwBufferUsed		
            dwBufferSize = dwBufferUsed;

			if( debug >= DEBUG_L2 ) {
				wprintf(L"[DumpEventInfo]: Attempting to reallocate buffer size: %lu\n", dwBufferSize );
			}

			// Re-allocate our buffer with the required size
            pwsBuffer = (LPWSTR)malloc(dwBufferSize);

			// If allocaton was successful
            if (pwsBuffer)
            {
				if( debug >= DEBUG_L2 ) {
					wprintf(L"[DumpEventInfo]: Allocation successful. Re-attempting to read event data\n" );
				}

				// Re-attempt to read event (as XML) now that we have appropriate buffer size
                if( EvtRender(NULL, hEvent, EvtRenderEventXml, dwBufferSize, pwsBuffer, &dwBufferUsed, &dwPropertyCount) ) 
				{
					if( debug >= DEBUG_L2 ) {
						wprintf(L"[DumpEventInfo]: Read successful. Last error code is: %lu\n", dwError );
					}

					// Reading was successful
					dwError = GetLastError();

					if( debug >= DEBUG_L2 ) {
						wprintf( L"[DumpEventInfo] Raw XML: %s\n", pwsBuffer );
					}

					// Parse the XML string into our XML reader
					doc.parse<0>( pwsBuffer );

					if( debug >= DEBUG_L2 ) {
						wprintf( L"[DumpEventInfo] XML parsing successful\n" );
					}

					// Retrieve the <Event> node
					rapidxml::xml_node<WCHAR> *nodeEvent = doc.first_node(L"Event");

					// Retrieve the <System> node
					rapidxml::xml_node<WCHAR> *nodeSystem = nodeEvent->first_node(L"System");
					// Children of the <System> node
					// You will recongize these as elements when viewing the event log in your viewer
					rapidxml::xml_node<WCHAR> *nodeEventID = nodeSystem->first_node(L"EventID");
					rapidxml::xml_node<WCHAR> *nodeChannel = nodeSystem->first_node(L"Channel");
					rapidxml::xml_node<WCHAR> *nodeEventRecordID = nodeSystem->first_node(L"EventRecordID");
					rapidxml::xml_node<WCHAR> *nodeProvider = nodeSystem->first_node(L"Provider");
					rapidxml::xml_node<WCHAR> *nodeComputer = nodeSystem->first_node(L"Computer");
					rapidxml::xml_node<WCHAR> *nodeTimeCreated = nodeSystem->first_node(L"TimeCreated");
					rapidxml::xml_node<WCHAR> *nodeTask = nodeSystem->first_node(L"Task");
					rapidxml::xml_node<WCHAR> *nodeLevel = nodeSystem->first_node(L"Level");

					if( debug >= DEBUG_L2 ) {
						wprintf( L"[DumpEventInfo] Extracting XML elements successful\n" );
					}

					// Recall there are two modes. The default mode will parse the event log XML, and the "last record" mode
					// (called MODE_FETCH_LAST_RECORD) will fetch only the last record and exit afterwards. 
					if( mode == MODE_FETCH_LAST_RECORD ) {
						return wcstol( nodeEventRecordID->value(), NULL, 10 );
					}

					// Extract the publisher name from the <Provider> node
					// We will need this to lookup the message string for this publisher
					LPWSTR pwszPublisherName = nodeProvider->first_attribute(L"Name")->value();

					if( debug >= DEBUG_L2 ) {
						wprintf( L"[DumpEventInfo] Publisher is: %s\n", pwszPublisherName );
					}

					// Setup an empty string to read the message string
					LPWSTR pwsMessage = NULL;

					// Get the handle to the provider's metadata that contains the message strings.
					EVT_HANDLE hProviderMetadata = EvtOpenPublisherMetadata(hRemote, pwszPublisherName, NULL, 0, 0);

					// If a provider handle was found
					if( hProviderMetadata != NULL ) 
					{
						if( debug >= DEBUG_L2 ) {
							wprintf( L"[DumpEventInfo] Publisher metadata found. Attempting to get message string\n");
						}

						// Get the message string associated with this event type
						pwsMessage = GetEventMessageDescription(hProviderMetadata, hEvent);

						// If a message was not found, default to an empty string
						if( pwsMessage == NULL ) {
							// Why are we setting to empty string?
							//pwsMessage = L"";

							if( debug >= DEBUG_L2 ) {
								wprintf( L"[DumpEventInfo] Message string not found. Assume empty\n");
							}
						}
					}
					else 
					{
						// Publisher/provider cannot be found. Do not display an error message. It occurs all too often when a 
						// publisher is not found, and skews the JSON results. when it prints itself to the main screen
						// printf("Error: EvtOpenPublisherMetadata for %s failed with %d\n", pwszPublisherName, GetLastError());						

						// Default the publisher to an empty string so we can continue
						pwszPublisherName = L"";

						if( debug >= DEBUG_L2 ) {
							wprintf( L"[DumpEventInfo] Publisher metadata not found. Assume empty\n");
						}
					}

					// We have all the results; print them to the screen
					if( outputFormat == OUTPUT_FORMAT_JSON ) 
					{
						wprintf(L"{\"record_id\":\"%s\",\"event_id\":\"%s\",\"logname\":\"%s\",\"source\":\"%s\",\"computer\":\"%s\",\"time_created\":\"%s\",\"task\":\"%s\",\"level\":\"%s\"", 
							nodeEventRecordID->value(), 
							nodeEventID->value(), 
							nodeChannel->value(), 
							nodeProvider->first_attribute(L"Name")->value(), 
							nodeComputer->value(), 
							nodeTimeCreated->first_attribute(L"SystemTime")->value(),
							nodeTask->value(),
							nodeLevel->value());
						
						// If a message string was found
						if( pwsMessage != NULL ) 
						{
							wprintf(L",\"message\":\"%s\"}", pwsMessage);

							if( debug >= DEBUG_L2 ) {
								wprintf( L"[DumpEventInfo] Attempting to free pwsMessage\n");
							}

							free(pwsMessage);

							if( debug >= DEBUG_L2 ) {
								wprintf( L"[DumpEventInfo] pwsMessage successfully freed\n");
							}
						} 
						else 
						{
							wprintf(L",\"message\":\"\"}");

							if( debug >= DEBUG_L2 ) {
								wprintf( L"[DumpEventInfo] No pwsMessage found to free\n");
							}
						}
					} 
					else 
					{
						// Note: A new line is not printed yet (see next steps)
						wprintf(L"%s||%s||%s||%s||%s||%s||%s||%s||", 
							nodeEventRecordID->value(), 
							nodeEventID->value(), 
							nodeChannel->value(), 
							nodeProvider->first_attribute(L"Name")->value(), 
							nodeComputer->value(), 
							nodeTimeCreated->first_attribute(L"SystemTime")->value(),
							nodeTask->value(),
							nodeLevel->value());

						// If a message string was found
						if( pwsMessage != NULL ) 
						{
							wprintf(L"%s\n", pwsMessage);
							free(pwsMessage);
						} 
						else 
						{
							wprintf(L"(no message provided)\n");
						}
					}
				} 
				else
				{
					// Reading was NOT successful

					// This time we were not expecting it to fail. Get the error code
					dwError = GetLastError();

					// Print error results to the screen
					fwprintf(stderr, L"[DumpEventInfo] Failed to render results with: %d\n", GetLastError());

					// Free up our allocation
					free(pwsBuffer);
				}				
            }
            else
            {
				// Allocation was unsuccessful
                fwprintf(stderr, L"[DumpEventInfo] malloc failed\n");
                dwError = ERROR_OUTOFMEMORY;
            }
        }
	}

	if( debug >= DEBUG_L2 ) {
		wprintf( L"[DumpEventInfo] Data dump completed\n" );
	}

    return dwError;
}


/****
 * GetEventMessageDescription
 *
 * DESC:
 *     Gets the specified message string from the event. If the event does not 
 *     contain the specified message, the function returns NULL.
 *
 * ARGS:
 *     hMetaData - Handle to open metadata for an event
 *     hEvent - Handle to open event
 *
 * RETURNS:
 *     If a message has been found, returns a string containing the message.
 *     Otherwise if no message has been found, returns NULL
 *
 *     Note: Caller is responsible for freeing the memory used by the string
 */
LPWSTR GetEventMessageDescription(EVT_HANDLE hMetadata, EVT_HANDLE hEvent)
{
	// The raw message string
    LPWSTR pBuffer = NULL;	
	// The processed message string (make it safe for JSON encoding)
	LPWSTR done = NULL;	
	// Size of the message string
    DWORD dwBufferSize = 0;	
	// Number of bytes used for message string
    DWORD dwBufferUsed = 0;		
	// Type of message string to retrieve from event log
	EVT_FORMAT_MESSAGE_FLAGS flags = EvtFormatMessageEvent;

	// Attempt to read provider-specific message from this event
    if (!EvtFormatMessage(hMetadata, hEvent, 0, 0, NULL, flags, dwBufferSize, pBuffer, &dwBufferUsed))
    {
		// An error occurred. Retrieve this error
        DWORD dwError = GetLastError();

		// If the error was due to our destination buffer being too small
        if (dwError == ERROR_INSUFFICIENT_BUFFER)
        {
            if ((flags == EvtFormatMessageKeyword))
                pBuffer[dwBufferSize-1] = L'\0';
            else
                dwBufferSize = dwBufferUsed;

			// Re-allocate our buffer with the required size
            pBuffer = (LPWSTR)malloc(dwBufferSize * sizeof(WCHAR));

			// If the re-allocation was successful
            if (pBuffer)
            {
				// Re-attempt to retrieve event message
                EvtFormatMessage(hMetadata, hEvent, 0, 0, NULL, flags, dwBufferSize, pBuffer, &dwBufferUsed);

                if ((flags == EvtFormatMessageKeyword))
                    pBuffer[dwBufferUsed-1] = L'\0';

				// Replace new lines with "\n" characters for client to handle
				// This makes the string JSON friendly
				done = repl_wcs(pBuffer, L"\\", L"\\\\");
            }
            else
            {
				// Allocation failed
                fwprintf(stderr, L"[Error][GetEventMessageDescription]: malloc failed\n");
            }
        }
        else if (dwError == ERROR_EVT_MESSAGE_NOT_FOUND)
		{
			// Message was not found. Will return NULL
		}
		else if (dwError == ERROR_EVT_MESSAGE_ID_NOT_FOUND) 
		{
			// Message ID not found. Will return NULL
		}
        else
        {
			// Unexpected error. Output to screen
            fwprintf(stderr, L"[Error][GetEventMessageDescription]: EvtFormatMessage failed with %u\n", dwError);
        }
    }

	// Return the JSON-friendly string 
    return done;
}

wchar_t *repl_wcs(const wchar_t *str, const wchar_t *old, const wchar_t *new_s) {

	/* Adjust each of the below values to suit your needs. */

	/* Increment positions cache size initially by this number. */
	size_t cache_sz_inc = 16;
	/* Thereafter, each time capacity needs to be increased,
	 * multiply the increment by this factor. */
	const size_t cache_sz_inc_factor = 3;
	/* But never increment capacity by more than this number. */
	const size_t cache_sz_inc_max = 1048576;

	wchar_t *pret, *ret = NULL;
	const wchar_t *pstr2, *pstr = str;
	size_t i, count = 0;
	ptrdiff_t *pos_cache = NULL;
	size_t cache_sz = 0;
	size_t cpylen, orglen, retlen, newlen, oldlen = wcslen(old);

	/* Find all matches and cache their positions. */
	while ((pstr2 = wcsstr(pstr, old)) != NULL) {
		count++;

		/* Increase the cache size when necessary. */
		if (cache_sz < count) {
			cache_sz += cache_sz_inc;
			pos_cache = (ptrdiff_t*)realloc(pos_cache, sizeof(*pos_cache) * cache_sz);
			if (pos_cache == NULL) {
				goto end_repl_wcs;
			}
			cache_sz_inc *= cache_sz_inc_factor;
			if (cache_sz_inc > cache_sz_inc_max) {
				cache_sz_inc = cache_sz_inc_max;
			}
		}

		pos_cache[count-1] = pstr2 - str;
		pstr = pstr2 + oldlen;
	}

	orglen = pstr - str + wcslen(pstr);

	/* Allocate memory for the post-replacement string. */
	if (count > 0) {
		newlen = wcslen(new_s);
		retlen = orglen + (newlen - oldlen) * count;
	} else	retlen = orglen;
	ret = (wchar_t*)malloc((retlen + 1) * sizeof(wchar_t));
	if (ret == NULL) {
		goto end_repl_wcs;
	}

	if (count == 0) {
		/* If no matches, then just duplicate the string. */
		wcscpy(ret, str);
	} else {
		/* Otherwise, duplicate the string whilst performing
		 * the replacements using the position cache. */
		pret = ret;
		wmemcpy(pret, str, pos_cache[0]);
		pret += pos_cache[0];
		for (i = 0; i < count; i++) {
			wmemcpy(pret, new_s, newlen);
			pret += newlen;
			pstr = str + pos_cache[i] + oldlen;
			cpylen = (i == count-1 ? orglen : pos_cache[i+1]) - pos_cache[i] - oldlen;
			wmemcpy(pret, pstr, cpylen);
			pret += cpylen;
		}
		ret[retlen] = L'\0';
	}

end_repl_wcs:
	/* Free the cache and return the post-replacement string,
	 * which will be NULL in the event of an error. */
	free(pos_cache);
	return ret;
}


BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
					 )
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}
