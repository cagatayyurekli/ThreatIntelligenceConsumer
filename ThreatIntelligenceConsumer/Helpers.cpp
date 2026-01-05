/*++
*
* @file:      ThreatIntelligenceConsumer/Helpers.cpp
*
* @summary:   Various helper functions.
*
* @author:    Connor McGarr (@33y0re)
*
--*/
#include "Helpers.hpp"
#include <string>

/**
*
* @brief			Retrieves the trace properties of our target AutoLogger from the Registry.
* @param[in,out]    TraceProperties - The target trace properties to populate.
* @return			ERROR_SUCCESS on success, otherwise appropriate error code.
*
*/
ULONG
RetrieveAutoLoggerTraceProperties (
	_Inout_ PEVENT_TRACE_PROPERTIES* TraceProperties,
	_In_ ULONG TracePropertiesSize
	)
{
	LSTATUS status;
	ULONG error;
	HKEY regHandle;
	ULONG historicalContext;
	ULONG doubleWordSize;
	ULONG guidStringSize;
	bool loggerFound;
	PEVENT_TRACE_PROPERTIES traceProps;
	PEVENT_TRACE_PROPERTIES tempProps;

	//
	// A GUID is 80 bytes as a string (78 + null terminator)
	//
	WCHAR guidString[78 + sizeof(UNICODE_NULL)];

	status = ERROR_SUCCESS;
	error = ERROR_SUCCESS;
	regHandle = nullptr;
	historicalContext = 0;
	doubleWordSize = sizeof(DWORD);
	guidStringSize = (78 + sizeof(UNICODE_NULL));
	loggerFound = false;
	traceProps = *TraceProperties;
	tempProps = nullptr;

	RtlZeroMemory(&guidString, sizeof(guidString));

	status = RegOpenKeyExW(HKEY_LOCAL_MACHINE,
						   AUTO_LOGGER_REGISTRY_PATH,
						   0,
						   KEY_READ,
						   &regHandle);
	if (status != ERROR_SUCCESS)
	{
		wprintf(L"[-] RegOpenKeyExW failed in RetrieveAutoLoggerTraceProperties! (Error: 0x%lx)\n", status);
		goto Exit;
	}

	//
	// The "HistoricalContext" value is the trace ID. We need to know
	// what the ID is for our trace properties, since we cannot query for it.
	// A query requires PPL (which we don't have).
	// 
	// AutoLogger trace sessions are assigned IDs starting at 2 and each
	// session (generally speaking) is enabled alphabetically (the exceptions
	// being session 3 and some of the other "earlier" sessions).
	// 
	// Since we know that our session has SecurityTrace enabled, a query
	// will result in access denied. However, there could be other
	// traces which also SecurityTrace enabled.
	// 
	// So what we do is we enumerate the number of AutoLoggers in the registry.
	// The "numbers" relatively map to the trace ID. So, therefore, the trace
	// session being used starts with the value "0" (MY_TRACE_NAME) - meaning
	// it will be the FIRST session alphabetically. The "ultimate" would just
	// to have the session name be exactly "0", as this always "wins" - but this
	// is a POC and we want some way to make the session truly attributable.
	// 
	// Since we assume our entry will be "first" alphabetically, we can brute-force
	// the ID this way. Starting with the first valid value (2 is the first ID - reserved usually
	// for the legacy kernel session and 3 is hardcoded for EventLog-Security), we call ControlTraceW
	// with EVENT_TRACE_CONTROL_QUERY. Access denied indicates the trace has SecurityTrace
	// enabled - and that this is our trace session.
	// 
	// This is obviously not perfect, but this is a POC! It should work in almost all scenarios.
	//

	//
	// Start brute-forcing the various logger IDs.
	//
	tempProps = reinterpret_cast<PEVENT_TRACE_PROPERTIES>(malloc(TracePropertiesSize));
	if (tempProps == nullptr)
	{
		wprintf(L"[-] malloc failed in RetrieveAutoLoggerTraceProperties! (GLE: %d)\n", GetLastError());

		status = ERROR_OUTOFMEMORY;
		goto Exit;
	}

	//
	// As mentioned, really "4" is the first valid ID to check.
	//
	for (ULONG i = 4; i < MAX_LOGGERS; i++)
	{
		//
		// Reset the placeholder properties
		//
		RtlZeroMemory(tempProps, TracePropertiesSize);

		RtlCopyMemory(tempProps,
					  *TraceProperties,
					  TracePropertiesSize);

		//
		// Our trace ID should always realistically be the first. However,
		// we are doing our due diligence by ensuring we find the first
		// session that results in access denied.
		//
		error = ControlTraceW(static_cast<TRACEHANDLE>(i),
							  NULL,
							  tempProps,
							  EVENT_TRACE_CONTROL_QUERY);

		//
		// We are looking for the first access denied error,
		// which indicates a session has SecurityTrace enabled.
		//
		if (error != ERROR_ACCESS_DENIED)
		{
			continue;
		}

		//
		// Access denied - this is our logger!
		//
		historicalContext = i;
		loggerFound = true;

		break;
	}

	if (!loggerFound)
	{
		wprintf(L"[-] Error! Could not find %s in the AutoLoggers!\n", MY_TRACE_NAME);

		status = ERROR_NOT_FOUND;
		goto Exit;
	}

	//
	// Update the logger ID
	//
	traceProps->Wnode.HistoricalContext = historicalContext;

	//
	// BufferSize
	//
	status = RegGetValueW(regHandle,
						  MY_TRACE_NAME,
						  L"BufferSize",
						  RRF_RT_REG_DWORD,
						  NULL,
						  &traceProps->BufferSize,
						  &doubleWordSize);
	if (status != ERROR_SUCCESS)
	{
		wprintf(L"[-] RegGetValueW failed in RetrieveAutoLoggerTraceProperties! (Error: 0x%lx)\n", status);
		goto Exit;
	}

	//
	// ClockType
	//
	status = RegGetValueW(regHandle,
						  MY_TRACE_NAME,
						  L"ClockType",
						  RRF_RT_REG_DWORD,
						  NULL,
						  &traceProps->Wnode.ClientContext,
						  &doubleWordSize);
	if (status != ERROR_SUCCESS)
	{
		wprintf(L"[-] RegGetValueW failed in RetrieveAutoLoggerTraceProperties! (Error: 0x%lx)\n", status);
		goto Exit;
	}

	//
	// FlushTimer
	//
	status = RegGetValueW(regHandle,
						  MY_TRACE_NAME,
						  L"FlushTimer",
						  RRF_RT_REG_DWORD,
						  NULL,
						  &traceProps->FlushTimer,
						  &doubleWordSize);
	if (status != ERROR_SUCCESS)
	{
		wprintf(L"[-] RegGetValueW failed in RetrieveAutoLoggerTraceProperties! (Error: 0x%lx)\n", status);
		goto Exit;
	}

	//
	// GUID (as string)
	//
	status = RegGetValueW(regHandle,
						  MY_TRACE_NAME,
						  L"Guid",
						  RRF_RT_REG_SZ,
						  NULL,
						  &guidString,
						  &guidStringSize);
	if (status != ERROR_SUCCESS)
	{
		wprintf(L"[-] RegGetValueW failed in RetrieveAutoLoggerTraceProperties! (Error: 0x%lx)\n", status);
		goto Exit;
	}

	if (CLSIDFromString(guidString,
						reinterpret_cast<LPCLSID>(&traceProps->Wnode.Guid)) != S_OK)
	{
		wprintf(L"[-] CLSIDFromString failed in RetrieveAutoLoggerTraceProperties! (Error: 0x%lx)\n", status);
		goto Exit;
	}

	//
	// LogFileMode
	//
	status = RegGetValueW(regHandle,
						  MY_TRACE_NAME,
						  L"LogFileMode",
						  RRF_RT_REG_DWORD,
						  NULL,
						  &traceProps->LogFileMode,
						  &doubleWordSize);
	if (status != ERROR_SUCCESS)
	{
		wprintf(L"[-] RegGetValueW failed in RetrieveAutoLoggerTraceProperties! (Error: 0x%lx)\n", status);
		goto Exit;
	}


	//
	// MaximumBuffers
	//
	status = RegGetValueW(regHandle,
						  MY_TRACE_NAME,
						  L"MaximumBuffers",
						  RRF_RT_REG_DWORD,
						  NULL,
						  &traceProps->MaximumBuffers,
						  &doubleWordSize);
	if (status != ERROR_SUCCESS)
	{
		wprintf(L"[-] RegGetValueW failed in RetrieveAutoLoggerTraceProperties! (Error: 0x%lx)\n", status);
		goto Exit;
	}

	//
	// MinimumBuffers
	//
	status = RegGetValueW(regHandle,
						  MY_TRACE_NAME,
						  L"MinimumBuffers",
						  RRF_RT_REG_DWORD,
						  NULL,
						  &traceProps->MinimumBuffers,
						  &doubleWordSize);
	if (status != ERROR_SUCCESS)
	{
		wprintf(L"[-] RegGetValueW failed in RetrieveAutoLoggerTraceProperties! (Error: 0x%lx)\n", status);
		goto Exit;
	}

	*TraceProperties = traceProps;
	status = ERROR_SUCCESS;

Exit:
	if (regHandle != nullptr)
	{
		RegCloseKey(regHandle);
	}

	if (tempProps != nullptr)
	{
		free(tempProps);
	}

	return static_cast<ULONG>(status);
}