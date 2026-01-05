/*++
*
* @file:      ThreatIntelligenceConsumer/Main.cpp
*
* @summary:   ThreatIntelligenceConsumer entry point.
*
* @author:    Connor McGarr (@33y0re)
*
--*/
#include "Trace.hpp"
#include "SecurityTrace.hpp"
#include "ThreatIntelligenceCallback.hpp"
#include "Helpers.hpp"

/**
*
* @brief        ThreatIntelligenceConsumer entry point.
* @param[in]    argc - Number of arguments.
* @param[in]	argv - Argument array.
* @return       ERROR_SUCCESS on success, otherwise appropriate error code.
*
*/
int
wmain (
	_In_ int argc,
	_In_ wchar_t** argv
	)
{
	ULONG error;
	PEVENT_TRACE_PROPERTIES traceProperties;
	HANDLE traceThread;

	error = ERROR_GEN_FAILURE;
	traceProperties = nullptr;
	traceThread = nullptr;

	error = ConfigureTracingProperties(&traceProperties,
									   MY_TRACE_NAME,
									   sizeof(MY_TRACE_NAME));
	if (error != ERROR_SUCCESS)
	{
		goto Exit;
	}

	error = RetrieveAutoLoggerTraceProperties(&traceProperties,
											  TRACE_PROPS_SIZE);
	if (error != ERROR_SUCCESS)
	{
		goto Exit;
	}

	//
	// Store the updated trace properties for the assembly thunk.
	//
	PreserveTraceProperties(traceProperties);

	//
	// Now patch ControlTraceW.
	//
	PatchControlTrace();

	//
	// Start consuming events
	//
	error = StartTracing(HandleThreatIntelligenceCallback,
						 &traceThread,
						 MY_TRACE_NAME);
	if (error != ERROR_SUCCESS)
	{
		wprintf(L"[-] StartTracing failed for MyTrace! (Error: 0x%lx)\n", error);
		goto Exit;
	}

	getchar();

Exit:
	//
	// Notice we do not stop the AutoLogger session here
	// by calling ControlTraceW with EVENT_TRACE_CONTROL_STOP.
	// Instead, this allows users to consume Threat-Intelligence
	// events once more when the application has exited.
	// 
	// You could call ControlTraceW here if desired.
	//
	if (traceThread != nullptr)
	{
		CloseHandle(traceThread);
	}

	CleanupSecurityTraceResources();

	return error;
}