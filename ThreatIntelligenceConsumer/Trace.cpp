/*++
*
* @file:      ThreatIntelligenceConsumer/Trace.cpp
*
* @summary:   ETW trace session management functionality.
*
* @author:    Connor McGarr (@33y0re)
*
--*/
#include "Trace.hpp"

/**
*
* @brief        Calls ProcessTrace on a separate thread to receive ETW events.
*
*/
static
void
ProcessMyTrace (
    _In_ PVOID TraceHandle
    )
{
    ULONG error;
    PROCESSTRACE_HANDLE* traceHandle;

    traceHandle = (PROCESSTRACE_HANDLE*)TraceHandle;

    //
    // Begin.
    //
    error = ProcessTrace(traceHandle, 1, NULL, NULL);
    if (error != ERROR_SUCCESS)
    {
        error = GetLastError();
        wprintf(L"[-] Error in ProcessTrace! (Error: 0x%lx)\n", error);
        goto Exit;
    }

    //
    // ProcessTrace only returns when we have finished processing events
    // (when ControlTrace w/ stop code is invoked)
    //
    CloseTrace(*traceHandle);

Exit:
    return;
}

/**
*
* @brief            Configures the non-AutoLogger trace settings
* @param[in,out]    TraceProperties - The trace properties,
* @param[in]        TraceName - The name of the ETW session.
* @param[in]        TraceNameSize - The size of the ETW session name.
* @return           ERROR_SUCCESS on success, otherwise appropriate Win32 error code.
*
*/
ULONG
ConfigureTracingProperties (
    _Inout_ PEVENT_TRACE_PROPERTIES* TraceProperties,
    _In_ LPCWSTR TraceName,
    _In_ ULONG TraceNameSize
    )
{
    ULONG error;
    PEVENT_TRACE_PROPERTIES traceProperties;

    error = ERROR_SUCCESS;

    traceProperties = (PEVENT_TRACE_PROPERTIES)malloc(TRACE_PROPS_SIZE);
    if (traceProperties == NULL)
    {
        wprintf(L"[-] malloc error in ConfigureTracingProperties!\n");
        error = ERROR_INSUFFICIENT_BUFFER;
        goto Exit;
    }

    //
    // This is necessary!
    //
    RtlZeroMemory(traceProperties, TRACE_PROPS_SIZE);

    //
    // Everything else is the standard settings not applicable to AutoLogger.
    // All other applicable settings (like max/min buffers come from the registry).
    //
    traceProperties->Wnode.BufferSize = TRACE_PROPS_SIZE;
    traceProperties->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    traceProperties->LogFileNameOffset = 0;
    traceProperties->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);

    //
    // Remember, we are dealing with AutoLogger here. There is no call
    // to StartTrace.
    //
	wprintf(L"[+] Successfully configured the tracing properties for the target ETW session!\n");

    *TraceProperties = traceProperties;

Exit:
    return error;
}

/**
*
* @brief        Configures the non-AutoLogger trace settings
* @param[in]    TraceProperties - The trace properties,
* @param[out]   ThreadHandle - The output thread handle the trace is being processed on.
* @param[in]    TraceName - The name of the target ETW trace to consume from.
* @return       ERROR_SUCCESS on success, otherwise appropriate Win32 error code.
*
*/
ULONG
StartTracing (
    _In_ PEVENT_RECORD_CALLBACK EventCallback,
    _Out_opt_ PHANDLE ThreadHandle,
    _In_ LPCWSTR TraceName
    )
{
    ULONG error;
    EVENT_TRACE_LOGFILEW traceLogFile;
    PROCESSTRACE_HANDLE* traceHandle;
    bool traceOpened;

    error = ERROR_SUCCESS;
    traceOpened = false;

    RtlZeroMemory(&traceLogFile, sizeof(traceLogFile));

    traceLogFile.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME |
                                    PROCESS_TRACE_MODE_EVENT_RECORD |
                                    PROCESS_TRACE_MODE_RAW_TIMESTAMP;
    traceLogFile.LoggerName = (LPWSTR)TraceName;
    traceLogFile.EventRecordCallback = EventCallback;

    if (ThreadHandle)
    {
        *ThreadHandle = NULL;
    }

    traceHandle = (PROCESSTRACE_HANDLE*)malloc(sizeof(PROCESSTRACE_HANDLE));
    if (traceHandle == NULL)
    {
        wprintf(L"[-] malloc error in StartTracing!\n");
        error = ERROR_INSUFFICIENT_BUFFER;
        goto Exit;
    }

    *traceHandle = OpenTraceW(&traceLogFile);
    if (*traceHandle == INVALID_PROCESSTRACE_HANDLE)
    {
        error = GetLastError();
        wprintf(L"[-] Error in OpenTraceW! (Error: 0x%lx)\n", error);
        goto Exit;
    }

    traceOpened = true;

    if (ThreadHandle)
    {
        *ThreadHandle = CreateThread(NULL,
                                     0,
                                     (LPTHREAD_START_ROUTINE)ProcessMyTrace,
                                     traceHandle,
                                     0,
                                     NULL);
        if (*ThreadHandle == NULL)
        {
            error = GetLastError();
            wprintf(L"[-] Error in OpenTraceW! (Error: 0x%lx)\n", error);
            goto Exit;
        }
    }
    else
    {
        ProcessMyTrace(traceHandle);
    }

    wprintf(L"[+] Started processing!\n");

Exit:
    if (error != ERROR_SUCCESS)
    {
        if (traceOpened)
        {
            CloseTrace(*traceHandle);
        }
    }

    return error;
}