#pragma once
#include <Windows.h>
#include <evntrace.h>
#include <evntcons.h>
#include <stdio.h>

//
// sechost!EtwpQueryRealTimeTraceProperties uses this size.
//
#define TRACE_PROPS_SIZE 0x1078

ULONG
ConfigureTracingProperties (
    _Inout_ PEVENT_TRACE_PROPERTIES* TraceProperties,
    _In_ LPCWSTR TraceName,
    _In_ ULONG TraceNameSize
    );

ULONG
StartTracing (
    _In_ PEVENT_RECORD_CALLBACK EventCallback,
    _Out_opt_ PHANDLE ThreadHandle,
    _In_ LPCWSTR TraceName
    );