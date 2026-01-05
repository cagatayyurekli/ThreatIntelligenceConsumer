#pragma once
#include <Windows.h>
#include <evntrace.h>
#include <evntcons.h>
#include <stdio.h>
#include <winternl.h>

#define SECURITY_TRACE_HOOK_SIZE 14

//
// Function pointer typedef for ControlTraceW
//
typedef
ULONG
(WINAPI *ControlTraceW_t)(
    _In_ CONTROLTRACE_ID TraceHandle,
    _In_ LPCWSTR InstanceName,
    _Inout_ PEVENT_TRACE_PROPERTIES Properties,
    _In_ ULONG ControlCode
    );

//
// Function definitions
//
void
PreserveTraceProperties (
    _In_ PEVENT_TRACE_PROPERTIES TraceProperties
    );

bool
PatchControlTrace ();

void
CleanupSecurityTraceResources ();