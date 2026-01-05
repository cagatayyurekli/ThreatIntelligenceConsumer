/*++
*
* @file:      ThreatIntelligenceConsumer/SecurityTrace.cpp
*
* @summary:   Functionality for consuming ETW trace sessions with SecurityTrace without PPL.
*
* @author:    Connor McGarr (@33y0re)
*
--*/
#include "SecurityTrace.hpp"
#include "Helpers.hpp"

//
// C linkage for Hooks.asm
//
extern "C"
{
    PEVENT_TRACE_PROPERTIES k_TraceProperties = nullptr;
	ControlTraceW_t g_OriginalControlTraceW = nullptr;
};

//
// Hooks.asm
//
extern
"C"
FORCEINLINE
ULONG
__fastcall
MyControlTraceW (
    _In_ CONTROLTRACE_ID TraceId,
    _In_ LPCWSTR InstanceName,
    _Inout_ PEVENT_TRACE_PROPERTIES Properties,
    _In_ ULONG ControlCode
    );

/**
*
* @brief        Creates the detour for non-query ControlTraceW calls.
* @param[in]    FunctionAddress - ControlTraceW's address.
* @param[in]	OriginalBytes - Original 14 bytes from ControlTraceW.
* @param[in]	SizeOfOriginalBytes - The size of the original bytes (14 bytes for a relative JMP).
* @return       The detour trampoline on success, otherwise NULL.
*
*/
static
PVOID
CreateControlTraceDetour (
	_In_ ULONG_PTR FunctionAddress,
	_In_ BYTE* OriginalBytes,
	_In_ SIZE_T SizeOfOriginalBytes
	)
{
	PVOID trampolineMemory;
	SIZE_T trampolineSize;
	BYTE* trampoline;
    ULONG oldProtection;

	trampolineMemory = nullptr;

    //
	// The installed hook is a jump (14 bytes). So we need to compensate
	// for this, plus the _additional_ absolute jump we will add to the trampoline.
    //
	trampolineSize = SizeOfOriginalBytes + SECURITY_TRACE_HOOK_SIZE;
	trampoline = nullptr;
    oldProtection = 0;

	//
	// Allocate the trampoline
	//
    trampolineMemory = malloc(trampolineSize);
    if (trampolineMemory == NULL)
    {
        wprintf(L"[-] Error! malloc failed in CreateControlTraceDetour! (GLE: %d)\n", GetLastError());
        goto Exit;
	}

    //
	// Mark the trampoline memory as executable
    //
    if (VirtualProtect(trampolineMemory,
                       trampolineSize,
                       PAGE_EXECUTE_READWRITE,
                       &oldProtection) == FALSE)
    {
        wprintf(L"[-] VirtualProtect! malloc failed in CreateControlTraceDetour! (GLE: %d)\n", GetLastError());
        goto Exit;
    }

	trampoline = (BYTE*)trampolineMemory;

	//
	// Copy original bytes
	//
	RtlCopyMemory(trampoline,
                  OriginalBytes,
                  SizeOfOriginalBytes);

	//
	// Build absolute JMP to ControlTraceW index
    // for legitimate execution (detours for non-query calls).
	//
	trampoline[SizeOfOriginalBytes + 0] = 0xFF;
	trampoline[SizeOfOriginalBytes + 1] = 0x25;
	*(ULONG*)(&trampoline[SizeOfOriginalBytes + 2]) = 0;  // RIP + 0
	*(ULONG_PTR*)(&trampoline[SizeOfOriginalBytes + 6]) = FunctionAddress + SizeOfOriginalBytes;

	//
	// We have updated some code. Flush the instruction cache.
	//
	FlushInstructionCache(GetCurrentProcess(),
                          trampolineMemory,
                          trampolineSize);

Exit:
	return trampolineMemory;
}

/**
*
* @brief        Patches ControlTraceW to avoid the query operation for the SecurityTrace session.
* @return       true on success, otherwise false.
*
*/
bool
PatchControlTrace ()
{
    bool result;
    HMODULE sechost;
    BYTE trampoline[14];
    SIZE_T writtenBytes;
    ULONG_PTR controlTraceW;
    ULONG controlTraceWSize;
    BYTE* originalControlTraceWBytes;

    writtenBytes = 0;
    controlTraceW = 0;
    controlTraceWSize = 0;
    originalControlTraceWBytes = nullptr;
    result = false;

    RtlZeroMemory(&trampoline, sizeof(trampoline));

	sechost = GetModuleHandleW(L"sechost.dll");
    if (sechost == NULL)
    {
        wprintf(L"[-] Error! GetModuleHandleW failed in PatchControlTrace! (GLE: %d)\n", GetLastError());
        goto Exit;
	}

    controlTraceW = reinterpret_cast<ULONG_PTR>(GetProcAddress(sechost, "ControlTraceW"));
    if (controlTraceW == 0)
    {
        wprintf(L"[-] Error! GetProcAddress failed in PatchControlTrace! (GLE: %d)\n", GetLastError());
        goto Exit;
    }

    //
    // Preserve ControlTraceW's original bytes.
    //
    originalControlTraceWBytes = reinterpret_cast<BYTE*>(malloc(SECURITY_TRACE_HOOK_SIZE));
    if (originalControlTraceWBytes == nullptr)
    {
        wprintf(L"[-] Error! malloc failed in PatchControlTrace! (GLE: %d)\n", GetLastError());
        goto Exit;
    }

	RtlZeroMemory(originalControlTraceWBytes, SECURITY_TRACE_HOOK_SIZE);

    //
    // Store the original bytes for ControlTraceW.
    //
    RtlCopyMemory(originalControlTraceWBytes,
                  reinterpret_cast<PVOID>(controlTraceW),
		          SECURITY_TRACE_HOOK_SIZE);

    //
    // Create standalone trampoline in separate executable memory
    // This will properly forward non-query calls to the original ControlTraceW
    //
    g_OriginalControlTraceW = reinterpret_cast<ControlTraceW_t>(CreateControlTraceDetour(controlTraceW,
                                                                                         originalControlTraceWBytes,
                                                                                         SECURITY_TRACE_HOOK_SIZE));
    if (g_OriginalControlTraceW == nullptr)
    {
        wprintf(L"[-] Error! CreateTrampoline failed in PatchControlTrace!\n");
        goto Exit;
    }

    //
    // RIP-relative jump into our patched function.
    //
    trampoline[0] = 0xFF;
    trampoline[1] = 0x25;

    //
    // Jump displacement is 0
    //
    *(ULONG*)(&trampoline[2]) = 0;
    *(ULONG_PTR*)(&trampoline[6]) = reinterpret_cast<ULONG_PTR>(MyControlTraceW);

    if (WriteProcessMemory(GetCurrentProcess(),
                           reinterpret_cast<PVOID>(controlTraceW),
                           trampoline,
                           sizeof(trampoline),
                           &writtenBytes) == FALSE)
    {
        wprintf(L"[-] Error! WriteProcessMemory failed in PatchEtwpQueryRealTimeTraceProperties! (GLE: %d)\n", GetLastError());
		goto Exit;
    }

    result = true;

Exit:
    if (originalControlTraceWBytes != NULL)
    {
        free(originalControlTraceWBytes);
    }

    return result;
}

/**
*
* @brief       Preserves the trace properties so we can "mimic" a query operation.
*
*/
void
PreserveTraceProperties (
	_In_ PEVENT_TRACE_PROPERTIES TraceProperties
    )
{
	k_TraceProperties = TraceProperties;

    return;
}

/**
*
* @brief        frees the detour trampoline memory.
*
*/
void
CleanupSecurityTraceResources ()
{
    if (g_OriginalControlTraceW != nullptr)
    {
        free(g_OriginalControlTraceW);
	}
}