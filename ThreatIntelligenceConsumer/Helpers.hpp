#pragma once
#include "Trace.hpp"

#define MAX_LOGGERS 0x50
#define MY_TRACE_NAME L"0MyThreatIntelTrace"
#define AUTO_LOGGER_REGISTRY_PATH L"SYSTEM\\CurrentControlSet\\Control\\WMI\\Autologger"

ULONG
RetrieveAutoLoggerTraceProperties (
	_Inout_ PEVENT_TRACE_PROPERTIES* TraceProperties,
	_In_ ULONG TracePropertiesSize
	);