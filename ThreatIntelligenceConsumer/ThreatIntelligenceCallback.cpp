/*++
*
* @file:      ThreatIntelligenceConsumer/Callback.cpp
*
* @summary:   ETW callback implementation.
*
* @author:    Connor McGarr (@33y0re)
*
--*/
#include "ThreatIntelligenceCallback.hpp"

/**
*
* @brief        Threat-Intelligence ETW callback.
* @param[in]    EventRecord - Associated ETW event record.
*
*/
void
HandleThreatIntelligenceCallback (
    _In_ PEVENT_RECORD EventRecord
    )
{
    wprintf(L"[+] [HandleThreatIntelligenceCallback] Hello from the Threat-Intelligence ETW callback!\n");

    //
    // Print the GUID
    //
    wprintf(L"  [*] GUID = {%08lX-%04hX-%04hX-%02hhX%02hhX-%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX}\n",
            EventRecord->EventHeader.ProviderId.Data1,
            EventRecord->EventHeader.ProviderId.Data2,
            EventRecord->EventHeader.ProviderId.Data3,
            EventRecord->EventHeader.ProviderId.Data4[0],
            EventRecord->EventHeader.ProviderId.Data4[1],
            EventRecord->EventHeader.ProviderId.Data4[2],
            EventRecord->EventHeader.ProviderId.Data4[3],
            EventRecord->EventHeader.ProviderId.Data4[4],
            EventRecord->EventHeader.ProviderId.Data4[5],
            EventRecord->EventHeader.ProviderId.Data4[6],
            EventRecord->EventHeader.ProviderId.Data4[7]);

    return;
}