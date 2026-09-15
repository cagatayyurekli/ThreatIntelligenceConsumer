# Three-provider Sense capture test

This profile requests only these three individual ETW providers:

| Provider | GUID |
| --- | --- |
| Microsoft.Windows.Sense.Client | `65a1b6fc-4c24-59c9-e3f3-ad11ac510b41` |
| Microsoft.Windows.DefenderCore1DS | `05ff9269-f73f-5d04-7f30-398bb2f6e5d0` |
| Microsoft.Windows.Sense.GeneratedETW | `c60418cc-7e07-400f-ae3b-d521c5dbd96f` |

The repeated Sense.Client entries are one provider. ProviderGroupGUIDs are not registered. Each provider requests level `0xff`, all keyword bits, and no MatchAll restriction. This configures the test listener; it does not establish which events the providers will emit or deliver on a particular Windows build.

## Install and capture

Download and extract the **ThreatIntelligenceConsumer-x64-sense-three-providers** artifact from the **Build x64 TDH-decoding NDJSON executable (three-provider test)** GitHub Actions workflow.

The registry file **replaces the existing `0MyThreatIntelTrace` lab session and all its provider subkeys**, so older provider registrations do not remain. It does not change other AutoLogger sessions. Close the consumer, and use elevated PowerShell in the extracted artifact directory:

```powershell
# Save the previous lab configuration if it exists.
$session = 'HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\0MyThreatIntelTrace'
$backup = '.\0MyThreatIntelTrace-before-' + (Get-Date -Format 'yyyyMMdd-HHmmss') + '.reg'
if (Test-Path 'HKLM:\SYSTEM\CurrentControlSet\Control\WMI\Autologger\0MyThreatIntelTrace') {
    reg.exe export $session $backup /y
    if ($LASTEXITCODE -ne 0) { throw 'Could not back up the existing lab session.' }
}
reg.exe import .\sense-three-providers.reg
if ($LASTEXITCODE -ne 0) { throw 'Profile import failed.' }
```

**Reboot Windows after importing.** Editing the registry does not replace the already running session. Do not import the original Threat-Intelligence profile or an all-provider profile on top of this test profile.

After reboot, inspect the session and its provider startup statuses:

```powershell
$key = 'HKLM:\SYSTEM\CurrentControlSet\Control\WMI\Autologger\0MyThreatIntelTrace'
Get-ItemProperty $key | Select-Object PSChildName, Start, Status
Get-ChildItem $key | ForEach-Object {
    Get-ItemProperty $_.PSPath |
        Select-Object PSChildName, Enabled, EnableLevel, MatchAnyKeyword, MatchAllKeyword, Status
}
```

There should be exactly three provider subkeys, matching the table above. A missing status is not proof of success; a successful startup status alone is not proof of event delivery.

Run the decoder from elevated PowerShell. Use a new output filename for each run because the consumer overwrites the specified file:

```powershell
$output = '.\sense-three-' + (Get-Date -Format 'yyyyMMdd-HHmmss') + '.ndjson'
.\ThreatIntelligenceConsumer-json.exe $output
```

Perform the lab activity while it runs. Press Enter to exit. Then count which providers actually delivered records:

```powershell
Get-Content $output | ForEach-Object { $_ | ConvertFrom-Json } |
    Group-Object provider_guid | Sort-Object Count -Descending |
    Select-Object Count, Name
```

Keep the NDJSON and the startup status output together. Zero rows from a provider means no records from that provider were observed in that run; it does not identify the cause.

## Output and scope

The existing multi-provider decoder is unchanged. It preserves `user_data_hex` and `extended_data`, and attempts bounded TDH metadata/property decoding with explicit decode status. Nested binary fields are not automatically decoded as Bond.

The three-provider scope comes from this AutoLogger profile, not a hardcoded output filter in the executable. Adding provider subkeys later broadens the capture. Real-time persistence is disabled for this profile to avoid persisting undelivered events from this test for the next boot. These settings do not guarantee lossless collection.

To return to a saved lab profile, close the consumer, delete only the `0MyThreatIntelTrace` registry key, import your saved backup, and reboot. Deleting the test key before restoration prevents the three test provider subkeys from being merged into the old configuration.

The profile uses the existing consumer's x64 AutoLogger mechanism. Runtime delivery from these three providers still needs to be verified on the research device.

Registry setting reference: [Microsoft: Configuring and Starting an AutoLogger Session](https://learn.microsoft.com/en-us/windows/win32/etw/configuring-and-starting-an-autologger-session).
