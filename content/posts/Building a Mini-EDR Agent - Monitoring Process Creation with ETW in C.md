+++
title = "Building a Mini-EDR Agent - Monitoring Process Creation with ETW in C"
date = "2026-03-26"
description = "Build a small EDR-style process monitor in C using ETW, the Microsoft Windows Kernel Process provider, and TDH payload parsing."

[extra]
toc = true
keywords = "ETW process monitoring, mini EDR agent, Windows kernel process provider, TDH, C security programming"

[taxonomies]
tags=["EDR", "Cybersecurity", "ETW", "Windows"]
+++

In my previous post, we built a mini-SIEM lab using Sysmon to gather high-quality telemetry from a Windows host. But how can an endpoint sensor observe process creation in real time without relying on Sysmon?

One useful source is [**Event Tracing for Windows (ETW)**](https://learn.microsoft.com/en-us/windows/win32/etw/event-tracing-portal), Windows' general-purpose tracing infrastructure. Production EDR products normally combine several user-mode and kernel-mode telemetry sources; ETW is one source rather than the mechanism behind every product.

In this post, we will ditch the pre-built collection tools and write a small EDR-style sensor in C. It will subscribe to the Windows Kernel Process provider and print an event whenever a new process starts.

Before diving into the code, let's look at the three main parts of ETW:

- **Providers** - The components generating logs (e.g. the Windows Kernel).
- **Controllers** - Applications that start and configure tracing sessions.
- **Consumers** - Applications that read events from real-time sessions or `.etl` files.

Our C program will act as both a controller (creating the trace session) and a consumer (parsing and printing events).

Let's build it step-by-step.

### Phase 1: Setting up the ETW Session (The Controller)

To receive events, we first need to start an ETW trace session and define the GUID of the provider we want to enable.

In our case, it is `Microsoft-Windows-Kernel-Process`, whose GUID is [`{22FB2CD6-0E7B-422B-A0C7-2FAD1F0E716}`](https://github.com/repnz/etw-providers-docs/blob/master/Manifests-Win10-18990/Microsoft-Windows-Kernel-Process.xml).

```c
#define _WIN32_WINNT 0x0600
#include <windows.h>
#include <stdio.h>
#include <evntrace.h>
#include <evntcons.h>
#include <tdh.h>

#pragma comment(lib, "tdh.lib")
#pragma comment(lib, "advapi32.lib")

static const GUID ProviderGuid =
{ 0x22FB2CD6, 0x0E7B, 0x422B, { 0xA0, 0xC7, 0x2F, 0xAD, 0x1F, 0xD0, 0xE7, 0x16 } };
```

In `main`, we configure the `EVENT_TRACE_PROPERTIES` structure. `EVENT_TRACE_REAL_TIME_MODE` makes events available to a real-time consumer instead of writing them to a disk file.

```c
// Setup session properties
TRACE_PROPERTIES sessionProps = { 0 };
sessionProps.Properties.Wnode.BufferSize = sizeof(TRACE_PROPERTIES);
sessionProps.Properties.Wnode.Flags = WNODE_FLAG_TRACED_GUID;
sessionProps.Properties.Wnode.ClientContext = 1; 
sessionProps.Properties.LogFileMode = EVENT_TRACE_REAL_TIME_MODE; // Crucial for EDR
sessionProps.Properties.LoggerNameOffset = offsetof(TRACE_PROPERTIES, SessionName);

// Start the trace session (Requires Administrator privileges!)
ULONG status = StartTraceW(&g_hSession, g_SessionName, &sessionProps.Properties);
```

### Phase 2: Subscribing to Kernel Events
Starting a session is not enough. We must enable our provider for that session with `EnableTraceEx2`.

```c
status = EnableTraceEx2(
    g_hSession,
    &ProviderGuid,
    EVENT_CONTROL_CODE_ENABLE_PROVIDER,
    TRACE_LEVEL_VERBOSE,
    0x10, // WINEVENT_KEYWORD_PROCESS
    0,
    0,
    NULL
);
```

### Phase 3: Consuming the Events (The Consumer)

Now that events are flowing into the session, we need to read them. We set up an `EVENT_TRACE_LOGFILEW` structure, point it to our session name, and provide an `EventRecordCallback` function that ETW calls for each event.

Finally, we call `ProcessTrace()`. This function blocks while it processes events and invokes our callback, until the trace is stopped.

```c
EVENT_TRACE_LOGFILEW logFile = { 0 };
logFile.LoggerName = g_SessionName;
logFile.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
logFile.EventRecordCallback = EventRecordCallback; // The function that handles data

TRACEHANDLE hTrace = OpenTraceW(&logFile);

printf("Listening for Process Starts... (Press Ctrl+C to stop)\n");
status = ProcessTrace(&hTrace, 1, NULL, NULL); // Blocks and processes events
```

### Phase 4: Parsing the Payload with TDH
Raw ETW data is an unformatted binary payload. Parsing it manually is error-prone, and its layout can change with Windows updates. Thankfully, Microsoft provides the **Trace Data Helper (TDH)** API, which uses the provider's manifest to parse the binary payload into readable strings and integers.

In `EventRecordCallback`, we verify the provider and select event ID `1`, which this provider's manifest defines as process start. We then use `TdhGetProperty` to extract fields such as `ProcessID` and `ImageName`. Event schemas can vary by provider version, so production code should inspect the event metadata rather than assume every Windows build exposes an identical payload.

```c
VOID WINAPI EventRecordCallback(PEVENT_RECORD pEvent)
{
    if (memcmp(&pEvent->EventHeader.ProviderId, &ProviderGuid, sizeof(GUID)) != 0) return;

    // Event ID 1 == Process Start
    if (pEvent->EventHeader.EventDescriptor.Id == 1)
    {
        printf("\n[+] Process Started!\n");
        printf("  ProcessID: %lu\n", GetUint32Property(pEvent, L"ProcessID"));
        printf("  ParentProcessID: %lu\n", GetUint32Property(pEvent, L"ParentProcessID"));

        PrintStringProperty(pEvent, L"ImageName");

        printf("--------------------------------------------------\n");
    }
}
```

*The complete program should include `GetUint32Property` and `PrintStringProperty` helpers that wrap `TdhGetProperty`, plus error handling for missing properties. The excerpts here focus on the ETW control flow.*

### Graceful Shutdown
Real-time ETW sessions are system-wide objects. If our program exits without stopping its session, that session can remain active. To prevent this, we handle `Ctrl+C` and stop it with `ControlTraceW`.

```c
BOOL WINAPI ConsoleHandler(DWORD signal) {
    if (signal == CTRL_C_EVENT && g_hSession) {
        printf("\nStopping trace session gracefully...\n");
        // Tell the kernel to stop our session
        ControlTraceW(g_hSession, g_SessionName, &stopProps.Properties, EVENT_TRACE_CONTROL_STOP);
        return TRUE;
    }
    return FALSE;
}
```

### Compiling and Running
To compile this sensor, use the MSVC compiler included with Visual Studio. Open the **x64 Native Tools Command Prompt** and run:

```cmd
cl.exe /O2 mini_edr.c
```

**Testing the Agent:**
Because ETW interacts directly with the Windows Kernel, **you must run this executable as an Administrator**.

Open an elevated command prompt, run `mini_edr.exe`, and then open an application like `notepad.exe` or `calc.exe`. You will see your mini-EDR catch the execution:

```
PS > .\mini_edr.exe
Trace Session 'ProcMonTrace_18872' Started.
Listening for Process Starts... (Press Ctrl+C to stop)

[+] Process Started!
  ProcessID: 18956
  ParentProcessID: 1600
  ImageName: \Device\HarddiskVolume3\Windows\System32\dllhost.exe
--------------------------------------------------

[+] Process Started!
  ProcessID: 19012
  ParentProcessID: 6692
  ImageName: \Device\HarddiskVolume3\Program Files\WindowsApps\Microsoft.WindowsNotepad_11.2512.26.0_x64__8wekyb3d8bbwe\Notepad\Notepad.exe
--------------------------------------------------

[+] Process Started!
  ProcessID: 19200
  ParentProcessID: 2040
  ImageName: \Device\HarddiskVolume3\Program Files\WindowsApps\Microsoft.WindowsCalculator_11.2508.4.0_x64__8wekyb3d8bbwe\CalculatorApp.exe
--------------------------------------------------
```

### Conclusion
Congratulations! You've just written a core component of an EDR engine.

Commercial EDRs add many layers: additional telemetry sources, tamper protection, buffering, enrichment, correlation, and remote analysis. This small consumer is not an EDR by itself, but it demonstrates one practical way to collect process telemetry on Windows.

In a future lab, we can compare this approach with a signed kernel driver that uses process-creation callbacks.
