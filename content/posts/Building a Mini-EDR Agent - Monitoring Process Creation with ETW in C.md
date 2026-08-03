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

In my previous post, we built a Mini-SIEM lab using Sysmon to gather high-quality telemetry from a Windows Host. But have you ever wondered how tools like CrowdStrike or Microsoft Defender actually intercept process creation in real-time?

Under the hood, most modern Endpoint Detection and Response (EDR) agents rely on a powerful Windows kernel feature called [**Event Tracing for Windows (ETW)**](https://learn.microsoft.com/en-us/windows/win32/etw/event-tracing-portal)

In this post we are going to ditch the pre-built tools and write our own simple EDR agent in C from scratch. Our agent will subscribe to the Windows Kernel process provider and print a real-time data to the console whenever a new process is created.

Before diving into the code let's understand the core architecture of ETW. It consists of three main components:
- **Providers** - The components generating logs (e.g. the Windows Kernel).
- **Controllers** - Applications that start and configure tracing sessions.
- **Consumers** - Applications that subscribe to the sessions and read the events in real-time or into `.etl` file.

Our C program will act as both Controller (creating the trace session) and a Consumer (parsing and printing logs).

Let's build it step-by-step.

### Phase 1: Setting up the ETW Session (The Controller)

To receive events, we first need to start an ETW trace session.
First we need to define the unique GUID for the provider we want to listen to.

In our case it's `Microsoft-Windows-Kernel-Process`.
This provider have GUID of [`{22FB2CD6-0E7B-422B-A0C7-2FAD1F0E716}`](https://github.com/repnz/etw-providers-docs/blob/master/Manifests-Win10-18990/Microsoft-Windows-Kernel-Process.xml)

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

In our `main` function, we configure the `EVENT_TRACE_PROPERTIES` structure. We tell the Windows Kernel that we want a real-time session (`EVENT_TRACE_REAL_TIME_MODE`) so we can get events instantly, rather than writing them to a disk file

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
Starting a session isn't enough. Right now, it's empty. We need to tell session to listen to our specific Kernel Provider using `EnableTraceEx2`.

```c
status = EnableTraceEx2(
    g_hSession,
    &ProviderGuid,
    EVENT_CONTROL_CODE_ENABLE_PROVIDER,
    TRACE_LEVEL_VERBOSE,
    0xFFFFFFFFFFFFFFFF, // Match any keywords (get all events)
    0,
    0,
    NULL
);
```

### Phase 3: Consuming the Events (The Consumer)

Now the logs are flowing into our session, we need to read them. We can set up an `EVENT_TRACE_LOGFILEW` structure, point it to our session name, and provide a callback function (`EventRecordCallback`) that Windows will trigger every time a new event arrives.

Finally, we call `ProcessTrace()`. This is a blocking function - it will sit in an infinite loop, monitoring queue and firing our callback for every event until we stop the program.

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

In our `EventRecordCallback`, we filter out noise and only look for Event ID `1` (Process Creation). We then use `TdhGetProperty` to extract specific fields like `ProcessID`, `ImageName`

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

*(Note: I wrote two helper functions, `GetUint32Property` and `PrintStringProperty`, which wrap the `TdhGetProperty` API to keep the callback clean. You can see them in the full source code).*

### Graceful Shutdown
ETW sessions live in the Windows Kernel. If our program crashes or exits without stopping the trace, the session remains active, consuming system resources. To prevent "zombie" sessions, we capture `Ctrl+C` signals and cleanly shut down using `ControlTraceW`

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
To compile this agent, you can use the MSVC compiler included with Visual Studion. Open the **x64 Native Tools Command Prompt** and run:

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

While commercial EDRs and massive layers of complexity (like hooking API calls, injecting DLLs, utilizing kernel callbacks like `PsSetCreateProcessNotifyRoutine`, 
and sending data to cloud AI agents), consuming ETW real-time feeds is the fundamental building block for modern Windows environments.

In future labs, we might get into upgrading our agent by writing Kernel Driver.
