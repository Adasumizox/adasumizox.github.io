+++
title = "Security Labs"
description = "Hands-on EDR, SIEM, and Windows telemetry projects by Daniel Jeczen."
template = "pages.html"
path = "labs"
+++

These labs turn security architecture into small systems you can inspect, run, and extend. Each project links to the full build notes and highlights a useful next experiment.

## Mini-EDR: process telemetry with ETW

A native C consumer for the `Microsoft-Windows-Kernel-Process` provider. The lab covers trace sessions, real-time event consumption, TDH payload parsing, and clean shutdown.

[Read the Mini-EDR build →](@/posts/Building a Mini-EDR Agent - Monitoring Process Creation with ETW in C.md)

**Good next steps:** add command-line capture, normalize device paths, enrich parent-child relationships, and write events to a durable queue.

## Mini-SIEM: Windows events to ClickHouse

An open-source pipeline that moves Sysmon events through Vector and Redpanda into ClickHouse, then explores the data in Grafana.

[Read the Mini-SIEM build →](@/posts/CRC - Building Mini-SIEM Lab Sysmon, Vector, Redpanda, ClickHouse & Grafana.md)

**Good next steps:** add schema validation, detection-as-code rules, pipeline health metrics, and repeatable test events.

## Lab principles

1. Keep every component replaceable.
2. Preserve enough raw context to investigate mistakes.
3. Measure dropped, delayed, and malformed events.
4. Treat detections as code: version, test, and review them.
