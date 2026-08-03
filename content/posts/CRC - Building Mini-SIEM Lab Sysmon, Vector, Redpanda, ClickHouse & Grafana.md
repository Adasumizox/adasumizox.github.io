+++
title = "Building a Mini-SIEM Lab: Sysmon, Vector, Redpanda, ClickHouse & Grafana"
date = "2026-02-22"
description = "Build a practical mini-SIEM pipeline from Windows Sysmon through Vector and Redpanda to ClickHouse and Grafana."

[extra]
toc = true
keywords = "mini SIEM lab, Sysmon Vector, Redpanda ClickHouse, Grafana security monitoring, Windows event pipeline"

[taxonomies] 
tags=["SIEM", "Cybersecurity", "ClickHouse", "Vector", "Grafana", "Podman"] 
+++

Building a Security Information and Event Management (SIEM) system from scratch is one of the best ways to understand how those enterprise system works.

In this lab, we will build a modern log pipeline using Windows host and WSL2 (Debian). Before diving into the code, let's understand core architecture of our pipeline:
1. **Ingestion ([Sysmon](https://learn.microsoft.com/pl-pl/sysinternals/downloads/sysmon) & [Vector](https://vector.dev/)):** Gathering logs from the operating system is crucial step. Usually we gather logs from different system so we need to transform them into a schema format (ECS/OCSF)
2. **Buffering ([Redpanda](https://www.redpanda.com/)):** A messaging queue that temporarily hold logs. This prevent database from crashing if a sudden spike in log volume occurs.
3. **Storage ([ClickHouse](https://clickhouse.com/)):** An OLAP Database which is adjusted to handling Real-Time Analytics. It is column-oriented and optimized for analyzing massive amounts of log data.
4. **Visualization ([Grafana](https://grafana.com/)):** The dashboard where security analysts run queries and visualize threats.

Let's build it step-by-step

## Phase 1: Ingestion (Sysmon & Vector)

First we need something to generate high-quality security logs. For that we can use **Sysmon** Windows service that logs process creation, network connection and more.
We can use some already existing config e.g. [SwitftOnSecurity](https://github.com/SwiftOnSecurity/sysmon-config)

Open an elevated PowerShell prompt on your Windows machine and run:

```
# Download config to temp
Invoke-WebRequest -Uri https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml -OutFile C:\Windows\Temp\sysmonconfig.xml

# Install sysmon with config
sysmon64.exe -accepteula -i C:\Windows\Temp\sysmonconfig.xml
```

Next step is installing `Vector` by DataDog to read those logs and send them to our pipeline.
*Note: You need to compile Vector from source to include [PR #24305](https://github.com/vectordotdev/vector/pull/24305). If you are compiling from Windows, ensure you have [LLVM](https://releases.llvm.org/download.html) and follow the [Vector manual installation guide](https://vector.dev/docs/setup/installation/manual/from-source/)*

Create your Vector configuration file. This config maps raw Windows Event Logs to the Elastic Common Schema (ECS) format, making the data clean and structured.

```
# vector.yaml
data_dir: C:\Users\USERNAME\AppData\Local\Temp\vector-data

api:
  enabled: true
  address: 127.0.0.1:8686

sources:
  sysmon_logs:
    type: windows_event_log
    channels:
      - Microsoft-Windows-Sysmon/Operational
      - Application
      - System
      - Security

transforms:
  remap_ecs:
    type: remap
    inputs:
      - sysmon_logs
    source: |
      # Metadata
      .ecs.version = "8.11.0"
      .event.kind = "event"
      .event.code = .event_id
      .event.provider = .provider_name
      .event.dataset = .channel

      # Map Log Level
      .log.level = .level

      # Timestamp
      .timestamp = parse_timestamp!(.timestamp, format: "%Y-%m-%dT%H:%M:%S.%fZ")
      .@timestamp = .timestamp

      # Host
      .host.name = .computer
      .host.os.family = "windows"
      .host.os.platform = "windows"

      # Event_data as primary source of truth
      ed = .event_data

      if .channel == "Microsoft-Windows-Sysmon/Operational" && !is_null(ed) {
        .event.module = "sysmon"

        # Sysmon Event 1: Process Creation
        if .event_id == 1 {
          .event.category = "process"
          .event.type = ["start"]

          .process.pid = to_int!(ed.ProcessId)
          .process.entity_id = ed.ProcessGuid
          .process.executable = ed.Image
          .process.command_line = ed.CommandLine
          .process.working_directory = ed.CurrentDirectory
          .process.integrity = ed.IntegrityLevel

          if !is_null(ed.Image) {
            path_parts = split!(ed.Image, "\\")
            .process.name = path_parts[-1]
          }

          # User Parsing
          if !is_null(ed.User) {
            user_parts = split!(ed.User, "\\")
            if length(user_parts) == 2 {
              .user.domain = user_parts[0]
              .user.name = user_parts[1]
            } else {
              .user.name = ed.User
            }
          }

          # Hash Parsing
          if !is_null(ed.Hashes) {
            hashes = parse_key_value!(ed.Hashes, key_value_delimiter: "=", field_delimiter: ",")
            if !is_null(hashes.MD5) { .process.hash.md5 = hashes.MD5 }
            if !is_null(hashes.SHA1) { .process.hash.sha1 = hashes.SHA1 }
            if !is_null(hashes.SHA256) { .process.hash.sha256 = hashes.SHA256 }
            if !is_null(hashes.IMPHASH) { .process.hash.imphash = hashes.IMPHASH }
          }

          # Parent Process
          .process.parent.pid = to_int!(ed.ParentProcessId)
          .process.parent.entity_id = ed.ParentProcessGuid
          .process.parent.executable = ed.ParentImage
          .process.parent.command_line = ed.ParentCommandLine

          if !is_null(ed.ParentImage) {
            parent_parts = split!(ed.ParentImage, "\\")
            .process.parent.name = parent_parts[-1]
          }
        }

        # Sysmon Event 3: Network Connection
        if .event_id == 3 {
          .event.category = "network"
          .event.type = ["connection", "start"]

          .source.ip = ed.SourceIp
          .source.port = to_int!(ed.SourcePort)
          .source.domain = ed.SourceHostname

          .destination.ip = ed.DestinationIp
          .destination.port = to_int!(ed.DestinationPort)
          .destination.domain = ed.DestinationHostname
          .network.transport  = ed.Protocol

          .process.pid = to_int!(ed.ProcessId)
          .process.entity_id = ed.ProcessGuid
          .process.executable = ed.Image
          if !is_null(ed.Image) {
            img_parts = split!(ed.Image, "\\")
            .process.name = img_parts[-1]
          }

          if !is_null(ed.User) {
            user_parts = split!(ed.User, "\\")
            if length(user_parts) == 2 {
              .user.domain = user_parts[0]
              .user.name = user_parts[1]
            }
          }
        }
      } else {
        # Handle standard Windows logs (Security, System, App)
        if .channel == "Security" {
          .event.category = "authentication"
            if .event_id == 4624 {
              .event.type = ["start", "authentication_success"]
              .event.outcome = "success"
            }
            if .event_id == 4625 {
              .event.type = ["start", "authentication_failure"]
              .event.outcome = "failure"
            }
        }
        if .channel == "System" { .event.category = "host" }
        if .channel == "Application" { .event.category = "process" }

        if !is_null(ed) {
          if !is_null(ed.TargetUserName) { .user.name = ed.TargetUserName }
          if !is_null(ed.TargetDomainName) { .user.domain = ed.TargetDomainName }
          if !is_null(ed.SubjectUserName) && ed.SubjectUserName != "-" { .user.effective.name = ed.SubjectUserName }
          if !is_null(ed.IpAddress) && ed.IpAddress != "-" { .source.ip = ed.IpAddress }
          if !is_null(ed.IpPort) && ed.IpPort != "-" { .source.port = to_int(ed.IpPort) ?? null }
          if !is_null(ed.ProcessName) && ed.ProcessName != "-" {
            .process.executable = ed.ProcessName
            p_parts = split!(ed.ProcessName, "\\")
            .process.name = p_parts[-1]
          }
          if !is_null(ed.ProcessId) { .process.pid = to_int(ed.ProcessId) ?? null }
        }
      }

      # Clean up raw fields to save bandwidth
      del(.event_data)
      del(.message)
      del(.task)
      del(.level_value)
      del(.record_id)
      del(.version)

# Send to Redpanda (Kafka)
sinks:
  to_redpanda:
    type: kafka
    inputs:
      - remap_ecs
    bootstrap_servers: 127.0.0.1:29092
    topic: event-logs
    encoding:
      codec: json
```

## Phase 2, 3 & 4: Buffering, Storage, UI
We will run our backend services in WSL2 (Debian) using Podman. Save following as `docker-compose.yml`

```
# docker-compose.yml
version: '3.8'

services:
  redpanda:
    image: docker.redpanda.com/redpandadata/redpanda:latest
    container_name: redpanda
    command:
      - redpanda
      - start
      - --kafka-addr internal://0.0.0.0:9092,external://0.0.0.0:29092
      # Advertise external to localhost so Windows Vector can reach it. Internal to redpanda:9092 so Clickhouse can reach it.
      - --advertise-kafka-addr internal://redpanda:9092,external://127.0.0.1:29092
      - --smp 1
      - --memory 1G
      - --mode dev-container
    ports:
      - "29092:29092"
      - "9092:9092"
      - "8081:8081"
      - "9644:9644"
    volumes:
      - redpanda_data:/var/lib/redpanda/data
    networks:
      - siem_net

  clickhouse:
    image: docker.io/clickhouse/clickhouse-server:latest
    container_name: clickhouse
    environment:
      - CLICKHOUSE_PASSWORD=siemlab
    ports:
      - "8123:8123" # HTTP port (Grafana uses this)
      - "9000:9000" # Native client port
    volumes:
      - clickhouse_data:/var/lib/clickhouse
      - ./init-db.sql:/docker-entrypoint-initdb.d/init-db.sql # Auto-initializes tables
    depends_on:
      - redpanda
    networks:
      - siem_net

  grafana:
    image: docker.io/grafana/grafana:latest
    container_name: grafana
    ports:
      - "3000:3000"
    environment:
      # Automatically install the ClickHouse plugin
      - GF_INSTALL_PLUGINS=grafana-clickhouse-datasource
    volumes:
      - grafana_data:/var/lib/grafana
    depends_on:
      - clickhouse
    networks:
      - siem_net

networks:
  siem_net:
    driver: bridge

volumes:
  redpanda_data:
  clickhouse_data:
  grafana_data:
```

RedPanda does not require additional configuration but ClickHouse and Grafana does.
#### Initializing Database

ClickHouse needs to know how to read the logs from Redpanda and where to store them. We do this using a three-step architecture.

1. **Target Table:** Where the data permanently lives.
2. **Kafka Engine Table:** A temporary consumer that pulls data from Redpanda
3. Materialized View: The pipeline connecting the consumer to the target table.

Let's save this as `init-db.sql` in the same directory as previous file so it will be initialized when database is initialized.
Here ingestion is smaller than our Event source, but we can extend that according to our use case.

```
-- init-db.sql
CREATE DATABASE IF NOT EXISTS siem;

-- 1. Storage Table: The actual storage for your ECS logs
CREATE TABLE IF NOT EXISTS siem.logs
(
    `@timestamp` DateTime64(3),
    `event.kind` String,
    `event.category` String,
    `event.type` Array(String),
    `event.code` UInt32,
    `host.name` String,
    `process.name` String,
    `process.pid` UInt32,
    `source.ip` String,
    `destination.ip` String,
    `raw_message` String -- Storing the raw JSON is great for students to dig into missing fields
) ENGINE = MergeTree()
ORDER BY `@timestamp`;

-- 2. Consumer Table: Pulls raw JSON from Redpanda.
CREATE TABLE IF NOT EXISTS siem.logs_queue
(
    message String
) ENGINE = Kafka
SETTINGS kafka_broker_list = 'redpanda:9092',
         kafka_topic_list = 'event-logs',
         kafka_group_name = 'clickhouse_consumer_group',
         kafka_format = 'JSONAsString';

-- 3. Pipeline: The Materialized View translating the Queue into Storage
CREATE MATERIALIZED VIEW IF NOT EXISTS siem.logs_mv TO siem.logs AS
SELECT
    -- Safely parse timestamp, default to current time if missing so the pipeline doesn't break
    ifNull(parseDateTime64BestEffortOrNull(JSONExtractString(message, '@timestamp'), 3), now64(3)) AS `@timestamp`,
    JSONExtractString(message, 'event', 'kind') AS `event.kind`,
    JSONExtractString(message, 'event', 'category') AS `event.category`,

    -- Convert raw JSON array strings to actual ClickHouse Arrays
    arrayMap(x -> replaceAll(x, '"', ''), JSONExtractArrayRaw(message, 'event', 'type')) AS `event.type`,

    JSONExtractUInt(message, 'event', 'code') AS `event.code`,
    JSONExtractString(message, 'host', 'name') AS `host.name`,
    JSONExtractString(message, 'process', 'name') AS `process.name`,
    JSONExtractUInt(message, 'process', 'pid') AS `process.pid`,
    JSONExtractString(message, 'source', 'ip') AS `source.ip`,
    JSONExtractString(message, 'destination', 'ip') AS `destination.ip`,
    message AS `raw_message`
FROM siem.logs_queue;
```

Now we need to install `podman` and `podman-compose` then start the stack

```
sudo apt install podman podman-compose
sudo podman-compose up -d
```

## Troubleshooting WSL2 & Podman Issues

When running Podman on WSL2, you might encounter a few known issue. Here is how to fix them:

**Error:** `WARN: The cgroupv2 manager is set to systemd but there is no systemd user session available`
*Fix:* You need to enable systemd inside WSL2. Edit or create `/etc/wsl.conf`

```
[boot]
systemd=true
```

**Error:** `netavark: nftables error: nft did not return successfully while applying ruleset`
*Fix:* Switch your firewall to legacy `iptables`:

```
sudo update-alternatives --set iptables /usr/sbin/iptables-legacy
sudo update-alternatives --set ip6tables /usr/sbin/ip6tables-legacy
```

If that fails, force Podman to use iptables via its config

```
sudo mkdir -p /etc/containers
echo -e "[network]\nfirewall_driver = \"iptables\"" | sudo tee -a /etc/containers/containers.conf
```

**Start Fresh**
If you mess up your configuration and need to wipe your state clean, run:

```
# Powershell
wsl --shutdown

# WSL2
podman system reset -f
sudo podman network prune -f
sudo podman-compose down
```

## Phase 4: UI and Threat Hunting with Grafana

If all services are running, it's time to connect Grafana to ClickHouse
1. Open browser and go to `http://localhost:3000`
2. Navigate to Connections > Data Sources > Add data source
3. Select ClickHouse and fill in the details:
	1. **Server Address:** clickhouse
	2. **Protocol:** HTTP
	3. **Secure (TLS):** Off
	4. **Username:** default
	5. **Password:** siemlab
	6. **Default Database (Advanced):** siem

Click "Save & Test". If it fails, check the logs with `sudo podman logs grafana`

#### Example Queries

Create a new dashboard, add a visualization, and try these queries to analyze your ingested data.

**Query 1: Find Noisy Processes**
Great for establishing a baseline of normal activity on host

```
SELECT
    `process.name`,
    count() AS total_events
FROM siem.logs
WHERE $__timeFilter(`@timestamp`) AND `process.name` != ''
GROUP BY `process.name`
ORDER BY total_events DESC
LIMIT 10
```

![result of query](query_popular.png)

**Query 2: Raw Event Log View**
A tabular view of recent events

```
SELECT
    `@timestamp` AS Time,
    `host.name` AS Host,
    `event.code` AS EventID,
    `process.name` AS Process,
    `source.ip` AS SourceIP,
    `destination.ip` AS DestIP
FROM siem.logs
WHERE $__timeFilter(`@timestamp`)
ORDER BY `@timestamp` DESC
LIMIT 100
```

![result of query](query_all.png)

Now you have local SIEM processing real-time Windows logs.
