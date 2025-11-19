# Secure Boot Compliance Inventory with PowerShell and Azure Log Analytics

## Overview

This project provides a **PowerShell automation script** to collect device inventory details and Secure Boot compliance status, including readiness for the **Windows UEFI CA 2023 certificate update**. The script sends this data to **Azure Log Analytics** for centralized monitoring and reporting.

## Why This Matters

The **UEFI CA 2023 update** is critical for maintaining Secure Boot integrity. Before enforcing policies or deploying updates, enterprises need visibility into:
- Which devices support UEFI and Secure Boot
- Which devices have applied the UEFI CA 2023 update
- Which devices require remediation

**Inventory is the first step** toward compliance and risk mitigation.

## Features

- Collects:
  - Device Name
  - Username & UPN
  - Serial Number
  - OS Version
  - Firmware Type (BIOS/UEFI)
  - Country (via public IP)

- Checks:
  - Secure Boot enabled status
  - UEFI CA 2023 update applied
  - Registry-based update state

- Sends data to **Azure Log Analytics** using the HTTP Data Collector API

- TLS 1.2 enforced for secure communication

- JSON payload compression for efficiency


## Prerequisites

- Windows device managed with Intune
- Azure Log Analytics Workspace  

> **Note:** Steps to set up an Azure Log Analytics Workspace are **out of scope for this repository**. Refer to [Microsoft Docs](https://learn.microsoft.com/en-us/azure/azure-monitor/logs/quick-create-workspace) for guidance.

## Usage

1. Update the script with:
   - `CustomerId` (Workspace ID)
   - `SharedKey` (Primary Key)
2. Run the script as a Remediation from Intune:
   
## Sample Output

```
DeviceName: LAPTOP123
Username: CONTOSO\jdoe
UserUPN: jdoe@contoso.com
SerialNumber: ABC123XYZ
OSVersion: 10.0.22631
FirmwareType: UEFI
Country: IN
SecureBootState: True
SecureBootUpdateStatus: True
SecureBootUpdateEnabled: True
SecureBootUpdateState: 1
```

## Query in Log Analytics

```kusto
DeviceDetails_CL
| summarize count() by SecureBootState, SecureBootUpdateStatus, Country
```

## Next Steps

- Build **Power BI dashboards** on top of Log Analytics
- Automate alerts for non-compliant devices using **Azure Monitor**
