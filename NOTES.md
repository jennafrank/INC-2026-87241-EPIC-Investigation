# INCIDENT 87241: COMPREHENSIVE HUNT NOTES
## Cloud Identity Compromise & Business Email Compromise (BEC)

**Date:** June 25, 2026  
**Hunter:** SOC Analyst (Training Hunt)  
**Organization:** LOG(N) Pacific  
**Platform:** Microsoft Sentinel (law-cyber-range workspace)  
**Investigation Window:** June 10-11, 2026 (primary); June 10-20, 2026 (full scope)  
**Times:** These notes use US Central Daylight Time (UTC−5), as displayed in the portal during the hunt. Where a UTC column appears, it gives the UTC time. The README uses UTC throughout.  
**Incident ID:** ad76cdddcd4de3a19d87770207112ccd0cb7c54ec6

---

> **Correction (later log review):** These are working notes from the hunt. A later review of `SigninLogs` and `AADNonInteractiveUserSignInLogs` found that the attacker's successful sign-ins were **browser sign-ins, not legacy authentication**. No Conditional Access policy applied (`notApplied`); the tenant relied on Security Defaults, which did not require MFA for those sign-ins. Where MFA was required (13 attempts), it blocked every one. The "583 sign-ins", "legacy auth bypass" and "90-day refresh token" statements below are superseded. The [README](README.md) has the verified figures.

## TABLE OF CONTENTS
1. [Hunt Overview](#hunt-overview)
2. [Initial Alert Context](#initial-alert-context)
3. [Victim Profile](#victim-profile)
4. [Attack Phase Breakdown](#attack-phase-breakdown)
5. [Schema & Table Discovery](#schema--table-discovery)
6. [Query Patterns & KQL Techniques](#query-patterns--kql-techniques)
7. [Attack Timeline (Detailed)](#attack-timeline-detailed)
8. [Threat Actor TTPs](#threat-actor-ttps)
9. [Forensic Evidence](#forensic-evidence)
10. [Containment Sequencing](#containment-sequencing)
11. [Lessons Learned](#lessons-learned)

---

## HUNT OVERVIEW

### What We Investigated
A low-rated, inherited-from-night-shift alert on finance user Mark Smith (m.smith@lognpacific.org) triggered by Entra ID Identity Protection detecting a sign-in from an anonymous IP address (103.69.224.136, Amsterdam).

### What We Found
A sophisticated, multi-staged attack:
- **Credential stuffing** + **MFA bypass** → initial access
- **Pre-auth reconnaissance** → target profiling
- **Data exfiltration** → VPN credentials + vendor banking details
- **Inbox rule creation** → email hiding
- **Power Automate automation** → persistent forwarding
- **BEC attack** → fraudulent payment redirection
- **Secondary compromise** → admin account also breached

### Hunt Methodology
**Hypothesis-driven, kill-chain focused:**
1. Start with alert → understand what triggered it
2. Pivot to authentication logs → find the breach moment
3. Follow the session → see what attacker did
4. Map persistence → find how they stayed in
5. Search for lateral movement → check for other compromises
6. Reconstruct intent → why did they do this?

---

## INITIAL ALERT CONTEXT

### Alert Details
| Field | Value |
|-------|-------|
| Alert ID | ad76cdddcd4de3a19d87770207112ccd0cb7c54ec6 |
| Incident ID | 87241 |
| Detection Type | Entra ID Identity Protection |
| Risk Event | Anonymous IP Address Sign-in |
| Flagged IP | 103.69.224.136 (Amsterdam, Noord-Holland, NL) |
| Risk Level | Informational (low-rated) |
| Alert Severity | Low |
| User ObjectId | fa5020a1-0d42-4839-bbfe-22db0861ced5 |
| Session GUID | 005d431a-380b-1f5e-e554-16d5010dc28e |

### Why It Was Low-Rated
The alert came in at "Informational" severity because:
- No malware detected
- No outage
- No known active threat
- Single sign-in from suspicious IP
- **BUT:** This was a false-negative. The "low rating" masked a critical compromise.

---

## VICTIM PROFILE

### Mark Smith (m.smith@lognpacific.org)
| Attribute | Value |
|-----------|-------|
| Email | m.smith@lognpacific.org |
| User ObjectId | fa5020a1-0d42-4839-bbfe-22db0861ced5 |
| Department | Finance |
| Role | Payment processor / Finance user |
| Org Position | Access to payment approval workflows |
| MFA Capable | Yes (but not enforced on legacy auth paths) |
| Risk State (pre-breach) | Low |
| Access Level | Finance approval authority |

### Secondary Compromise
| User | Compromise Time | Source IP | Access |
|------|---|---|---|
| mohammed_admin@lognpacific.com | 10:08-10:10 PM Jun 10 | 103.69.224.136 | Azure Portal, ADIbizaUX, Security Copilot |

**Significance:** Same source IP, same timeframe, indicates **broader admin compromise**: attacker was actively breaching multiple admin accounts.

---

## ATTACK PHASE BREAKDOWN

### PHASE 1: PRE-AUTH RECONNAISSANCE (10:08 PM - 10:13 PM)

**Objective:** Map targets, identify high-value users, profile security controls

#### Sub-Phase 1A: MFA Posture Profiling

**Graph API Calls from 103.69.224.136:**

```
Query: /beta/reports/authenticationMethods/userRegistrationDetails
Filter: userPrincipalName eq 'm.smith@lognpacific.org' and isMfaCapable eq true
Timestamp: 10:09:37 PM, 10:10:07 PM, 10:12:26 PM (3 calls)
Purpose: Check if m.smith has MFA registered
Result: YES: m.smith is MFA-capable but vulnerability: legacy auth paths don't enforce it
```

**KQL Query Used:**
```kusto
MicrosoftGraphActivityLogs
| where IPAddress == "103.69.224.136"
| where TimeGenerated >= datetime(2026-06-10T22:00:00Z) and TimeGenerated < datetime(2026-06-11T00:00:00Z)
| where RequestUri contains "reports"
| project TimeGenerated, IPAddress, RequestUri
| sort by TimeGenerated asc
```

**What This Tells Us:**
- Attacker conducting **passive reconnaissance** before active attacks
- They identified m.smith as a **valid target** (MFA-capable but potentially bypassable)
- They know how to use **Graph API authentication endpoints**: sophisticated threat actor

#### Sub-Phase 1B: Group Membership Enumeration

```
Query: /v1.0/users/fa5020a1-0d42-4839-bbfe-22db0861ced5/memberOf/microsoft.graph.group/$count
Purpose: Discover what security groups m.smith belongs to
Result: Learn about payment approval groups, finance teams, delegation chains
```

**Why This Matters:**
- Attacker wants to know: *Who can approve payments? What groups give access?*
- Part of **initial targeting**: understand organizational structure

#### Sub-Phase 1C: Secondary Admin Reconnaissance

```
User: mohammed_admin@lognpacific.com
Access: Azure Portal (login failures), ADIbizaUX, Security Copilot
Timestamp: Same window, same IP
Implication: Attacker probing MULTIPLE admin accounts from same IP
```

**Hypothesis at This Point:**
Attacker has a **list of valid usernames** (from external breach or OSINT) and is testing authentication paths. They found m.smith is MFA-capable but want to discover if legacy auth bypass is possible.

---

### PHASE 2: CREDENTIAL TESTING & INITIAL COMPROMISE (9:21 PM - 10:13 PM)

#### Sub-Phase 2A: Password Spray (Early Attempt)

```
Timestamp: Jun 10, 9:21:32 PM, 9:21:52 PM
User: m.smith@lognpacific.org
Client: Microsoft Office
Error: ErrorCode 50126 (Invalid password)
Action: Spray from unknown IP (possible earlier wave)
```

**Significance:**
- First attempt from **different IP** than 103.69.224.136
- Suggests **multi-wave attack**: first spray fails, pause, second wave from fresh IP
- Attacker waiting for lockout to expire or trying different credential source

#### Sub-Phase 2B: Second Wave - Legacy Auth Bypass (10:13 PM)

```
Timestamp: Jun 10, 10:13:10 PM (22:13:10 in 24-hour format)
User: m.smith@lognpacific.org
Source IP: 103.69.224.136
Client: One Outlook Web (legacy OAuth client)
Authentication Requirement: singleFactorAuthentication
MFA Satisfied: NO
ErrorCode: 0 (SUCCESS)
Result Type: Success
Session Token Issued: 005d431a-380b-1f5e-e554-16d5010dc28e
```

**The Critical Moment:**
This is **the breach**. The attacker obtained a valid **refresh token** that will be reused for 583+ subsequent sign-ins.

**Why This Succeeded (Root Cause):**
1. **Legacy OAuth client** (One Outlook Web) is NOT subject to modern Conditional Access policies
2. **Security Defaults** enforce MFA, but only on *modern* auth flows
3. Legacy clients have an **exempt authentication path**: they only require password
4. Attacker exploited this **legacy authentication gap**

**KQL Query to Find This:**
```kusto
SigninLogs
| where UserPrincipalName == "m.smith@lognpacific.org"
| where ResultType == 0
| where IPAddress == "103.69.224.136"
| where TimeGenerated >= datetime(2026-06-10T22:00:00Z) and TimeGenerated < datetime(2026-06-11T00:00:00Z)
| where AppDisplayName == "One Outlook Web"
| project TimeGenerated, AuthenticationRequirement, ClientAppId, CorrelationId
```

**Critical Detail:** `AuthenticationRequirement == "singleFactorAuthentication"`: this is the smoking gun.

---

### PHASE 3: SESSION EXPLOITATION & DATA EXFILTRATION (10:13 PM - 10:42 PM)

#### Sub-Phase 3A: OneDrive File Access & Exfiltration

**Timeline:**
```
10:35:11 PM: PageViewed: OneDrive file browser
10:37:20 PM: FileAccessed: Documents folder (2x)
10:37:20 PM: ListViewed: Folder listings
10:37:22 PM: FileDownloaded: VPN-Access-Credentials.txt
10:37:22 PM: FileDownloaded: Vendor-Banking-Details.txt
10:37:23 PM: FileDownloaded: Book.xlsx
```

**CloudAppEvents Query:**
```kusto
CloudAppEvents
| where AccountObjectId == "fa5020a1-0d42-4839-bbfe-22db0861ced5"
| where Timestamp >= datetime(2026-06-10T22:13:10Z) and Timestamp < datetime(2026-06-11T13:00:00Z)
| where ActionType == "FileDownloaded"
| project Timestamp, ActionType, ObjectName
| sort by Timestamp asc
```

**Files Exfiltrated:**

1. **VPN-Access-Credentials.txt**
   - Content: VPN authentication tokens, server addresses, pre-shared keys
   - Significance: **CRITICAL**: gives attacker access to internal network
   - Implication: On-premises compromise is now possible
   - Threat level: Escalates from cloud-only to hybrid infrastructure attack

2. **Vendor-Banking-Details.txt**
   - Content: Vendor account numbers, payment routing information, bank details
   - Significance: **INTELLIGENCE FOR BEC**: attacker learns how payments are structured
   - Use: Craft convincing fraudulent payment request to CFO
   - Timing: Downloaded right before 11:13 PM BEC email

3. **Book.xlsx**
   - Content: Unknown (possibly financial records, payment history, or contact list)
   - Significance: Potential additional leverage or intelligence

**Why This Exfiltration Matters:**
- Attacker went from **opportunistic access** to **targeted intelligence gathering**
- Downloaded files **within 1 minute** (10:37:22-10:37:23): coordinated, not exploratory
- Selected files **by name**: knew where to look (pre-recon paid off)

---

#### Sub-Phase 3B: Inbox Rule Creation (Persistence & Hiding)

**Rule #1: "Invoice Processing"**
```
Created: Jun 10, 10:28:22 PM
Trigger: FROM: j.reynolds@lognpacific.org
Action: MoveToFolder = Archive
StopProcessingRules = True
Purpose: Hide replies from CFO about fraudulent payment request
Effect: Any email from j.reynolds goes to Archive folder automatically
```

**Rule #2: "Backup Copy"**
```
Created: Jun 10, 10:32:31 PM
Details: Unknown (partially captured in logs)
Likely Purpose: Additional email hiding/archiving
```

**OfficeActivity Query:**
```kusto
OfficeActivity
| where UserId == "m.smith@lognpacific.org"
| where TimeGenerated >= datetime(2026-06-10T22:13:10Z) and TimeGenerated < datetime(2026-06-11T13:00:00Z)
| where Operation == "New-InboxRule"
| project TimeGenerated, Operation, Item
| sort by TimeGenerated asc
```

**Strategic Significance:**
- Attacker preparing the **cover-up** before the attack
- Rule targets **exactly the CFO** who will receive the fraudulent request
- **Brilliant social engineering:** CFO's corrections/warnings hidden by automated rule
- Attacker understands **email workflow**: knows replies will come

---

### PHASE 4: AUTOMATION & PERSISTENCE SETUP (10:38 PM - 11:05 PM)

#### Sub-Phase 4A: Power Automate Flow Creation

```
Timestamp: Jun 10, 11:05:05 PM
Action: CreateFlow
Flow Name: (Not captured in logs, but executes at 7:41 AM Jun 11)
Service: Microsoft Power Automate
Service Principal: 7ab7862c-4c57-491e-8a45-d52a7e023983
Function: Automated mail forwarding
```

**CloudAppEvents Query:**
```kusto
CloudAppEvents
| where AccountObjectId == "fa5020a1-0d42-4839-bbfe-22db0861ced5"
| where ActionType == "CreateFlow"
| where Timestamp >= datetime(2026-06-10T22:00:00Z) and Timestamp < datetime(2026-06-11T13:00:00Z)
| project Timestamp, ActionType, ObjectName
```

**What This Flow Does:**
- Configured to automatically **forward emails** from m.smith's mailbox
- Executes **without user interaction**: runs as a scheduled automation
- Service Principal **7ab7862c-4c57-491e-8a45-d52a7e023983** = Power Automate application identity
- Target: Send copies to attacker's exfil email (merovingian1337@proton.me)

**Why Create This Flow?**
- **Persistent access** after attacker logs off
- **Captures all future emails**: payment approvals, internal discussions, credential resets
- **Survives password reset**: flow still runs with service principal
- **Defeats MFA**: no authentication needed; runs programmatically

---

### PHASE 5: BUSINESS EMAIL COMPROMISE (11:13 PM - 11:17 PM)

#### Sub-Phase 5A: Primary Fraudulent Email

```
Timestamp: Jun 10, 11:13:44 PM
Source IP: 103.69.224.136 (attacker's IP)
Client: One Outlook Web
From: m.smith@lognpacific.org
To: j.reynolds@lognpacific.org (CFO)
Subject: Updated Banking Details - Pacific IT Monthly
Content: Fraudulent request to update payment routing
Size: 7,447 bytes
```

**OfficeActivity Query:**
```kusto
OfficeActivity
| where UserId == "m.smith@lognpacific.org"
| where TimeGenerated >= datetime(2026-06-10T22:13:10Z) and TimeGenerated < datetime(2026-06-11T13:00:00Z)
| where Operation == "Send"
| where OfficeWorkload == "Exchange"
| project TimeGenerated, Operation, Item
| sort by TimeGenerated asc
```

**Why This Email Works:**
1. **Sender = m.smith** (trusted finance colleague): not external/suspicious
2. **Recipient = j.reynolds** (CFO): decision maker who approves payments
3. **Subject = Banking Details**: vague, plausible, matches exfiltrated file ("Vendor-Banking-Details.txt")
4. **Content = Professional**: attacker crafted it to look like internal communication
5. **Timing = Right context**: sent 4 minutes after vendor banking details were reviewed
6. **Inbox rule already set**: j.reynolds' replies will be auto-archived (hidden from m.smith)

**Email Subject Line:**
```
"Updated Banking Details - Pacific IT Monthly"
```

#### Sub-Phase 5B: Multi-Channel Reinforcement via Teams

```
Timestamp: Jun 10, 11:17:56 PM (4 min after email)
Action: MessageSent
Channel: Microsoft Teams
From: m.smith (attacker-controlled session)
To: j.reynolds (CFO)
Purpose: Reinforce urgent payment change request
Effect: Increase credibility through multiple channels
```

**CloudAppEvents Query:**
```kusto
CloudAppEvents
| where AccountObjectId == "fa5020a1-0d42-4839-bbfe-22db0861ced5"
| where ActionType == "MessageSent"
| where Timestamp >= datetime(2026-06-10T22:13:10Z) and Timestamp < datetime(2026-06-11T13:00:00Z)
| project Timestamp, ActionType
```

**Attacker's Logic:**
- Email alone might be ignored or questioned
- Teams message **same user, 4 minutes later** creates **false sense of legitimacy**
- Two channels = higher perceived urgency
- "Follow up on email I just sent" tactic

---

### PHASE 6: AUTOMATED EXFILTRATION & PERSISTENCE (7:41 AM JUN 11)

#### Sub-Phase 6A: Power Automate Flow Executes

```
Timestamp: Jun 11, 7:41:09 AM (9+ hours after initial breach)
Action: Programmatic mail forward via Graph API
Endpoint: POST /v1.0/me/messages/{message-id}/forward
Response Code: 202 (Accepted)
Source IP: 20.150.129.194 (Office 365 infrastructure)
Service Principal: Power Automate (7ab7862c-4c57-491e-8a45-d52a7e023983)
```

**MicrosoftGraphActivityLogs Query:**
```kusto
MicrosoftGraphActivityLogs
| where TimeGenerated >= datetime(2026-06-10T22:00:00Z) and TimeGenerated < datetime(2026-06-11T14:00:00Z)
| where RequestUri contains "forward"
| project TimeGenerated, RequestUri, ResponseStatusCode, IPAddress
| sort by TimeGenerated asc
```

**Critical Details:**

1. **Source IP = 20.150.129.194** (Microsoft Office 365 datacenter, NOT attacker IP)
   - Attacker doesn't need to be logged in
   - Automation runs from cloud infrastructure
   - Normal user can't distinguish from legitimate mail operations

2. **Service Principal = Power Automate**
   - Identified by AppId: 7ab7862c-4c57-491e-8a45-d52a7e023983
   - Legitimate Microsoft service
   - But being **abused for persistence**

3. **Response Code = 202 (Accepted)**
   - Forward operation succeeded
   - All emails to m.smith now forwarded to attacker

#### Sub-Phase 6B: Secondary Email (Exfiltration Confirm)

```
Timestamp: Jun 11, 7:41:09 AM (same moment as forward)
From: m.smith@lognpacific.org
To: merovingian1337@proton.me (attacker's external email)
Subject: FW: Updated Banking Details - Pacific IT Monthly
Size: 10,883 bytes
Client IP: 20.190.190.224 (different from attacker's initial IP)
Purpose: Attacker confirms forward is working, captures email copy
```

**OfficeActivity Query:**
```kusto
OfficeActivity
| where UserId == "m.smith@lognpacific.org"
| where TimeGenerated >= datetime(2026-06-11T07:40:00Z) and TimeGenerated < datetime(2026-06-11T07:42:00Z)
| where Operation == "Send"
| project TimeGenerated, ClientIP, Parameters
```

**Evidence of Layering:**
- Multiple IPs involved:
  - **103.69.224.136** = initial attacker IP
  - **20.150.129.194** = Office 365 service (forward execution)
  - **20.190.190.224** = secondary exfil email IP
- Attacker testing **multiple infrastructure paths** for persistence

---

## SCHEMA & TABLE DISCOVERY

### Key Learning: Schema Precision is Critical

Throughout this hunt, correct column names were essential. **One wrong column name = silent query failure.**

#### Tables Used & Their Quirks

| Table | Platform | Key IP Column | User Column | Time Column | Notes |
|-------|----------|---|---|---|---|
| SigninLogs | Sentinel | IPAddress | UserPrincipalName | TimeGenerated | Most complete sign-in data |
| AADSignInEventsBeta | Sentinel | IPAddress | AccountUpn | TimeGenerated | Similar to SigninLogs, beta |
| EntraIdSignInEvents | Sentinel | IPAddress | (AccountName?) | Timestamp | Defender XDR table |
| IdentityLogonEvents | Sentinel | IPAddress | AccountName | TimeGenerated | Account-level logons |
| CloudAppEvents | Sentinel | IPAddress | AccountObjectId | Timestamp | Critical for file/flow operations |
| OfficeActivity | Sentinel | ClientIP | UserId | TimeGenerated | Exchange, Teams, SharePoint |
| MicrosoftGraphActivityLogs | Sentinel | IPAddress | (embedded in RequestUri) | TimeGenerated | Graph API calls |
| EmailEvents | Sentinel | (none directly) | (complex) | Timestamp | Email send/receive records |
| AuditLogs | Sentinel | (NO IP FIELD) | (varies) | TimeGenerated | Directory changes only |
| BehaviorAnalytics | Sentinel | IPAddress | (varies) | TimeGenerated | UEBA anomaly scores |

### Lessons on Column Naming Inconsistencies

```
Same thing, different names:
- IPAddress vs IpAddress vs ClientIP vs SourceIP
- UserPrincipalName vs AccountUpn vs AccountName vs UserId
- Timestamp vs TimeGenerated (Defender XDR vs Sentinel convention)
```

**Best Practice:** Always run `TableName | take 1` or `TableName | getschema` before querying.

---

## QUERY PATTERNS & KQL TECHNIQUES

### Pattern 1: Multi-Source Pivot (Finding the Attacker)

**Goal:** Find everything the IP 103.69.224.136 did

**Approach:** Query each table separately (union fails due to schema differences)

```kusto
// SigninLogs
SigninLogs
| where IPAddress == "103.69.224.136"
| where TimeGenerated >= datetime(2026-06-10T22:13:10Z) and TimeGenerated < datetime(2026-06-11T13:00:00Z)
| project TimeGenerated, AppDisplayName, ResultType, AuthenticationRequirement
| sort by TimeGenerated asc

// CloudAppEvents
CloudAppEvents
| where IPAddress == "103.69.224.136"
| where Timestamp >= datetime(2026-06-10T22:13:10Z) and Timestamp < datetime(2026-06-11T13:00:00Z)
| project Timestamp, ActionType, ObjectName
| sort by Timestamp asc

// OfficeActivity
OfficeActivity
| where ClientIP == "103.69.224.136"
| where TimeGenerated >= datetime(2026-06-10T22:13:10Z) and TimeGenerated < datetime(2026-06-11T13:00:00Z)
| project TimeGenerated, Operation, Item
| sort by TimeGenerated asc
```

**Why Separate Queries?**
- Column names differ by table
- Union operator tries to use ALL columns from ALL tables
- Causes "Failed to resolve column" errors
- Safer to query individually, then mentally merge timeline

---

### Pattern 2: Authentication Requirement Analysis (Finding the Bypass)

**Goal:** Prove attacker didn't satisfy MFA, despite session requiring "multiFactorAuthentication"

```kusto
SigninLogs
| where UserPrincipalName == "m.smith@lognpacific.org"
| where TimeGenerated >= datetime(2026-06-10T22:13:10Z) and TimeGenerated < datetime(2026-06-11T13:00:00Z)
| where ResultType == 0  // Successful logins only
| summarize 
    Total = count(),
    MFARequired = countif(AuthenticationRequirement == "multiFactorAuthentication"),
    SingleFactor = countif(AuthenticationRequirement == "singleFactorAuthentication")
| project Total, MFARequired, SingleFactor
```

**Key Insight:**
- MFARequired (318) + SingleFactor (265) = 583 total
- But **MFA never actually satisfied**
- Session token from 10:13:10 PM reused for all 583 sign-ins
- Password reset alone **won't** kill this token

---

### Pattern 3: Distinct Value Counting (App Access)

**Goal:** How many different apps did the attacker access?

```kusto
SigninLogs
| where UserPrincipalName == "m.smith@lognpacific.org"
| where IPAddress == "103.69.224.136"
| where TimeGenerated >= datetime(2026-06-10T22:13:10Z) and TimeGenerated < datetime(2026-06-11T13:00:00Z)
| where ResultType == 0
| summarize DistinctApps = dcount(AppDisplayName)

Result: 7 distinct apps
```

**Apps Identified:**
1. One Outlook Web
2. Microsoft Office
3. Microsoft Teams Services
4. Microsoft Teams Web Client
5. Azure Portal
6. Microsoft Flow Portal
7. (Graph API / implicit)

---

### Pattern 4: File Operation Distinction (Read vs. Copy)

**Goal:** Separate normal file access from exfiltration

```kusto
// Normal activity: FileAccessed
CloudAppEvents
| where AccountObjectId == "fa5020a1-0d42-4839-bbfe-22db0861ced5"
| where ActionType == "FileAccessed"
| summarize count()
// Result: Many (baseline reading behavior)

// Exfiltration: FileDownloaded
CloudAppEvents
| where AccountObjectId == "fa5020a1-0d42-4839-bbfe-22db0861ced5"
| where ActionType == "FileDownloaded"
| where Timestamp >= datetime(2026-06-10T22:13:10Z) and Timestamp < datetime(2026-06-11T13:00:00Z)
| summarize count()
// Result: 3 (targeted exfil)
```

**Critical Lesson:**
- **FileAccessed** = opened file in place (user's normal job)
- **FileDownloaded** = copied file out (exfiltration)
- These are **functionally different** despite both being file operations

---

### Pattern 5: JSON Parsing for Nested Data

**Goal:** Extract structured data from OfficeActivity Item field

```kusto
OfficeActivity
| where UserId == "m.smith@lognpacific.org"
| where Operation == "Send"
| where TimeGenerated >= datetime(2026-06-10T22:13:10Z) and TimeGenerated < datetime(2026-06-11T13:00:00Z)
| extend ItemData = parse_json(Item)
| project 
    TimeGenerated,
    Subject = tostring(ItemData.Subject),
    Recipients = tostring(ItemData.Recipients),
    SizeInBytes = tostring(ItemData.SizeInBytes)
```

**Why Needed:**
- Item field is JSON string, not structured columns
- Can't access `.Subject` directly
- Must parse_json() first, then extract fields
- Common mistake: forgetting parse_json() causes "null" results

---

## ATTACK TIMELINE (DETAILED)

### June 10, 2026 Timeline

| Time | UTC | Event | Evidence | Significance |
|------|-----|-------|----------|---|
| 21:21:32 | 2:21 AM+1 | Password spray attempt #1 | SigninLogs ErrorCode 50126 | Early wave, may be different attacker or prep from hours earlier |
| 21:21:52 | 2:21 AM+1 | Password spray attempt #2 | SigninLogs ErrorCode 50126 | Second failed attempt same minute |
| 22:08:00 | 03:08 AM+1 | Secondary admin recon begins | Mohammed_admin access starts | Multi-account targeting |
| 22:09:37 | 03:09 AM+1 | MFA posture profiling #1 | MicrosoftGraphActivityLogs userRegistrationDetails | Attacker discovers m.smith is MFA-capable |
| 22:10:07 | 03:10 AM+1 | MFA posture profiling #2 | MicrosoftGraphActivityLogs (repeated call) | Confirmation/retesting |
| 22:12:26 | 03:12 AM+1 | MFA posture profiling #3 | MicrosoftGraphActivityLogs (3rd call) | Final probe |
| 22:13:10 | **03:13 AM+1** | **BREACH MOMENT** | **SigninLogs ResultType=0, One Outlook Web, singleFactorAuthentication** | **Initial compromise, session token issued** |
| 22:13:30 | 03:13 AM+1 | Session established | SigninLogs correlation ID | Attacker now has valid token |
| 22:28:22 | 03:28 AM+1 | Inbox rule "Invoice Processing" created | OfficeActivity New-InboxRule | Cover-up: auto-archive j.reynolds emails |
| 22:32:31 | 03:32 AM+1 | Inbox rule "Backup Copy" created | OfficeActivity New-InboxRule | Additional hiding mechanism |
| 22:35:11 | 03:35 AM+1 | OneDrive page viewed | CloudAppEvents PageViewed | Attacker browses file system |
| 22:37:20 | 03:37 AM+1 | Documents folder accessed | CloudAppEvents FileAccessed | Reconnaissance of available files |
| 22:37:22 | 03:37 AM+1 | **VPN credentials exfiltrated** | CloudAppEvents FileDownloaded | **Critical: On-prem access compromised** |
| 22:37:22 | 03:37 AM+1 | **Vendor banking details exfiltrated** | CloudAppEvents FileDownloaded | **Critical: BEC intelligence gathered** |
| 22:37:23 | 03:37 AM+1 | **Spreadsheet exfiltrated** | CloudAppEvents FileDownloaded | **Additional data theft** |
| 22:38:44 | 03:38 AM+1 | Sign-in event recorded | CloudAppEvents SignInEvent | Token reuse begins |
| 22:41:36 | 03:41 AM+1 | Sharing inheritance broken | CloudAppEvents "Broke sharing inheritance" | Attacker modifying permissions |
| 22:42:37 | 03:42 AM+1 | Folder created | CloudAppEvents FolderCreated | Infrastructure setup |
| 23:05:05 | 04:05 AM+1 | **Power Automate flow created** | CloudAppEvents CreateFlow | **Persistence mechanism established** |
| 23:13:44 | **04:13 AM+1** | **BEC EMAIL SENT** | **OfficeActivity Send, To: j.reynolds@lognpacific.org, Subject: "Updated Banking Details"** | **Primary attack launches** |
| 23:17:56 | 04:17 AM+1 | **Teams follow-up sent** | CloudAppEvents MessageSent | **Multi-channel social engineering** |
| 23:18:27 | 04:18 AM+1 | Secondary authentication | (AppAccessContext recorded) | Session token remains valid |

### June 11, 2026 Timeline

| Time | UTC | Event | Evidence | Significance |
|------|-----|-------|----------|---|
| 06:14:23 AM | 11:14 AM+1 | MailItemsAccessed | CloudAppEvents MailItemsAccessed | Attacker mailbox access continues |
| 07:41:09 AM | **12:41 PM+1** | **AUTOMATED FORWARD EXECUTES** | **MicrosoftGraphActivityLogs forward API, ResponseCode 202, Source IP 20.150.129.194** | **Persistence activated, mail forwarding to attacker begins** |
| 07:41:09 AM | **12:41 PM+1** | **EXFIL EMAIL SENT** | **OfficeActivity Send, To: merovingian1337@proton.me** | **Attacker confirms forward, captures email copy** |
| 07:42-07:43 AM | 12:42-12:43 PM+1 | Continued mailbox access | MailItemsAccessed | Attacker monitoring mailbox |

---

## THREAT ACTOR TTPs

### MITRE ATT&CK Framework Mapping

**Reconnaissance Phase:**
- **T1598.003**: Phishing: Spearphishing Link (external breach led to this user/password)
- **T1592.003**: Gather Victim Org Info: Identify roles, departments (graph API enumeration)
- **T1087.004**: Account Discovery: Cloud Account (group/org enumeration via Graph)
- **T1526**: Cloud Service Discovery (Azure Portal, Security Copilot access attempts)

**Weaponization & Initial Access:**
- **T1110.004**: Brute Force: Credential Stuffing (password spray with leaked credentials)
- **T1078.004**: Valid Accounts: Cloud Accounts (obtained valid m.smith credentials)

**Exploitation & Privilege Escalation:**
- **T1621**: Multi-Factor Authentication Interception or Bypass (legacy auth gap)
- **T1550.001**: Use Alternate Authentication Material: Application Access Token (session token reuse)

**Defense Evasion:**
- **T1535**: Unused/Unsupported Cloud Regions (attempted Azure Portal, may be testing geo-restrictions)
- **T1207**: Rogue Domain Controller (not applicable here)
- **T1114.002**: Email Collection: Remote Email Collection (via inbox rules)

**Persistence:**
- **T1098.001**: Account Manipulation: Additional Cloud Credentials (created inbox rules, flow)
- **T1136.003**: Create Account: Cloud Account (created Power Automate flow as persistence)
- **T1547.014**: Boot or Logon Autostart Execution: Emond (Power Automate flow auto-runs)

**Collection:**
- **T1114.002**: Email Collection: Remote Email Collection (mail forwarding rule)
- **T1530**: Data from Cloud Storage (exfiltrated OneDrive files)
- **T1537**: Transfer Data to Cloud Account (forwarded emails to external email)

**Exfiltration:**
- **T1020.001**: Automated Exfiltration: Traffic Duplication (Power Automate mail forwarding)
- **T1537**: Transfer Data to Cloud Account (emails to merovingian1337@proton.me)

**Impact:**
- **T1566.002**: Phishing: Spearphishing Link (BEC attack on CFO)
- **T1586.003**: Compromise Accounts: Cloud Accounts (m.smith compromise impacts org)

---

## FORENSIC EVIDENCE

### Session Token Analysis

**Session ID:** 005d431a-380b-1f5e-e554-16d5010dc28e

**Token Characteristics:**
```
Issued: Jun 10, 2026, 22:13:10 CDT (Jun 11, 03:13:10 UTC)
Issued By: One Outlook Web (legacy OAuth client)
Auth Level: singleFactorAuthentication
Refresh Token Lifetime: 90 days (default)
Expiration: ~Sep 8, 2026 (if not revoked)
Reuse Count: 583+ sign-ins
Reuse Window: 9+ hours
```

**Why This Token Is Dangerous:**
1. **Issued without MFA**: attacker didn't have to satisfy MFA
2. **Valid for 90 days**: persists even after password reset
3. **Reusable across apps**: works for Email, Teams, SharePoint, Graph API
4. **No re-authentication**: doesn't require MFA prompt for subsequent operations
5. **Can't be killed by password reset**: requires explicit session revocation

**Remediation Sequence:**
```
Step 1: REVOKE refresh token (Session > Sign out all)
Step 2: VERIFY token invalidated (attempt sign-in with old token = fail)
Step 3: RESET password (now no old token can get new token)
Step 4: FORCE re-authentication (user logs in with new password)
```

---

### Data Exfiltration Analysis

**Files Stolen:**

1. **VPN-Access-Credentials.txt**
   - Estimated Size: ~5-10 KB
   - Contents: Likely VPN certificate, pre-shared keys, VPN gateway addresses
   - Impact: **CRITICAL**: On-premises access compromised
   - Risk: Attacker can now reach internal servers, databases, file shares

2. **Vendor-Banking-Details.txt**
   - Estimated Size: ~2-3 KB
   - Contents: Vendor account numbers, bank routing, payment instructions
   - Impact: **CRITICAL**: Intelligence for fraudulent payment
   - Timing: Downloaded 36 minutes before BEC email sent (time to craft payload)

3. **Book.xlsx**
   - Estimated Size: ~50-100 KB (typical spreadsheet)
   - Contents: Unknown (possibly financial records, payment history, internal contacts)
   - Impact: **HIGH**: Additional leverage or intelligence

**Exfiltration Method:** Direct download via Outlook Web interface (OneDrive sync)
**Detection Opportunity:** CloudAppEvents FileDownloaded is the ONLY way to detect this (not FileAccessed)

---

### Email Rule Analysis

**Rule #1: "Invoice Processing"**

```
Properties:
  Name: Invoice Processing
  Enabled: True
  Conditions:
    - FROM: j.reynolds@lognpacific.org
  Actions:
    - MoveToFolder: Archive
    - StopProcessingRules: True
  Created: Jun 10, 22:28:22 CDT (Jun 11, 03:28:22 UTC)
  Created By: m.smith (attacker session)
```

**Impact:**
- All emails from CFO → Archive automatically
- CFO's warnings/corrections never seen by m.smith
- Even if CFO says "That's not our vendor!" → hidden
- **Perfect cover-up mechanism**

**Detection:** OfficeActivity Operation == "New-InboxRule"
**Remediation:** Delete rule + check Archive folder for suppressed emails

---

### Power Automate Flow Analysis

**Flow Properties:**
```
Service Principal: 7ab7862c-4c57-491e-8a45-d52a7e023983 (Power Automate)
Flow Type: Cloud Flow (automated)
Trigger: (Unknown, possibly time-based or event-based)
Action: Forward email to external recipient
Target Email: merovingian1337@proton.me
Execution Time: 7:41:09 AM Jun 11
Response Status: 202 (Accepted)
```

**Why This Is Dangerous:**
1. **Runs without user logged in**: doesn't require attacker presence
2. **Service principal execute**: Cloud infrastructure sends emails
3. **Difficult to detect**: not a user action, hard to audit
4. **Survives password reset**: token is service principal, not user token
5. **Persistent**: continues forwarding all future emails indefinitely

**Detection:** CloudAppEvents CreateFlow, MicrosoftGraphActivityLogs forward API call
**Remediation:** Delete flow in Power Automate Admin Center BEFORE resetting password

---

## CONTAINMENT SEQUENCING

### Critical: Why Order Matters

**WRONG ORDER → Attacker Stays In**
```
1. Reset password ❌
2. Delete rules ❌ (already reset, attacker can't log in, rules persist)
3. Delete flow ❌ (already deleted password, can't get rid of flow)

Result: Flow still forwarding emails!
```

**CORRECT ORDER → Complete Removal**
```
1. Revoke all sessions ✓ (sign out all devices)
   Command: Azure AD > Users > m.smith > Sign-out all sessions
   Effect: Invalidate all refresh tokens immediately
   
2. Delete Power Automate flow ✓ (automation stops)
   Location: Power Automate Admin Center
   Effect: No more automated forwarding
   
3. Delete inbox rules ✓ (remove hiding)
   Locations: Outlook > Rules > Delete "Invoice Processing", "Backup Copy"
   Effect: Restore visibility to CFO emails
   
4. Reset password ✓ (last step)
   Location: Azure AD > Reset Password
   Effect: Attacker can't log in with old password
   Note: Won't affect existing sessions (already revoked), won't affect flows (already deleted)
```

### Why Revoke Sessions FIRST?

**Session Token = Attacker's Key**
- Valid for 90 days from June 10 = until ~Sept 8
- **Password reset doesn't revoke it**
- Attacker can still use token even after password changed
- Only way to kill it: explicit session revocation

**Example Timeline:**
```
22:13:10 PM Jun 10: Session token issued (refresh token valid 90 days)
Jul 1: Admin resets m.smith password (attacker still has token!)
Jul 2: Attacker uses old token → still works
Jul 15: Attacker obtains new refresh token using old token
Aug 1: Password is now old news; attacker still has multiple tokens

vs.

Jun 11: Admin revokes all sessions (refresh token NOW INVALID)
Jun 11: Password reset (redundant, but complete)
Jun 11: Attacker tries old token → rejected
Result: Attacker completely locked out
```

---

## LESSONS LEARNED

### Skill Gaps Revealed in This Hunt

1. **KQL Schema Precision**
   - **Gap:** Assuming column names are consistent across tables
   - **Reality:** IPAddress, IpAddress, ClientIP, SourceIP: same concept, different names
   - **Fix:** ALWAYS run `TableName | take 1` before querying
   - **Drill:** Practice schema exploration on unknown tables

2. **Legacy Authentication Paths**
   - **Gap:** Didn't understand why MFA wasn't enforced on One Outlook Web
   - **Reality:** Modern Conditional Access exempts legacy OAuth clients for backward compatibility
   - **Fix:** Learn CA policy exemptions; understand legacy protocol support
   - **Drill:** Document which clients are "legacy" and why policies exempt them

3. **Session Token Lifetime**
   - **Gap:** Didn't initially realize refresh tokens survive password reset
   - **Reality:** Entra ID keeps refresh tokens valid for 90 days; only explicit revocation kills them
   - **Fix:** Session revocation MUST come before password reset
   - **Drill:** Test password reset + session reuse in lab environment

4. **Multi-Source Pivoting**
   - **Gap:** Tried to union tables with different schemas
   - **Reality:** Union requires compatible schemas; must query separately
   - **Fix:** Query each table individually, merge results mentally
   - **Drill:** Practice building multi-table timelines without union

5. **Persistence Mechanism Understanding**
   - **Gap:** Didn't immediately recognize Power Automate as persistence risk
   - **Reality:** Flows run as service principals, exempt from user-based controls
   - **Fix:** Recognize automation platforms (Power Automate, Logic Apps, Functions) as persistence vectors
   - **Drill:** Study how each automation platform's execution model impacts incident response

6. **JSON Parsing in KQL**
   - **Gap:** Didn't know how to extract data from Item field in OfficeActivity
   - **Reality:** Requires parse_json() before accessing nested properties
   - **Fix:** Always identify JSON fields; parse before projecting
   - **Drill:** Practice extracting data from common JSON fields (Item, Parameters, AdditionalFields)

### KQL Instinct Gaps

1. **Over-reliance on assumptions**
   - Assumed column names would be discoverable
   - **Fix:** Build queries incrementally; test each clause

2. **Not filtering early enough**
   - Queries returned too much data
   - **Fix:** Add time, user, IP filters before exploring

3. **Not documenting failed queries**
   - When a query failed, didn't save the error for learning
   - **Fix:** Keep a "query troubleshooting log"

4. **Underutilizing distinct/summarize**
   - Could have counted more efficiently
   - **Fix:** Master distinct, countif, summarize patterns

### Methodology Misses

1. **Not scoping by device first**
   - Started with workspace-wide queries
   - **Fix:** Pivot to device/IP scope early to reduce noise

2. **Not asking "why" questions**
   - Found facts but didn't explain mechanisms
   - **Fix:** For each finding, explain root cause

3. **Skipping the "what else?" pivot**
   - Completed questions instead of pursuing threads
   - **Fix:** After each finding, ask: what else did this IP do? What other users?

### Control Gaps Revealed

| Control | Why It Failed | Impact |
|---------|---|---|
| Conditional Access | Legacy auth paths exempt | Single-factor sign-in allowed |
| MFA Enforcement | Not applied to legacy clients | No MFA prompt or check |
| Session Timeout | 90-day default | Token valid for months |
| Email Rule Auditing | No alerts on rule creation | Attacker rules went unnoticed |
| Power Automate Approval | Not required for mail flows | Attacker could create persistence |
| Anomalous Login Detection | UEBA not sensitive enough | Credential stuffing not flagged |
| Activity Logging | No real-time alerts on Graph API abuse | Recon queries not caught |

---

## HUNT STATISTICS

### Coverage
- **Incident Window:** 9 hours (Jun 10, 10 PM: Jun 11, 7 AM)
- **Investigation Scope:** 10 days (Jun 10-20)
- **Log Sources Queried:** 8 tables (SigninLogs, CloudAppEvents, OfficeActivity, MicrosoftGraphActivityLogs, EmailEvents, IdentityLogonEvents, BehaviorAnalytics, AuditLogs)
- **Flags Answered:** 37 questions

### Activity Volume
- **Total Sign-ins from Attacker IP:** 583
- **Distinct Applications Accessed:** 7
- **Files Exfiltrated:** 3
- **Inbox Rules Created:** 2
- **Power Automate Flows Created:** 1
- **BEC Email Sent To:** 1 target (CFO)
- **Days of Access After Initial Compromise:** 1 day (automation continued)

### Evidence Density
- **Attacker IP in Log Sources:** 7 of 8 tables
- **Session Token Reuse Count:** 583+
- **Time Between Initial Access & BEC Attack:** 1 hour
- **Time Between BEC Attack & Automated Exfiltration:** 8 hours

---

## RECOMMENDED READING & REFERENCES

### Microsoft Documentation
- [Revoke user access in an emergency in Microsoft Entra ID](https://learn.microsoft.com/en-us/entra/identity/users/users-revoke-access)
- [Conditional Access: Legacy Authentication](https://learn.microsoft.com/en-us/entra/identity/conditional-access/block-legacy-authentication)
- [Microsoft Graph API: Mail Forwarding](https://learn.microsoft.com/en-us/graph/api/message-createforward)
- [Power Automate Security Best Practices](https://learn.microsoft.com/en-us/power-automate/security)

### MITRE ATT&CK
- [T1078.004: Valid Accounts: Cloud Accounts](https://attack.mitre.org/techniques/T1078/004/)
- [T1110.004: Brute Force: Credential Stuffing](https://attack.mitre.org/techniques/T1110/004/)
- [T1114.002: Email Collection: Remote Email Collection](https://attack.mitre.org/techniques/T1114/002/)
- [T1537: Transfer Data to Cloud Account](https://attack.mitre.org/techniques/T1537/)

### Threat Intelligence
- [Octo Tempest: Microsoft Threat Intelligence Profile](https://learn.microsoft.com/en-us/security/threat-intelligence)

---

## CONCLUSION

This hunt demonstrated a complete, multi-stage cloud compromise attack exploiting:
1. Credential stuffing from external breach
2. Legacy authentication gaps (bypass Conditional Access)
3. Session token reuse (no MFA needed)
4. Pre-auth reconnaissance (Graph API enumeration)
5. Targeted data exfiltration (VPN + banking details)
6. Persistence via automation (Power Automate)
7. BEC attack (fraudulent payment redirection)
8. Cover-up mechanisms (inbox rules hiding replies)

**Key Takeaway:** Modern cloud attacks move fast. The attacker achieved their objective (fraudulent payment redirection) within 4 hours. Immediate detection and response are critical.

**Skills Developed:**
- Schema discovery in unfamiliar tables
- Multi-source pivoting and correlation
- Session token analysis
- Persistence mechanism identification
- Kill-chain reconstruction
- Incident response sequencing

---

**Hunt Completed:** June 25, 2026  
**Time Spent:** ~8 hours  
**Flags Solved:** 30+ of 37  
**Quality:** Comprehensive, detailed, methodical

