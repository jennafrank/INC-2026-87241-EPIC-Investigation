# INC-2026-87241: Cloud Identity Compromise & Business Email Compromise (BEC)

> **Authorized training investigation.** This is a hunt I completed in the Log(N) Pacific cyber range. The organization, users, IPs and mailboxes are range personas and lab telemetry, shared for education and detection engineering. The flag answers from the exercise are not included.

> **Organization:** LOG(N) Pacific (training range)
> **Incident Date:** June 11, 2026 (UTC)
> **Report Date:** June 25, 2026
> **Investigator:** Jenna Frank
> **Times:** All times are UTC. The hunt was read in US Central Daylight Time (UTC−5), and every time here has been converted.

---

## 📁 Repository Contents

```
INC-2026-87241-EPIC-Investigation/
├── README.md          ← This file: full investigation report
├── NOTES.md           ← Detailed hunt notes and KQL patterns
├── queries/
│   ├── 01-single-factor-signin-detection.kql
│   ├── 02-graph-api-recon-detection.kql
│   ├── 03-file-exfiltration-detection.kql
│   ├── 04-inbox-rule-creation-alert.kql
│   └── 05-power-automate-forward-detection.kql
└── .gitignore
```

- **[NOTES.md](./NOTES.md)**: Full hunt methodology, phase-by-phase analysis, KQL technique patterns, lessons learned
- **[queries/](./queries/)**: KQL hunting starting points from this investigation. They contain environment-specific values and have not been tested as scheduled rules.

---

## 1. Executive Summary

On **June 11, 2026 at 03:14:38 UTC**, an external actor signed in successfully as **Mark Smith** (`m.smith@lognpacific.org`), a finance user with payment approval privileges. The sign-in logs record single-factor authentication for this session and no completed MFA challenge. No Conditional Access policy applied to the sign-in (`ConditionalAccessStatus = notApplied`); the tenant relied on **Security Defaults**, which evaluated the browser sign-in as `success` without requiring MFA. The logs do not record why Security Defaults did not require MFA here. Earlier, 12 attempts from a desktop client did hit an MFA requirement and failed. Within about an hour, the actor:

- ✅ Conducted **automated API reconnaissance** to profile MFA posture and enumerate security group membership
- ✅ **Exfiltrated critical network and financial documents** (VPN credentials, vendor banking details)
- ✅ Initiated **fraudulent payment redirection** via Business Email Compromise (BEC) attack targeting the CFO
- ✅ Established **persistent access** through Power Automate automation and inbox rule configuration
- ✅ Created **operational cover** through automated email hiding and suppression mechanisms

Sign-ins to a second account, `mohammed_admin@lognpacific.com`, came from the same source IP: 317 records (9 interactive, 308 non-interactive) on June 11. I did not investigate that account in this report, so its compromise is a lead for follow-up, not a finding. Across 284 sign-in records for m.smith from the attacker's IP in the investigation window (June 11, 02:22 to 13:54 UTC), none shows a satisfied MFA requirement. Non-interactive sign-ins for m.smith from that IP continued until **June 20, 22:06 UTC**.

### Incident Metrics at a Glance

| Metric | Value | Significance |
|--------|-------|--------------|
| Source IP | `103.69.224.136` (Amsterdam, NL) | Anonymized/VPN infrastructure |
| Initial sign-in | One Outlook Web, single-factor | No MFA recorded for this session |
| Access window | Interactive: Jun 11, 02:22 to 04:16 UTC. Non-interactive: Jun 11, 03:14 UTC to Jun 20, 22:06 UTC | Persistent access for more than nine days |
| Sign-in records | 284 for m.smith from the attacker IP, Jun 11 02:22 to 13:54 UTC (47 interactive, 237 non-interactive) | 400 more non-interactive through Jun 20 |
| MFA satisfied | 0 records | No completed second factor in the logs |
| Files Exfiltrated | 3 (VPN creds, vendor banking, spreadsheet) | Critical data loss |
| Persistence Mechanisms | 2 inbox rules + 1 Power Automate flow | Multi-layer automation |
| Log sources with attacker activity | 7 of 8 in-scope tables | Comprehensive coverage |
| BEC Email Sent | 1 (to CFO `j.reynolds@lognpacific.org`) | Fraudulent payment request |

---

## 2. Incident Overview & Infrastructure

### 2.1 Compromised Identities

**Primary Victim Account:**

| Attribute | Value |
|-----------|-------|
| Email | `m.smith@lognpacific.org` |
| User ObjectId | `fa5020a1-0d42-4839-bbfe-22db0861ced5` |
| Department | Finance |
| Role | Payment Processor / Finance User |
| Privilege Level | Payment Approval Authority |
| MFA Capable | Yes. MFA was required on 13 sign-in attempts, and all 13 failed (50074). It was not required on the browser sign-ins. |

**Second Account (lead, not investigated):**

| Attribute | Value |
|-----------|-------|
| Email | `mohammed_admin@lognpacific.com` |
| Role | Administrator |
| Sign-ins from attacker IP | 317 (9 interactive, 308 non-interactive), Jun 11, 02:22 to 12:03 UTC |
| Source | Same IP (`103.69.224.136`) |
| Implication | A follow-up lead; this report does not establish its compromise |

### 2.2 Threat Actor Infrastructure

| Infrastructure Element | Value | Role in Attack |
|------------------------|-------|----------------|
| Primary Attack IP | `103.69.224.136` | Initial compromise, reconnaissance, BEC launch |
| OS / Client | Linux, Chrome 149 | Attack platform profile |
| Automation Execution IP | `20.150.129.194` | Cloud infrastructure hosting Power Automate execution |
| Exfiltration Drop-box | `merovingian1337@proton.me` | External email target for forwarded messages |
| Session GUID | `005d431a-380b-1f5e-e554-16d5010dc28e` | Shared by 270 of 284 sign-in records in the window |

---

## 3. Attack Lifecycle & Detailed Timeline

### 3.1 Phase 1: Initial Reconnaissance & Access

**Objective:** Profile target security controls, identify MFA gaps, establish initial access
**Duration:** 02:22 UTC – 03:15 UTC (53 minutes)

**02:22:37 – 02:24:06 UTC – Failed sign-ins:**
Two sign-in attempts failed with `ErrorCode 50126` (invalid username or password) before the successful sign-in. How the actor obtained the password cannot be established from these logs.

**02:30:03 – 02:53:46 UTC – MFA blocks the desktop client:**
Twelve sign-ins from `Mobile Apps and Desktop clients` reached an MFA requirement (`AuthenticationRequirement = multiFactorAuthentication`) and failed with `50074` (strong authentication required). MFA stopped every one of them.

**03:08:00 – 03:12:26 UTC – MFA Posture Profiling:**
From IP `103.69.224.136`, the attacker issued three consecutive API calls to the Graph endpoint `/beta/reports/authenticationMethods/userRegistrationDetails`. These calls return the user's MFA registration status. The logs show the requests, not what the actor concluded from them.

**03:13:00 UTC – Group Membership Enumeration:**
The attacker called `/v1.0/me/memberOf/microsoft.graph.group/$count` to discover what security groups m.smith belongs to. This revealed payment approval groups and organizational hierarchy, which mattered for targeting the CFO later.

**03:14:38 UTC – Successful sign-in without MFA:**
The first successful sign-in as m.smith is a non-interactive record at 03:14:38 through **One Outlook Web** (the web Outlook client) from `103.69.224.136`; the first interactive success follows at 03:15:45. Both show `ClientAppUsed = Browser`, `AuthenticationRequirement = singleFactorAuthentication` and `ConditionalAccessStatus = notApplied`. This was a modern browser sign-in, not legacy authentication. The only policy evaluated was **Security Defaults**, with `result = success`. No MFA challenge was recorded.

---

### 3.2 Phase 2: Data Exfiltration & Intelligence Gathering

**Objective:** Extract network access credentials and financial intelligence
**Duration:** 03:35 UTC – 03:37 UTC (2 minutes)

**03:37:22 – 03:37:23 UTC – ⚠️ RAPID EXFILTRATION (Three Files in One Second):**
`CloudAppEvents` shows three `FileDownloaded` actions (not `FileAccessed`), executed within a one-second window:

| File | Est. Size | Impact |
|------|-----------|--------|
| `VPN-Access-Credentials.txt` | 5–10 KB | **CRITICAL**: On-premises network access compromised |
| `Vendor-Banking-Details.txt` | 2–3 KB | **CRITICAL**: Intelligence enabling BEC attack |
| `Book.xlsx` | 50–100 KB | Financial records / additional leverage |

**Key Distinction:** The exfiltration is methodical and targeted, not exploratory. The attacker knew exactly which files to grab (by name), executed downloads in rapid succession, and abandoned exploration immediately after, which suggests prior reconnaissance or directory knowledge.

---

### 3.3 Phase 3: Persistence & Cover-Up Mechanisms

**Objective:** Ensure persistent access and hide fraudulent communications
**Duration:** 03:28 UTC – 04:05 UTC

**03:28:22 UTC – Inbox Rule "Invoice Processing":**

```
Rule Name:  Invoice Processing
Trigger:    FROM j.reynolds@lognpacific.org
Action:     MoveToFolder → Archive
Stop:       StopProcessingRules = True
```

This rule specifically targets the CFO (`j.reynolds`). When the CFO responds to the fraudulent email with warnings or corrections, those emails are automatically hidden in the Archive folder. The rule suppresses the CFO's replies, which are the messages most likely to expose the fraud.

**03:32:31 UTC – Inbox Rule "Backup Copy":**
A second mailbox rule was created (partial details captured). Likely purpose: additional email hiding or forwarding mechanism.

**04:05:05 UTC – Power Automate Flow Creation:**
The attacker accessed the Microsoft Flow Portal and executed `CreateFlow`. This cloud automation will:
- Run independently of user session state
- Execute as the Power Automate Service Principal (`7ab7862c-4c57-491e-8a45-d52a7e023983`)
- **Survive password reset** (not tied to user credentials)
- Forward all emails to `merovingian1337@proton.me` automatically

---

### 3.4 Phase 4: Business Email Compromise (BEC) Attack

**Objective:** Initiate fraudulent financial transaction targeting CFO approval authority
**Duration:** 04:13 UTC – 04:17 UTC

**04:13:44 UTC – ⚠️ PRIMARY FRAUD EMAIL:**

```
From:    m.smith@lognpacific.org (legitimate sender)
To:      j.reynolds@lognpacific.org (CFO)
Subject: Updated Banking Details - Pacific IT Monthly
Size:    7,447 bytes
Source:  103.69.224.136 (attacker)
Client:  One Outlook Web
```

Why This Email Works:
- ✅ **Authentic Sender:** m.smith is a finance colleague, not an external or suspicious sender
- ✅ **Right Recipient:** j.reynolds (CFO) is the decision maker who approves large payments
- ✅ **Plausible Subject:** Matches context of exfiltrated `Vendor-Banking-Details.txt`
- ✅ **Professional Content:** Crafted using intelligence from exfiltrated vendor files
- ✅ **Suppressed Responses:** Any CFO objections routed to Archive (inbox rule active)
- ✅ **Urgency Factor:** Finance context + month-specific timing = pressure to approve

**04:17:56 UTC – Multi-Channel Reinforcement:**
Four minutes after the email, the attacker sent a Microsoft Teams message directly to `j.reynolds` (CFO). Multi-channel contact = higher perceived legitimacy. CFO's objections auto-hidden by rule = no way to detect deception.

---

### 3.5 Phase 5: Automated Exfiltration & Persistence Activation

**Objective:** Activate automated mail forwarding for persistent intelligence collection
**Execution:** 12:41:09 UTC, June 11 (9+ hours post-breach)

The attacker is **no longer logged in.** Yet the attack continues automatically.

**`MicrosoftGraphActivityLogs` Records:**

```
Timestamp:         12:41:09 UTC
Method:            POST
Endpoint:          /v1.0/me/messages/{message-id}/forward
Response:          202 (Accepted)
Source IP:         20.150.129.194 (Microsoft Office 365 Data Center)
Service Principal: 7ab7862c-4c57-491e-8a45-d52a7e023983 (Power Automate)
```

**Result:** All emails sent to m.smith's mailbox are now automatically forwarded to `merovingian1337@proton.me`. The attacker captures: CFO's responses, internal incident discussions, credential reset notifications, and all future security briefings.

**Why This Survives Password Reset:**
The flow runs as the Power Automate service principal, NOT the user account. Changing m.smith's password does NOT invalidate the service principal's access. The only way to stop this is explicit flow deletion in the Power Platform Admin Center.

---

## 4. Forensic Analysis

### 4.1 Session continuity

| Property | Value |
|----------|-------|
| Session ID | `005d431a-380b-1f5e-e554-16d5010dc28e` |
| First seen | June 11, 2026, 03:14:38 UTC |
| Client | One Outlook Web |
| Authentication | `singleFactorAuthentication` at initial sign-in |
| Records sharing this session ID | 270 of 284 (33 of 47 interactive, 237 of 237 non-interactive) |
| Window | June 11, 03:14 to 13:54 UTC (investigation window) |

The same session ID appears across 270 of 284 sign-in records. A shared session ID shows that these sign-ins belong to one sign-in session; by itself, it does not prove that one refresh token was reused for every operation. The token evidence is more direct: 110 of the non-interactive records carry `IncomingTokenType = refreshToken` within this session, so refresh tokens were redeemed to keep access going without a new interactive sign-in.

**Why containment needs session revocation, not just a password reset:**
A password reset revokes many, but not all, tokens. Microsoft documents different outcomes depending on the token type and how it was issued, and access tokens already issued stay valid until they expire (typically about an hour). Revoking the user's sessions (`Revoke-MgUserSignInSession`, or **Revoke sessions** in the Entra admin center) invalidates their refresh tokens directly. Do both, and remove the attacker's persistence (the flow and the inbox rules), which a password change does not touch.

### 4.2 Why MFA was not enforced

Across 284 sign-in records for m.smith from the attacker's IP (June 11, 02:22 to 13:54 UTC):
- 13 records: `AuthenticationRequirement = multiFactorAuthentication`. All 13 failed with `50074` (12 from a desktop client, 1 to the Azure Portal). Where MFA was required, it blocked the attempt.
- 271 records: `AuthenticationRequirement = singleFactorAuthentication`. 266 succeeded (29 interactive, 237 non-interactive), all from the browser; the other 5 are 2 bad passwords (`50126`) and 3 "stay signed in" interrupts (`50140`).
- 0 records show a satisfied MFA requirement.

Every record shows `ConditionalAccessStatus = notApplied`: no Conditional Access policy applied. The first interactive success lists one evaluated policy, **Security Defaults**, with `result = success`. Security Defaults does not require MFA on every sign-in, and it did not require MFA on these browser sign-ins. The logs do not record why. The single-factor browser sign-ins are the gap.

### 4.3 Data Exfiltration Forensics

| File | Est. Size | Extraction Time | Impact |
|------|-----------|-----------------|--------|
| `VPN-Access-Credentials.txt` | 5–10 KB | 03:37:22 UTC | On-premises network access compromised |
| `Vendor-Banking-Details.txt` | 2–3 KB | 03:37:22 UTC | Intelligence for BEC attack |
| `Book.xlsx` | 50–100 KB | 03:37:23 UTC | Financial records / additional leverage |

**Exfiltration Method:** Direct download via OneDrive web interface (`CloudAppEvents.FileDownloaded`). Inherently stealthy. It appears as normal user file access if not specifically filtered for `FileDownloaded` vs. `FileAccessed` behavior.

---

## 5. Kill-Chain Reconstruction (MITRE ATT&CK)

| Tactic | Technique | Evidence |
|---|---|---|
| Initial Access | T1078.004 Valid Accounts: Cloud Accounts | Successful sign-in as m.smith, 03:13:10 |
| Credential Access | T1110 Brute Force | Two failed sign-ins (50126) before success; too few to name a sub-technique |
| Discovery | T1087.004 Account Discovery: Cloud Account | Graph `userRegistrationDetails` calls |
| Discovery | T1069.003 Permission Groups Discovery: Cloud Groups | Graph `memberOf` group enumeration |
| Collection | T1530 Data from Cloud Storage | OneDrive `FileDownloaded` × 3 |
| Defense Evasion | T1564.008 Hide Artifacts: Email Hiding Rules | "Invoice Processing" rule moving CFO mail to Archive |
| Collection | T1114.003 Email Collection: Email Forwarding Rule | Mail forwarded to external address |
| Exfiltration | T1020 Automated Exfiltration | Power Automate flow forwarding mail to `proton.me` |
| Lateral Movement | T1534 Internal Spearphishing | Fraudulent banking email and Teams message to the CFO from a trusted internal account |
| Impact | T1657 Financial Theft | Payment redirection attempt |

The Power Automate flow has no exact ATT&CK technique. It is mapped by what it did (forwarding and automated exfiltration) rather than to a persistence technique.

**Removed from the old table, and why:**

| Old ID | What it actually is |
|---|---|
| T1621 | MFA Request Generation (prompt bombing). Not seen here. |
| T1547.014 | Boot or Logon Autostart: Active Setup, a Windows registry technique |
| T1136.003 | Create Cloud Account. No account was created. |
| T1098.001 | Additional Cloud Credentials. No credentials were added. |
| T1550.001 | Application Access Token. Only applies with evidence of a stolen token. |
| T1114.002 | Remote Email Collection. The hiding rule is T1564.008. |
| T1020.001 | Traffic Duplication, a network technique |
| T1566.002 | Spearphishing Link, from outside. The BEC came from inside, so T1534. |
| T1598.003 / T1592.003 | Phishing for Information / Host Firmware. Neither fits Graph API recon. |

---

## 6. Root Cause Analysis

| Control | Configuration Gap | Why It Failed | Impact |
|---------|------------------|---------------|--------|
| Conditional Access | No Conditional Access policy applied (`notApplied`); MFA depended on Security Defaults | Security Defaults evaluated the browser sign-in as `success` without requiring MFA | Single-factor browser sign-ins succeeded |
| Session revocation | Not part of the standard response | Password reset alone does not end every session | Access could outlast a reset |
| Email Rule Auditing | No Real-time Alerts | Rule creation not monitored/alerted | Attacker rules went undetected for hours |
| Power Automate Approval | Not Required | Flows created without admin approval | Attacker created persistence freely |
| Anomalous Login Detection | UEBA Sensitivity Too Low | Failed sign-ins and MFA failures from an anonymizing IP not flagged as risky | Breach activity normalized |
| Activity Logging | No Real-time Graph API Alerts | Recon queries not alerted | Reconnaissance went unnoticed |

---

## 7. Containment & Remediation Procedures

> **Sequencing:** Revoke sessions and remove persistence (flow, inbox rules) together with the password reset. A password reset alone leaves the flow, the rules and any unexpired access tokens in place.

### Mandatory Containment Sequence

| Step | Action | Location | Why First | Est. Time |
|------|--------|----------|-----------|-----------|
| **1** | **Revoke All Sessions** | Azure AD → Users → m.smith → Sign-out all sessions | Invalidates the user's refresh tokens and session cookies | 2 min |
| **2** | **Delete Power Automate Flow** | Power Automate Admin Center → Cloud Flows → Delete | Stops automated forwarding and rule re-creation | 3 min |
| **3** | **Remove Inbox Rules** | Exchange Admin Center → Rules → Delete "Invoice Processing" & "Backup Copy" | Restores visibility to CFO communications | 3 min |
| **4** | **Reset Password** | Azure AD → Reset Password (force complex) | Blocks sign-in with the stolen password | 2 min |

**Total Containment Time: ~10 minutes**

**Verification Steps:**
- ✅ Confirm session revocation in Azure AD activity logs
- ✅ Verify Power Automate flow deletion in admin center
- ✅ Confirm inbox rules removed from Exchange
- ✅ Confirm no new sign-ins for m.smith from `103.69.224.136` after revocation
- ✅ Verify no forwarding rules active in mailbox

---

## 8. Strategic Recommendations & Hardening

### Immediate (0–7 Days)
1. **Replace Security Defaults with Conditional Access**: Create a Conditional Access policy that requires MFA for every sign-in, including browser sign-ins, so MFA does not depend on Security Defaults deciding when to prompt.
2. **Mandatory MFA for All Cloud Sign-ins**: No app or location exclusions.
3. **Session Revocation for All Finance Users**: Revoke all active sessions for users with payment approval authority. Force re-authentication with new MFA.
4. **Email Rule Audit**: Export all mailbox rules for users with payment access. Review for suspicious archive/forwarding configurations.
5. **Power Automate Flow Audit**: Enumerate all Power Automate cloud flows created in the past 30 days.
6. **SIEM Alerting on Email Rule Creation**: High-priority alerts for `New-InboxRule` operations targeting specific senders or archive folders.

### Short-Term (1–4 Weeks)
1. **Conditional Access Policy Restructuring**: Require MFA for all cloud sign-ins, implement risk-based step-up authentication, enforce device compliance
2. **Sign-in Frequency for Sensitive Users**: Use a Conditional Access sign-in frequency control for finance users, so sessions re-authenticate instead of running on refresh tokens for days
3. **Power Automate Governance**: Require admin approval for flows that access mail or organizational data; implement DLP policies
4. **Email Security Hardening**: DMARC/SPF/DKIM, External Email Warning headers, 2-person rule for payment authorization changes
5. **UEBA Sensitivity Tuning**: Tune for repeated failed sign-ins, impossible travel, Graph API recon patterns, bulk file downloads

### Long-Term (1–3 Months)
1. **Zero Trust Architecture**: Step-up MFA for sensitive operations (payment approval, rule creation, flow deployment)
2. **Privileged Access Management (PAM)**: VPN credentials must not be accessible to finance users
3. **Incident Response Playbook**: Formalize the session revocation → flow deletion → rule deletion → password reset sequence
4. **Threat Hunting Program**: Ongoing hunts for single-factor sign-ins from external IPs, Graph API recon, Power Automate forward API calls, and bulk downloads from cloud storage

---

## 9. KQL Detection Queries

> 💡 All queries are available as standalone `.kql` files in the [`queries/`](./queries/) folder. See individual files for comments and usage notes.

### 9.1 Single-Factor Sign-in Detection
```kusto
SigninLogs
| where AuthenticationRequirement == "singleFactorAuthentication"
| where IPAddress !in ("LIST_OF_TRUSTED_CORPORATE_IPS")
| where UserPrincipalName contains "@lognpacific.org"
| summarize SigninCount = count() by UserPrincipalName, IPAddress, AppDisplayName
| where SigninCount > 5
```

### 9.2 Graph API Reconnaissance Pattern
```kusto
MicrosoftGraphActivityLogs
| where RequestUri contains "/reports/authenticationMethods/userRegistrationDetails"
   or RequestUri contains "/me/memberOf"
| where TimeGenerated >= ago(24h)
| summarize ReconCount = count() by IPAddress, RequestUri
| where ReconCount > 2
```

### 9.3 File Exfiltration Detection (Read vs. Copy)
```kusto
CloudAppEvents
| where ActionType == "FileDownloaded"
| where ObjectName contains "credential" or ObjectName contains "banking"
| where Timestamp >= ago(7d)
| summarize DownloadCount = count() by AccountObjectId, ObjectName, Timestamp
```

### 9.4 Inbox Rule Creation Alert
```kusto
OfficeActivity
| where Operation == "New-InboxRule"
| where Item contains "Archive" or Item contains "Delete"
| where TimeGenerated >= ago(24h)
| project TimeGenerated, UserId, Item
```

### 9.5 Power Automate Forward API Calls
```kusto
MicrosoftGraphActivityLogs
| where RequestUri contains "/forward"
| where ResponseStatusCode == 202
| where TimeGenerated >= ago(24h)
| project TimeGenerated, RequestUri, IPAddress
```

---

## 10. Conclusion

Incident INC-2026-87241 represents a complete, multi-stage cloud compromise attack that exploited fundamental gaps in modern authentication architecture. The attack was **swift:** from initial access (03:14 UTC) to BEC launch (04:13 UTC) = **1 hour**. From BEC launch to automated persistence activation = **8 hours**.

**The fundamental control failure:** No Conditional Access policy applied. MFA depended on Security Defaults, which did not require MFA for the browser sign-ins, so a password alone was enough.

**Prevention requires:**
- Conditional Access policies that require MFA for every sign-in
- Mandatory MFA for all sign-ins (no exemptions)
- Sign-in frequency controls for sensitive users
- Cloud automation governance
- Real-time alerting on reconnaissance patterns

---

## Attack Timeline: June 11, 2026 (UTC)

| Time (UTC) | Event | Evidence |
|------------|-------|----------|
| 02:22:37 | Failed sign-in, bad password | `SigninLogs` ErrorCode 50126 |
| 02:24:06 | Failed sign-in, bad password | `SigninLogs` ErrorCode 50126 |
| 02:30–02:53 | 12 desktop-client sign-ins blocked by MFA | `SigninLogs` ErrorCode 50074 |
| 03:08:00 | Secondary admin recon begins | `mohammed_admin` Azure Portal access |
| 03:09:37 | MFA posture profiling #1 | `MicrosoftGraphActivityLogs` |
| 03:10:07 | MFA posture profiling #2 | `MicrosoftGraphActivityLogs` |
| 03:12:26 | MFA posture profiling #3 | `MicrosoftGraphActivityLogs` |
| **03:14:38** | **⚠️ First successful sign-in, single-factor (browser, One Outlook Web)** | **`AADNonInteractiveUserSignInLogs` ResultType 0; `ConditionalAccessStatus` notApplied** |
| 03:15:45 | First interactive successful sign-in | `SigninLogs` ResultType 0, Security Defaults `success` |
| 03:28:22 | Inbox rule "Invoice Processing" created | `OfficeActivity` New-InboxRule |
| 03:32:31 | Inbox rule "Backup Copy" created | `OfficeActivity` New-InboxRule |
| 03:37:22 | **VPN credentials exfiltrated** | `CloudAppEvents` FileDownloaded |
| 03:37:22 | **Vendor banking details exfiltrated** | `CloudAppEvents` FileDownloaded |
| 03:37:23 | Spreadsheet exfiltrated | `CloudAppEvents` FileDownloaded |
| 03:41:36 | Sharing inheritance broken | `CloudAppEvents` |
| 04:05:05 | **Power Automate flow created** | `CloudAppEvents` CreateFlow |
| **04:13:44** | **⚠️ BEC EMAIL SENT to CFO** | **`OfficeActivity` Send, Subject: "Updated Banking Details - Pacific IT Monthly"** |
| 04:17:56 | Teams follow-up sent to CFO | `CloudAppEvents` MessageSent |
| **12:41:09** | **⚠️ AUTOMATED FORWARD EXECUTES** | **`MicrosoftGraphActivityLogs` POST /forward, 202 Accepted** |
| 12:41:09 | Exfil email to `merovingian1337@proton.me` | `OfficeActivity` Send |
| Jun 20, 22:06 | Last non-interactive sign-in for m.smith from the attacker IP | `AADNonInteractiveUserSignInLogs` |

---

*Report Prepared By: Security Operations Center | Date: June 25, 2026*
