# INC-2026-87241 — Cloud Identity Compromise & Business Email Compromise (BEC)

![Incident](https://img.shields.io/badge/Incident-INC--2026--87241-red?style=for-the-badge)
![Severity](https://img.shields.io/badge/Severity-CRITICAL-red?style=for-the-badge)
![Status](https://img.shields.io/badge/Status-CONCLUDED-darkgrey?style=for-the-badge)
![Platform](https://img.shields.io/badge/Platform-Microsoft%20Sentinel-blue?style=for-the-badge&logo=microsoft)

> **Classification:** RESTRICTED – INTERNAL IR USE ONLY
> **Organization:** LOG(N) Pacific
> **Incident Date:** June 10–11, 2026
> **Report Date:** June 25, 2026
> **Prepared By:** Security Operations Center

---

## 📁 Repository Contents

```
INC-2026-87241-EPIC-Investigation/
├── README.md          ← This file — full investigation report
├── NOTES.md           ← Detailed hunt notes, flag answers (Q01–Q37), KQL patterns
├── queries/
│   ├── 01-legacy-auth-bypass-detection.kql
│   ├── 02-graph-api-recon-detection.kql
│   ├── 03-file-exfiltration-detection.kql
│   ├── 04-inbox-rule-creation-alert.kql
│   └── 05-power-automate-forward-detection.kql
└── .gitignore
```

- **[NOTES.md](./NOTES.md)** — Full hunt methodology, phase-by-phase analysis, all 37 flag answers, KQL technique patterns, lessons learned
- **[queries/](./queries/)** — Standalone KQL detection queries extracted from the investigation, ready to deploy in Microsoft Sentinel

---

## 1. Executive Summary

On **June 10, 2026 at 22:13:10 UTC**, an external threat actor successfully compromised the cloud identity of **Mark Smith** (`m.smith@lognpacific.org`), a finance user with payment approval privileges at LOG(N) Pacific. The attack exploited a critical legacy authentication gap in Conditional Access policies, bypassing global Multi-Factor Authentication (MFA) controls. Within 4 hours, the attacker:

- ✅ Conducted **automated API reconnaissance** to profile MFA posture and enumerate security group membership
- ✅ **Exfiltrated critical network and financial documents** (VPN credentials, vendor banking details)
- ✅ Initiated **fraudulent payment redirection** via Business Email Compromise (BEC) attack targeting the CFO
- ✅ Established **persistent access** through Power Automate automation and inbox rule configuration
- ✅ Created **operational cover** through automated email hiding and suppression mechanisms

Parallel analysis indicates a **secondary compromise** of administrative account `mohammed_admin@lognpacific.com` from the same source infrastructure, suggesting **broader organizational targeting**. The attacker maintained active session access for 9+ hours post-breach with **zero MFA satisfaction** across 583 sign-in operations.

### Incident Metrics at a Glance

| Metric | Value | Significance |
|--------|-------|--------------|
| Source IP | `103.69.224.136` (Amsterdam, NL) | Anonymized/VPN infrastructure |
| Breach Entry Point | One Outlook Web (Legacy OAuth) | Bypassed Conditional Access |
| Session Duration | 9+ hours (Jun 10 22:13 → Jun 11 07:41) | Persistent active compromise |
| Total Sign-ins | 583 operations | Widespread account abuse |
| MFA Satisfied | **0 times** | Zero second-factor authentication |
| Files Exfiltrated | 3 (VPN creds, vendor banking, spreadsheet) | Critical data loss |
| Persistence Mechanisms | 2 inbox rules + 1 Power Automate flow | Multi-layer automation |
| Log Sources Compromised | 7 of 8 in-scope tables | Comprehensive coverage |
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
| MFA Capable | Yes (but not enforced on legacy auth paths) |

**Secondary Compromised Account:**

| Attribute | Value |
|-----------|-------|
| Email | `mohammed_admin@lognpacific.com` |
| Role | Administrator |
| Compromise Window | 10:08 PM – 10:10 PM UTC, June 10 |
| Source | Same IP (`103.69.224.136`) |
| Implication | Coordinated multi-account targeting campaign |

### 2.2 Threat Actor Infrastructure

| Infrastructure Element | Value | Role in Attack |
|------------------------|-------|----------------|
| Primary Attack IP | `103.69.224.136` | Initial compromise, reconnaissance, BEC launch |
| OS / Client | Linux, Chrome 149 | Attack platform profile |
| Automation Execution IP | `20.150.129.194` | Cloud infrastructure hosting Power Automate execution |
| Exfiltration Drop-box | `merovingian1337@proton.me` | External email target for forwarded messages |
| Session GUID | `005d431a-380b-1f5e-e554-16d5010dc28e` | Persistent token across 583 operations |

---

## 3. Attack Lifecycle & Detailed Timeline

### 3.1 Phase 1: Initial Reconnaissance & Authentication Bypass

**Objective:** Profile target security controls, identify MFA gaps, establish initial access
**Duration:** 21:21 UTC – 22:13 UTC (52 minutes)

**21:21:32 UTC – Credential Stuffing (Wave 1):**
The attacker performed initial password spray testing against `m.smith@lognpacific.org` using the Microsoft Office client. Two consecutive attempts failed with `ErrorCode 50126` (Invalid password), indicating the credentials were from an external breach or OSINT operation.

**22:08:00 – 22:12:26 UTC – MFA Posture Profiling:**
From IP `103.69.224.136`, the attacker issued three consecutive API calls to the Graph endpoint `/beta/reports/authenticationMethods/userRegistrationDetails`. These calls explicitly queried whether m.smith was registered for MFA tokens. The attacker discovered: **MFA is registered, but the legacy authentication path may bypass it.**

**22:13:00 UTC – Group Membership Enumeration:**
The attacker called `/v1.0/me/memberOf/microsoft.graph.group/$count` to discover what security groups m.smith belongs to. This revealed payment approval groups and organizational hierarchy — critical for targeting the CFO later.

**22:13:10 UTC – ⚠️ BREACH MOMENT (Legacy Auth Bypass):**
The attacker authenticated successfully as m.smith via **One Outlook Web** (legacy OAuth protocol). Modern Conditional Access policies were configured to enforce MFA, BUT legacy OAuth clients were explicitly exempted for backward compatibility. The attacker's authentication request was processed through the legacy path, which only required `singleFactorAuthentication`. **No MFA challenge was issued.** The attacker obtained a refresh token valid for 90 days.

---

### 3.2 Phase 2: Data Exfiltration & Intelligence Gathering

**Objective:** Extract network access credentials and financial intelligence
**Duration:** 22:35 UTC – 22:37 UTC (2 minutes)

**22:37:22 – 22:37:23 UTC – ⚠️ RAPID EXFILTRATION (Three Files in One Second):**
`CloudAppEvents` shows three `FileDownloaded` actions (not `FileAccessed`), executed within a one-second window:

| File | Est. Size | Impact |
|------|-----------|--------|
| `VPN-Access-Credentials.txt` | 5–10 KB | **CRITICAL** — On-premises network access compromised |
| `Vendor-Banking-Details.txt` | 2–3 KB | **CRITICAL** — Intelligence enabling BEC attack |
| `Book.xlsx` | 50–100 KB | Financial records / additional leverage |

**Key Distinction:** The exfiltration is methodical and targeted, not exploratory. The attacker knew exactly which files to grab (by name), executed downloads in rapid succession, and abandoned exploration immediately after — indicating prior reconnaissance or directory knowledge.

---

### 3.3 Phase 3: Persistence & Cover-Up Mechanisms

**Objective:** Ensure persistent access and hide fraudulent communications
**Duration:** 22:28 UTC – 23:05 UTC

**22:28:22 UTC – Inbox Rule "Invoice Processing":**

```
Rule Name:  Invoice Processing
Trigger:    FROM j.reynolds@lognpacific.org
Action:     MoveToFolder → Archive
Stop:       StopProcessingRules = True
```

This rule specifically targets the CFO (`j.reynolds`). When the CFO responds to the fraudulent email with warnings or corrections, those emails are automatically hidden in the Archive folder. **This is brilliant operational security** — the attacker anticipated the natural response sequence and designed the rule to suppress it.

**22:32:31 UTC – Inbox Rule "Backup Copy":**
A second mailbox rule was created (partial details captured). Likely purpose: additional email hiding or forwarding mechanism.

**23:05:05 UTC – Power Automate Flow Creation:**
The attacker accessed the Microsoft Flow Portal and executed `CreateFlow`. This cloud automation will:
- Run independently of user session state
- Execute as the Power Automate Service Principal (`7ab7862c-4c57-491e-8a45-d52a7e023983`)
- **Survive password reset** (not tied to user credentials)
- Forward all emails to `merovingian1337@proton.me` automatically

---

### 3.4 Phase 4: Business Email Compromise (BEC) Attack

**Objective:** Initiate fraudulent financial transaction targeting CFO approval authority
**Duration:** 23:13 UTC – 23:17 UTC

**23:13:44 UTC – ⚠️ PRIMARY FRAUD EMAIL:**

```
From:    m.smith@lognpacific.org (legitimate sender)
To:      j.reynolds@lognpacific.org (CFO)
Subject: Updated Banking Details - Pacific IT Monthly
Size:    7,447 bytes
Source:  103.69.224.136 (attacker)
Client:  One Outlook Web
```

Why This Email Works:
- ✅ **Authentic Sender:** m.smith is a finance colleague — not external/suspicious
- ✅ **Right Recipient:** j.reynolds (CFO) is the decision maker who approves large payments
- ✅ **Plausible Subject:** Matches context of exfiltrated `Vendor-Banking-Details.txt`
- ✅ **Professional Content:** Crafted using intelligence from exfiltrated vendor files
- ✅ **Suppressed Responses:** Any CFO objections routed to Archive (inbox rule active)
- ✅ **Urgency Factor:** Finance context + month-specific timing = pressure to approve

**23:17:56 UTC – Multi-Channel Reinforcement:**
Four minutes after the email, the attacker sent a Microsoft Teams message directly to `j.reynolds` (CFO). Multi-channel contact = higher perceived legitimacy. CFO's objections auto-hidden by rule = no way to detect deception.

---

### 3.5 Phase 5: Automated Exfiltration & Persistence Activation

**Objective:** Activate automated mail forwarding for persistent intelligence collection
**Execution:** 07:41:09 AM UTC, June 11 (9+ hours post-breach)

The attacker is **no longer logged in.** Yet the attack continues automatically.

**`MicrosoftGraphActivityLogs` Records:**

```
Timestamp:         07:41:09 AM UTC
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

### 4.1 Session Token Exploitation

| Property | Value |
|----------|-------|
| Session ID | `005d431a-380b-1f5e-e554-16d5010dc28e` |
| Issued | June 10, 2026, 22:13:10 UTC |
| Issued By | One Outlook Web (legacy OAuth client) |
| Authentication Level | `singleFactorAuthentication` (NO MFA) |
| Token Type | Refresh Token |
| Default Lifetime | 90 days (expires ~September 8, 2026) |
| Reuse Count | **583+ sign-in operations** |
| Reuse Window | 9+ hours continuous |

**CRITICAL FINDING:** This single token was reused for all 583 subsequent operations. The attacker **never re-authenticated.** The subsequent sign-in records show varying `AuthenticationRequirement` values, but these describe what *would* be required if the token were freshly issued — not what was actually satisfied.

**Why Password Reset Doesn't Solve This:**
Microsoft Entra ID issues a refresh token valid for 90 days. **Changing the password does not invalidate existing refresh tokens.** The attacker's token remains live for 89 more days after a password reset.

**The Only Solution: Session Revocation**
Entra ID provides a global "sign-out all sessions" function that immediately invalidates all refresh tokens. This must be executed **BEFORE** password reset.

### 4.2 MFA Bypass Mechanism

```
Modern Auth Flow:  Password Required → MFA Required → Token Issued
Legacy Auth Flow:  Password Only → Token Issued (MFA Exempted)
```

Legacy OAuth protocols (like One Outlook Web, legacy Exchange ActiveSync) are exempted from modern Conditional Access for backward compatibility. **This exemption is intentional** — older applications can't handle MFA challenges. However, it creates a security gap.

**The Numbers:**
Across 583 total sign-in records from the attacker's IP:
- 318 records: `AuthenticationRequirement = "multiFactorAuthentication"`
- 265 records: `AuthenticationRequirement = "singleFactorAuthentication"`
- **0 records: actual MFA satisfaction (no second-factor challenge logs)**

Modern CA policies were **completely bypassed** for the entire compromise.

### 4.3 Data Exfiltration Forensics

| File | Est. Size | Extraction Time | Impact |
|------|-----------|-----------------|--------|
| `VPN-Access-Credentials.txt` | 5–10 KB | 22:37:22 UTC | On-premises network access compromised |
| `Vendor-Banking-Details.txt` | 2–3 KB | 22:37:22 UTC | Intelligence for BEC attack |
| `Book.xlsx` | 50–100 KB | 22:37:23 UTC | Financial records / additional leverage |

**Exfiltration Method:** Direct download via OneDrive web interface (`CloudAppEvents.FileDownloaded`). Inherently stealthy — appears as normal user file access if not specifically filtered for `FileDownloaded` vs. `FileAccessed` behavior.

---

## 5. Kill-Chain Reconstruction (MITRE ATT&CK)

| Phase | Techniques |
|-------|-----------|
| **Reconnaissance** | T1598.003, T1592.003, T1087.004, T1526 — MFA profiling via Graph API, group enumeration, cloud service scanning |
| **Initial Access** | T1110.004, T1078.004 — Credential stuffing, valid account compromise |
| **Exploitation** | T1621, T1550.001 — MFA bypass via legacy OAuth, session token reuse across 583 operations |
| **Defense Evasion** | T1114.002 — Inbox rules hiding CFO responses, Archive folder suppression |
| **Persistence** | T1098.001, T1136.003, T1547.014 — Power Automate flow, inbox rules, mail forwarding surviving password reset |
| **Collection** | T1114.002, T1530 — Email forwarding, OneDrive file exfiltration |
| **Exfiltration** | T1020.001, T1537 — Automated email forwarding to external account |
| **Impact** | T1566.002, T1586.003 — BEC attack on CFO, fraudulent payment redirection |

---

## 6. Root Cause Analysis

| Control | Configuration Gap | Why It Failed | Impact |
|---------|------------------|---------------|--------|
| Conditional Access | Legacy Auth Exemption | Legacy protocols explicitly exempt from MFA | Attacker used legacy OAuth to bypass all MFA |
| MFA Enforcement | Not Applied to Legacy Clients | Legacy clients unable to handle MFA challenges | Single-factor sufficient for breach |
| Session Timeout | 90-day default | Refresh token valid for months by default | Token survives password reset |
| Email Rule Auditing | No Real-time Alerts | Rule creation not monitored/alerted | Attacker rules went undetected for hours |
| Power Automate Approval | Not Required | Flows created without admin approval | Attacker created persistence freely |
| Anomalous Login Detection | UEBA Sensitivity Too Low | Credential stuffing not flagged as risky | Breach activity normalized |
| Activity Logging | No Real-time Graph API Alerts | Recon queries not alerted | Reconnaissance went unnoticed |

---

## 7. Containment & Remediation Procedures

> ⚠️ **CRITICAL SEQUENCING WARNING:** If password reset is performed BEFORE session revocation, the attacker's refresh token remains valid for 89 more days. The sequence below is mandatory.

### Mandatory Containment Sequence

| Step | Action | Location | Why First | Est. Time |
|------|--------|----------|-----------|-----------|
| **1** | **Revoke All Sessions** | Azure AD → Users → m.smith → Sign-out all sessions | Invalidates 90-day refresh token immediately | 2 min |
| **2** | **Delete Power Automate Flow** | Power Automate Admin Center → Cloud Flows → Delete | Stops automated forwarding and rule re-creation | 3 min |
| **3** | **Remove Inbox Rules** | Exchange Admin Center → Rules → Delete "Invoice Processing" & "Backup Copy" | Restores visibility to CFO communications | 3 min |
| **4** | **Reset Password** | Azure AD → Reset Password (force complex) | Now-useless without active token; attacker cannot log in | 2 min |

**Total Containment Time: ~10 minutes**

**Verification Steps:**
- ✅ Confirm session revocation in Azure AD activity logs
- ✅ Verify Power Automate flow deletion in admin center
- ✅ Confirm inbox rules removed from Exchange
- ✅ Test m.smith sign-in with old token (should fail)
- ✅ Verify no forwarding rules active in mailbox

---

## 8. Strategic Recommendations & Hardening

### Immediate (0–7 Days)
1. **Block Legacy Authentication Globally** — Configure Conditional Access to explicitly block all legacy OAuth clients. Modern applications support modern auth; those that don't should be retired.
2. **Mandatory MFA for All Cloud Sign-ins** — No exemptions for legacy clients.
3. **Session Revocation for All Finance Users** — Revoke all active sessions for users with payment approval authority. Force re-authentication with new MFA.
4. **Email Rule Audit** — Export all mailbox rules for users with payment access. Review for suspicious archive/forwarding configurations.
5. **Power Automate Flow Audit** — Enumerate all Power Automate cloud flows created in the past 30 days.
6. **SIEM Alerting on Email Rule Creation** — High-priority alerts for `New-InboxRule` operations targeting specific senders or archive folders.

### Short-Term (1–4 Weeks)
1. **Conditional Access Policy Restructuring** — Require MFA for all cloud sign-ins, implement risk-based step-up authentication, enforce device compliance
2. **Session Token Lifetime Reduction** — Reduce refresh token lifetime from 90 days to 30 days
3. **Power Automate Governance** — Require admin approval for flows that access mail or organizational data; implement DLP policies
4. **Email Security Hardening** — DMARC/SPF/DKIM, External Email Warning headers, 2-person rule for payment authorization changes
5. **UEBA Sensitivity Tuning** — Tune for credential stuffing, impossible travel, Graph API recon patterns, bulk file downloads

### Long-Term (1–3 Months)
1. **Zero Trust Architecture** — Step-up MFA for sensitive operations (payment approval, rule creation, flow deployment)
2. **Privileged Access Management (PAM)** — VPN credentials must not be accessible to finance users
3. **Incident Response Playbook** — Formalize the session revocation → flow deletion → rule deletion → password reset sequence
4. **Threat Hunting Program** — Ongoing hunts for legacy OAuth sign-ins, Graph API recon, Power Automate forward API calls, and bulk downloads from cloud storage

---

## 9. KQL Detection Queries

> 💡 All queries are available as standalone `.kql` files in the [`queries/`](./queries/) folder. See individual files for comments and usage notes.

### 9.1 Legacy Auth Bypass Detection
```kusto
SigninLogs
| where AuthenticationRequirement == "singleFactorAuthentication"
| where IPAddress !in ("LIST_OF_TRUSTED_CORPORATE_IPS")
| where UserPrincipalName contains "@lognpacific.org"
| where AppDisplayName in ("One Outlook Web", "Other Legacy Clients")
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

Incident INC-2026-87241 represents a complete, multi-stage cloud compromise attack that exploited fundamental gaps in modern authentication architecture. The attack was **swift:** from initial access (22:13 UTC) to BEC launch (23:13 UTC) = **1 hour**. From BEC launch to automated persistence activation = **8 hours**.

**The fundamental control failure:** Legacy authentication exemption in Conditional Access. While necessary for backward compatibility, this exemption created an unmonitored, MFA-free entry point.

**Prevention requires:**
- Elimination of legacy authentication protocols
- Mandatory MFA for all sign-ins (no exemptions)
- Reduced session token lifetimes
- Cloud automation governance
- Real-time alerting on reconnaissance patterns

---

## Attack Timeline — June 10–11, 2026

| Time (UTC) | Event | Evidence |
|------------|-------|----------|
| 21:21:32 | Credential stuffing wave 1 (failed) | `SigninLogs` ErrorCode 50126 |
| 21:21:52 | Credential stuffing wave 2 (failed) | `SigninLogs` ErrorCode 50126 |
| 22:08:00 | Secondary admin recon begins | `mohammed_admin` Azure Portal access |
| 22:09:37 | MFA posture profiling #1 | `MicrosoftGraphActivityLogs` |
| 22:10:07 | MFA posture profiling #2 | `MicrosoftGraphActivityLogs` |
| 22:12:26 | MFA posture profiling #3 | `MicrosoftGraphActivityLogs` |
| **22:13:10** | **⚠️ BREACH — Legacy OAuth bypass** | **`SigninLogs` ResultType=0, singleFactorAuthentication** |
| 22:28:22 | Inbox rule "Invoice Processing" created | `OfficeActivity` New-InboxRule |
| 22:32:31 | Inbox rule "Backup Copy" created | `OfficeActivity` New-InboxRule |
| 22:37:22 | **VPN credentials exfiltrated** | `CloudAppEvents` FileDownloaded |
| 22:37:22 | **Vendor banking details exfiltrated** | `CloudAppEvents` FileDownloaded |
| 22:37:23 | Spreadsheet exfiltrated | `CloudAppEvents` FileDownloaded |
| 22:41:36 | Sharing inheritance broken | `CloudAppEvents` |
| 23:05:05 | **Power Automate flow created** | `CloudAppEvents` CreateFlow |
| **23:13:44** | **⚠️ BEC EMAIL SENT to CFO** | **`OfficeActivity` Send, Subject: "Updated Banking Details - Pacific IT Monthly"** |
| 23:17:56 | Teams follow-up sent to CFO | `CloudAppEvents` MessageSent |
| *(Jun 11)* | | |
| **07:41:09** | **⚠️ AUTOMATED FORWARD EXECUTES** | **`MicrosoftGraphActivityLogs` POST /forward, 202 Accepted** |
| 07:41:09 | Exfil email to `merovingian1337@proton.me` | `OfficeActivity` Send |

---

*Report Prepared By: Security Operations Center | Date: June 25, 2026*
*Classification: RESTRICTED – INTERNAL IR USE ONLY*
*Distribution: Executive Leadership, CISO, IR Team*
