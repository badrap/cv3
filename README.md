# CV3 - Common Vendor Excuse & Evasion Enumeration

**A taxonomy of vendor dismissal patterns for legitimate vulnerability reports**

Vendors deflect, delay, or retaliate against good-faith security disclosures. CV3 enumerates and names these patterns so researchers and coordinators can cite a specific ID rather than re-arguing recurring disclosure patterns every time.

The taxonomy follows the canonical order of a vulnerability disclosure:

> We never received your report.  
> And if we did, it isn't really a bug.  
> And if it is, it isn't exploitable.  
> And if it is, it isn't severe.  
> And if it is, your report doesn't qualify.  
> And if it does, a fix is on the roadmap.  
> And if it never ships, you are the problem.  
> And if you say so in public, you'll be hearing from our counsel.  

---

## Table of Contents

- [TL;DR](#tldr)
- [The Taxonomy](#the-taxonomy)
  - [Critical Framing Note](#critical-framing-note)
  - [Category A - Compensating-Control Misuse](#category-a---compensating-control-misuse-cv3-001--cv3-010)
  - [Category B - Threat-Model Gaming](#category-b---threat-model-gaming-cv3-011--cv3-019)
  - [Category C - Severity Manipulation / CVSS Gaming](#category-c---severity-manipulation--cvss-gaming-cv3-020--cv3-028)
  - [Category D - "By Design" / Expected Behavior](#category-d---by-design--expected-behavior-cv3-029--cv3-035)
  - [Category E - Asset Dismissal](#category-e---asset-dismissal-cv3-036--cv3-042)
  - [Category F - Process Deflection](#category-f---process-deflection-cv3-043--cv3-053-cv3-079--cv3-082)
  - [Category G - Legal Deflection](#category-g---legal-deflection-cv3-054--cv3-062)
  - [Category H - Shoot-the-Messenger](#category-h---shoot-the-messenger-cv3-063--cv3-069)
  - [Category I - Coordination Manipulation](#category-i---coordination-manipulation-cv3-070--cv3-074-cv3-083--cv3-087)
  - [Category J - Disinformation about the Bug Itself](#category-j---disinformation-about-the-bug-itself-cv3-075--cv3-078)
- [Structural Conventions](#structural-conventions)
- [Rationale](#rationale)
- [Prior Art](#prior-art)
- [License](#license)

---

## TL;DR

- **Vendors deflect legitimate vulnerability reports through a recognizable, repeating set of patterns** that fall into two broad families: technical dismissals (where engineering or risk arguments are misused to deny a real flaw) and process/legal deflections (where contracts, scope, communication, or law are weaponized against the reporter). This v0.1 enumerates **87 leaf-level patterns** across **10 top-level categories**, each grounded in a documented incident or in the disclosure literature.
- **Substantial prior art exists, but none of it is a true "CV3"**: the Bugcrowd VRT, HackerOne report-state docs, OWASP Vulnerability Disclosure Cheat Sheet, CERT/CC's "Troubleshooting CVD" chapter, the disclose.io research-threats archive, and academic work by Moussouris, Matwyshyn, Pfefferkorn, and Weulen Kranenbarg et al. each cover slices of the problem, but no published taxonomy systematically enumerates *vendor evasion patterns* the way CWE enumerates weakness patterns. CV3 explicitly positions itself as complementing - not competing with - the VRT and disclose.io.
- **The most useful framing for v0.1 is a flat, citable, ID-numbered list** organized by category, with each entry containing a name, a 1-2 sentence description, a representative pattern indicator, and a documented exemplar. That structure (a) supports the "CV3-042 right now" use case, (b) mirrors CWE's leaf-entry style, and (c) makes the taxonomy easy to extend through community pull requests in the disclose.io tradition.

---

## The Taxonomy

### Critical Framing Note

A "vendor evasion" taxonomy has a structural failure mode: researchers using it to accuse vendors who are correctly refusing to fix non-bugs. Reports against `system()`, `eval()`, `pickle.loads`, MCP stdio servers, or other primitives whose entire contract is "execute what the caller specifies" are not vendor evasions when refused - they are misidentifications of the trust boundary. CV3 names the *pattern of language*, not the verdict. An entry's **Does NOT apply when** clause is what distinguishes evasion from reasonable response, and applying CV3 IDs without checking that clause first is itself a form of disclosure dysfunction.

---

### Category A - Compensating-Control Misuse (CV3-001 … CV3-010)

*Claiming an unrelated or insufficient control negates the vulnerability.*

---

**CV3-001 | WAF-Will-Catch-It**

Claiming a Web Application Firewall makes the underlying flaw irrelevant, despite well-documented WAF bypass classes. The fix shifts to the WAF rather than the vulnerable code.

*Pattern indicator: "Our WAF blocks SQLi payloads, so this is informational."*

Bugcrowd's "Three Principles of Bug Bounty Duplicates" explicitly rejects WAF-as-fix; Sika Security's WAF-evasion review documents systematic bypasses including the CVE-2025-29927 Next.js middleware-header bypass.

Related: CV3-006 (Defense-in-Depth-As-Excuse)

---

**CV3-002 | Region-Blocked-So-Safe**

Asserting that geo/IP blocking removes risk, ignoring VPNs, proxies, and compromised in-region devices.

*Pattern indicator: "We geofence to allowed countries; this isn't exploitable for our users."*

The Australian Cyber Security Centre's "Geo-blocking in Context" warns this is bypassed routinely; DigiCert/Vercara documentation notes geo-blocking is "losing its edge."

Related: CV3-004 (Behind-the-VPN)

---

**CV3-003 | Network-Segmentation-Handwave**

Pointing to claimed network segmentation that has not been verified to actually isolate the vulnerable component from relevant attack paths.

*Pattern indicator: "That system is on an internal segment; external attackers can't reach it."*

Numerous ICS/OT disclosures where "air-gapped" or "segmented" systems were reachable via engineering workstations or vendor remote-access channels.

Related: CV3-004 (Behind-the-VPN), CV3-017 (Air-Gap-Assumed)

---

**CV3-004 | Behind-the-VPN**

Dismissing a vulnerability because the asset is "only reachable from the corporate VPN," when the same asset is later found internet-exposed via a forgotten subdomain, cloud misconfiguration, or shadow IT.

*Pattern indicator: "This endpoint requires VPN access; it's not accessible to external attackers."*

Recurring pattern in cloud-migration postmortems where dev/staging assets migrated without removing VPN-only assumptions.

Related: CV3-002 (Region-Blocked-So-Safe), CV3-003 (Network-Segmentation-Handwave), CV3-038 (Test/Staging-So-Doesn't-Matter)

---

**CV3-005 | Authenticated-Endpoint-Therefore-Safe**

Treating "requires login" as a full security mitigation, ignoring credential stuffing, IDOR, account creation flows, or the CVSS Privileges Required (PR) metric, which distinguishes *having* credentials from *having high-privileged* credentials.

*Pattern indicator: "Only authenticated users can reach this endpoint; unauthenticated exploitation is not possible."*

Broad class of IDOR bugs dismissed as "authenticated only" despite any registered user being able to exploit them - a pattern critiqued in HackerOne's public disclosed reports.

Related: CV3-012 (Insider-Only-So-Doesn't-Count), CV3-014 (Trusted-User-Required)

---

**CV3-006 | Defense-in-Depth-As-Excuse**

Citing "defense in depth" as a reason *not* to fix a specific layer, inverting the principle. Defense in depth assumes each layer will sometimes fail; citing it to justify leaving a layer broken nullifies the rationale.

*Pattern indicator: "Even if this were exploited, our other security layers would stop the attacker."*

Critiqued in Bugcrowd VRT guidance against treating WAF coverage as an equivalent fix; see also CV3-001.

Related: CV3-001 (WAF-Will-Catch-It), CV3-008 (We-Have-Logging/Detection), CV3-009 (EDR-Will-Catch-the-Payload)

---

**CV3-007 | Rate-Limiting-Suffices**

Claiming a rate limit prevents enumeration or brute-force attacks without demonstrating that the limit is enforced server-side, applied per-account (not per-IP), and resistant to distributed or rotating clients.

*Pattern indicator: "We rate-limit that endpoint; bulk enumeration isn't feasible."*

Credential-stuffing disclosures where per-IP rate limits were trivially bypassed with residential proxies; account-enumeration bugs similarly dismissed.

Related: CV3-005 (Authenticated-Endpoint-Therefore-Safe)

---

**CV3-008 | We-Have-Logging/Detection**

Substituting detection capability for prevention, without committing to specific alerting thresholds, response SLAs, or demonstrating that the detection actually fires on the reported attack pattern.

*Pattern indicator: "We'd see this in our SIEM before any real damage occurred."*

Post-incident reviews routinely reveal that detection rules existed but were not tuned to fire on the specific attack pattern, or that SLA gaps allowed attackers to complete objectives before response.

Related: CV3-006 (Defense-in-Depth-As-Excuse), CV3-009 (EDR-Will-Catch-the-Payload)

---

**CV3-009 | EDR-Will-Catch-the-Payload**

Citing endpoint detection and response (EDR) coverage as a reason not to fix an exploitable code-execution flaw, without demonstrating that the EDR triggers on the reported exploit technique.

*Pattern indicator: "Our EDR solution would flag any exploitation attempt at the endpoint level."*

Memory-corruption and LOLBin-based exploit disclosures where EDR bypass is a documented and practiced technique; the existence of EDR does not neutralize the underlying vulnerability.

Related: CV3-006 (Defense-in-Depth-As-Excuse), CV3-008 (We-Have-Logging/Detection), CV3-010 (Compiler-Mitigations-Handle-It)

---

**CV3-010 | Compiler-Mitigations-Handle-It**

Asserting that compiler-level mitigations (ASLR, DEP/NX, CFG, stack cookies) neutralize a memory-corruption vulnerability without demonstrating that exploitability is actually constrained given the specific flaw, platform, and available exploit primitives.

*Pattern indicator: "Modern compilers include stack canaries and ASLR; this class of bug is not practically exploitable."*

CVE disclosures for heap-corruption and type-confusion bugs where researchers subsequently published working exploits despite "mitigated" claims; public ASLR-bypass and info-leak chaining techniques are well-cataloged.

Related: CV3-009 (EDR-Will-Catch-the-Payload), CV3-025 (Theoretical-Only)

---

### Category B - Threat-Model Gaming (CV3-011 … CV3-019)

*Re-defining the threat model to write the vulnerability out of scope.*

---

**CV3-011 | Not-In-Our-Threat-Model**

Declaring an attack class out of consideration after the fact, with no publicly published threat model that could have put the reporter on notice before submission.

*Pattern indicator: "Attacks of this type are outside our threat model."*

Vendors in regulated sectors (finance, healthcare) retroactively invoking a "threat model" that was never published to dismiss reports on lateral-movement or supply-chain vectors.

Related: CV3-015 (Customer-Misconfiguration), CV3-047 (Disingenuous-Out-of-Scope)

---

**CV3-012 | Insider-Only-So-Doesn't-Count**

Treating any vector that requires authenticated or employee-level access as ignorable, despite OWASP Top 10 listing Broken Access Control as the most prevalent web vulnerability class.

*Pattern indicator: "An attacker would need an existing account to exploit this."*

Privilege-escalation and IDOR bugs dismissed under this pattern are a consistent staple of HackerOne public disclosures; OWASP's A01:2021 (Broken Access Control) exists precisely because the "authenticated-only" framing is insufficient.

Related: CV3-005 (Authenticated-Endpoint-Therefore-Safe), CV3-014 (Trusted-User-Required)

---

**CV3-013 | Physical-Access-Game-Over**

Dismissing local or physical attacks (evil-maid, JTAG, SD-card swap) with "if the attacker has physical access, you've already lost" - ignoring that laptop theft, public kiosks, ATMs, medical devices, and voting machines all have adversaries who specifically seek physical access.

*Pattern indicator: "Physical access to the device is a prerequisite, so this is out of scope."*

Voatz vs. MIT (2020): Voatz disputed attack scenarios as "unrealistic" despite the State of West Virginia having commissioned the MIT analysis. Trail of Bits' subsequent audit confirmed the MIT findings (StateScoop coverage).

**Does NOT apply when:** The product is genuinely not designed to resist a physically-present attacker - e.g., a consumer router's reset button, a developer-mode toggle on hardware explicitly sold as developer hardware - and the threat model is documented and published.

Related: CV3-011 (Not-In-Our-Threat-Model), CV3-017 (Air-Gap-Assumed)

---

**CV3-014 | Trusted-User-Required**

Reframing a privilege-escalation flaw as "requires a malicious admin" when the reported bug *is* the path to gaining that privileged access.

*Pattern indicator: "Only an administrator could trigger this behavior."*

Privilege-escalation disclosures where the entire point is that a lower-privileged user can reach admin-equivalent capabilities; the "trusted user" framing assumes the post-exploitation state rather than the entry condition.

Related: CV3-005 (Authenticated-Endpoint-Therefore-Safe), CV3-012 (Insider-Only-So-Doesn't-Count)

---

**CV3-015 | Customer-Misconfiguration**

Declaring that the bug only manifests under non-default configurations the customer "shouldn't have" set, even when that configuration is documented, common in production, or reachable through the product's own UI without warnings.

*Pattern indicator: "This only occurs if the customer has misconfigured the system outside of our recommended settings."*

Web frameworks where disabling CSRF protection is a documented one-liner, and bugs triggered by that setting are dismissed as "misconfiguration" despite the setting being a standard deployment choice.

**Does NOT apply when:** The configuration is genuinely off-policy - documented in a hardening guide that explicitly prohibits it, gated behind a prominent security warning in the UI, and not commonly set in production deployments.

Related: CV3-011 (Not-In-Our-Threat-Model), CV3-016 (Won't-Fix-You-Misuse-Our-Product)

---

**CV3-016 | Won't-Fix-You-Misuse-Our-Product**

Pinning the security issue on user error rather than insecure-by-default design, allowing the vendor to avoid fixing behavior that a reasonable user would not recognize as dangerous.

*Pattern indicator: "Users should not be doing X with our product; this is operator error."*

"Security by obscurity" defaults in enterprise software (e.g., default credentials, plaintext storage enabled by default) dismissed as user-misuse when researchers flag them.

Related: CV3-015 (Customer-Misconfiguration), CV3-032 (Customer-Demanded-It)

---

**CV3-017 | Air-Gap-Assumed**

ICS/OT and medical-device vendors assuming network isolation that does not exist in actual customer deployments, dismissing vulnerabilities as irrelevant because "the device is not internet-connected."

*Pattern indicator: "Our devices operate on isolated networks; network-based attacks are not part of our risk model."*

St. Jude Medical vs. MedSec (2016): St. Jude initially denied the cardiac device vulnerabilities were exploitable, in part on network-isolation grounds; FDA and DHS independently confirmed the flaws in Jan 2017. Medtronic pacemaker disclosures by Billy Rios and Jonathan Butts followed a similar arc.

Related: CV3-003 (Network-Segmentation-Handwave), CV3-013 (Physical-Access-Game-Over)

---

**CV3-018 | Threat-Actor-Wouldn't-Bother**

"Nobody would actually exploit this" - dismissing a vulnerability by asserting that no realistic attacker would invest the effort, while ignoring opportunistic, automated, and supply-chain attackers who actively scan for and weaponize exactly this class of bug.

*Pattern indicator: "The sophistication required makes this an unrealistic attack scenario."*

Shodan and similar services routinely find automated exploitation within hours of PoC publication; the "nobody would bother" framing is contradicted by mass-exploitation events for bugs initially characterized as "low practical risk."

Related: CV3-025 (Theoretical-Only), CV3-026 (No-Real-Life-Exploitation-Observed)

---

**CV3-019 | Single-Tenant-Therefore-Safe**

Dismissing multi-tenant cloud bugs because the reporter only proved cross-tenant impact in their own tenant, requiring the researcher to prove harm against *other customers* as a condition of acknowledging the flaw.

*Pattern indicator: "You only demonstrated access to your own tenant's data; no other customers were affected."*

A recurring pattern in cloud-platform bug bounty disclosures; tenant-isolation bypass bugs frequently get reclassified as "no customer impact" when the researcher (correctly) stopped short of accessing real customer data. See also CV3-069 (Demanding-Illegal-Proof).

Related: CV3-069 (Demanding-Illegal-Proof), CV3-081 (Demand-Customer-Data-As-Proof)

---

### Category C - Severity Manipulation / CVSS Gaming (CV3-020 … CV3-028)

*Distorting the severity calculus to drop the bug below the action threshold.*

---

**CV3-020 | CVSS-AV-Downgrade**

Scoring the Attack Vector as Adjacent or Local without justification when the vector is actually Network, thereby reducing the base score and deprioritizing the report.

*Pattern indicator: "We scored this as AV:A because the endpoint is not directly internet-accessible."*

The 2025 CISA/researcher disagreement on the Next.js middleware bypass (CVE-2025-29927): initial vendor scoring placed the attack vector lower than researchers and CISA concluded was warranted, documented by Mazehq's analysis.

Related: CV3-004 (Behind-the-VPN), CV3-021 (CVSS-PR-Inflation)

---

**CV3-021 | CVSS-PR-Inflation**

Marking Privileges Required (PR) as High when the bug enables privilege acquisition, or when "any registered user" qualifies as the attacker - treating the post-exploitation state as the entry precondition.

*Pattern indicator: "Exploitation requires administrative access, so we've scored PR:H."*

Privilege-escalation disclosures where the reported path *is* the route from low-privilege to high-privilege; marking PR:H under those circumstances makes the CVSS score circular.

Related: CV3-014 (Trusted-User-Required), CV3-020 (CVSS-AV-Downgrade)

---

**CV3-022 | CVSS-UI-Inflation**

Asserting User Interaction (UI) is Required when the actual trigger is invisible to the victim - an auto-loaded image, background fetch, prefetch, or drive-by iframe - thereby reducing the base score.

*Pattern indicator: "The victim must click a link, so we've scored UI:R."*

Zoom's local web server disclosure (Leitschuh, CVE-2019-13450): exploitation occurred via an iframe that silently invoked the local web server; characterizing this as requiring meaningful user interaction understated the severity.

Related: CV3-020 (CVSS-AV-Downgrade), CV3-023 (CVSS-Scope-Reduction)

---

**CV3-023 | CVSS-Scope-Reduction**

Refusing to mark Scope as Changed (S:C) when the reported exploit demonstrably crosses sandbox, tenant, or origin boundaries, keeping the score in a lower range.

*Pattern indicator: "The impact is confined to the vulnerable component, so Scope is Unchanged."*

Cross-tenant cloud bugs and same-site scripting vulnerabilities where the vulnerable component is clearly distinct from the impacted component, but vendors score S:U to keep the CVSS base score below patch-SLA thresholds.

Related: CV3-022 (CVSS-UI-Inflation), CV3-024 (CVSS-Confidentiality-Lowballing)

---

**CV3-024 | CVSS-Confidentiality-Lowballing**

Treating PII, authentication tokens, or session credentials as Low confidentiality impact because "no financial data" is exposed, ignoring that authentication material and personal data are themselves high-value targets.

*Pattern indicator: "No payment card data or financial records are accessible, so C:L."*

API-key or session-token disclosure reports downgraded to "Informational" on the grounds that the exposed data is "not financial" - a framing at odds with GDPR/CCPA regulatory definitions and real-world attacker motivation.

Related: CV3-023 (CVSS-Scope-Reduction), CV3-027 (Informational-Reclassification)

---

**CV3-025 | Theoretical-Only**

Declaring a vulnerability "theoretical" when no public exploit exists yet, conflating *exploit availability* with *exploitability*. Absence of a public exploit is not evidence that exploitation is infeasible.

*Pattern indicator: "There is no known working exploit for this vulnerability."*

Discussed by Jeff Williams in "What Makes a Vulnerability Theoretical"; numerous CVEs initially labeled "theoretical" or "not practically exploitable" have had working exploits published within weeks of disclosure.

**Does NOT apply when:** The reporter has not demonstrated a working PoC against current code and the asserted impact relies on speculative chaining (e.g., "this *could* be exploited if X, Y, and Z were all true simultaneously"). The evasion is calling a working PoC "theoretical"; the legitimate response is requesting one when the PoC is genuinely absent.

Related: CV3-018 (Threat-Actor-Wouldn't-Bother), CV3-026 (No-Real-Life-Exploitation-Observed)

---

**CV3-026 | No-Real-Life-Exploitation-Observed**

Using absence of observed in-the-wild exploitation as a proxy for low severity, even though most vulnerabilities are exploited before detection, and most exploitation is never publicly attributed.

*Pattern indicator: "We have not observed this vulnerability being exploited in real-life usage of our products."*

Cellebrite's response to Moxie Marlinspike's UFED disclosure (Signal blog, 2021): *"Based on our reviews, we have not found any instance of this vulnerability being exploited in the real-life usage of our solutions."* The absence of observed exploitation was cited as severity mitigation.

Related: CV3-025 (Theoretical-Only), CV3-018 (Threat-Actor-Wouldn't-Bother)

---

**CV3-027 | Informational-Reclassification**

Routing technically valid reports to the "Informative" bucket on bug bounty platforms (HackerOne, Bugcrowd) to avoid bounty payment and reputation impact while still benefiting from the researcher's finding.

*Pattern indicator:* A report is triaged as valid, then later reclassified to "Informative" with no substantive explanation.

HackerOne's "Informative" close-code compresses a wide range of outcomes - from genuinely low-impact findings to valid bugs the program doesn't want to pay for - into a single opaque bucket.

Related: CV3-050 (We-Already-Knew), CV3-052 (Bounty-Haggling)

---

**CV3-028 | Self-Inflicted-Only**

Labeling Self-XSS, self-CSRF, or local-only denial-of-service as zero-impact even when the reported finding is demonstrably chainable to other in-scope vulnerabilities.

*Pattern indicator: "This only affects the attacker's own account/session; there is no impact to other users."*

Self-XSS dismissed as non-issue despite documented chains (e.g., self-XSS + CSRF + social engineering escalating to account takeover) documented in HackerOne's "Self-XSS" blog post and researcher writeups.

Related: CV3-025 (Theoretical-Only), CV3-006 (Defense-in-Depth-As-Excuse)

---

### Category D - "By Design" / Expected Behavior (CV3-029 … CV3-035)

*Asserting intended design to avoid acknowledging a security flaw.*

---

**CV3-029 | Working-As-Intended**

Asserting that observed behavior is intentional design when (a) the behavior violates a security property a reasonable user would expect, (b) the "intent" was retrofitted after the report was submitted, or (c) the claimed intent cannot be reconciled with the product's stated security guarantees.

*Pattern indicator: "This is the expected behavior of our system and not a security vulnerability."*

Apple's initial response to the 2019 Group FaceTime eavesdropping bug: pre-accept audio transmission was characterized as expected state-machine behavior, despite obviously violating the user expectation that audio is not transmitted before a call is accepted.

**Does NOT apply when:** The report targets the inherent semantics of a clearly-scoped primitive whose entire contract is "execute what the caller specifies" - `system()`, `eval()`, `pickle.loads`, raw SQL execution APIs, shell-exec libraries, or MCP stdio servers executing user-configured commands. Demanding such primitives "sanitize" their inputs misidentifies the trust boundary; vendor pushback in those cases is correct, not evasive.

Related: CV3-030 (Documented-Behavior), CV3-031 (It's-A-Feature-Not-A-Bug)

---

**CV3-030 | Documented-Behavior**

Pointing to documentation that *describes* the dangerous behavior - without security warnings - to argue it cannot be a bug because it was written down. Documentation of a behavior is not the same as documentation of its security implications.

*Pattern indicator: "This behavior is documented in our user guide, so it cannot be a vulnerability."*

Networking equipment and enterprise software where default-insecure behaviors (plaintext fallbacks, debug endpoints, default credentials) appear in product documentation without security warnings; vendors cite the documentation as a defense when the behaviors are reported.

Related: CV3-029 (Working-As-Intended), CV3-034 (Spec-Compliance-Shield)

---

**CV3-031 | It's-A-Feature-Not-A-Bug**

Refusing to treat an exploitable feature as a security vulnerability, asserting that because the functionality was intentionally built, it cannot constitute a flaw. Applies where the "feature" creates an attack path beyond its intended purpose.

*Pattern indicator: "The behavior you've described is a documented feature of our product, not a vulnerability."*

Historically: Outlook desktop integrations and embedded object execution; Slack link-preview request forgery; marketing pixels used for cross-site tracking. The feature was intentional; the exploitable side-effect was not.

**Does NOT apply when:** The "feature" is a power-user primitive whose dangerous semantics are inherent to its stated purpose - debug consoles, scripting hooks, raw eval/exec APIs, developer-mode toggles. The evasion is dressing up an unintended exploit path as "intended"; the legitimate version is correctly identifying that the user invoked a sharp tool whose risks are documented.

Related: CV3-029 (Working-As-Intended), CV3-032 (Customer-Demanded-It)

---

**CV3-032 | Customer-Demanded-It**

Citing customer demand as the justification for retaining insecure default behavior - plaintext auth fallbacks, legacy protocol support, disableable security features - rather than addressing the underlying security design debt.

*Pattern indicator: "Our enterprise customers require this functionality; we cannot remove it."*

TLS 1.0/1.1 retention, SSLv3 retention post-POODLE, and similar "customer compatibility" arguments used to delay deprecation of demonstrably broken configurations.

Related: CV3-016 (Won't-Fix-You-Misuse-Our-Product), CV3-031 (It's-A-Feature-Not-A-Bug)

---

**CV3-033 | Industry-Standard-Behavior**

"Everyone does it this way" - invoking industry-wide prevalence of a vulnerability class as a justification for not fixing it. Prevalence of a behavior does not establish that the behavior is secure.

*Pattern indicator: "This is standard industry practice; all major vendors implement it this way."*

Prompt-injection dismissals in AI/LLM products, where vendors characterize the behavior as an inherent property of LLMs shared by all competitors; HTTP response-splitting and similar web vulnerabilities were historically dismissed on similar grounds before becoming recognized CVE classes.

Related: CV3-029 (Working-As-Intended), CV3-034 (Spec-Compliance-Shield)

---

**CV3-034 | Spec-Compliance-Shield**

Hiding behind an RFC or protocol specification as a defense against a security vulnerability, when the implementation has discretion to implement the spec more safely and the specification itself does not require the insecure behavior.

*Pattern indicator: "Our implementation is fully compliant with RFC XXXX; the vulnerability is in the specification, not our code."*

HTTP/1.1 request-smuggling vulnerabilities where vendors pointed to RFC ambiguities rather than implementing the more conservative parsing behavior available to them.

**Does NOT apply when:** Deviating from the specification would cause genuine interoperability breakage with deployed systems, and the security improvement is properly the specification's job to define. In that case, the right path is an RFC erratum or successor specification, not a unilateral implementation change - and that is a legitimate vendor position.

Related: CV3-030 (Documented-Behavior), CV3-033 (Industry-Standard-Behavior)

---

**CV3-035 | Won't-Fix-Inherited**

Declaring a vulnerability in an inherited dependency or upstream library "not our problem" while continuing to ship the affected version in a production product. The vendor receives the security benefit of the library without accepting responsibility for its flaws.

*Pattern indicator: "This vulnerability is in an upstream library; you should report it to them."*

Project Zero's 2025 "Reporting Transparency" initiative was a direct response to the "upstream patch gap" - the window between an upstream fix and downstream vendor integration. When downstream vendors actively disclaim responsibility, the gap widens indefinitely.

Related: CV3-040 (Third-Party-Vendor-Problem), CV3-041 (Acquired-Company-Code), CV3-076 ("Not-Our-Code")

---

### Category E - Asset Dismissal (CV3-036 … CV3-042)

*Denying responsibility for a vulnerable asset by contesting its scope or status.*

---

**CV3-036 | Decommissioned-Asset-Claim**

Claiming an exposed asset is "being retired" or "already decommissioned" to avoid acting on a still-live vulnerability, without providing verifiable evidence that the asset is offline.

*Pattern indicator: "That system is in the process of being decommissioned; it is no longer actively maintained."*

DemandScience (2024): a 122-million-record exposure was traced to a system the vendor declared had been decommissioned approximately two years earlier (Cybersecurity Insiders coverage). The asset was still serving traffic at the time of the report.

**Does NOT apply when:** The vendor can demonstrate the asset is genuinely offline - no DNS resolution, no listening services, no recorded traffic - within a defined remediation SLA, and provides verification the reporter can independently confirm.

Related: CV3-037 (Legacy-System-Therefore-Out-of-Scope), CV3-042 (Deprecated-Endpoint)

---

**CV3-037 | Legacy-System-Therefore-Out-of-Scope**

Carving out all pre-cloud-migration or "legacy" infrastructure as categorically out of scope for security response, while still serving live traffic from those assets.

*Pattern indicator: "That infrastructure is part of our legacy environment and is excluded from our bug bounty scope."*

Widespread pattern in organizations mid-migration: legacy systems remain in production for years, continue to handle customer data, but are excluded from VDP/bug-bounty programs by blanket "legacy" scope exclusions.

Related: CV3-036 (Decommissioned-Asset-Claim), CV3-039 (Old-Version-No-Longer-Supported)

---

**CV3-038 | Test/Staging-So-Doesn't-Matter**

Dismissing reports against `staging.`, `dev.`, or `qa.` subdomains that contain real customer data, share authentication infrastructure with production, or are reachable by external attackers.

*Pattern indicator: "This is a staging environment and does not contain production data."*

Staging environments with real customer PII or live payment integrations are routinely discovered in bug bounty disclosures; the "staging" label does not reflect the data sensitivity. HackerOne's public disclosed reports document multiple cases of staging-to-prod auth token reuse.

Related: CV3-004 (Behind-the-VPN), CV3-036 (Decommissioned-Asset-Claim)

---

**CV3-039 | Old-Version-No-Longer-Supported**

Dismissing a report by asserting the vulnerability was analyzed against an old, unsupported version - without proving that the same vulnerabilities are actually fixed in the current version.

*Pattern indicator: "The application version you tested is outdated; please retest against our current release."*

Voatz vs. MIT (2020): Voatz stated the analyzed Android app was *"at least 27 versions old at the time of their disclosure and not used in an election"* - but the same underlying flaws were never proven fixed until Trail of Bits' independent audit confirmed the MIT findings (StateScoop coverage).

**Does NOT apply when:** The vendor can demonstrate (a) the vulnerable code path no longer exists in the current codebase and (b) no production deployment runs the old version. Pointing at "old version" without proving the bug is actually fixed in current code is the evasive form.

Related: CV3-036 (Decommissioned-Asset-Claim), CV3-037 (Legacy-System-Therefore-Out-of-Scope), CV3-071 (Quick-Fix-Marked-As-Fix)

---

**CV3-040 | Third-Party-Vendor-Problem**

Passing responsibility to a SaaS provider, cloud platform, or component supplier while the vulnerable integration is the reporting vendor's own product and their own responsibility to customers.

*Pattern indicator: "This vulnerability is in our third-party provider's infrastructure; please contact them directly."*

A class of API-integration bugs where the vendor's own OAuth flow or webhook configuration creates the vulnerability, but the vendor redirects researchers to the upstream platform.

Related: CV3-035 (Won't-Fix-Inherited), CV3-041 (Acquired-Company-Code), CV3-076 ("Not-Our-Code")

---

**CV3-041 | Acquired-Company-Code**

Disclaiming security responsibility for vulnerabilities in code or infrastructure inherited from a recent acquisition, while continuing to sell and operate the acquired product.

*Pattern indicator: "This system was part of an acquisition and has not yet been integrated into our security program."*

Post-M&A disclosures where the acquired product continues to serve customers under the acquiring company's brand while security response is deferred indefinitely pending "integration." Customers have no visibility into which product lines are in scope for security response.

Related: CV3-035 (Won't-Fix-Inherited), CV3-040 (Third-Party-Vendor-Problem)

---

**CV3-042 | Deprecated-Endpoint**

Claiming an API endpoint or feature is deprecated and therefore not a security concern, while the endpoint still accepts traffic, processes live data, and has no planned removal date or enforced sunset.

*Pattern indicator: "That API endpoint has been deprecated; we recommend migrating to our new API."*

APIs marked "deprecated" in documentation but still fully operational and serving production integrations for years; the deprecation label functions as indefinite scope exclusion without any actual decommissioning.

Related: CV3-036 (Decommissioned-Asset-Claim), CV3-037 (Legacy-System-Therefore-Out-of-Scope)

---

### Category F - Process Deflection (CV3-043 … CV3-053, CV3-079 … CV3-082)

*Using administrative, procedural, or platform mechanics to stall, deny, or silence reports.*

---

**CV3-043 | No-Security-Contact**

Providing no discoverable security contact - no `security.txt`, no `security@` address, no Vulnerability Disclosure Policy - making it structurally impossible for researchers to report in good faith.

*Pattern indicator:* Researcher cannot find a security contact and falls back to general support or social media; report never reaches a security team.

Documented as "the greatest hurdle for researchers" by CISA's Beardsley and Larson (May 2024). CISA's "Secure by Design" guidance explicitly calls out missing security contacts as a baseline failure.

Related: CV3-044 (Black-Hole-Inbox), CV3-074 (Force-Through-Their-Bounty)

---

**CV3-044 | Black-Hole-Inbox**

Reports sent to a documented security channel receive no substantive response. In the common variant, an autoresponder fires and provides a plausible-deniability surface ("we acknowledged receipt"); in the more extreme variant, even that is absent and the channel functions as a dead drop.

*Pattern indicator:* Report delivered to a documented, non-bouncing channel; at most an automated acknowledgment is received; no human engagement follows.

Described as a near-universal researcher experience in Cosive's "Don't Shoot the Messenger".

**Does NOT apply when:** The reporter has not allowed a reasonable response window, the message failed delivery (bounce, DKIM/SPF/DMARC, attachment filtering), or the channel used was not the vendor's documented one.

Related: CV3-043 (No-Security-Contact), CV3-045 (Ghosting-Post-Triage), CV3-079 (No-Support-Contract)

---

**CV3-045 | Ghosting-Post-Triage**

A triager confirms the report and accepts it for remediation, then the program or vendor stops responding entirely - no patch timeline, no status updates, no resolution.

*Pattern indicator:* Report transitions to "triaged" or "in progress," then goes silent for weeks or months.

The Register (January 2026): HackerOne's Internet Bug Bounty program ghosted researcher Tomek Ciolek for $8,500 across two confirmed CVEs in Argo CD after initial triage acceptance.

Related: CV3-044 (Black-Hole-Inbox), CV3-046 (Indefinite-Patch-Delay)

---

**CV3-046 | Indefinite-Patch-Delay**

A vulnerability is acknowledged and accepted but never remediated - a "pile of unfixed bugs" pattern where triage completion is used as a substitute for actual remediation.

*Pattern indicator:* Report ages for quarters or years in "accepted" or "in remediation" status with no shipped fix.

Katie Moussouris (Computer Weekly, 2024): *"We often see a big pile of unfixed bugs … programmes well funded by publicly traded companies."* The incentive structure of some bounty programs rewards triage throughput, not remediation velocity.

Related: CV3-045 (Ghosting-Post-Triage), CV3-070 (Embargo-Stretching)

---

**CV3-047 | Disingenuous-Out-of-Scope**

Reclassifying a clearly in-scope finding as out-of-scope after submission - especially after triage confirmation - using a scope interpretation that was not available to the reporter at submission time.

*Pattern indicator:* Report accepted by triage, then closed as out-of-scope with a retroactive interpretation of program rules.

Recurring pattern in HackerOne/Bugcrowd public disclosure discussions; Intigriti's mediation documentation acknowledges that scope disputes are among the most common researcher grievances.

Related: CV3-048 (Retroactive-Scope-Change), CV3-011 (Not-In-Our-Threat-Model)

---

**CV3-048 | Retroactive-Scope-Change**

Editing the program brief to exclude a vulnerability category *after* a report in that category has been submitted - sometimes called "scope shrinkage."

*Pattern indicator:* Program scope changes simultaneously with or shortly after a significant report; the change retroactively excludes the reported finding.

Documented in researcher community forums and Bugcrowd's "Scope Integrity" guidance; the pattern exploits the fact that program briefs are mutable and researchers have no version-controlled copy of the scope they relied upon at submission time.

Related: CV3-047 (Disingenuous-Out-of-Scope)

---

**CV3-049 | False-Duplicate**

Marking a report as a duplicate of an unrelated or non-existent prior report, depriving the researcher of bounty and credit without providing verifiable evidence that the original report exists.

*Pattern indicator:* Report closed as "Duplicate" with no original report ID, no technical correlation, or a cited original with a different root cause.

Alameen Karim Merali's Medium writeup on false-duplicate abuse; HackerOne's mediation process only intervenes above a signal threshold, leaving newcomers disproportionately exposed to this pattern.

**Does NOT apply when:** The vendor provides the original report ID, timestamp, and triage notes (with sensitive details redacted), and the technical root cause genuinely matches. A real duplicate is verifiable; a false one is asserted without evidence.

Related: CV3-050 (We-Already-Knew), CV3-075 (Reproduction-Denial)

---

**CV3-050 | We-Already-Knew**

Closing a report as "Informative" or "Known" on the basis of an internally tracked issue, without providing documentary evidence that the issue predates the researcher's submission.

*Pattern indicator: "We are already aware of this issue and have it tracked internally."*

Intigriti's own "Duplicate, related or known" documentation explicitly warns programs to provide context when invoking this close reason; researchers report frequent abuse of the "we knew" claim as an undocumented blanket dismissal.

**Does NOT apply when:** The vendor produces a dated internal ticket, commit hash, or audit finding that predates the researcher's submission and demonstrates the same root cause. "Trust us, we knew" without artifacts is the evasive form.

Related: CV3-049 (False-Duplicate), CV3-051 (Patch-In-Pipeline)

---

**CV3-051 | Patch-In-Pipeline**

"We were going to fix this anyway" - used to deny researcher credit or bounty payment after a vulnerability is reported, claiming the fix was already in development without providing evidence of a pre-existing remediation effort.

*Pattern indicator: "Our engineering team had already identified this issue and a fix is currently in development."*

Recurring pattern in bounty program disputes; like CV3-050, the claim is unfalsifiable without documentary evidence (ticket, commit, sprint record) predating the report.

Related: CV3-050 (We-Already-Knew), CV3-072 (Silent-Patching-No-Credit)

---

**CV3-052 | Bounty-Haggling**

Paying significantly less than the published bounty range after triage, typically by reclassifying the vulnerability's severity downward post-acceptance to fit a lower payout band.

*Pattern indicator:* Report triaged as high/critical, paid at low/medium rate with a retroactive severity reclassification.

Documented in researcher survey data (Bugcrowd's annual "State of Bug Bounty" and HackerOne's researcher surveys); severity reclassification after triage is cited as a primary contributor to researcher distrust of programs.

Related: CV3-027 (Informational-Reclassification), CV3-047 (Disingenuous-Out-of-Scope)

---

**CV3-053 | AI-Slop-Accusation-Misapplied**

Dismissing a careful, human-written, well-documented vulnerability report by labeling it "AI-generated slop" - a cover story legitimized by the real and documented problem of LLM-generated junk reports flooding bounty programs.

*Pattern indicator: "This report appears to have been generated by an AI tool and does not demonstrate original security research."*

Daniel Stenberg's 2025-2026 closure of curl's bug bounty program after a flood of LLM-generated false reports (Bleeping Computer, January 2026) is the canonical case establishing the legitimate form of this concern. The evasion is misapplying the label to well-researched reports that predate or contradict the LLM-slop profile.

**Does NOT apply when:** The report exhibits actual hallmarks of LLM-generated slop: hallucinated function names, references to non-existent CVEs or code paths, generic templated language with no product-specific detail, no working PoC, or refusal/inability to clarify specifics when challenged. The evasion is *misapplying* the label; applying it correctly to genuine LLM-generated nonsense is a legitimate triage decision.

Related: CV3-065 (Methodology-Attack), CV3-075 (Reproduction-Denial)

---

**CV3-079 | No-Support-Contract**

Refusing to engage on security vulnerability reports from non-paying users, treating security response as a commercial support tier rather than a public-safety obligation.

*Pattern indicator: "Please contact your account manager to open a support case."* - in reply to a security report from a community, free-tier, or trial user.

Enterprise software vendors channeling vulnerability reports through commercial support queues where community and trial users have no access, effectively blackholing reports from the highest-motivated, most technically capable segment of reporters.

**Does NOT apply when:** The vendor maintains a public security contact channel (security.txt, security@, VDP) separate from commercial support tiers, even if remediation cadence is prioritized for paying customers.

Related: CV3-043 (No-Security-Contact), CV3-044 (Black-Hole-Inbox)

---

**CV3-080 | Need-More-Data-Loop**

Repeatedly requesting additional reproduction details - especially details already provided or that would require the reporter to perform unauthorized access - as a stalling mechanism. The loop itself is the evasion: it wears down the reporter or pushes them toward committing further "unauthorized access" to satisfy each new request.

*Pattern indicator:* Sequential, escalating requests for data that was already provided, or requests that can only be fulfilled by accessing systems the reporter has no authorization to touch.

A pattern documented in CVD breakdown narratives where vendors acknowledge an issue but cycle through "we need the exact request/response," "now we need the raw HTTP log," "now we need the database schema" without any request being definitively satisfied.

**Does NOT apply when:** The vendor identifies specific, genuinely missing technical details (logs, version info, request traces, environment configuration) the reporter can lawfully provide, and the request is made once with clear triage reasoning. Related to CV3-069 (Demanding-Illegal-Proof) when the demanded data involves PII or customer-confidential material.

Related: CV3-069 (Demanding-Illegal-Proof), CV3-075 (Reproduction-Denial), CV3-081 (Demand-Customer-Data-As-Proof)

---

**CV3-081 | Demand-Customer-Data-As-Proof**

Asking the reporter to demonstrate impact by accessing actual customer data, PII, or production credentials they have no authorization to touch - framed as ordinary triage information-gathering rather than explicitly as a proof-of-exploit request.

*Pattern indicator: "Can you provide an example of a real customer record that was affected?"*

Cloud-platform disclosures where the security team, after receiving a clear tenant-isolation PoC, asks for "a specific example of another customer's data" - which would require the researcher to commit the very unauthorized access the disclosure was intended to avoid.

**Does NOT apply when:** The vendor offers a test environment, sample data, synthetic records, or a designated test account the reporter can use safely and legally.

Related: CV3-069 (Demanding-Illegal-Proof), CV3-080 (Need-More-Data-Loop), CV3-019 (Single-Tenant-Therefore-Safe)

---

**CV3-082 | Patch-Behind-Paywall**

Issuing a security fix only to paying or commercially-supported customers, leaving free-tier, community, or end-of-support users vulnerable to a now-documented issue - and, after public disclosure, to any attacker who reads the advisory.

*Pattern indicator:* Security advisory linked to a paid support tier or commercial upgrade, with no mitigation available to non-paying users.

Enterprise software vendors shipping CVE patches as part of a paid maintenance subscription; open-source forks or community editions receive no backport. After public disclosure, the unpatched population becomes an easy target.

**Does NOT apply when:** The unsupported tier is genuinely end-of-life with a documented and announced sunset date, public migration guidance, and a negligible deployed footprint.

Related: CV3-046 (Indefinite-Patch-Delay), CV3-079 (No-Support-Contract)

---

### Category G - Legal Deflection (CV3-054 … CV3-062)

*Using legal instruments to intimidate, silence, or retaliate against the reporter.*

---

**CV3-054 | CFAA-Threat**

Invoking the U.S. Computer Fraud and Abuse Act against a good-faith security reporter, exploiting the statute's remaining civil-suit "loss" threshold (the $5,000 floor can be met by remediation costs alone) even after *Van Buren v. United States* (2021) narrowed criminal exposure.

*Pattern indicator:* Vendor's legal team references "unauthorized access," "CFAA," or "computer fraud statutes" in response to a vulnerability disclosure.

DJI's Shenzhen legal team threatened Kevin Finisterre with CFAA mid-NDA negotiation (CyberScoop, November 2017), despite Finisterre having responsibly disclosed a credentials-exposure vulnerability. Riana Pfefferkorn's "Shooting the Messenger" (Stanford CIS, 2022) documents how civil CFAA suits remain viable even after *Van Buren*.

Related: CV3-055 (DMCA-§1201-Threat), CV3-059 (Criminal-Referral), CV3-061 (NDA-Tied-to-Bounty)

---

**CV3-055 | DMCA-§1201-Threat**

Invoking DMCA Section 1201 anti-circumvention provisions against security researchers who reverse-engineered a product, despite the triennial DMCA security-research exemption (most recently renewed; see New America / OTI brief).

*Pattern indicator:* Vendor references "circumvention of technological protection measures" or "DMCA §1201" in a cease-and-desist or litigation threat directed at a researcher.

Multiple EFF-documented cases of DMCA §1201 threats against researchers conducting good-faith security analysis; the exemption process requires renewal every three years and creates uncertainty that vendors exploit.

Related: CV3-054 (CFAA-Threat), CV3-056 (Copyright-Takedown), CV3-058 (Patent-Infringement-Pretext)

---

**CV3-056 | Copyright-Takedown**

Filing DMCA takedown notices against a researcher's proof-of-concept code, blog posts, or disclosure write-ups to suppress public knowledge of the vulnerability rather than to protect legitimate copyright interests.

*Pattern indicator:* DMCA takedown against a PoC repository, researcher blog, or conference presentation containing excerpts of vendor code.

E-Soft YouTube takedown documented in attrition.org's legal-threats archive; copyright claims used to remove vulnerability demonstration videos that contained brief excerpts of vendor software.

Related: CV3-055 (DMCA-§1201-Threat), CV3-057 (Trade-Secret/Defamation-Suit)

---

**CV3-057 | Trade-Secret/Defamation-Suit**

Filing a defamation, trade-secret, or tortious-interference suit against a researcher or research firm for publishing accurate vulnerability findings, using litigation costs as a deterrent rather than seeking to correct false statements.

*Pattern indicator:* Lawsuit filed after public disclosure of a confirmed vulnerability, asserting reputational or commercial damage.

*St. Jude Medical v. MedSec & Muddy Waters* (September 2016) - canonical case: defamation suit followed by FDA and DHS independently confirming the cardiac device vulnerabilities; proposed settlement included gag clauses preventing future disclosure even to federal regulators (MD+DI, 2017; Carson Block legal filing, August 2017).

Related: CV3-054 (CFAA-Threat), CV3-062 (Gag-Clause-Settlement), CV3-068 (Public-Smear/Counter-PR)

---

**CV3-058 | Patent-Infringement-Pretext**

Using a patent infringement threat to suppress security research or a disclosure presentation, weaponizing IP law against technical security work that doesn't actually infringe a valid patent claim.

*Pattern indicator:* Vendor references patent rights in a letter or lawsuit targeting a security researcher's presentation or tools.

*HID Global v. Chris Paget / IOActive* (2007): patent-infringement threat used to suppress an RFID-cloning presentation at a security conference; documented in EFF's Coders' Rights FAQ as an exemplar of IP-law abuse against security research.

Related: CV3-054 (CFAA-Threat), CV3-055 (DMCA-§1201-Threat)

---

**CV3-059 | Criminal-Referral**

Referring a good-faith security reporter to law enforcement or prosecutors, characterizing standard vulnerability-discovery techniques as criminal activity.

*Pattern indicator:* Vendor contacts law enforcement, files a police report, or publicly calls for prosecution of a researcher who disclosed a vulnerability.

Missouri DESE / Governor Mike Parson (October 2021 - February 2022): journalist Josh Renaud was threatened with prosecution after reporting that teacher SSNs were embedded in HTML source of a state website. Parson called the discovery "hacking." Cole County prosecutor declined to file charges; the underlying vulnerability had been trivially discoverable by anyone with a browser (The Register, iTnews coverage).

Related: CV3-054 (CFAA-Threat), CV3-063 ("Hacker"-Labeling), CV3-068 (Public-Smear/Counter-PR)

---

**CV3-060 | Cease-and-Desist**

Sending a cease-and-desist letter to a researcher for publishing a vulnerability report, testing an API, or distributing compatible security tools - using legal correspondence as intimidation without a viable underlying legal claim.

*Pattern indicator:* Vendor or vendor's counsel sends a C&D letter threatening litigation over a disclosure or security tool.

Talkspace's C&D to John Jackson over a free-subscription bug (TechCrunch, March 2020); What3Words v. Aaron Toponce (April 2021) over sharing the WhatFreeWords open-source alternative - characterized as a *"thinly-veiled threat of legal action"* by TechCrunch.

Related: CV3-054 (CFAA-Threat), CV3-057 (Trade-Secret/Defamation-Suit)

---

**CV3-061 | NDA-Tied-to-Bounty**

Conditioning bounty payment or vulnerability credit on signing a perpetual, broadly-worded non-disclosure agreement that functions as a gag clause preventing any future public disclosure of the vulnerability or the vendor's response.

*Pattern indicator:* Bounty payment is made contingent on signing an NDA prior to receiving payment; the NDA is not time-limited or scoped to the period before patch release.

DJI's NDA in the Finisterre case was described by Finisterre's attorneys as *"likely crafted in bad faith to silence anyone that signed it"* and functioned as a blanket gag rather than a standard confidentiality agreement pending patch (The Register, November 2017; Gizmodo coverage).

Related: CV3-062 (Gag-Clause-Settlement), CV3-074 (Force-Through-Their-Bounty)

---

**CV3-062 | Gag-Clause-Settlement**

Settling a dispute or lawsuit on terms that forbid the researcher from making future disclosures to regulators, sector authorities (FDA, DHS, ICS-CERT), or other affected parties - extending silence beyond the public to include the oversight bodies the researcher would have the strongest independent interest in notifying.

*Pattern indicator:* Settlement agreement includes clauses prohibiting disclosure to named regulatory agencies or third-party coordinators, not merely public disclosure.

The proposed *St. Jude Medical v. MedSec* settlement included a clause preventing MedSec from disclosing findings to FDA or DHS without 14 days' advance notice to the vendor (Carson Block legal filing, August 2017). The clause would have effectively given St. Jude veto power over regulatory disclosure.

Related: CV3-057 (Trade-Secret/Defamation-Suit), CV3-061 (NDA-Tied-to-Bounty)

---

### Category H - Shoot-the-Messenger (CV3-063 … CV3-069)

*Attacking the reporter's character, motives, identity, or methods to delegitimize the finding.*

---

**CV3-063 | "Hacker"-Labeling**

Publicly branding a good-faith reporter a "hacker" with criminal connotations - in press releases, official statements, or law-enforcement referrals - to shift public and regulatory attention from the vulnerability to the reporter's conduct.

*Pattern indicator:* Vendor uses "hacker," "unauthorized access," or "breach" language in public communications about a responsible disclosure.

Missouri Governor Mike Parson, in a press conference and official letter to teachers (October 2021), described Josh Renaud as "a hacker" for viewing HTML source containing exposed SSNs. DJI labeled Kevin Finisterre "a hacker who obtained some of this data" in its public response to his disclosure.

Related: CV3-059 (Criminal-Referral), CV3-068 (Public-Smear/Counter-PR)

---

**CV3-064 | Bad-Faith-Attribution**

Publicly asserting that a researcher's motivations are malicious, competitive, or agenda-driven - characterizing a coordinated disclosure effort as a "campaign" or "attack" to deflect attention from the findings.

*Pattern indicator: "These researchers have an agenda to harm our company / are conducting a coordinated campaign against us."*

Voatz CEO Nimit Sawhney accused MIT researchers of an *"urge to make a scandal"* and a *"coordinated campaign"* in a Fortune magazine interview (March 2020), despite the analysis being commissioned by the State of West Virginia.

Related: CV3-063 ("Hacker"-Labeling), CV3-065 (Methodology-Attack)

---

**CV3-065 | Methodology-Attack**

Attacking the researcher's methodology - wrong app version, failure to use the official bug-bounty channel, anonymous identity, inadequate technical credentials - to discredit findings without engaging with the technical substance.

*Pattern indicator: "The researchers did not use current software / did not follow our disclosure process / cannot be verified as credentialed experts."*

Voatz's public response to the MIT research combined CV3-039 (Old-Version), CV3-064 (Bad-Faith-Attribution), and CV3-065: wrong app version, researcher identity/affiliation, and failure to use the Bugcrowd program were all cited to question findings that Trail of Bits subsequently confirmed.

Related: CV3-064 (Bad-Faith-Attribution), CV3-066 (Identity/Affiliation-Demand)

---

**CV3-066 | Identity/Affiliation-Demand**

Demanding that the researcher dox themselves, identify all collaborators, or disclose their employer as a precondition for engaging with the report - creating exposure to employer pressure or retaliation as a side effect.

*Pattern indicator: "Please provide your full legal name, employer, and a list of everyone who has access to this information."*

What3Words demanded Aaron Toponce identify everyone he had shared the WhatFreeWords open-source alternative with, as part of its C&D response (TechCrunch, April 2021). The demand was for information well beyond what was necessary for triage.

Related: CV3-065 (Methodology-Attack), CV3-067 (Employer-Pressure)

---

**CV3-067 | Employer-Pressure**

Contacting a researcher's employer to apply pressure, frame the researcher as having conducted unauthorized activity, or seek to have the researcher disciplined - going around the researcher to achieve silencing through professional consequences.

*Pattern indicator:* Vendor contacts the researcher's employer directly about the disclosure without the researcher's knowledge or consent.

Charlie Miller / T-Mobile / Google: vendor contacted Miller's employer about a vulnerability report, delivering what attrition.org's archive documents as a "responsible disclosure lecture" to the employer rather than engaging with the technical finding.

Related: CV3-066 (Identity/Affiliation-Demand), CV3-068 (Public-Smear/Counter-PR)

---

**CV3-068 | Public-Smear/Counter-PR**

Issuing press releases, holding press conferences, or publishing official statements framing the researcher as the source of harm - shifting the public narrative from "vendor had a vulnerability" to "researcher behaved improperly."

*Pattern indicator:* Vendor initiates proactive media outreach positioning the researcher as an actor who threatened or harmed users.

Missouri DESE's official letter to teachers (October 2021) stated that *"an individual took the records of at least three educators"* - framing what was actually a view-source disclosure as an act of data theft, covered by The Register and iTnews.

Related: CV3-063 ("Hacker"-Labeling), CV3-064 (Bad-Faith-Attribution), CV3-059 (Criminal-Referral)

---

**CV3-069 | Demanding-Illegal-Proof**

Asking the researcher to demonstrate full impact by performing acts that would themselves constitute unauthorized access - e.g., "prove you can read other customers' data" without providing authorization to do so.

*Pattern indicator: "Can you demonstrate that you could access another user's account / extract production records / exfiltrate customer data?"*

EFF's Coders' Rights FAQ flags this as a recurring trap in vendor responses: the demand converts good-faith research into a crime if the researcher complies, and is used as a pretext to dismiss the report if they refuse. Related to CV3-081 (Demand-Customer-Data-As-Proof) when the framing is administrative rather than explicit.

Related: CV3-019 (Single-Tenant-Therefore-Safe), CV3-080 (Need-More-Data-Loop), CV3-081 (Demand-Customer-Data-As-Proof)

---

### Category I - Coordination Manipulation (CV3-070 … CV3-074, CV3-083 … CV3-087)

*Distorting the coordinated disclosure process to the vendor's advantage.*

---

**CV3-070 | Embargo-Stretching**

Repeatedly extending the agreed disclosure embargo without delivering a fix, exploiting researchers' goodwill and their reluctance to publish without warning - indefinitely delaying public notification.

*Pattern indicator:* Vendor requests embargo extension past the agreed deadline without producing a shipped patch or concrete commit date.

Project Zero's 2021 adoption of a strict 90+30 day policy and its 2025 "Reporting Transparency" initiative were direct responses to repeated embargo-stretching by vendors who used researcher cooperation as an indefinite patch-delay mechanism.

Related: CV3-046 (Indefinite-Patch-Delay), CV3-071 (Quick-Fix-Marked-As-Fix)

---

**CV3-071 | Quick-Fix-Marked-As-Fix**

Shipping a partial mitigation that addresses a surface symptom of the vulnerability and closing the report, without fixing the underlying flaw - or shipping a fix that is later regressed.

*Pattern indicator:* Vendor closes report as "Resolved" after a change that does not address the root cause or that is reverted in a subsequent release.

Zoom's response to Jonathan Leitschuh's disclosure (CVE-2019-13450): a "quick fix" disabled meeting-creator video defaults but left the local web server - the actual attack surface - in place. The fix was later regressed; Threatpost and Gizmodo (July 2019) documented the regression.

Related: CV3-070 (Embargo-Stretching), CV3-072 (Silent-Patching-No-Credit), CV3-039 (Old-Version-No-Longer-Supported)

---

**CV3-072 | Silent-Patching-No-Credit**

Shipping a security fix without issuing a CVE, publishing a security advisory, or providing researcher credit - preventing defenders from prioritizing the patch and preventing the reporter from receiving recognition.

*Pattern indicator:* Vulnerability disappears in a release changelog entry like "miscellaneous security improvements"; no CVE assigned; no credit to reporter.

Rapid7's Tod Beardsley ("The Hidden Harm of Silent Patches," 2022): *"No credit, no explanation, no CVE ID - this was the standard silent patching model."* Fortinet's November 2025 FortiWeb disclosure (FG-IR-25-910 / CVE-2025-64446) is a recent exemplar documented by CSO Online.

Related: CV3-071 (Quick-Fix-Marked-As-Fix), CV3-051 (Patch-In-Pipeline)

---

**CV3-073 | Branded-Vuln-Hijack**

The vendor races to brand, name, and publicly disclose the vulnerability under their own narrative before the researcher can publish - seizing control of the story while the researcher is still under embargo.

*Pattern indicator:* Vendor publishes an advisory naming and framing the vulnerability before the coordinated disclosure date, cutting off the researcher's ability to control their own publication.

The CrushFTP / VulnCheck / Outpost24 dispute over CVE-2025-31161 (2025): competing claims over disclosure credit and narrative control, with the timing and framing of the initial advisory contested by multiple parties.

Related: CV3-070 (Embargo-Stretching), CV3-072 (Silent-Patching-No-Credit)

---

**CV3-074 | Force-Through-Their-Bounty**

Mandating that any disclosure of a vulnerability must go through the vendor's proprietary bug-bounty platform with attached NDA terms - using the platform as a funnel that prevents public disclosure and conditions payment on silence.

*Pattern indicator:* VDP or disclosure policy states that all reports must be submitted via a named platform and that submission implies acceptance of that platform's NDA terms.

PayPal's VDP funneled all reporters into HackerOne with mandatory NDA terms; CSO Online's "Bug bounty platforms buy researcher silence" (2020) documents how platform-embedded NDAs are used to structurally prevent researchers from ever making public disclosures.

Related: CV3-061 (NDA-Tied-to-Bounty), CV3-043 (No-Security-Contact)

---

**CV3-083 | Coordinated-Disclosure-Refusal**

Refusing to participate in any coordinated disclosure timeline whatsoever - blocking multi-party CVD even when the vulnerability affects downstream products, third-party integrators, or other vendors sharing a vulnerable component.

*Pattern indicator: "We do not negotiate disclosure dates."* - or complete non-engagement with proposed embargo timelines.

Multi-party protocol or library vulnerabilities where one affected vendor's refusal to coordinate forces other parties to choose between disclosing without a complete patch matrix or indefinitely delaying notification to all affected users.

**Does NOT apply when:** The vendor commits to immediate public disclosure on a verifiable and published timeline, AND there are no downstream parties requiring coordination (e.g., a self-contained bug in a single product with no library, protocol, or platform fan-out).

Related: CV3-070 (Embargo-Stretching), CV3-084 (Downstream-Notification-Blockade), CV3-085 (Unilateral-Process-Insistence)

---

**CV3-084 | Downstream-Notification-Blockade**

Preventing CERT/CC, sector ISACs, ICS-CERT, or other neutral coordinators from notifying downstream parties - effectively asserting that no one else needs to know about the vulnerability until the vendor's internal patch timeline completes.

*Pattern indicator:* Vendor instructs coordinator not to notify downstream integrators or affected parties pending the vendor's own patch release.

Particularly damaging in the ICS/OT and medical device sectors, where a shared embedded component may be present in dozens of downstream products; a single vendor's blockade delays the entire downstream notification chain.

**Does NOT apply when:** The vendor is running its own verified downstream notification with a documented timeline and demonstrated outreach to all known affected parties - and the coordinator can independently verify that outreach is occurring.

Related: CV3-083 (Coordinated-Disclosure-Refusal), CV3-086 (Coordinator-Bypass), CV3-087 (Multi-Party-Free-Riding)

---

**CV3-085 | Unilateral-Process-Insistence**

Refusing to engage with any disclosure framework other than the vendor's own internal process - treating the vendor's internal queue as the only legitimate venue and refusing to discuss downstream impact, third-party coordinators, or multi-party timelines.

*Pattern indicator: "Our security team is the appropriate contact for all issues; we do not engage with third-party coordinators."*

Vendors in critical infrastructure who refuse CERT/CC or ICS-CERT involvement despite the vulnerability affecting multiple downstream OEMs - routing all discussion through a proprietary portal that has no multi-party coordination capability.

**Does NOT apply when:** The vendor's internal process genuinely incorporates multi-party coordination, downstream notification, and external coordinator engagement - e.g., an ISO/IEC 30111-aligned PSIRT with documented coordinator outreach procedures.

Related: CV3-083 (Coordinated-Disclosure-Refusal), CV3-086 (Coordinator-Bypass)

---

**CV3-086 | Coordinator-Bypass**

Communicating directly with the original reporter to draw them away from CERT/CC, ICS-CERT, FIRST members, or other neutral coordinators already engaged - fragmenting the coordination and isolating the reporter from third-party support.

*Pattern indicator:* Vendor contacts the researcher directly after a coordinator has been brought in, offering faster resolution or payment in exchange for withdrawing the coordinator.

Documented in CERT/CC's "Troubleshooting CVD" chapter as a pattern that undermines multi-party coordination precisely when it is most needed - vendors use direct outreach to fragment reporter coalitions before a coordinated disclosure date.

**Does NOT apply when:** The neutral coordinator has explicitly withdrawn from the case, or the reporter has independently requested to proceed with direct vendor contact without coordinator involvement.

Related: CV3-083 (Coordinated-Disclosure-Refusal), CV3-085 (Unilateral-Process-Insistence)

---

**CV3-087 | Multi-Party-Free-Riding**

In a multi-party CVD covering a shared vulnerable component (a library, protocol, or hardware platform), one vendor refuses to participate in coordinated fixes or coordinated disclosure while benefiting from other parties' remediation - leaving their product vulnerable after others have shipped patches and a public advisory exists.

*Pattern indicator:* Public advisory is released with a coordinated patch matrix; one named affected vendor's product remains unpatched indefinitely and the vendor did not participate in the coordination.

Shared TLS/crypto library vulnerabilities where multiple OEM vendors patch and disclose together, but one or more embedded-systems vendors never participate and never ship a fix - leaving their customers exposed to a now-public exploit after all other vendors have patched.

**Does NOT apply when:** The vendor's product is verifiably not affected by the shared issue (documented with technical evidence), or the vendor has deployed an alternative remediation that is publicly documented and independently verifiable.

Related: CV3-083 (Coordinated-Disclosure-Refusal), CV3-084 (Downstream-Notification-Blockade), CV3-035 (Won't-Fix-Inherited)

---

### Category J - Disinformation about the Bug Itself (CV3-075 … CV3-078)

*Making false or misleading factual claims about the vulnerability's nature, reproducibility, or severity.*

---

**CV3-075 | Reproduction-Denial**

Issuing "cannot reproduce" as a final, terminal answer without documenting the reproduction attempt, engaging on environment specifics, or asking the reporter for clarifying details - using an asserted inability to reproduce as a no-cost close reason.

*Pattern indicator: "We were unable to reproduce the issue in our environment."* - with no version/config detail, no request for clarification, no follow-up.

Closely paired with CV3-049 (False-Duplicate) as a low-effort close mechanism; unlike False-Duplicate it requires no fabricated prior report. Documented across researcher survey data as one of the most commonly reported forms of non-engagement.

**Does NOT apply when:** The vendor documents the reproduction attempt with specifics (versions tested, configuration, request/response traces) and asks the reporter for any genuinely missing details needed to replicate the environment. A good-faith "cannot reproduce" is collaborative and traceable; the evasive form is terminal and undocumented.

Related: CV3-049 (False-Duplicate), CV3-080 (Need-More-Data-Loop), CV3-053 (AI-Slop-Accusation-Misapplied)

---

**CV3-076 | "Not-Our-Code"**

Blaming a third-party library or component for a vulnerability that manifests in the vendor's own integration or configuration of that library, while shipping the vulnerable integration as a single, branded product.

*Pattern indicator: "The vulnerability is in [upstream library]; you should report it to the library maintainers."*

Distinct from CV3-035 (Won't-Fix-Inherited) in that CV3-076 specifically misdescribes where the bug lies - the vendor's integration is the actual vulnerable code, not the upstream library itself.

Related: CV3-035 (Won't-Fix-Inherited), CV3-040 (Third-Party-Vendor-Problem)

---

**CV3-077 | Number-Inflation-of-Steps**

Mischaracterizing trivial exploitation as a multi-step, highly technical procedure to imply that exploitation requires rare expertise and is therefore unlikely or low-severity.

*Pattern indicator:* Vendor describes the exploit path with inflated step counts or technical complexity to minimize the apparent risk.

Missouri Governor Parson stated that *"the data had to be taken through eight separate steps in order to generate a SSN"* - describing the act of base64-decoding a value visible in HTML source (The Register, iTnews). The "eight steps" characterization was widely mocked by security professionals.

Related: CV3-025 (Theoretical-Only), CV3-018 (Threat-Actor-Wouldn't-Bother)

---

**CV3-078 | Public-Statement-Contradicting-Internal-Triage**

Vendor denies the existence or validity of a vulnerability publicly while internally triaging, patching, or escalating the same issue - creating a public record that contradicts the vendor's actual internal assessment.

*Pattern indicator:* Public statement or press release says "no vulnerability exists" or "our products are not affected" while internal tickets, commits, or regulatory communications show active remediation.

St. Jude Medical's public denial of cardiac device vulnerabilities (2016): St. Jude denied the flaws publicly until FDA and DHS independently confirmed them in January 2017. Internal St. Jude documents produced in subsequent litigation showed awareness and remediation activity during the same period.

Related: CV3-068 (Public-Smear/Counter-PR), CV3-072 (Silent-Patching-No-Credit)

---

## Structural Conventions

1. **Stable IDs, evolving entries.** Once a CV3 ID has been assigned, it permanently refers to the same pattern. The textual content of an entry (description, pattern indicator, exemplars, "does NOT apply when" clauses, related-pattern links) may be clarified, expanded, or corrected over time; this is expected and encouraged as the literature and incident record grow. What may not change is the *identity* of the pattern an ID refers to. If a pattern's scope or meaning needs to shift substantively, the original ID is marked `DEPRECATED` with a pointer to a new ID, mirroring CWE's policy. ID assignment is not required to be contiguous or sequential.
2. **One-pattern-per-leaf.** Resist the urge to combine related patterns (e.g., "WAF + Network Segmentation") into a single entry; they get cited separately.
3. **Required fields:** Name, ID, Description (1-2 sentences), Pattern Indicator, Exemplar Incident with citation, Related Patterns, See-Also (CWE, CAPEC, ATT&CK where relevant).
4. **Optional fields:** Counter-evidence checklist - what would make a given dismissal *legitimate* rather than evasive. Critical for fairness and to prevent CV3 from being used as a one-sided weapon. v0.1 ships this field for the most-abusable entries; all entries should have it by v1.0.
5. **Crowdsourcing model.** Mirror Bugcrowd VRT and disclose.io: GitHub repo, open contribution guidelines, public changelog of additions and merges.
6. **Explicit non-goals.** CV3 does *not* score severity (use VRT/CVSS), does *not* arbitrate individual disputes (use HackerOne/Bugcrowd mediation, CERT/CC), and does *not* make legal claims (defer to EFF / disclose.io).

## Rationale

**1. The problem is real, recurring, and largely unenumerated.** Coordinated Vulnerability Disclosure (CVD) is described by CERT/CC's *Guide to Coordinated Vulnerability Disclosure* as a "wicked problem," and CERT/CC publishes a "Troubleshooting CVD" chapter precisely because the same dysfunctions recur. EFF's Coders' Rights FAQ, Brookings ("America's anti-hacking laws pose a risk to national security"), and Riana Pfefferkorn's "Shooting the Messenger" (Stanford CIS, 2022) all document that vendors routinely "shoot the messenger" - but none of these works tries to enumerate the specific *patterns* of dismissal in a structured way.

**2. Existing partial taxonomies are adjacent but distinct.** The Bugcrowd Vulnerability Rating Taxonomy (open-sourced 2017, currently v1.18) classifies *vulnerabilities* by priority, not vendor responses; HackerOne's report-state model has only five close states (Resolved / Informative / Not Applicable / Duplicate / Spam), which compresses a much richer space of dismissal patterns into opaque buckets; disclose.io's `research-threats` repo (continuing attrition.org's "Legal Threats Against Security Researchers" list) catalogs *individual incidents* without abstracting them into named patterns. CV3 fills the gap between incident archives and platform close-codes.

**3. Famous incidents map cleanly onto a small set of recurring patterns.** Voatz vs. MIT (disputing scope, claiming "old version," attacking researcher motives, weaponizing CFAA via amicus brief), DJI vs. Finisterre (retroactive NDA, CFAA threat, scope ambiguity, "hacker" labeling), St. Jude vs. MedSec/Muddy Waters (defamation suit, "we use external auditors" deflection), Cellebrite vs. Signal (silent partial patch, "no real-life exploitation observed"), Missouri DESE/Parson (criminalizing the reporter, "hacker" label for F12), Talkspace, What3Words, and Zoom/Leitschuh (delayed patches, "quick fix" that wasn't) are all instances of just a dozen or so root patterns. This is what makes the taxonomy tractable.

**4. AI-generated "slop" reports have shifted the legitimacy debate.** The closure of certain bounty programs after a flood of LLM-generated false reports is the inverse problem: it gives vendors a legitimate-sounding cover story ("we suspect AI slop") that can also be misused to dismiss real, careful reports. CV3 includes this pattern (CV3-053), with the explicit caveat that the dismissal is only an evasion when applied to a non-AI, well-documented report.

**5. The legal landscape only partially helps researchers.** *Van Buren v. United States* (2021) narrowed the CFAA, and DOJ's 2022 charging policy explicitly disfavors prosecution of good-faith research, but Pfefferkorn (2022) shows that the CFAA's $5,000 "loss" threshold still allows civil suits where remediation costs alone qualify - meaning that "shoot-the-messenger" CFAA threats remain a live tool even where prosecution is unlikely. CV3 treats legal threats as a category in their own right (Category G).

---

## Prior Art

| Resource | What it covers | Gap CV3 fills |
|---|---|---|
| **Bugcrowd VRT** (github.com/bugcrowd/vulnerability-rating-taxonomy, v1.18) | Baseline severity ratings for vuln *classes* (P1-P5), including a documented "out-of-scope/won't-pay" list | Doesn't name *vendor behaviors*; rates bugs, not responses |
| **HackerOne close-codes** (Resolved / Informative / Not Applicable / Duplicate / Spam) | Platform-level outcome categories | Coarse-grained; doesn't distinguish honest "Informative" from disingenuous "Informative" |
| **Intigriti "Duplicate, related or known"** docs | Acknowledges programs marking reports as duplicates of internally known issues | Describes the mechanic, not the abuse pattern |
| **OWASP Vulnerability Disclosure Cheat Sheet** | Best-practice guidance for both sides | Prescriptive, not descriptive of failure modes |
| **CERT/CC Guide to CVD**, esp. "Troubleshooting CVD" | Catalogs problems like unresponsive vendors, multi-vendor coordination failures, branded-vuln dynamics | Closest existing work; uses prose rather than ID-numbered patterns |
| **disclose.io / `research-threats` repo** (continuing attrition.org's "Legal Threats Against Security Researchers" list, FIN'd in May 2021) | Incident-level archive of legal threats | Incident catalog, not a pattern abstraction |
| **EFF Coders' Rights Vulnerability Reporting FAQ** | Legal landscape and researcher protections | Legal advice, not evasion taxonomy |
| **Pfefferkorn, "Shooting the Messenger" (Stanford CIS, 2022)** | CFAA "loss" threshold as retaliation tool | Single legal mechanism, deeply analyzed |
| **Matwyshyn et al. (Northeastern; CDT 2018 report)** | CFAA/DMCA chilling effects | Field-level analysis, not pattern enumeration |
| **Weulen Kranenbarg et al., "Don't shoot the messenger" (*Crime Science*, 2018)** | Criminological analysis of researcher-vendor dynamics | Theoretical framework |
| **Moussouris (Luta Security) talks/interviews 2019-2024** | "Bug-bounty Botox," NDA-as-silencing, pile-of-unfixed-bugs critique | Industry critique, anecdotal pattern naming |
| **Project Zero disclosure FAQ + 2025 "Reporting Transparency"** | 90+30 deadline policy, won't-fix derestriction policy | Researcher-side policy, not vendor patterns |

CV3 has a clear niche. The closest analog is CERT/CC's "Troubleshooting CVD" chapter, but it is prose, not an ID-stable enumeration, and it focuses on *coordination problems* rather than on *vendor evasion patterns* specifically. CV3 explicitly cites VRT, HackerOne close-codes, and CERT/CC and positions itself as the missing "vendor-side" complement.

---

## License

This work is licensed under [Creative Commons Attribution-ShareAlike 4.0 International (CC BY-SA 4.0)](https://creativecommons.org/licenses/by-sa/4.0/).

SPDX-License-Identifier: `CC-BY-SA-4.0`

> **Acknowledgement:** The taxonomy data in this repository was researched and curated with the assistance of [Claude Opus 4.7](https://www.anthropic.com/claude) (Anthropic).
