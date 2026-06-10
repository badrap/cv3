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
> And if it never ships, you are the problem, really.  
> And if you continue to be a problem, you'll be hearing from our counsel.  

---

## Table of Contents

- [The Taxonomy](#the-taxonomy)
  - [CV3-100 - Report Not Reportable](#cv3-100---report-not-reportable)
  - [CV3-200 - Working as Intended](#cv3-200---working-as-intended)
  - [CV3-300 - Not Exploitable in Practice](#cv3-300---not-exploitable-in-practice)
  - [CV3-400 - Not Severe Enough](#cv3-400---not-severe-enough)
  - [CV3-500 - Report Doesn't Qualify](#cv3-500---report-doesnt-qualify)
  - [CV3-600 - Fix Is on the Roadmap](#cv3-600---fix-is-on-the-roadmap)
  - [CV3-700 - Shoot the Messenger](#cv3-700---shoot-the-messenger)
  - [CV3-800 - Send in the Lawyers](#cv3-800---send-in-the-lawyers)
- [Structural Conventions](#structural-conventions)
- [Rationale](#rationale)
- [Prior Art](#prior-art)
- [License](#license)

---

## The Taxonomy

**CV3-N00 entries are category anchors.** Each names a whole family of evasion and is itself citable: cite the anchor when a vendor response clearly belongs to the family but no specific leaf fits.

**CV3-N01 and up are leaf patterns** within that family. Cite the most specific leaf that fits.

> [!IMPORTANT]  
> **Critical Framing Note**
>
> A "vendor evasion" taxonomy has a structural failure mode: researchers using it to accuse vendors who are correctly refusing to fix non-bugs. Reports against `system()`, `eval()`, `pickle.loads`, MCP stdio servers, or other primitives whose entire contract is "execute what the caller specifies" are not vendor evasions when refused; they are misidentifications of the trust boundary.
>
> CV3 names the *pattern of language*, not the verdict. For this reason, **every entry carries a "Does NOT apply when" clause**, and applying a CV3 ID without checking that clause first is itself a form of disclosure dysfunction. When the clause holds, the dismissal is legitimate.

---

### CV3-100 - Report Not Reportable

*"Thank you for your report. Your ticket number is [object Object]."*

**The family:** The report never reaches anyone empowered to act on it. The vendor provides no usable security channel, or the channel exists only as a formality. This is the earliest and most structural evasion: everything downstream of it never happens.

**Does NOT apply when:** The vendor maintains a discoverable, functioning public security channel (`security.txt`, `security@`, a VDP) and the reporter simply did not use it or did not allow a reasonable response window.

---

**CV3-101 | No-Accessible-Security-Contact**

No discoverable security contact exists - no `security.txt`, no `security@` address, no vulnerability disclosure policy - or the only route to a security team runs through a paid support tier that community, free-tier, or trial users cannot access. Either way, good-faith reporting is structurally impossible for the people most likely to find the bug.

*Pattern indicator:* Researcher falls back to general support or social media and the report never reaches a security team; or a security report is answered with *"please open a case with your account manager."*

Contacting the right people is described as [the greatest hurdle for researchers](https://www.cisa.gov/news-events/news/engaging-security-researchers-embracing-see-something-say-something-culture) by CISA's Beardsley and Larson (2024), writing from CISA's role as the U.S. federal government's central CVD team. Enterprise vendors channeling vulnerability reports into commercial support queues blackhole reports from the most motivated segment of reporters.

**Does NOT apply when:** A public security channel exists separate from commercial support tiers, even if remediation cadence is prioritized for paying customers.

Related: CV3-102 (Black-Hole-Inbox)

---

**CV3-102 | Black-Hole-Inbox**

Reports sent to a documented security channel receive no substantive response. In the common variant, an autoresponder fires and provides a plausible-deniability surface ("we acknowledged receipt"); in the more extreme variant, even that is absent and the channel functions as a dead drop.

*Pattern indicator:* Report delivered to a documented, non-bouncing channel; at most an automated acknowledgment is received; no human engagement follows.

Described as a near-universal researcher experience in Cosive's ["Don't Shoot the Messenger"](https://www.cosive.com/blog/dont-shoot-the-messenger-security-txt-and-collaborating-effectively-with-security-researchers).

**Does NOT apply when:** The reporter has not allowed a reasonable response window, the message failed delivery (bounce, DKIM/SPF/DMARC, attachment filtering), or the channel used was not the vendor's documented one.

Related: CV3-101 (No-Accessible-Security-Contact), CV3-601 (Accepted-Never-Fixed)

---

### CV3-200 - Working as Intended

*"This is the expected behavior of our system."*

**The family:** The vendor denies that what was reported is a vulnerability at all, or that it is *theirs*: it is intentional, documented, demanded by customers, required by the spec, somebody else's code, or an asset that doesn't count anymore. The shared move is substituting a claim about intent, provenance, or status for an analysis of the security property that was violated.

**Does NOT apply when:** The claimed intent, provenance, or status is verifiable, was established before the report, and genuinely places the behavior outside the security guarantees a reasonable user of the product would rely on.

---

**CV3-201 | Intended-Therefore-Not-A-Bug**

Offering intentionality as a substitute for security analysis. Manifestations: "working as intended" (the behavior was designed, therefore it cannot be a flaw), "documented behavior" (it appears in the user guide - without security warnings - therefore it cannot be a flaw), and "it's a feature, not a bug" (the functionality was deliberately built, therefore its exploitable side-effects don't count). In each form, the claimed intent either violates a security property a reasonable user would expect, was retrofitted after the report, or cannot be reconciled with the product's stated guarantees - and documentation of a behavior is not documentation of its security implications.

*Pattern indicator: "This is the expected behavior of our system and not a security vulnerability."*

Zoom's first response to the 2019 disclosure of its hidden local web server ([CVE-2019-13450](https://medium.com/bugbountywriteup/zoom-zero-day-4-million-webcams-maybe-an-rce-just-get-them-to-visit-your-website-ac75c83f4ef5)) was to [defend the server as a deliberate workaround](https://www.zoom.com/en/blog/response-to-video-on-concern/) for a browser confirmation prompt: intentional design offered as the answer to a security finding, until public pressure forced an emergency patch removing it. Default-insecure behaviors (plaintext fallbacks, debug endpoints, default credentials) are routinely defended by pointing to documentation that describes them without warning about them.

**Does NOT apply when:** The report targets the inherent semantics of a clearly-scoped primitive whose entire contract is "execute what the caller specifies" - `system()`, `eval()`, `pickle.loads`, raw SQL execution APIs, shell-exec libraries, debug consoles, or MCP stdio servers executing user-configured commands. Demanding such primitives "sanitize" their inputs misidentifies the trust boundary; vendor pushback there is correct, not evasive.

Related: CV3-203 (Norm-Compliance-Shield), CV3-308 (Blame-The-Operator)

---

**CV3-202 | Customer-Demanded-It**

Citing customer demand as the justification for retaining insecure default behavior - plaintext auth fallbacks, legacy protocol support, disableable security features - rather than addressing the underlying security design debt.

*Pattern indicator: "Our enterprise customers require this functionality; we cannot remove it."*

TLS 1.0/1.1 retention, SSLv3 retention post-POODLE, and similar "customer compatibility" arguments used to delay deprecation of demonstrably broken configurations.

**Does NOT apply when:** The capability is opt-in rather than default, carries prominent warnings, has a published deprecation timeline, and the vendor tracks the underlying issue rather than closing it.

Related: CV3-201 (Intended-Therefore-Not-A-Bug), CV3-308 (Blame-The-Operator)

---

**CV3-203 | Norm-Compliance-Shield**

Appealing to an external norm - industry-wide practice or a protocol specification - as a reason not to fix. "Everyone does it this way" treats prevalence of a vulnerability class as proof of its acceptability; "we're fully RFC-compliant" hides behind a specification when the implementation has discretion to behave more safely and the spec does not require the insecure behavior.

*Pattern indicator: "This is standard industry practice; all major vendors implement it this way."* / *"Our implementation is fully compliant with RFC XXXX."*

Prompt-injection dismissals in LLM products framed as an inherent property shared by all competitors; HTTP request-smuggling vulnerabilities defended by pointing to RFC ambiguities rather than adopting the more conservative parsing available to the implementation.

**Does NOT apply when:** Deviating from the specification would cause genuine interoperability breakage with deployed systems and the security improvement is properly the specification's job - in which case the legitimate path is an erratum or successor spec, and saying so is a defensible vendor position.

Related: CV3-201 (Intended-Therefore-Not-A-Bug)

---

**CV3-204 | Upstream-Deflection**

Disclaiming responsibility because the vulnerable code came from somewhere else - an upstream library, a third-party service, or a recent acquisition - while continuing to ship, sell, and operate the affected product. Manifestations: "report it to the library maintainers" while the affected version keeps shipping; "that's our cloud provider's infrastructure" when the vendor's own integration or configuration is the vulnerable part; and "that system hasn't been integrated into our security program yet" for acquired products still serving customers under the acquirer's brand. The aggravated form misdescribes where the bug actually lives, pointing upstream when the flaw is in the vendor's own integration.

*Pattern indicator: "This vulnerability is in [upstream component]; you should report it to them."*

Project Zero's ["Reporting Transparency" initiative](https://projectzero.google/2025/07/reporting-transparency.html) responded directly to the upstream patch gap - the window between an upstream fix and downstream integration, which widens indefinitely when downstream vendors disclaim responsibility. OAuth-flow and webhook-configuration bugs are routinely redirected to the upstream platform despite the integration being the vendor's own code; post-M&A products commonly sit outside any security program for years.

**Does NOT apply when:** The flaw is genuinely upstream, the vendor simultaneously reports or confirms it upstream, commits to integrating the fix on a stated timeline, and accepts responsibility for interim mitigations in its own product.

Related: CV3-611 (Multi-Party-Free-Riding), CV3-205 (Sunset-Claimed-Still-Live)

---

**CV3-205 | Sunset-Claimed-Still-Live**

Exempting an asset from security response by labeling it end-of-life - "being decommissioned," "legacy infrastructure outside our bug bounty scope," "deprecated endpoint" - while it verifiably continues to serve traffic, process live data, and in many cases handle customer PII, with no enforced sunset.

*Pattern indicator: "That system is being retired / is legacy / is deprecated and no longer actively maintained."*

[DemandScience (2024)](https://www.bleepingcomputer.com/news/security/leaked-info-of-122-million-linked-to-b2b-data-aggregator-breach/): contact data on 122 million people was stolen from an exposed system the vendor said had been decommissioned roughly two years earlier, a "decommissioned" system nonetheless left online for an attacker to find. Organizations mid-cloud-migration routinely exclude "legacy" systems from VDP scope while those systems remain in production for years; APIs marked deprecated stay fully operational indefinitely, the label functioning as a scope exclusion without any decommissioning.

**Does NOT apply when:** The vendor demonstrates the asset is genuinely offline (no DNS resolution, no listening services, no recorded traffic) within a defined remediation SLA - or the lifecycle claim comes with an announced sunset date, public migration guidance, and verification the reporter can independently confirm.

Related: CV3-206 (Just-A-Staging-Environment), CV3-207 (Old-Version-Tested)

---

**CV3-206 | Just-A-Staging-Environment**

Dismissing reports against `staging.`, `dev.`, or `qa.` subdomains that contain real customer data, share authentication infrastructure with production, or are reachable by external attackers. The environment label is offered as a proxy for data sensitivity, which it does not reflect.

*Pattern indicator: "This is a staging environment and does not contain production data."*

Staging environments with real customer PII or live payment integrations are routinely discovered in bug bounty disclosures; HackerOne public reports document staging-to-prod auth token reuse.

**Does NOT apply when:** The environment verifiably contains only synthetic data, shares no credentials or trust relationships with production, and its compromise grants no foothold toward production systems.

Related: CV3-205 (Sunset-Claimed-Still-Live), CV3-303 (Unreachable-By-Assumption)

---

**CV3-207 | Old-Version-Tested**

Dismissing a report by asserting the vulnerability was analyzed against an old, unsupported version - without proving that the same flaw is actually fixed in the current version. The burden is silently shifted to the reporter to re-prove the bug rather than to the vendor to show the vulnerable code path is gone.

*Pattern indicator: "The application version you tested is outdated; please retest against our current release."*

Voatz vs. MIT (2020): Voatz emphasized that the analyzed Android app was ["at least 27 versions old"](https://statescoop.com/mit-researchers-find-vulnerabilities-in-voatz-mobile-voting-app/), but Trail of Bits' subsequent audit found no security-relevant changes in the codebase that would affect the researchers' claims, confirming the MIT findings.

**Does NOT apply when:** The vendor demonstrates (a) the vulnerable code path no longer exists in the current codebase and (b) no production deployment runs the old version.

Related: CV3-205 (Sunset-Claimed-Still-Live), CV3-603 (Quick-Fix-Marked-As-Fixed)

---

### CV3-300 - Not Exploitable in Practice

*"The sophistication required makes this an unrealistic attack scenario."*

**The family:** The flaw is conceded to exist in some form, but exploitation is argued away: another control would stop it, the attacker can't reach it, the attacker would need credentials or physical presence, the threat model excludes it, or no one would bother. The shared move is substituting an unverified assumption about the attacker for an analysis of the bug.

**Does NOT apply when:** The exploitation barrier is specific, verified, and documented, not merely asserted, and the vendor demonstrates it against the reported attack path rather than against attackers in general.

---

**CV3-301 | Another-Layer-Will-Catch-It**

Claiming that a different security layer compensates for the broken one, so the broken layer needn't be fixed - inverting defense in depth, which assumes each layer will sometimes fail. Manifestations include the WAF ("our WAF blocks those payloads"), detection ("we'd see this in our SIEM"), the endpoint ("our EDR would flag the exploitation attempt"), and compiler mitigations ("ASLR and stack canaries make this impractical"). In every variant the fix is silently relocated to a layer with well-documented bypass classes, without demonstrating that the layer actually stops the reported technique.

*Pattern indicator: "Even if this were exploited, our other security layers would stop the attacker."*

Bugcrowd's ["Three Principles of Bug Bounty Duplicates"](https://www.bugcrowd.com/blog/the-three-principles-of-bug-bounty-duplicates/) explicitly rejects WAF-as-fix; the recommended interim mitigation for the Next.js middleware bypass ([CVE-2025-29927](https://github.com/vercel/next.js/security/advisories/GHSA-f82v-jwr5-mffw)), stripping a header at the WAF or proxy, was exactly that: an interim measure pending the actual patch. EDR bypass and ASLR-defeat chaining are documented, practiced techniques, and post-incident reviews routinely find that detection rules existed but never fired on the actual attack pattern.

**Does NOT apply when:** The compensating layer is demonstrated to block the specific reported technique, the vendor commits to fixing the underlying flaw on a stated timeline, and the layer is treated as a stopgap rather than the resolution.

Related: CV3-302 (Rate-Limiting-Suffices), CV3-309 (No-Exploit-No-Problem)

---

**CV3-302 | Rate-Limiting-Suffices**

Claiming a rate limit prevents enumeration or brute-force attacks without demonstrating that the limit is enforced server-side, applied per-account (not per-IP), and resistant to distributed or rotating clients.

*Pattern indicator: "We rate-limit that endpoint; bulk enumeration isn't feasible."*

Credential-stuffing disclosures where per-IP rate limits were trivially bypassed with residential proxies; account-enumeration bugs similarly dismissed.

**Does NOT apply when:** The vendor demonstrates the limit against a distributed client model (not a single IP) and the limit's parameters actually preclude the reported attack at realistic attacker scale.

Related: CV3-301 (Another-Layer-Will-Catch-It), CV3-304 (Authentication-As-Mitigation)

---

**CV3-303 | Unreachable-By-Assumption**

Asserting that a network barrier puts the vulnerable component out of the attacker's reach, without verifying that the barrier exists, holds, or covers the relevant attack paths. Manifestations: geo/IP blocking (bypassed by VPNs, proxies, and in-region compromised devices), claimed network segmentation (unverified against engineering workstations and vendor remote-access channels), VPN-only access (defeated by forgotten subdomains, cloud misconfigurations, and shadow IT), and the assumed air gap (ICS/OT and medical devices that are "not internet-connected" in the threat model but networked in actual deployments).

*Pattern indicator: "That system is on an internal segment / behind the VPN / geofenced / air-gapped; external attackers can't reach it."*

The Australian Cyber Security Centre's ["Geo-blocking in context"](https://www.cyber.gov.au/business-government/protecting-devices-systems/hardening-systems-applications/network-hardening/geo-blocking-in-context-realities-risks-and-recommendations) guidance warns geo-blocking is routinely bypassed via VPNs, proxies, and compromised in-region devices; "air-gapped" ICS systems are repeatedly found reachable via engineering workstations; St. Jude Medical initially denied its cardiac device flaws before [FDA and DHS independently confirmed them](https://www.hipaajournal.com/fda-confirms-muddy-waters-claims-st-jude-medical/) (2017); cloud-migration postmortems repeatedly surface "VPN-only" assets that became internet-exposed.

**Does NOT apply when:** The isolation is verified against the reported attack path - the vendor demonstrates (and ideally lets the reporter confirm) that the component is unreachable from the positions the report describes, including indirect paths.

Related: CV3-401 (Prerequisite-Inflation), CV3-206 (Just-A-Staging-Environment)

---

**CV3-304 | Authentication-As-Mitigation**

Treating "requires an account" as a full security mitigation - ignoring that any registered user qualifies as the attacker, that account creation is often open, and that credential stuffing and IDOR exist. [OWASP's A01:2021 (Broken Access Control)](https://owasp.org/Top10/A01_2021-Broken_Access_Control/) is the most prevalent web vulnerability class precisely because "authenticated-only" is not a meaningful barrier.

*Pattern indicator: "An attacker would need an existing account to exploit this."*

IDOR and privilege-escalation bugs dismissed as "authenticated only" despite any self-registered user being able to exploit them - a recurring pattern across HackerOne public disclosures.

**Does NOT apply when:** Accounts are genuinely scarce and vetted (no self-registration, no trial tier), and the required privilege level is itself a meaningful barrier - in which case the privilege requirement belongs in the severity discussion, not as grounds for dismissal.

Related: CV3-305 (Privilege-Circularity), CV3-302 (Rate-Limiting-Suffices)

---

**CV3-305 | Privilege-Circularity**

Dismissing a privilege-escalation flaw as "requires a privileged user" when the reported bug *is* the path to acquiring that privilege - assuming the post-exploitation state as the entry precondition. The same circularity appears in scoring as marking Privileges Required: High for the very bug that grants those privileges.

*Pattern indicator: "Only an administrator could trigger this behavior."*

Privilege-escalation disclosures where the entire point is that a lower-privileged user can reach admin-equivalent capabilities; scoring such reports PR:H makes the severity score circular.

**Does NOT apply when:** The reported path genuinely starts from a privilege level that has no unprivileged route to it, and the vendor shows that no in-scope user population holds that level by default.

Related: CV3-304 (Authentication-As-Mitigation), CV3-401 (Prerequisite-Inflation)

---

**CV3-306 | Not-In-Our-Threat-Model**

Declaring an attack class out of consideration after the fact, with no publicly published threat model that could have put the reporter on notice before submission.

*Pattern indicator: "Attacks of this type are outside our threat model."*

Vendors in regulated sectors (finance, healthcare) retroactively invoking a "threat model" that was never published to dismiss reports on lateral-movement or supply-chain vectors.

**Does NOT apply when:** The threat model was published before the report was submitted, the exclusion is specific rather than retrofitted, and the excluded class is a defensible boundary for the product's actual deployment context.

Related: CV3-502 (Retroactive-Scope-Exclusion), CV3-307 (Physical-Access-Game-Over)

---

**CV3-307 | Physical-Access-Game-Over**

Dismissing local or physical attacks (evil-maid, JTAG, SD-card swap) with "if the attacker has physical access, you've already lost" - ignoring that laptop theft, public kiosks, ATMs, medical devices, and voting machines all have adversaries who specifically seek physical access.

*Pattern indicator: "Physical access to the device is a prerequisite, so this is out of scope."*

Voatz vs. MIT (2020): Voatz disputed attack scenarios as "unrealistic" despite the State of West Virginia having commissioned the MIT analysis; Trail of Bits' subsequent audit confirmed the MIT findings.

**Does NOT apply when:** The product is genuinely not designed to resist a physically-present attacker - e.g., a consumer router's reset button, a developer-mode toggle on hardware explicitly sold as developer hardware - and the threat model is documented and published.

Related: CV3-306 (Not-In-Our-Threat-Model), CV3-303 (Unreachable-By-Assumption)

---

**CV3-308 | Blame-The-Operator**

Pinning the issue on the customer's configuration or the user's behavior rather than on insecure-by-default design. In the configuration variant, the bug "only manifests under non-default settings the customer shouldn't have set," even when that configuration is documented, common in production, and reachable through the product's own UI without warnings. In the misuse variant, dangerous default behavior (default credentials, plaintext storage, debug endpoints) is reframed as operator error that a reasonable user could not have recognized as dangerous.

*Pattern indicator: "This only occurs if the customer has misconfigured the system" / "Users should not be doing X with our product."*

Web frameworks where disabling CSRF protection is a documented one-liner and bugs triggered by that setting are dismissed as "misconfiguration"; default-credential and insecure-default findings dismissed as user misuse across enterprise software.

**Does NOT apply when:** The configuration or use is genuinely off-policy - explicitly prohibited in a hardening guide, gated behind a prominent security warning in the UI, and not commonly found in production deployments.

Related: CV3-202 (Customer-Demanded-It), CV3-201 (Intended-Therefore-Not-A-Bug)

---

**CV3-309 | No-Exploit-No-Problem**

Treating the absence of exploitation *evidence* as evidence of non-exploitability. Two manifestations: "the vulnerability is theoretical" because no public exploit exists yet (conflating exploit availability with exploitability), and "we have not observed in-the-wild exploitation" (ignoring that most exploitation is never detected or attributed, and that absence of observation is not absence of activity).

*Pattern indicator: "There is no known working exploit" / "We have not observed this being exploited in real-life usage of our products."*

Cellebrite's response to [Moxie Marlinspike's UFED disclosure](https://signal.org/blog/cellebrite-vulnerabilities/) (2021) cited the absence of observed real-world exploitation as severity mitigation; numerous CVEs initially labeled "not practically exploitable" have had working exploits published within weeks of disclosure.

**Does NOT apply when:** The reporter has not demonstrated a working PoC against current code and the asserted impact relies on speculative chaining ("this *could* be exploited if X, Y, and Z were all simultaneously true"). The evasion is calling a working PoC theoretical; requesting one when it is genuinely absent is legitimate triage.

Related: CV3-310 (Attacker-Wouldn't-Bother), CV3-301 (Another-Layer-Will-Catch-It)

---

**CV3-310 | Attacker-Wouldn't-Bother**

Asserting that no realistic attacker would invest the effort - either by claiming the required sophistication is implausibly high, or by actively mischaracterizing trivial exploitation as a long, highly technical multi-step procedure. Both forms ignore opportunistic, automated, and supply-chain attackers who scan for and weaponize exactly this class of bug.

*Pattern indicator: "The sophistication required makes this an unrealistic attack scenario."* - or an inflated step count describing a trivial action.

Mass exploitation routinely begins within hours of PoC publication for bugs initially characterized as low practical risk. Missouri's governor asserted that exposed teacher SSNs in a state website's HTML source ["had to be taken through eight separate steps"](https://techcrunch.com/2021/10/15/f12-isnt-hacking-missouri-governor-threatens-to-prosecute-local-journalist-for-finding-exposed-state-data), a characterization of base64 decoding that security professionals widely mocked.

**Does NOT apply when:** The exploitation cost claim is concrete and defensible (e.g., requires a hardware lab, per-device physical tampering, or chaining with an unrelated unfixed zero-day), is presented as a severity input rather than grounds for dismissal, and the bug is still tracked for remediation.

Related: CV3-309 (No-Exploit-No-Problem), CV3-402 (Impact-Deflation)

---

### CV3-400 - Not Severe Enough

*"We've reassessed this as informational."*

**The family:** The bug is acknowledged but its severity is engineered downward until it falls below the action threshold, by overstating what the attacker needs, understating what the attacker gets, or reclassifying the finding into a bucket that requires no fix and no payment. Distinct from CV3-300: there the claim is that exploitation won't happen; here, that it wouldn't matter.

**Does NOT apply when:** The severity assessment is justified metric-by-metric against the reported attack path, and the reporter is given the reasoning rather than just the result.

---

**CV3-401 | Prerequisite-Inflation**

Overstating what the attacker needs, in whatever scoring system is in use: scoring the attack vector as local or adjacent when it is network-reachable; marking privileges-required high when any self-registered user qualifies or when the bug itself grants the privilege; asserting user interaction is required when the trigger is invisible to the victim (auto-loaded image, background fetch, drive-by iframe). Each inflated prerequisite lowers the score and the priority.

*Pattern indicator: "We scored this as AV:A because the endpoint is not directly internet-accessible."* / *"The victim must click a link, so UI:R."*

[Zoom's local web server bug (CVE-2019-13450)](https://medium.com/bugbountywriteup/zoom-zero-day-4-million-webcams-maybe-an-rce-just-get-them-to-visit-your-website-ac75c83f4ef5) was exploitable via an embedded iframe that silently invoked the server: "user interaction" reduced to visiting a webpage. Disputes over vendor-assigned attack-vector and privileges-required values recur throughout public bounty disclosures.

**Does NOT apply when:** Each contested metric is defended with specifics about the reported attack path, and the vendor engages on the reporter's counter-evidence rather than restating the score.

Related: CV3-305 (Privilege-Circularity), CV3-303 (Unreachable-By-Assumption)

---

**CV3-402 | Impact-Deflation**

Understating what the attacker gets: refusing to acknowledge boundary crossings (sandbox, tenant, origin) that the exploit demonstrably achieves, or treating PII, authentication tokens, and session credentials as low-value because "no financial data" is exposed - a framing at odds with regulatory definitions and actual attacker motivation.

*Pattern indicator: "The impact is confined to the vulnerable component."* / *"No payment card data is accessible, so confidentiality impact is low."*

Cross-tenant cloud bugs scored as if no boundary was crossed to keep the score below patch-SLA thresholds; API-key and session-token exposures downgraded to informational because the data is "not financial."

**Does NOT apply when:** The claimed boundary genuinely isn't crossed in the demonstrated exploit, or the exposed data verifiably carries no authentication value, no regulatory weight, and no chaining potential - and the vendor shows its reasoning.

Related: CV3-401 (Prerequisite-Inflation), CV3-403 (Informational-Reclassification)

---

**CV3-403 | Informational-Reclassification**

Routing technically valid reports to the "Informative" bucket on bug bounty platforms to avoid bounty payment and reputation impact while still benefiting from the researcher's finding.

*Pattern indicator:* A report is triaged as valid, then later reclassified to "Informative" with no substantive explanation.

HackerOne's "Informative" close-code compresses everything from genuinely low-impact findings to valid bugs the program doesn't want to pay for into a single opaque bucket.

**Does NOT apply when:** The reclassification comes with a substantive technical explanation of why the finding has no security impact, and the explanation survives the reporter's rebuttal.

Related: CV3-507 (Bounty-Haggling), CV3-501 (Unverifiable-Prior-Knowledge)

---

**CV3-404 | Self-Inflicted-Only**

Labeling self-XSS, self-CSRF, or local-only denial-of-service as zero-impact even when the reported finding is demonstrably chainable to other in-scope vulnerabilities.

*Pattern indicator: "This only affects the attacker's own account/session; there is no impact to other users."*

Self-XSS dismissed as a non-issue despite documented chains (self-XSS + CSRF + social engineering escalating to account takeover) in researcher writeups and bounty-platform guidance.

**Does NOT apply when:** No plausible chain is demonstrated or proposed, and the impact genuinely terminates at the attacker's own session. A standalone self-XSS with no chaining path is legitimately low priority.

Related: CV3-309 (No-Exploit-No-Problem)

---

### CV3-500 - Report Doesn't Qualify

*"Duplicate of a known internal issue."*

**The family:** Rather than disputing the bug, the vendor disputes the *report*: it duplicates something unverifiable, it fell out of scope after the fact, it can't be reproduced, it needs ever more data, it requires proof the reporter can't lawfully give, it looks like AI slop, or paying full price for it is suddenly negotiable. The shared move is using triage mechanics as a no-cost close mechanism.

**Does NOT apply when:** The triage decision is evidenced with artifacts, traces, and specifics, and survives the reporter's response. A verifiable close is not an evasion.

---

**CV3-501 | Unverifiable-Prior-Knowledge**

Closing a report on the strength of an unevidenced claim of prior knowledge: "duplicate" of a prior report whose ID, timestamp, and root-cause match are never produced; "we already track this internally" without a dated ticket; "a fix was already in development" without a commit or sprint record predating the submission. In all three forms the claim denies credit and payment while remaining unfalsifiable by design.

*Pattern indicator:* Report closed as Duplicate/Known/In-pipeline with no original report ID, no dated artifact, or a cited original with a different root cause.

False-duplicate abuse is documented across researcher writeups; Intigriti's own ["Duplicate, related or known" documentation](https://kb.intigriti.com/en/articles/4917102-duplicate-related-or-known-vulnerability-reports) explicitly asks programs to be fair and provide context when invoking this close reason; platform mediation typically intervenes only above a signal threshold, leaving newcomers most exposed.

**Does NOT apply when:** The vendor produces the dated artifact - original report ID with timestamp and triage notes (sensitive details redacted), internal ticket, commit hash, or audit finding - that predates the submission and matches the same root cause. A real duplicate is verifiable; a false one is asserted.

Related: CV3-503 (Reproduction-Denial), CV3-403 (Informational-Reclassification)

---

**CV3-502 | Retroactive-Scope-Exclusion**

Removing a clearly in-scope finding from scope after submission - either by reinterpreting the program brief in a way that was not available to the reporter at submission time, or by editing the brief itself ("scope shrinkage") so the exclusion appears to have always existed. Exploits the fact that briefs are mutable and researchers hold no version-controlled copy of the scope they relied on.

*Pattern indicator:* Report accepted by triage, then closed as out-of-scope under a new reading of the rules; or the program scope changes simultaneously with a significant report.

Scope disputes are among the most common researcher grievances acknowledged in platform mediation documentation; the brief-editing variant is documented in researcher community forums.

**Does NOT apply when:** The exclusion existed verbatim in the brief at submission time and the reporter's reading of it was not reasonable - reasonable ambiguity should resolve in the reporter's favor.

Related: CV3-306 (Not-In-Our-Threat-Model), CV3-508 (Safe-Harbor-Stripping)

---

**CV3-503 | Reproduction-Denial**

Issuing "cannot reproduce" as a final, terminal answer without documenting the reproduction attempt, engaging on environment specifics, or asking the reporter for clarifying details - an asserted inability to reproduce used as a no-cost close reason.

*Pattern indicator: "We were unable to reproduce the issue in our environment."* - with no version/config detail, no request for clarification, no follow-up.

Documented across researcher survey data as one of the most commonly reported forms of non-engagement.

**Does NOT apply when:** The vendor documents the attempt with specifics (versions tested, configuration, request/response traces) and asks for genuinely missing details. A good-faith "cannot reproduce" is collaborative and traceable; the evasive form is terminal and undocumented.

Related: CV3-501 (Unverifiable-Prior-Knowledge), CV3-504 (Need-More-Data-Loop)

---

**CV3-504 | Need-More-Data-Loop**

Repeatedly requesting additional reproduction details - especially details already provided or that would require unauthorized access to obtain - as a stalling mechanism. The loop itself is the evasion: it wears down the reporter or pushes them toward committing further "unauthorized access" to satisfy each new request.

*Pattern indicator:* Sequential, escalating requests for data already provided, or for data only obtainable by accessing systems the reporter has no authorization to touch.

Documented in CVD breakdown narratives where vendors acknowledge an issue but cycle through "we need the exact request/response," "now the raw HTTP log," "now the database schema" without any request being definitively satisfied.

**Does NOT apply when:** The vendor identifies specific, genuinely missing technical details the reporter can lawfully provide, and the request is made once with clear triage reasoning.

Related: CV3-505 (Proof-Requires-Crime), CV3-503 (Reproduction-Denial)

---

**CV3-505 | Proof-Requires-Crime**

Making acknowledgment conditional on proof the reporter cannot lawfully produce - and dismissing the report when they correctly refuse. The demand form asks the researcher to demonstrate full impact by performing acts that would themselves constitute unauthorized access ("prove you can read other customers' data"), whether framed explicitly or disguised as routine triage information-gathering ("can you provide an example of a real affected customer record?"). The dismissal form closes the report for lacking exactly that proof ("you only demonstrated access to your own tenant; no other customers were affected").

*Pattern indicator: "Can you demonstrate access to another user's account / extract a real customer record?"* - or a tenant-isolation PoC closed as "no customer impact" because the researcher stopped at their own data.

[EFF's Coders' Rights FAQ](https://www.eff.org/issues/coders/vulnerability-reporting-faq) flags this as a recurring trap: complying converts good-faith research into a crime, refusing becomes the pretext for dismissal. Cloud tenant-isolation bypasses are routinely reclassified as "no customer impact" when the researcher (correctly) stopped short of accessing real customer data.

**Does NOT apply when:** The vendor offers a test environment, synthetic records, or a designated second test account the reporter can use safely and legally to demonstrate the crossing.

Related: CV3-504 (Need-More-Data-Loop), CV3-402 (Impact-Deflation)

---

**CV3-506 | AI-Slop-Accusation-Misapplied**

Dismissing a careful, human-written, well-documented vulnerability report by labeling it "AI-generated slop" - a cover story legitimized by the real and documented problem of LLM-generated junk reports flooding bounty programs.

*Pattern indicator: "This report appears to have been generated by an AI tool and does not demonstrate original security research."*

**Does NOT apply when:** The report exhibits actual hallmarks of LLM-generated slop: hallucinated function names, references to non-existent CVEs or code paths, generic templated language with no product-specific detail, no working PoC, or inability to clarify specifics when challenged. Applying the label correctly to genuine LLM-generated nonsense is legitimate triage.

Daniel Stenberg's [closure of curl's bug bounty program](https://www.bleepingcomputer.com/news/security/curl-ending-bug-bounty-program-after-flood-of-ai-slop-reports/) (2026) after a flood of LLM-generated false reports established the legitimate form of the concern; the evasion is misapplying the label to well-researched reports that contradict the slop profile.

Related: CV3-702 (Methodology-Attack), CV3-503 (Reproduction-Denial)

---

**CV3-507 | Bounty-Haggling**

Paying significantly less than the published bounty range after triage, typically by reclassifying the vulnerability's severity downward post-acceptance to fit a lower payout band.

*Pattern indicator:* Report triaged as high/critical, paid at low/medium rate with a retroactive severity reclassification.

Severity reclassification after triage is cited in researcher survey data (Bugcrowd's "State of Bug Bounty", HackerOne researcher surveys) as a primary contributor to researcher distrust of programs.

**Does NOT apply when:** The revised severity is justified with the metric-level reasoning of CV3-401/402's clauses, the reasoning predates the payout decision, and the program's published rules anticipated the reclassification path.

Related: CV3-403 (Informational-Reclassification), CV3-402 (Impact-Deflation)

---

**CV3-508 | Safe-Harbor-Stripping**

Retroactively declaring that the researcher violated program terms or the product's terms of service - testing "too far," using an "unauthorized" technique, touching an "excluded" asset - specifically to void the program's safe-harbor protection and convert a covered, good-faith report into legal exposure. Bridges report disqualification and legal retaliation: the scope ruling kills the bounty, the safe-harbor ruling manufactures liability.

*Pattern indicator: "Your testing violated our program terms, so the safe harbor provisions do not apply to your activity."*

A recurring feature of program-terms disputes in researcher forums; safe-harbor language conditioned on subjective "good faith" or "authorized testing" determinations leaves the vendor as sole judge of whether its own legal shield applies. (Canonical public exemplar wanted - contributions welcome.)

**Does NOT apply when:** The violated term is specific, was published at submission time, and the violation is documented conduct genuinely outside it (e.g., exfiltrating bulk data after proving the point, social-engineering employees against an explicit prohibition) - not a reinterpretation constructed after the report.

Related: CV3-502 (Retroactive-Scope-Exclusion), CV3-801 (Civil-Threat-Or-Suit)

---

### CV3-600 - Fix Is on the Roadmap

*"Thank you for your patience."*

**The family:** The bug is accepted, and then the remediation or the disclosure is manipulated: the fix never ships, the embargo never ends, the patch is partial or silent or paywalled, the story is seized or sanitized, or multi-party coordination is blocked, bypassed, or free-ridden. The shared move is converting the researcher's cooperation into indefinite vendor control over both the fix and the narrative.

**Does NOT apply when:** The vendor communicates a concrete, evidenced remediation and disclosure plan and then follows it. Delays grounded in verifiable engineering reality, communicated proactively, are not evasions.

---

**CV3-601 | Accepted-Never-Fixed**

A vulnerability is confirmed and accepted for remediation, and then never remediated. In the silent variant, the program or vendor stops responding entirely after triage - no patch timeline, no status updates. In the communicative variant, the report ages for quarters or years in "accepted" or "in remediation" status, with triage completion functioning as a substitute for an actual fix.

*Pattern indicator:* Report transitions to "triaged" or "in progress," then either goes silent or accumulates status updates with no shipped fix.

[The Register (January 2026)](https://www.theregister.com/2026/01/07/hackerone_ghosted_researcher/): HackerOne's Internet Bug Bounty program ghosted researcher Jakub Ciolek for months over an $8,500 reward for two confirmed, fixed Argo CD CVEs, responding only after press inquiries. Katie Moussouris has repeatedly criticized [well-funded programs sitting on piles of unfixed bugs](https://www.computerweekly.com/news/366636232/Why-bug-bounty-schemes-have-not-led-to-secure-software): incentive structures that reward triage throughput, not remediation velocity.

**Does NOT apply when:** The vendor maintains an active, evidenced remediation effort with a credible timeline, communicates delays proactively, and supports interim mitigations and (where needed) coordinated disclosure before the fix.

Related: CV3-602 (Embargo-Stretching), CV3-102 (Black-Hole-Inbox)

---

**CV3-602 | Embargo-Stretching**

Repeatedly extending the agreed disclosure embargo without delivering a fix, exploiting researchers' goodwill and their reluctance to publish without warning - indefinitely delaying public notification.

*Pattern indicator:* Vendor requests embargo extension past the agreed deadline without producing a shipped patch or concrete commit date.

Project Zero's strict [90+30 day policy](https://googleprojectzero.blogspot.com/p/vulnerability-disclosure-policy.html) and its ["Reporting Transparency" initiative](https://projectzero.google/2025/07/reporting-transparency.html) were direct responses to vendors using researcher cooperation as an indefinite patch-delay mechanism.

**Does NOT apply when:** An extension request is specific, bounded, evidenced (e.g., the fix breaks a dependency matrix that requires coordinated downstream releases), and rare rather than serial.

Related: CV3-601 (Accepted-Never-Fixed), CV3-608 (Coordination-Refusal)

---

**CV3-603 | Quick-Fix-Marked-As-Fixed**

Shipping a partial mitigation that addresses a surface symptom and closing the report, without fixing the underlying flaw - or shipping a fix that is later regressed.

*Pattern indicator:* Report closed as "Resolved" after a change that does not address the root cause or that is reverted in a subsequent release.

[Zoom's response to Jonathan Leitschuh's disclosure](https://medium.com/bugbountywriteup/zoom-zero-day-4-million-webcams-maybe-an-rce-just-get-them-to-visit-your-website-ac75c83f4ef5) (CVE-2019-13450): the initially proposed fix adjusted meeting video defaults while leaving the hidden local web server, the actual attack surface, in place; only after public disclosure did Zoom ship an emergency patch removing the server, with Apple pushing its own silent macOS update to excise it from machines where Zoom had been uninstalled.

**Does NOT apply when:** The shipped mitigation verifiably closes the reported attack path, the root-cause work is tracked openly with a timeline, and the reporter is given the chance to retest before closure.

Related: CV3-207 (Old-Version-Tested), CV3-604 (Silent-Patching-No-Credit)

---

**CV3-604 | Silent-Patching-No-Credit**

Shipping a security fix without issuing a CVE, publishing an advisory, or crediting the reporter - preventing defenders from prioritizing the patch and the reporter from receiving recognition.

*Pattern indicator:* Vulnerability disappears under a changelog entry like "miscellaneous security improvements"; no CVE assigned; no credit.

Rapid7's Tod Beardsley described no-credit, no-explanation, no-CVE releases as the standard silent patching model (["The Hidden Harm of Silent Patches"](https://www.rapid7.com/blog/post/2022/06/06/the-hidden-harm-of-silent-patches/), 2022); Fortinet's [silently patched FortiWeb zero-day](https://www.csoonline.com/article/4091939/fortinets-silent-patch-sparks-alarm-as-a-critical-fortiweb-flaw-is-exploited-in-the-wild.html) (CVE-2025-64446, November 2025), fixed in a release whose notes never mentioned it while exploitation was underway, is a recent exemplar.

**Does NOT apply when:** The reporter explicitly requested anonymity or no advisory, or the fix genuinely carries no security relevance for deployed users - and the vendor can say which.

Related: CV3-603 (Quick-Fix-Marked-As-Fixed), CV3-501 (Unverifiable-Prior-Knowledge)

---

**CV3-605 | Patch-Behind-Paywall**

Issuing a security fix only to paying or commercially-supported customers, leaving free-tier, community, or end-of-support users vulnerable to a now-documented issue - and, after public disclosure, to any attacker who reads the advisory.

*Pattern indicator:* Security advisory linked to a paid support tier or commercial upgrade, with no mitigation available to non-paying users.

Enterprise vendors shipping CVE patches as part of a paid maintenance subscription while community editions receive no backport; after public disclosure, the unpatched population becomes an easy target.

**Does NOT apply when:** The unsupported tier is genuinely end-of-life with a documented and announced sunset date, public migration guidance, and a negligible deployed footprint.

Related: CV3-101 (No-Accessible-Security-Contact), CV3-601 (Accepted-Never-Fixed)

---

**CV3-606 | Branded-Vuln-Hijack**

The vendor races to brand, name, and publicly disclose the vulnerability under its own narrative before the researcher can publish - seizing control of the story while the researcher is still honoring the embargo.

*Pattern indicator:* Vendor publishes an advisory naming and framing the vulnerability before the coordinated disclosure date, cutting off the researcher's own publication.

Adjacent illustration: the [CrushFTP / VulnCheck / Outpost24 dispute](https://www.securityweek.com/details-emerge-on-cve-controversy-around-exploited-crushftp-vulnerability/) over CVE-2025-31161 (2025), where a second CVE assignment and competing advisories cut across an agreed coordinated-disclosure timeline, though there the first mover was a third-party CNA rather than the vendor. (Canonical vendor-led exemplar wanted - contributions welcome.)

**Does NOT apply when:** Early publication was forced by active in-the-wild exploitation or a leak, the researcher was notified before or simultaneously with the advisory, and credit is preserved.

Related: CV3-607 (Narrative-Laundering), CV3-604 (Silent-Patching-No-Credit)

---

**CV3-607 | Narrative-Laundering**

Pressuring the researcher to publish a sanitized account - severity softened, exploitability details removed, root cause obscured, vendor-approved language substituted - as a condition of credit, payment, or continued cooperation. Distinct from CV3-606: there the vendor seizes the story; here the vendor edits the researcher's story.

*Pattern indicator:* Credit or payment made contingent on the vendor's review and approval of the researcher's writeup, with requested edits that minimize rather than correct.

A recurring feature of coordinated disclosures, typically visible only in researcher accounts of the negotiation; advisory-review clauses in program terms provide the lever. (Canonical public exemplar wanted - contributions welcome.)

**Does NOT apply when:** Requested edits are narrowly protective and time-limited (e.g., withholding a weaponizable exploit detail until patch adoption reaches a stated threshold) and do not alter the description of severity, impact, or the vendor's response.

Related: CV3-606 (Branded-Vuln-Hijack), CV3-804 (Gag-Conditions)

---

**CV3-608 | Coordination-Refusal**

Refusing to participate in coordinated disclosure - declining to negotiate any timeline, or insisting that the vendor's own internal process is the only legitimate venue and refusing to engage with neutral coordinators (CERT/CC, ICS-CERT, FIRST members) - even when the vulnerability affects downstream products, integrators, or other vendors sharing the component.

*Pattern indicator: "We do not negotiate disclosure dates."* / *"Our security team is the appropriate contact for all issues; we do not engage with third-party coordinators."*

Multi-party protocol and library vulnerabilities where one vendor's refusal forces all other parties to choose between disclosing without a complete patch matrix or indefinitely delaying notification; critical-infrastructure vendors routing all discussion through proprietary portals with no multi-party capability.

**Does NOT apply when:** The vendor's internal process genuinely incorporates multi-party coordination and downstream notification (e.g., an ISO/IEC 30111-aligned PSIRT with documented coordinator outreach), or the bug is self-contained in a single product with no downstream fan-out and the vendor commits to a verifiable public disclosure timeline.

Related: CV3-609 (Downstream-Notification-Blockade), CV3-610 (Coordinator-Bypass)

---

**CV3-609 | Downstream-Notification-Blockade**

Preventing CERT/CC, sector ISACs, ICS-CERT, or other neutral coordinators from notifying downstream parties - effectively asserting that no one else needs to know until the vendor's internal patch timeline completes.

*Pattern indicator:* Vendor instructs the coordinator not to notify downstream integrators or affected parties pending the vendor's own patch release.

Particularly damaging in ICS/OT and medical devices, where a shared embedded component may exist in dozens of downstream products; a single vendor's blockade delays the entire notification chain.

**Does NOT apply when:** The vendor is running its own verified downstream notification with a documented timeline and demonstrated outreach to all known affected parties - and the coordinator can independently verify the outreach.

Related: CV3-608 (Coordination-Refusal), CV3-611 (Multi-Party-Free-Riding)

---

**CV3-610 | Coordinator-Bypass**

Communicating directly with the original reporter to draw them away from a coordinator already engaged - offering faster resolution or payment in exchange for withdrawing the coordinator, fragmenting the coordination and isolating the reporter from third-party support.

*Pattern indicator:* Vendor contacts the researcher directly after a coordinator is involved, offering a better deal contingent on proceeding without the coordinator.

Coordination breakdowns of this kind are catalogued in CERT/CC's ["Troubleshooting CVD"](https://certcc.github.io/CERT-Guide-to-CVD/howto/coordination/cvd_recipes/) guidance; fragmenting the reporter-coordinator relationship undermines multi-party coordination precisely when it is most needed.

**Does NOT apply when:** The coordinator has explicitly withdrawn, or the reporter independently requested direct vendor contact without coordinator involvement.

Related: CV3-608 (Coordination-Refusal), CV3-804 (Gag-Conditions)

---

**CV3-611 | Multi-Party-Free-Riding**

In a multi-party CVD covering a shared vulnerable component, one vendor refuses to participate in coordinated fixes or disclosure while benefiting from other parties' remediation - leaving its product unpatched after others have shipped fixes and a public advisory exists.

*Pattern indicator:* Coordinated advisory and patch matrix released; one named affected vendor's product remains unpatched indefinitely, having never joined the coordination.

Shared TLS/crypto library vulnerabilities where multiple OEMs patch and disclose together while one or more embedded-systems vendors never participate and never ship - leaving their customers exposed to a now-public exploit.

**Does NOT apply when:** The vendor's product is verifiably not affected (documented with technical evidence), or the vendor deployed an alternative remediation that is publicly documented and independently verifiable.

Related: CV3-204 (Upstream-Deflection), CV3-609 (Downstream-Notification-Blockade)

---

**CV3-612 | Public-Denial-Private-Patch**

Publicly denying the existence or validity of a vulnerability while internally triaging, patching, or escalating the same issue - creating a public record that contradicts the vendor's actual internal assessment.

*Pattern indicator:* Press statement says "no vulnerability exists" or "our products are not affected" while internal tickets, commits, or regulatory communications show active remediation.

St. Jude Medical publicly denied its cardiac device vulnerabilities and [sued the researchers](https://www.cnbc.com/2016/09/07/st-jude-sues-short-seller-over-heart-device-allegations.html) (2016) until [FDA and DHS independently confirmed the flaws](https://www.hipaajournal.com/fda-confirms-muddy-waters-claims-st-jude-medical/) in January 2017 and fixes followed; Muddy Waters' founder argued the vulnerabilities would not have been remediated absent the public disclosure.

**Does NOT apply when:** The public statement and internal activity genuinely concern different issues, and the vendor can demonstrate the distinction.

Related: CV3-701 (Public-Delegitimization), CV3-604 (Silent-Patching-No-Credit)

---

### CV3-700 - Shoot the Messenger

*"This individual illegally accessed our systems."*

**The family:** The vendor responds to the report by going after the reporter: reframing them publicly as a criminal or bad actor, attacking their methods instead of their findings, demanding their identity, pressuring their employer, or cutting off their access. The shared move is shifting the question from "is the product vulnerable?" to "who is this person and what did they do wrong?"

**Does NOT apply when:** The reporter's conduct genuinely exceeded good-faith research norms (extortion, bulk exfiltration, destructive testing) and the vendor's response is proportionate to that documented conduct rather than to the disclosure itself.

---

**CV3-701 | Public-Delegitimization**

Publicly reframing the reporter as the source of harm: branding them a "hacker" with criminal connotations in press releases and official statements, asserting malicious or competitive motives ("a coordinated campaign against us"), or proactively framing a responsible disclosure as data theft or an attack. The shared aim is shifting public and regulatory attention from the vulnerability to the reporter's character and conduct.

*Pattern indicator:* Vendor-initiated public communications using "hacker," "unauthorized access," "breach," or motive-attribution language about a good-faith disclosure.

Missouri's governor publicly called journalist Josh Renaud ["a hacker"](https://techcrunch.com/2021/10/15/f12-isnt-hacking-missouri-governor-threatens-to-prosecute-local-journalist-for-finding-exposed-state-data) for viewing HTML source containing exposed teacher SSNs (2021), and the state's official letter framed the view-source disclosure as records theft; [DJI publicly labeled Kevin Finisterre a "hacker"](https://www.dpreview.com/news/7000205676/researcher-says-he-was-threatened-after-finding-major-dji-security-flaw) who accessed its servers without permission; [Voatz publicly accused the MIT researchers of acting in bad faith](https://statescoop.com/mit-researchers-find-vulnerabilities-in-voatz-mobile-voting-app/), findings later confirmed by Trail of Bits.

**Does NOT apply when:** The factual characterization is accurate and proportionate - the person actually extorted, leaked, or sold the data - and the vendor's account distinguishes that conduct from the act of reporting.

Related: CV3-802 (Criminal-Referral), CV3-612 (Public-Denial-Private-Patch)

---

**CV3-702 | Methodology-Attack**

Attacking the researcher's methodology - wrong app version, failure to use the official channel, anonymous identity, inadequate credentials - to discredit findings without engaging with the technical substance.

*Pattern indicator: "The researchers did not use current software / did not follow our disclosure process / cannot be verified as credentialed experts."*

Voatz's public response to the MIT research combined the old-version claim (CV3-207), motive attribution (CV3-701), and methodology attacks - all against findings Trail of Bits subsequently confirmed.

**Does NOT apply when:** The methodological flaw is real and material to the finding's validity (the tested code path genuinely doesn't exist in any deployed version), and the vendor engages with the substance alongside the critique.

Related: CV3-506 (AI-Slop-Accusation-Misapplied), CV3-701 (Public-Delegitimization)

---

**CV3-703 | Identity-Demand**

Demanding that the researcher identify themselves, all collaborators, or their employer as a precondition for engaging with the report - creating exposure to pressure or retaliation as a side effect, and going well beyond what triage requires.

*Pattern indicator: "Please provide your full legal name, employer, and a list of everyone who has access to this information."*

[What3Words demanded Aaron Toponce identify everyone](https://www.techdirt.com/articles/20210430/22510246716/what3words-sends-ridiculous-legal-threat-to-security-researcher-over-open-source-alternative.shtml) he had shared the WhatFreeWords open-source alternative with, as part of its legal-threat letter (2021).

**Does NOT apply when:** Identity is required by a published program rule the reporter accepted (e.g., sanctions/KYC checks for bounty payment), is requested for that purpose alone, and anonymous reporting without payment remains available.

Related: CV3-704 (Employer-Pressure), CV3-801 (Civil-Threat-Or-Suit)

---

**CV3-704 | Employer-Pressure**

Contacting a researcher's employer to apply pressure, frame the researcher as having conducted unauthorized activity, or seek professional consequences - achieving silence by going around the researcher.

*Pattern indicator:* Vendor contacts the researcher's employer about the disclosure without the researcher's knowledge or consent.

A recurring feature of researcher accounts of disclosure gone wrong: going around the researcher to their employer achieves silencing without engaging the finding. (Canonical public exemplar wanted - contributions welcome.)

**Does NOT apply when:** The research was conducted using the employer's infrastructure or authority in a way that makes the employer a party to the matter, and contact is limited to that fact.

Related: CV3-703 (Identity-Demand), CV3-701 (Public-Delegitimization)

---

**CV3-705 | Access-Revocation-Retaliation**

Punishing the report through the product itself: banning the researcher's account, revoking API keys, terminating their service, or blacklisting them from the bounty program in response to a good-faith disclosure. Neither a legal instrument nor a public statement - direct retaliation through access control, which also conveniently prevents the researcher from verifying any fix.

*Pattern indicator:* Researcher's account is suspended or program access revoked shortly after submitting a report, with no claim of conduct beyond the research itself.

[Apple terminated Charlie Miller's iOS developer account](https://www.theregister.com/2011/11/08/apple_excommunicates_charlie_miller/) within hours of his demonstrating an App Store code-signing bypass (2011), a case sitting squarely on this entry's clause, since the demonstration itself violated program terms; Miller's reaction, that Apple gives researchers developer access and then expels them for doing research, captures the chilling effect either way. Frequently paired with terms-of-service violation claims (see CV3-508).

**Does NOT apply when:** The revocation responds to documented conduct outside good-faith research norms (bulk exfiltration, service disruption, repeated testing against an explicit prohibition), is proportionate, and is explained.

Related: CV3-508 (Safe-Harbor-Stripping), CV3-704 (Employer-Pressure)

---

### CV3-800 - Send in the Lawyers

*"Govern yourself accordingly."*

**The family:** Legal instruments aimed at the reporter instead of the bug: civil threats and suits under whatever statute is nearest to hand, criminal referrals, takedowns of the publication, and silence or evidence-destruction extracted as a condition of payment or settlement. The shared move is converting the cost and fear of legal process into a substitute for remediation.

**Does NOT apply when:** A viable legal claim addresses documented conduct genuinely outside good-faith research, and the vendor pursues that conduct, not the disclosure.

---

**CV3-801 | Civil-Threat-Or-Suit**

Threatening or filing civil legal action against a good-faith reporter, with the statute as an interchangeable detail: anti-hacking laws (the U.S. CFAA - whose civil "loss" threshold can be met by remediation costs alone, even after [*Van Buren*](https://www.supremecourt.gov/opinions/20pdf/19-783_k53l.pdf) narrowed criminal exposure - the UK Computer Misuse Act, and equivalents elsewhere), anti-circumvention provisions (DMCA §1201 despite the security-research exemption), defamation and trade-secret claims against accurate published findings, patent-infringement pretexts against research presentations, or a cease-and-desist letter with no viable underlying claim. The cost of legal process is the weapon; the merits are largely irrelevant.

*Pattern indicator:* Vendor or counsel references "unauthorized access," computer-fraud statutes, "circumvention of technological protection measures," defamation, trade secrets, or patent rights in response to a vulnerability disclosure - or sends a C&D over a report, an API test, or a compatible tool.

[DJI's legal team threatened Kevin Finisterre with the CFAA](https://www.theregister.com/2017/11/16/dji_bug_bounty_nda/) mid-NDA negotiation over a responsibly disclosed credentials exposure (2017); [*St. Jude Medical v. MedSec & Muddy Waters*](https://www.cnbc.com/2016/09/07/st-jude-sues-short-seller-over-heart-device-allegations.html) (2016) was a defamation suit over findings the FDA and DHS later confirmed; [HID Global's patent-infringement threat against IOActive's Chris Paget](https://www.computerweekly.com/news/1280096306/RFID-cloning-presentation-moves-forward-despite-legal-threats) (2007) suppressed an RFID-cloning Black Hat talk; [Talkspace sent a C&D](https://techcrunch.com/2020/03/09/talkspace-cease-desist/) over a free-subscription bug report (2020); [What3Words' letter to Aaron Toponce](https://www.techdirt.com/articles/20210430/22510246716/what3words-sends-ridiculous-legal-threat-to-security-researcher-over-open-source-alternative.shtml) was characterized in press coverage as a thinly veiled litigation threat (2021). Riana Pfefferkorn's ["Shooting the Messenger"](https://scholarship.richmond.edu/jolt/vol29/iss1/3/) (Richmond Journal of Law & Technology, 2022) documents the continued viability of civil CFAA suits.

**Does NOT apply when:** The claim is viable and addresses conduct genuinely outside good-faith research - actual extortion, publication of stolen customer data, distribution of the vendor's proprietary code beyond what demonstration requires - and is scoped to that conduct.

Related: CV3-802 (Criminal-Referral), CV3-508 (Safe-Harbor-Stripping), CV3-803 (Publication-Takedown)

---

**CV3-802 | Criminal-Referral**

Referring a good-faith security reporter to law enforcement or prosecutors, characterizing standard vulnerability-discovery techniques as criminal activity - conscripting the state into the retaliation.

*Pattern indicator:* Vendor contacts law enforcement, files a police report, or publicly calls for prosecution of a researcher who disclosed a vulnerability.

Missouri DESE / Governor Parson (2021-2022): journalist Josh Renaud was referred for prosecution for reporting that teacher SSNs were embedded in a state website's HTML source; [the county prosecutor declined to file charges](https://www.theregister.com/2022/02/15/missouri_html_hacking/), and the eventually released investigative file showed nothing resembling hacking.

**Does NOT apply when:** The referred conduct is genuinely criminal beyond research norms (extortion, sale of data, destructive intrusion) and the referral is scoped to it.

Related: CV3-801 (Civil-Threat-Or-Suit), CV3-701 (Public-Delegitimization)

---

**CV3-803 | Publication-Takedown**

Using platform content mechanisms - DMCA takedown notices and equivalents - against a researcher's proof-of-concept code, blog posts, talks, or demonstration videos, to suppress public knowledge of the vulnerability rather than to protect a legitimate copyright interest.

*Pattern indicator:* Takedown filed against a PoC repository, researcher blog, or conference recording containing brief excerpts of vendor software.

Takedowns of researcher publications and demonstration material are documented across the [disclose.io research-threats archive](https://github.com/disclose/research-threats), which continues attrition.org's catalogue of legal threats against security researchers.

**Does NOT apply when:** The published material substantially reproduces the vendor's proprietary code or assets beyond what demonstrating the vulnerability requires, and the takedown is scoped to that material.

Related: CV3-801 (Civil-Threat-Or-Suit), CV3-804 (Gag-Conditions)

---

**CV3-804 | Gag-Conditions**

Extracting silence as a condition of engagement, payment, or settlement. Manifestations: bounty payment conditioned on a perpetual, broadly-worded NDA that functions as a blanket gag rather than a confidentiality agreement pending patch; a disclosure policy that funnels all reports through a platform whose terms impose the same NDA by default; and settlement terms that prohibit disclosure not just to the public but to regulators and coordinators (FDA, DHS, CERT/CC) - the aggravated form, since it silences exactly the oversight bodies with the strongest independent interest.

*Pattern indicator:* Payment, credit, or settlement contingent on signing a non-time-limited NDA; a VDP stating that submission implies acceptance of platform NDA terms; settlement clauses naming regulators among the prohibited audiences.

[DJI's NDA in the Finisterre case](https://www.theregister.com/2017/11/16/dji_bug_bounty_nda/) was described by Finisterre's attorneys as likely crafted in bad faith to silence anyone who signed it; the proposed [*St. Jude v. MedSec* settlement](https://www.mddionline.com/regulatory-quality/why-did-st-jude-medical-have-egg-on-its-face-in-2017-) would have barred the defendants from independently disclosing anything about the products to FDA, DHS, or any other regulator absent an official request or subpoena; CSO Online (["Bug bounty platforms buy researcher silence"](https://www.csoonline.com/article/569201/bug-bounty-platforms-buy-researcher-silence-violate-labor-laws-critics-say.html), 2020) documents platform-embedded NDAs structurally preventing public disclosure.

**Does NOT apply when:** Confidentiality is time-limited and scoped to the period before patch release (or another concrete, verifiable milestone), and never extends to regulators or neutral coordinators.

Related: CV3-805 (Evidence-Deletion-Demand), CV3-607 (Narrative-Laundering), CV3-610 (Coordinator-Bypass)

---

**CV3-805 | Evidence-Deletion-Demand**

Demanding that the researcher destroy all data, proofs-of-concept, traffic captures, and notes as a precondition for engagement, payment, or settlement - removing their ability to verify the eventual fix, defend against later legal action, or escalate to a coordinator. Compelled destruction is a separate and stronger instrument than compelled silence: silence can be broken if the vendor acts in bad faith; destroyed evidence cannot.

*Pattern indicator:* Engagement or payment conditioned on certified deletion of all material related to the finding, before or instead of remediation.

[Uber's 2016 handling of its breach](https://techcrunch.com/2022/10/06/ubers-former-security-chief-found-guilty-of-covering-up-2016-data-breach/) paid the intruders $100,000 through its bug bounty program in exchange for NDAs, data deletion, and a false statement that no data had been taken: the concealment for which its former CSO was convicted of obstruction; DJI's negotiation with Finisterre included demands concerning the disclosed data alongside its gag terms.

**Does NOT apply when:** The deletion request is scoped to genuinely sensitive material the researcher has no need to retain (bulk customer PII captured incidentally), is requested after remediation and verification, and leaves the researcher's own working notes and PoC intact.

Related: CV3-804 (Gag-Conditions), CV3-705 (Access-Revocation-Retaliation)

---

## Structural Conventions

1. **ID scheme.** `CV3-N00` entries are category anchors; `CV3-N01` through `CV3-N99` are leaf patterns within that category. `CV3-000`-`CV3-099` and `CV3-9xx` are unallocated headroom for future categories and meta-entries; if the numeric space is ever exhausted, the scheme extends to `CV3-Axx` and onward. Only the hundreds digit carries meaning - leaves within a block are assigned sequentially, and no semantics attach to the tens or ones digits.

2. **Stable IDs, evolving entries.** Once assigned, an ID permanently refers to the same pattern. Entry text (description, indicators, exemplars, clauses, related links) may be clarified, expanded, or corrected over time; the *identity* of the pattern may not change. If a pattern's scope or meaning needs to shift substantively - including moving to a different category - the original ID is marked `DEPRECATED` with a pointer to a newly issued ID in the correct block, mirroring CWE's policy. Dead numbers are cheap; ambiguous numbers are not.

3. **Anchors are citable.** Cite the most specific leaf that fits; cite the anchor (`CV3-N00`) when the behavior clearly belongs to the family but no leaf matches. An anchor citation is also a signal that the family may be missing a leaf - consider opening an issue.

4. **One rebuttal logic per leaf.** A leaf is a distinct pattern when it requires a distinct rebuttal. Variants that share a single rebuttal logic (e.g., WAF/EDR/SIEM/compiler-mitigation excuses, all answered by "demonstrate the layer stops the reported technique and fix the flaw anyway") live in one entry as listed manifestations. Variants with different rebuttals (e.g., "requires an account" vs. "the bug grants the privilege you claim it requires") get separate leaves.

5. **Required fields, every entry:** Name, ID, Description (1-3 sentences; manifestations listed inline where merged), Pattern indicator, Exemplar or grounding in the disclosure literature, **Does NOT apply when** clause, Related patterns. The clause is mandatory for anchors and leaves alike - an entry without a falsifiability condition is a one-sided weapon, which is exactly what the framing note prohibits. Entries whose exemplar is generic are marked *canonical public exemplar wanted*.

6. **Crowdsourcing model.** Mirror Bugcrowd VRT and disclose.io: GitHub repo, open contribution guidelines, public changelog of additions and merges. New leaves are proposed with all required fields; new categories require demonstrated volume that existing anchors can't absorb.

7. **Explicit non-goals.** CV3 does *not* score severity (use VRT/CVSS), does *not* arbitrate individual disputes (use HackerOne/Bugcrowd mediation, CERT/CC), and does *not* make legal claims (defer to EFF / disclose.io).

---

## Rationale

**The problem is real, recurring, and largely unenumerated.** Coordinated Vulnerability Disclosure is described in CERT/CC's [*Guide to Coordinated Vulnerability Disclosure*](https://certcc.github.io/CERT-Guide-to-CVD/) as a "wicked problem," and CERT/CC maintains a ["Troubleshooting CVD"](https://certcc.github.io/CERT-Guide-to-CVD/howto/coordination/cvd_recipes/) chapter precisely because the same dysfunctions recur. [EFF's Coders' Rights FAQ](https://www.eff.org/issues/coders/vulnerability-reporting-faq), Brookings, and Riana Pfefferkorn's ["Shooting the Messenger"](https://scholarship.richmond.edu/jolt/vol29/iss1/3/) (2022) all document that vendors routinely retaliate against reporters - but none of these works enumerates the specific *patterns* of dismissal in a structured, citable way. CV3 fills the gap between incident archives and platform close-codes.

**Famous incidents map cleanly onto a small set of recurring patterns.** Voatz vs. MIT, DJI vs. Finisterre, St. Jude vs. MedSec/Muddy Waters, Cellebrite vs. Signal, Missouri DESE, Talkspace, What3Words, and Zoom/Leitschuh each decompose into a handful of root patterns that appear again and again across the record. That convergence is what makes the taxonomy tractable - and why a single incident frequently appears as the exemplar for several entries.

**The legitimacy question cuts both ways.** The flood of LLM-generated junk reports that closed curl's bounty program gives vendors a legitimate-sounding cover story that can also be misused against careful human research (CV3-506). The same dual structure runs through the whole taxonomy: nearly every evasion has a legitimate twin, which is why every entry carries a *Does NOT apply when* clause.

**The legal landscape only partially protects researchers.** [*Van Buren v. United States*](https://www.supremecourt.gov/opinions/20pdf/19-783_k53l.pdf) (2021) narrowed the CFAA and [DOJ's 2022 charging policy](https://www.justice.gov/opa/pr/department-justice-announces-new-policy-charging-cases-under-computer-fraud-and-abuse-act) disfavors prosecuting good-faith research, but civil suits remain viable where remediation costs alone meet the loss threshold - and equivalent statutes outside the U.S. carry their own exposure. Legal retaliation therefore remains a category in its own right (CV3-800), organized by mechanism rather than by statute so that non-U.S. instruments have a home.

---

## Prior Art

| Resource | What it covers | Gap CV3 fills |
|---|---|---|
| **[Bugcrowd VRT](https://github.com/bugcrowd/vulnerability-rating-taxonomy)** | Baseline severity ratings for vuln *classes* (P1-P5), including a documented "out-of-scope/won't-pay" list | Doesn't name *vendor behaviors*; rates bugs, not responses |
| **HackerOne close-codes** (Resolved / Informative / Not Applicable / Duplicate / Spam) | Platform-level outcome categories | Coarse-grained; doesn't distinguish honest "Informative" from disingenuous "Informative" |
| **[Intigriti "Duplicate, related or known" docs](https://kb.intigriti.com/en/articles/4917102-duplicate-related-or-known-vulnerability-reports)** | Acknowledges programs marking reports as duplicates of internally known issues | Describes the mechanic, not the abuse pattern |
| **[OWASP Vulnerability Disclosure Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Vulnerability_Disclosure_Cheat_Sheet.html)** | Best-practice guidance for both sides | Prescriptive, not descriptive of failure modes |
| **[CERT/CC Guide to CVD](https://certcc.github.io/CERT-Guide-to-CVD/)**, esp. ["Troubleshooting CVD"](https://certcc.github.io/CERT-Guide-to-CVD/howto/coordination/cvd_recipes/) | Catalogs problems like unresponsive vendors, multi-vendor coordination failures, branded-vuln dynamics | Closest existing work; prose rather than ID-numbered patterns |
| **[disclose.io / `research-threats` repo](https://github.com/disclose/research-threats)** (continuing attrition.org's legal-threats list) | Incident-level archive of legal threats | Incident catalog, not a pattern abstraction |
| **[EFF Coders' Rights Vulnerability Reporting FAQ](https://www.eff.org/issues/coders/vulnerability-reporting-faq)** | Legal landscape and researcher protections | Legal advice, not evasion taxonomy |
| **[Pfefferkorn, "Shooting the Messenger"](https://scholarship.richmond.edu/jolt/vol29/iss1/3/)** (29 Rich. J.L. & Tech. 89, 2022) | CFAA "loss" threshold as retaliation tool | Single legal mechanism, deeply analyzed |
| **Matwyshyn et al. (Northeastern; CDT 2018 report)** | CFAA/DMCA chilling effects | Field-level analysis, not pattern enumeration |
| **[Weulen Kranenbarg et al., "Don't shoot the messenger"](https://link.springer.com/article/10.1186/s40163-018-0090-8)** (*Crime Science*, 2018) | Criminological analysis of researcher-vendor dynamics | Theoretical framework |
| **[Moussouris (Luta Security) talks/interviews](https://www.computerweekly.com/news/366636232/Why-bug-bounty-schemes-have-not-led-to-secure-software)** | NDA-as-silencing, pile-of-unfixed-bugs critique | Industry critique, anecdotal pattern naming |
| **[Project Zero disclosure policy](https://googleprojectzero.blogspot.com/p/vulnerability-disclosure-policy.html) + ["Reporting Transparency"](https://projectzero.google/2025/07/reporting-transparency.html)** | 90+30 deadline policy, won't-fix derestriction | Researcher-side policy, not vendor patterns |

CV3's closest analog is CERT/CC's "Troubleshooting CVD" chapter, but that is prose, not an ID-stable enumeration, and it focuses on *coordination problems* rather than on *vendor evasion patterns* specifically. CV3 positions itself as the missing vendor-side complement to the VRT, platform close-codes, and the disclose.io incident archives - complementing them, not competing with them.

---

## License

This work is licensed under [Creative Commons Attribution-ShareAlike 4.0 International (CC BY-SA 4.0)](https://creativecommons.org/licenses/by-sa/4.0/).

SPDX-License-Identifier: `CC-BY-SA-4.0`

> **Acknowledgement:** The taxonomy data in this repository was researched and curated with the assistance of [Claude](https://www.anthropic.com/claude) (Anthropic).
