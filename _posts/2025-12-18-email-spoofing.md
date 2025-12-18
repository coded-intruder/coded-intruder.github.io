---
layout: post
title: "Cross‑Tenant Email Spoofing in Shared Mail Infrastructure (Namecheap Case Study)"
subtitle: "How a shared mail backend allowed authenticated spoofing across tenant boundaries and what changed after disclosure"
date: 2025-12-18 00:00:00 +0100
categories: [red-team, email-security, case-study, infrastructure, blog]
tags: [email-spoofing, SPF, DKIM, DMARC, shared-infrastructure, cross-tenant, trust-boundary, cloud-security, defensive-evasion]
---
**Email spoofing is not new.**
What is less discussed is how **shared mail infrastructure** can unintentionally enable *authenticated spoofing across tenant boundaries* even when **SPF, DKIM, and DMARC all appear to pass**.

As organizations migrate to managed and multi-tenant email platforms, trust is placed in provider controlled configurations such as shared SPF records, centralized DKIM signing, and abstracted routing layers. While these designs simplify deployment and scale, they also introduce subtle failure modes where **authentication success does not necessarily imply sender legitimacy**.

This post examines how these trust boundaries can break down, how spoofed emails can pass standard authentication checks, and why “SPF/DKIM/DMARC = secure” is a dangerous assumption without proper domain isolation and monitoring.

At its core, email authentication is still **infrastructure trust–based**, not identity–based.

In many real-world deployments, domains are required to include **shared provider-controlled SPF mechanisms** (for example, universal `include:` records) as part of their email configuration. These shared records often authorize large IP ranges used by thousands of tenants. Once a receiving mail server sees an authorized IP and a valid DKIM signature from the provider, **trust is implicitly extended — not just to the infrastructure, but to every tenant operating within it**.

This creates a dangerous assumption: that authorization at the provider level automatically implies legitimacy at the domain level. In practice, an attacker who simply registers a domain or mailbox with the same email provider may gain access to **infrastructure that is already trusted by the target domain’s SPF and DKIM configuration**. No exploitation of mail servers is required only correct positioning within shared trust boundary.

When authentication mechanisms are satisfied by *shared infrastructure* rather than *strict domain isolation*, spoofing becomes less about breaking cryptography and more about **abusing configuration inheritance**.

## Email Authentication Refresher

Modern email authentication relies on three primary mechanisms: **SPF**, **DKIM**, and **DMARC**. These controls are heavily documented, so this section intentionally avoids basic explanations and focuses on the aspects relevant to multi-tenant environments.

**SPF (Sender Policy Framework)** authorizes *infrastructure*, not identity. It answers a single question: *Is this sending IP permitted to send mail on behalf of this domain?*
It does **not** validate who is using that infrastructure, nor does it distinguish between tenants sharing the same outbound mail systems.

**DKIM (DomainKeys Identified Mail)** provides message integrity and domain-level authentication by attaching a cryptographic signature. In hosted environments, this signature is often applied centrally by the provider, using provider-managed keys rather than tenant-isolated signing domains.

**DMARC (Domain-based Message Authentication, Reporting & Conformance)** acts as a policy layer on top of SPF and DKIM. Importantly, DMARC uses **logical OR** evaluation:

* If *either* SPF **or** DKIM passes **and** aligns with the visible `From:` domain, DMARC passes.

This behavior is correct by specification but it introduces subtle risk in shared infrastructure models. When SPF authorization and DKIM signing are both satisfied by provider-controlled systems, authentication success may reflect *infrastructure trust* rather than *domain legitimacy*.

In other words, an email can be fully authenticated while still violating the intended trust boundary between tenants.

## The Shared Infrastructure Trust Boundary

Email authentication mechanisms were designed to answer a narrow question: **"Was this message sent from infrastructure authorized by the domain?"** They were **not** designed to answer **"Was this message sent by the legitimate owner of the visible identity?"** 

This distinction matters more in multi-tenant mail platforms than most people realize.

In shared email infrastructure, thousands of unrelated domains often rely on the same outbound mail servers, the same IP pools, and in some cases the same DKIM signing domains. To make this work at scale, providers typically require customers to:

- Include a provider-controlled SPF record (often via a broad `include:` mechanism)
- Rely on **centralized DKIM signing** performed by the provider.
- Accept **abstracted routing layers** where message origin is no longer domain-specific.

From the receiver's perspective, this creates a simplified trust model:

* if the IP is authorized and the message is cryptographically intact, the sender is trusted

The problem is that this trust is extended to infrastructure outside our control, not to tenants.

Once a provider's mail servers are authorized in SPF, and once their DKIM signatures are trusted, any tenant operating inside that infrastructure inherits that trusts. The receiving server has no visibility into which customer initiated the message, only that it came from an approved system.

This is where the tenant boundary quietly collapses.

An attacker does not need to compromise mail servers, bypass cryptography, or exploit SMTP software. In many cases, they only need to **position themselves correctly inside the same trusted email ecosystem**, for example, by registering a domain or mailbox with the same provider used by the target.

At that point, spoofing becomes a configuration problem, not an exploitation problem.

if SPF authorizes the provider's IP range, and DKIM signatures are applied at the provider level, then authentication success can occur even when the visible From sender identity does not belong to the actual tenant that originated the message.

This is why statements like "SPF, DKIM, and DMARC all passed" can be technically true while still being operationally misleading.


## Case Study: Cross-Tenant Spoofing in Namecheap Private Email
During independent research into email authentication behavior, I identified a cross-tenant spoofing condition in Namecheap’s Private Email service. The issue did not involve exploitation of mail servers or cryptographic failures, but rather how shared authentication infrastructure was trusted across tenant boundaries.

### Header Analysis: Authentication Without Tenant Legitimacy

To validate that this was not a mail client UI artifact, the message headers were inspected.

The email originated from a tenant-controlled mailbox within Namecheap Private Email infrastructure (`user@abctest-insurance.pro`) while presenting a visible `From:` identity belonging to `support@namecheap.com`.

Relevant authentication results are shown below:

```
From: support@namecheap.com
Return-Path: <user@abctest-insurance.pro>

Received: from out-14.pe-b.jellyfish.systems (out-14.pe-b.jellyfish.systems [198.54.127.82])
        by mx.google.com with ESMTPS
        for <codedintruder@gmail.com>;
        Sun, 20 Oct 2024 13:41:05 -0700 (PDT)

Received: from prod-lbout-phx.jellyfish.systems (new-01.privateemail.com [198.54.118.220])
        by pe-b.jellyfish.systems (Postfix) with ESMTPA
        for <codedintruder@gmail.com>;
        Sun, 20 Oct 2024 20:41:04 +0000 (UTC)

Received: from MTA-12.privateemail.com (unknown [10.50.14.28])
        by NEW-01.privateemail.com (Postfix) with ESMTPS
        for <codedintruder@gmail.com>;
        Sun, 20 Oct 2024 16:41:04 -0400 (EDT)

DKIM-Signature: v=1; a=rsa-sha256; d=namecheap.com; s=default;
Authentication-Results: mx.google.com;
        dkim=pass header.i=@namecheap.com header.s=default;
        spf=pass smtp.mailfrom=user@abctest-insurance.pro;
        dmarc=pass (p=REJECT sp=REJECT) header.from=namecheap.com
```

All standard authentication checks passed:

* **SPF** passed because the sending IP was authorized for the originating tenant domain.
* **DKIM** passed because the message was signed using a provider-controlled DKIM key trusted for `namecheap.com`.
* **DMARC** passed due to alignment with the visible `From:` domain and successful DKIM validation.

At no point did the receiving system evaluate *tenant ownership* of the visible sender identity. Authentication success reflected **infrastructure authorization**, not **domain-level legitimacy**.

This demonstrates the core issue:
when SPF and DKIM trust is delegated to shared provider infrastructure, **cross-tenant identity abuse can occur without breaking any authentication mechanism**.

The message was authenticated correctly — but authenticated **too broadly**.


### Evidence: Authenticated Spoofed Email
The following screenshots taken from standard mail client shows how this issue manifests in **user interface level**.

The message was sent from Namecheap Private Email Tenant while using a different Namecheap-hosted domain in the visible `From:` address.

The **verified** check indicates that authentication checks were satisfied.

![Figure-1.1 Screenshot showing namecheap verified header](/assets/images/email_spoof/namecheap-spoof.png)
*Figure-1.1 email client marking the sender as sent from a verified domain*
![Figure-1.2 Screenshot showing more header information](/assets/images/email_spoof/namecheap2.png)
*Figure-1.2 Visible sender identity (`support@namecheap.com`) originating from a different tenant (`abctest-insurance.pro`)*

This could enable targeted phishing against Namecheap customers, impersonating official support with full inbox placement and trust indicators.

Mail clients base trust decisions on upstream authentication results rather than tenant ownership. Because the message originated from infrastructure authorized by the target domain's SPF record and was signed with a trusted DKIM key, the client correctly interpreted the message as authenticated.

### Impact: Why This Matters

This behavior enables high-confidence impersonation without triggering traditional email security controls. Because the message passes SPF, DKIM, and DMARC, it is:

- Delivered to inboxes instead of spam
- Displayed with verified sender indicators
- Trusted by automated mail gateways and end users

In this case, the spoofed identity (support@namecheap.com) is a high-value operational sender, meaning the impact extends beyond generic phishing into areas such as:

- Account takeover via trusted support workflows
- Social engineering of customers already in active support conversations
- Abuse of password reset, billing, or incident response trust paths

### Disclosure and Provider Response

After responsible disclosure, Namecheap provided the following summary of actions taken to address the issue:

> Dear Client,  
>
> We appreciate your help in finding the issue so we can improve our system.  
>
> Below you can find details as to what actions we took to fix it. 
>
> To address the major risk, a fix was deployed to ensure that digital signatures accurately reflected the authenticated domain of the sender. This adjustment allowed recipient servers to correctly identify the true source of the email, mitigating the risk of address forgery.  
>
> As a next step, measures were introduced to prevent sending emails with forged From addresses. This action ensures that users cannot manipulate the From field to impersonate domains hosted on our platform.  
>
> Furthermore, a separate SPF record for [namecheap.com](http://namecheap.com/) domain was added. This enhancement provides better control over authorized sending addresses, strengthening the domain's email security posture.  
>
> By implementing these corrective actions, we improved the integrity and authenticity of emails sent through Private Email, reducing the risk of spoofing attacks.

These actions reflect configuration and policy improvements, rather than changes to the underlying protocols, and they significantly reduce the risk of cross-tenant identity abuse on the platform.

## Key Takeaways

- Authentication success (SPF/DKIM/DMARC passing) does not automatically imply tenant-level legitimacy.
- Shared email infrastructure can unintentionally extend trust beyond the intended domain boundaries.
- Responsible disclosure and provider-side fixes can mitigate such risks without altering protocol specifications.
- Organizations should treat “authenticated” UI indicators as necessary but not sufficient trust signals and enforce additional controls for high-value senders.

## MITRE ATT&CK Mapping

This behavior enables adversaries to conduct high-confidence phishing and impersonation attacks by abusing trusted infrastructure rather than exploiting software vulnerabilities.

- **T1566.002 – Phishing: Spearphishing via Service**  
  Spoofed emails that pass SPF, DKIM, and DMARC can be delivered with verified sender indicators, enabling targeted impersonation of trusted service providers and support workflows.

- **T1199 – Trusted Relationship**  
  The attack abuses implicit trust relationships created by shared email infrastructure, where authentication success is derived from provider-level trust rather than tenant-level identity validation.

- **T1585.002 – Establish Accounts: Email Accounts**  
  The adversary simply registers an email account or domain with the same hosted provider to gain access to pre-trusted sending infrastructure.

- **T1672 - Email Spoofing**
  The shared infrastructure trust boundary allows header manipulation (From:) without breaking SPF/DKIM/DMARC, bypassing automated defenses.

Links:  
- https://attack.mitre.org/techniques/T1566/002/  
- https://attack.mitre.org/techniques/T1199/  
- https://attack.mitre.org/techniques/T1585/002/
- https://attack.mitre.org/techniques/T1672/
