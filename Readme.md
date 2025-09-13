**1. what is API?**

An API (Application Programming Interface) is a set of rules and protocols that allows different software applications to communicate with each other, enabling them to exchange data and functionality.

<img width="1000" height="470" alt="Image" src="https://github.com/user-attachments/assets/412695f9-b9a4-4c97-902b-80773e477b38" />

---

**2. What is a protocol?**

A protocol is a set of rules and standards that define how data is formatted, transmitted, and received between two or more devices, systems, or applications.

| Layer (OSI) | Protocol Examples           |
| ----------- | --------------------------- |
| Application | HTTP, HTTPS, FTP, SMTP, DNS |
| Transport   | TCP, UDP, QUIC              |
| Network     | IP (IPv4/IPv6), ICMP        |
| Data Link   | Ethernet, Wi-Fi (802.11)    |
| Security    | TLS/SSL, IPSec              |

4️⃣ **Why Protocols Matter**

Without protocols, devices wouldn’t know how to interpret signals or how to respond.

They ensure consistency, security, and efficiency of communication.

5️⃣ **Real-World Analogy**

Two people speaking the same language and agreeing on how a conversation works (say hello, talk, say goodbye) — that’s a protocol. If one speaks English and the other Japanese without a translator, communication fails.

---

**3. how data is transferred in a network?**

Data is transferred over a network by breaking it into packets. Each packet carries header information (IP addresses, ports, sequence numbers) and payload (the actual data). Packets move through routers and switches following protocols like TCP/IP. At the destination, packets are reassembled and passed up the stack to the application. Security protocols like TLS can encrypt the data so it’s confidential in transit.

<img width="1024" height="1536" alt="Image" src="https://github.com/user-attachments/assets/cffe61e9-a85a-4bf2-99ae-c67fe9709c10" />

---

**4. Difference between HTTP and HTTPS?**

| Term                                           | Definition                                                                                                  |
| ---------------------------------------------- | ----------------------------------------------------------------------------------------------------------- |
| **HTTP (HyperText Transfer Protocol)**         | A protocol for transferring hypertext (web pages, resources) between browsers and web servers in plaintext. |
| **HTTPS (HyperText Transfer Protocol Secure)** | HTTP **over TLS/SSL**, which encrypts the communication between client and server.                          |


| Feature                     | **HTTP**                                                          | **HTTPS**                                                                         |
| --------------------------- | ----------------------------------------------------------------- | --------------------------------------------------------------------------------- |
| **Security**                | No encryption — data travels in plaintext.                        | Encrypted with **TLS/SSL** — data secured in transit.                             |
| **Port**                    | Default **80**                                                    | Default **443**                                                                   |
| **Certificate Required**    | Not needed                                                        | Needs an **SSL/TLS certificate** issued by a trusted Certificate Authority (CA).  |
| **Data Integrity**          | Vulnerable to interception, tampering, man-in-the-middle attacks. | Protects against interception and tampering.                                      |
| **Authentication**          | None by default.                                                  | Server identity verified through the certificate.                                 |
| **SEO / Browser Treatment** | Labeled “Not Secure” by modern browsers.                          | Preferred by browsers; gets SEO ranking benefits.                                 |
| **Performance**             | Slightly faster (no encryption overhead).                         | Modern TLS is very efficient; plus supports HTTP/2/3 which can be faster overall. |

---

**5. When to use HTTP vs HTTPS?**

**1️⃣ Use HTTP (non-secure) only when:**

No sensitive data is involved (purely public content).
Example: A static test page or an internal dev tool on a private network not exposed externally.

Prototyping or debugging where encryption overhead isn’t needed temporarily.

Very controlled environments (air-gapped or private labs) where both endpoints are trusted.

⚠️ Even in these cases, modern browsers will often warn users “Not Secure.”


**2️⃣ Use HTTPS when:**

Any sensitive or personal data is sent or received (login credentials, payment info, health records).

User authentication is required (logins, sessions, APIs with tokens).

Compliance standards apply (PCI-DSS for credit cards, HIPAA for health data, GDPR for EU privacy).

Public-facing websites — all modern browsers and search engines expect HTTPS.

APIs used by mobile/web apps — to prevent interception and tampering of API calls.

SEO & browser trust — Google ranks HTTPS sites higher and Chrome marks HTTP “Not Secure.”

---

**6. What is SSL?**

SSL stands for Secure Sockets Layer. It’s a cryptographic protocol that encrypts data between client and server, ensuring confidentiality, integrity, and authentication. Although SSL itself is outdated and replaced by TLS, the term is still widely used to refer to the certificates and secure connections we see as HTTPS in browsers


**How SSL/TLS Works (Simplified)**

Handshake:

Browser requests a secure connection.

Server sends its SSL certificate (contains public key).

Browser verifies certificate validity.

Key Exchange:

Client and server agree on session keys for encryption.

Secure Communication:

All data sent between client and server is encrypted using the session key.


| SSL                                       | TLS                               |
| ----------------------------------------- | --------------------------------- |
| Older, less secure versions (SSL 2.0/3.0) | Modern, more secure (TLS 1.2/1.3) |
| Deprecated, not recommended               | Actively maintained, recommended  |


<img width="1536" height="1024" alt="Image" src="https://github.com/user-attachments/assets/7ee6b59c-34e9-4988-bdeb-15d8e19e1ef4" />

---

**7. Difference between API and REST API?**

| Feature          | API                           | REST API                       |
| ---------------- | ----------------------------- | ------------------------------ |
| **Type**         | Broad concept                 | Subtype of Web API             |
| **Protocol**     | Any (HTTP, TCP, SDKs, etc.)   | HTTP only                      |
| **Design Style** | Any (SOAP, GraphQL, etc.)     | REST architecture              |
| **Data Format**  | Any (binary, XML, JSON, etc.) | Typically JSON or XML          |
| **Usage**        | OS, libraries, databases, web | Web services only              |
| **Stateless?**   | Not always                    | Yes, always (REST requirement) |


---

**8. REST vs SOAP vs GraphQL**


| Feature            | **REST API**                            | **SOAP API**                          | **GraphQL API**                                                           |
| ------------------ | --------------------------------------- | ------------------------------------- | ------------------------------------------------------------------------- |
| **Protocol**       | HTTP (or other protocols)               | XML-based protocol (often HTTP)       | Uses HTTP, but is a query language                                        |
| **Message Format** | JSON, XML, etc.                         | XML                                   | JSON                                                                      |
| **State**          | Stateless                               | Stateful                              | Stateless (but can support real-time with subscriptions)                  |
| **Complexity**     | Simple, widely used                     | Complex, verbose (XML)                | Complex, powerful, but requires more tooling                              |
| **Flexibility**    | Moderate (can have over-fetching)       | Low (very rigid, strict standards)    | Very flexible (client defines the query)                                  |
| **Caching**        | Built-in caching support (HTTP caching) | No inherent caching                   | No inherent caching (needs custom setup)                                  |
| **Security**       | Depends on implementation (e.g., OAuth) | Built-in security (WS-Security)       | Depends on implementation (e.g., JWT)                                     |
| **Error Handling** | Standard HTTP error codes               | Detailed fault codes                  | Errors included in the response with error messages                       |
| **Use Case**       | General-purpose, CRUD operations        | Enterprise-level, secure transactions | Real-time apps, flexible data queries (e.g., mobile, frontend-heavy apps) |


**When to Use Each:**

**REST:**

Ideal for general web services and CRUD operations.

When simplicity and wide adoption are priorities.

Best for public APIs where caching, performance, and simplicity matter.

**SOAP:**

When security and transaction integrity are critical (e.g., financial services, payment gateways).

When working in enterprise environments where strict standards and reliability are required.

Where features like WS-Security are necessary.

**GraphQL:**

When clients need precise control over the data they query.

In mobile or frontend-heavy applications where over-fetching/under-fetching is a concern.

For real-time applications (e.g., live chat, social media feeds).

---

**9. main API security practices**


**🔐 1. HTTPS (TLS Encryption)**

All API traffic should go over HTTPS, not HTTP.

Encrypts data in transit → prevents eavesdropping and man-in-the-middle attacks.

Use strong TLS versions (TLS 1.2 or 1.3).

**🔐 2. OAuth 2.0**

Industry-standard authorization framework.

Allows third-party apps to access an API without exposing user credentials.

Uses access tokens, refresh tokens, scopes, and expiration.

Example: “Login with Google.”

**🔐 3. WebAuthn**

Modern authentication standard (FIDO2).

Provides passwordless or multi-factor authentication.

Uses public-key cryptography, making phishing much harder.

**🔐 4. Implement Authorization**

Clearly separate authentication (who you are) from authorization (what you can do).

Use RBAC (Role-Based Access Control) or ABAC (Attribute-Based Access Control).

Enforce least privilege: users/services get only what they need.

**🔐 5. Leveled API Keys**

Issue API keys with different access levels:

Read-only keys.

Read-write keys.

Admin keys.

Rotate and revoke keys regularly.

Keep keys secret (not in public repos).

**🔐 6. Rate Limiting & Throttling**

Limit the number of requests per client per time window.

Protects against DoS attacks and API abuse.

Common patterns: 1000 requests/minute per user.

**🔐 7. API Versioning**

Maintain separate versions (v1, v2) to handle breaking changes.

Allows deprecation without breaking existing clients.

Helps maintain security patches for older versions.

**🔐 8. Allow Listing (a.k.a. Whitelisting)**

Restrict API access to specific IPs, apps, or organizations.

Blocks unknown or malicious sources from calling your API.

**🔐 9. OWASP API Security Risks**

Key risks to mitigate (per OWASP API Security Top 10):

Broken Object Level Authorization (BOLA).

Broken User Authentication.

Excessive Data Exposure.

Lack of Rate Limiting.

Security Misconfigurations.

Injection attacks (SQLi, NoSQLi).

Insufficient Logging & Monitoring.

**🔐 10. API Gateway**

A central point to enforce security controls:

Authentication.

Rate limiting.

Logging.

Routing and load balancing.

Examples: Kong, AWS API Gateway, Apigee.

**🔐 11. Error Handling**

Don’t leak internal system details (stack traces, DB errors) in API responses.

Use generic error messages (e.g., “Invalid credentials”).

Use consistent HTTP status codes.

**🔐 12. Input Validation**

Validate and sanitize all input from clients.

Use allow-lists for expected values.

Protect against injection attacks (SQLi, XSS).

Use JSON schema validation for API payloads.