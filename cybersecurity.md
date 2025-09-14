**1. cybersecurity?**

Cybersecurity is the practice of protecting systems, networks, applications, and data from digital attacks, unauthorized access, disruption, or destruction.

| Goal                | Meaning                                                   |
| ------------------- | --------------------------------------------------------- |
| **Confidentiality** | Keeping data private (only authorized people can see it). |
| **Integrity**       | Ensuring data is accurate and not tampered with.          |
| **Availability**    | Making sure systems and data are accessible when needed.  |

**Key Areas of Cybersecurity**

| Area                                   | What It Protects                                          |
| -------------------------------------- | --------------------------------------------------------- |
| **Network Security**                   | Routers, firewalls, VPNs, intrusion detection.            |
| **Application Security**               | Secure coding, penetration testing, web/API protection.   |
| **Endpoint Security**                  | Protecting laptops, servers, IoT devices.                 |
| **Cloud Security**                     | Data and services hosted in the cloud.                    |
| **Identity & Access Management (IAM)** | User authentication and authorization.                    |
| **Data Security**                      | Encryption, backups, data loss prevention.                |
| **Incident Response**                  | Detecting and responding to attacks.                      |
| **Governance & Compliance**            | Policies, audits, and standards (GDPR, HIPAA, ISO 27001). |


**Types of Threats Cybersecurity Protects Against**

Malware (viruses, ransomware, trojans).

Phishing and social engineering.

Data breaches.

Denial-of-service (DoS/DDoS) attacks.

Insider threats.

Advanced persistent threats (APTs).

---

**2. Types of hackers**


**🔹 White Hat Hackers (Ethical Hackers)**

Intent: Good. They find and fix vulnerabilities.

Activities:

Penetration testing

Security audits

Bug bounty programs

Example: Security engineers at Google or a certified ethical hacker doing a penetration test.

**Black Hat Hackers (Malicious Hackers)**

Intent: Bad. They exploit vulnerabilities for personal gain or to cause harm.

Activities:

Data theft

Malware deployment

Ransomware attacks

Example: Hacker groups stealing credit card data or launching ransomware campaigns.

**Gray Hat Hackers**

Intent: Mixed. They break rules but not necessarily for malicious reasons.

Activities:

Test systems without permission

Sometimes disclose vulnerabilities, sometimes exploit

Example: A hacker who finds a flaw and reveals it publicly without the owner’s consent.

**Script Kiddies**

Intent: Often malicious but unskilled. They use existing tools or scripts created by others.

Activities:

DDoS attacks using ready-made tools

Website defacement

Example: Teenagers using pre-made exploit kits without understanding the code.

**Hacktivists**

Intent: Political or social causes.

Activities:

Website defacement to spread messages

DDoS against governments or companies

Example: Groups like Anonymous targeting government sites.

** State-Sponsored Hackers (Nation-State Actors)**

Intent: Government-backed operations for espionage or sabotage.

Activities:

Cyber espionage

Infrastructure attacks

Spying on rivals

Example: Alleged groups like APT28, Lazarus Group.

** Cyber Terrorists**

Intent: Cause fear, panic, or large-scale damage.

Activities:

Disrupting critical infrastructure

Spreading extremist propaganda online

**🔹 Whistleblowers / Insider Threats**

Intent: Varies (exposing wrongdoing, revenge).

Activities:

Leaking confidential data

Selling access to external attackers

Example: Employees leaking sensitive data or credentials.


| Hacker Type     | Intent    | Legal?    | Example Activity        |
| --------------- | --------- | --------- | ----------------------- |
| White Hat       | Good      | ✅ Legal   | Security testing        |
| Black Hat       | Bad       | ❌ Illegal | Data theft              |
| Gray Hat        | Mixed     | ⚠ Depends | Unauthorized scanning   |
| Script Kiddie   | Often Bad | ❌ Illegal | Using premade tools     |
| Hacktivist      | Political | ❌ Illegal | DDoS for cause          |
| State-Sponsored | Espionage | ❌ Illegal | Infrastructure hacking  |
| Cyber Terrorist | Harm/Fear | ❌ Illegal | Critical systems attack |
| Insider Threat  | Mixed     | ❌ Illegal | Data leak or sabotage   |


---

**3. what is phishing attacks?**

A phishing attack is a type of social engineering where attackers trick people into revealing sensitive information (like passwords, credit card numbers, or personal data) or installing malware — usually by pretending to be a trusted entity.

It’s called “phishing” because attackers “fish” for victims’ data.


**🔹 How It Works**

Deception – The attacker impersonates a legitimate entity (bank, email provider, government agency).

Bait – They send an email, text, or link urging the user to take urgent action (update account, verify identity, claim prize).

Hook – Victim clicks the malicious link or downloads an attachment.

Harvest Data or Install Malware – Credentials are stolen or malware executes silently.

**🔹 Common Delivery Methods**

Email phishing – The most common form.

Spear phishing – Targeted at specific individuals or organizations.

Smishing – Phishing via SMS/text message.

Vishing – Phishing via voice calls.

Clone phishing – Attacker clones a legitimate message but changes links.

Website phishing – Fake login pages mimicking real sites.

**🔹 Real-World Examples**

Fake PayPal or bank emails asking users to “confirm” account details.

Emails appearing to be from Microsoft 365 or Google Workspace prompting password resets.

**🔹 How to Recognize Phishing**

Suspicious sender addresses.

Urgent or threatening language (“Your account will be closed!”).

Misspellings and generic greetings (“Dear Customer”).

Links that don’t match legitimate URLs.

| Measure                         | Why It Helps                         |
| ------------------------------- | ------------------------------------ |
| Verify sender & URLs            | Stops fake emails/websites           |
| Use Multi-Factor Authentication | Reduces impact if credentials stolen |
| Security awareness training     | Employees learn to spot phishing     |
| Anti-phishing email filters     | Block suspicious messages            |
| Keep systems updated            | Mitigates malware from attachments   |


---

**4. what is malware attacks?**

A malware attack is a cyberattack in which malicious software (malware) is installed on a device, system, or network — either with or without the user’s knowledge — to steal data, disrupt operations, gain unauthorized access, or cause damage.

“Malware” = Malicious + Software.

**🔹 How a Malware Attack Works**

Delivery – The attacker distributes malware (via email attachment, malicious website, infected USB, drive-by downloads, etc.).

Execution – User opens the file or visits the link; malware installs itself.

Action – Malware performs its intended malicious behavior (stealing credentials, encrypting files, spying, etc.).

Persistence – Malware may hide itself or create backdoors for future access.

**🔹 Real-World Examples**

WannaCry Ransomware (2017) – encrypted hundreds of thousands of computers globally.

ILOVEYOU Virus (2000) – a mass-mailing worm disguised as a love letter.

Zeus Trojan – stole banking credentials worldwide.

**Common Infection Vectors**

Malicious email attachments or links (phishing).

Compromised or fake software downloads.

Exploiting unpatched vulnerabilities in software.

Removable media (USB drives).

**🔹 Preventive Measures**

| Action                           | Why It Helps                               |
| -------------------------------- | ------------------------------------------ |
| Keep systems patched and updated | Fixes exploitable vulnerabilities.         |
| Use reputable antivirus / EDR    | Detects and blocks malware.                |
| Enable firewalls                 | Blocks unauthorized network access.        |
| Train users on safe practices    | Reduces chance of opening malicious files. |
| Implement least-privilege access | Limits the impact of malware.              |
| Regular backups                  | Mitigates ransomware damage.               |

---

**5. what is ransomware attack?**

A ransomware attack is a type of malware attack where the attacker encrypts a victim’s files or locks their system, then demands a ransom payment (usually in cryptocurrency) to restore access.

It’s called “ransomware” because it combines “ransom” + “software.”

**🔹 How It Works**

Infection – The attacker spreads ransomware via phishing emails, malicious downloads, or exploiting vulnerabilities.

Encryption / Lockout – Once executed, ransomware encrypts files or locks screens.

Ransom Demand – Victim sees a message demanding payment (often with a deadline).

Payment & Decryption – Attackers promise to provide a decryption key after payment (but there’s no guarantee).

**🔹 Common Delivery Methods**

Phishing emails with malicious attachments or links.

Drive-by downloads from compromised websites.

Exploiting unpatched systems (Remote Desktop Protocol, outdated OS).

Malvertising (malicious ads).

**🔹 Why It’s Dangerous**

Can halt business operations.

May leak sensitive data (“double extortion”).

Costs include ransom, downtime, and recovery.

**Prevention & Mitigation**

| Step                                | Why It Helps                                   |
| ----------------------------------- | ---------------------------------------------- |
| Regular data backups (offline)      | Restore files without paying ransom.           |
| Keep systems patched                | Prevent exploitation of known vulnerabilities. |
| Security awareness training         | Users learn to spot phishing attempts.         |
| Endpoint detection & response (EDR) | Detect ransomware behavior early.              |
| Use least-privilege access          | Limits spread of ransomware across systems.    |

---

6. what is DDoS attack?

A DDoS attack (Distributed Denial of Service) is a cyberattack where an attacker uses many compromised computers or devices (often a botnet) to flood a target server, network, or service with massive traffic, making it unavailable to legitimate users.

Think of it as a digital traffic jam — so much junk traffic that real visitors can’t get through.

**🔹 How It Works**

Botnet Creation – Attacker infects thousands of devices with malware, turning them into “bots” or “zombies.”

Traffic Flood – All these bots simultaneously send a huge number of requests to the target.

Resource Exhaustion – The target’s bandwidth, CPU, or memory is overwhelmed.

Service Outage – Legitimate users can’t access the service.

**Types of DDoS Attacks**

| Type                            | What It Targets                                                     |
| ------------------------------- | ------------------------------------------------------------------- |
| **Volumetric**                  | Overwhelm bandwidth (e.g., UDP floods, ICMP floods).                |
| **Protocol / Network Layer**    | Exploit weaknesses in network protocols (e.g., SYN floods).         |
| **Application Layer (Layer 7)** | Mimic legitimate requests to overload web apps (e.g., HTTP floods). |

**🔹 Why It’s Dangerous**

Knocks websites or services offline.

Causes lost revenue, reputation damage, and SLA breaches.

Can act as a smokescreen for other cyberattacks.

**🔹 Defensive Measures**

| Defense                                                       | How It Helps                                     |
| ------------------------------------------------------------- | ------------------------------------------------ |
| **Rate limiting / throttling**                                | Limits excessive requests per IP.                |
| **CDN & load balancers**                                      | Absorb large amounts of traffic.                 |
| **Web Application Firewall (WAF)**                            | Filters malicious requests.                      |
| **DDoS mitigation services** (Cloudflare, AWS Shield, Akamai) | Specialized large-scale defense.                 |
| **Network monitoring & alerting**                             | Detect anomalies early.                          |
| **Anycast routing**                                           | Distribute traffic across multiple data centers. |

---

**7. what is SQL Injection (SQLi) attack?**

A SQL Injection attack is a type of web security vulnerability where an attacker inserts (or “injects”) malicious SQL statements into an application’s database query.
If the application does not properly validate or escape user input, the attacker can run arbitrary SQL commands on the database.

**🔹 How It Works**

User Input → SQL Query
Application takes input (like a login form) and plugs it directly into an SQL query without sanitization.

Malicious Input
Attacker crafts input containing SQL code — for example:

' OR '1'='1

Execution on DB Server
The database runs the attacker’s SQL code as part of the query.

Result
Attacker can bypass authentication, read or modify sensitive data, or even delete entire tables.

**🔹 Example Scenario**

Vulnerable Code (Python + SQL):

# ❌ Vulnerable
username = request.GET['user']
query = f"SELECT * FROM users WHERE username = '{username}'"
cursor.execute(query)


Attacker Input:

' OR '1'='1

Resulting Query:

SELECT * FROM users WHERE username = '' OR '1'='1'


**🔹 What Attackers Can Do**

Bypass authentication.

Read sensitive data (credit cards, passwords).

Modify or delete data.

Execute administrative operations on the database.

In severe cases, gain control over the server hosting the DB.

**🔹 Preventive Measures**

| Defense Technique                               | Why It Helps                          |
| ----------------------------------------------- | ------------------------------------- |
| **Parameterized Queries / Prepared Statements** | Keeps data separate from code.        |
| **Use ORM safely** (SQLAlchemy, Django ORM)     | Automatically parameterizes queries.  |
| **Input validation & escaping**                 | Rejects or sanitizes dangerous input. |
| **Least-privilege DB accounts**                 | Limits damage if compromised.         |
| **Web Application Firewall (WAF)**              | Filters common SQLi patterns.         |
| **Keep software patched**                       | Fixes known vulnerabilities.          |

**🔹 Safe Example**

# ✅ Safe with parameterized query
cursor.execute("SELECT * FROM users WHERE username = %s", (username,))

This treats username purely as data, not executable SQL.

---

8. what is Firewall?

A firewall is a network security device or software that monitors and controls incoming and outgoing network traffic based on predetermined security rules.
It acts as a barrier between a trusted network (like your computer or company LAN) and an untrusted network (like the internet).

**What It Does**

Filters traffic (packets) based on IP addresses, ports, and protocols.

Blocks unauthorized access into or out of your network.

Can be hardware (router, appliance) or software (Windows Firewall).

Types of Firewalls

| Type                                   | Description                                                      |
| -------------------------------------- | ---------------------------------------------------------------- |
| **Packet-filtering firewall**          | Checks packets against rules (IP, port, protocol).               |
| **Stateful inspection firewall**       | Tracks the state of active connections.                          |
| **Application-layer firewall (proxy)** | Filters traffic at the application level (HTTP, FTP).            |
| **Next-Generation Firewall (NGFW)**    | Includes deep packet inspection, intrusion prevention, and more. |

**Example**

Allow web traffic on port 80/443 but block all other inbound connections.

---

**9. what is Antivirus?**

Antivirus software is a program installed on a computer or server that detects, blocks, and removes malicious software (malware) such as viruses, worms, Trojans, ransomware, spyware, etc

**What It Does**

Scans files and processes for known malware signatures.

Uses heuristics and behavior analysis to detect new threats.

Quarantines or deletes malicious files.

Offers real-time protection and scheduled scans.

**Examples**

Windows Defender

Norton Antivirus

McAfee

Kaspersky

| Feature      | Firewall                             | Antivirus                                  |
| ------------ | ------------------------------------ | ------------------------------------------ |
| **Purpose**  | Controls **network traffic**         | Detects and removes **malware** on devices |
| **Focus**    | Network perimeter security           | Endpoint/device security                   |
| **Blocks**   | Unauthorized connections (in/out)    | Malicious files, processes, scripts        |
| **Type**     | Hardware or software                 | Software (sometimes part of a suite)       |
| **Examples** | Cisco ASA, pfSense, Windows Firewall | Norton, McAfee, Windows Defender           |


---

**11. what is hashing in cybersecurity?**

Hashing is the process of taking input data (any size) and transforming it into a fixed-length string (hash value or digest) using a mathematical algorithm.
It’s a one-way function — meaning you cannot (practically) reverse the hash to get the original data.

**🔹 Key Characteristics**

| Property                | Meaning                                             |
| ----------------------- | --------------------------------------------------- |
| **Deterministic**       | Same input → same hash every time.                  |
| **Fixed length**        | Output size is constant (e.g., SHA-256 → 256 bits). |
| **One-way**             | Hard/impossible to reverse the process.             |
| **Fast**                | Efficient to compute.                               |
| **Collision-resistant** | Hard to find two different inputs with same hash.   |


**🔹 Why Hashing is Used in Cybersecurity**

Password Storage

Systems store hashed passwords (not plaintext).

When a user logs in, their password is hashed and compared to the stored hash.

Even if database leaks, plaintext passwords are protected (if hashed properly with salt).
Example:

password123 → SHA-256 → ef92b778... (stored)

Data Integrity Verification

Used to check whether files or messages have been altered.

If the hash of a file changes, it’s been tampered with.

Digital Signatures & Certificates

Hashing ensures the signed data hasn’t changed.

Blockchain & Cryptocurrencies

Hashing secures blocks, transactions, and addresses.

**🔹 Common Hashing Algorithms**

| Algorithm                  | Output Size | Notes                                          |
| -------------------------- | ----------- | ---------------------------------------------- |
| **MD5**                    | 128 bits    | Obsolete (vulnerable to collisions).           |
| **SHA-1**                  | 160 bits    | Obsolete for security-critical use.            |
| **SHA-256**                | 256 bits    | Widely used, secure.                           |
| **SHA-3**                  | 256+ bits   | Newer standard.                                |
| **bcrypt, scrypt, Argon2** | Variable    | Designed for password hashing (slow + salted). |

**Hashing vs Encryption**

| Feature         | Hashing                           | Encryption                       |
| --------------- | --------------------------------- | -------------------------------- |
| **Reversible?** | No (one-way)                      | Yes (two-way with key).          |
| **Purpose**     | Verify integrity, store passwords | Keep data confidential.          |
| **Key needed?** | No                                | Yes (encryption/decryption key). |

---

**12. what is vulnerability scanning?**

Vulnerability scanning is an automated process of identifying security weaknesses (vulnerabilities) in computers, networks, applications, and systems.
It’s a proactive security measure — scanning before an attacker exploits those weaknesses.

**🔹 How It Works**

Asset Discovery
– The scanner identifies systems, IP addresses, services, and applications.

Fingerprinting
– It determines software versions, open ports, and configurations.

Vulnerability Check
– Compares the discovered information against a database of known vulnerabilities (like CVEs).

Reporting
– Generates a report with severity levels, CVE references, and remediation suggestions.

**Types of Vulnerability Scanning**

| Type                          | Purpose                                                                                 |
| ----------------------------- | --------------------------------------------------------------------------------------- |
| **Network-based scanning**    | Scans network devices (routers, switches, servers) for open ports, weak configurations. |
| **Host-based scanning**       | Checks individual systems for missing patches, weak passwords, misconfigurations.       |
| **Application scanning**      | Tests web/mobile apps for vulnerabilities (SQLi, XSS, misconfigurations).               |
| **Wireless scanning**         | Detects rogue access points, weak Wi-Fi encryption.                                     |
| **Credentialed scanning**     | Uses valid credentials to get deeper system info.                                       |
| **Non-credentialed scanning** | Tests from an outsider’s perspective.                                                   |

**🔹 Why It’s Important**

Identifies vulnerabilities before attackers do.

Helps meet compliance standards (PCI DSS, HIPAA, ISO 27001).

Reduces risk by prioritizing and patching critical flaws.

Supports continuous security improvement.

**🔹 Common Tools**

Open Source: OpenVAS, Nikto, Nmap (for basic scanning)

Commercial: Nessus, QualysGuard, Rapid7 InsightVM, Acunetix

**Vulnerability Scanning vs. Penetration Testing**

| Feature       | Vulnerability Scanning     | Penetration Testing                   |
| ------------- | -------------------------- | ------------------------------------- |
| **Nature**    | Automated, broad coverage  | Manual + automated, targeted          |
| **Goal**      | Identify known weaknesses  | Exploit weaknesses to see real impact |
| **Frequency** | Regularly (weekly/monthly) | Periodically (quarterly/annually)     |
