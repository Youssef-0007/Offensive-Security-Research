# **Secure Chat System — Multi-Layer Offensive Security Analysis**
_By: Youssef Essam Hasan_

---

# **Overview**
This report presents a professional, end-to-end offensive security analysis of a **single secure messaging system** that underwent several incremental security hardening steps. Despite these improvements, the system's architectural assumptions created predictable and compounding vulnerabilities that ultimately enabled full compromise.

Across all layers, the system relied on:
- Client-side execution during cryptographic operations
- Unsafe use of AES-ECB for encrypted storage
- Unvalidated Diffie–Hellman parameters
- Vulnerable server-side native code
- SQL injection vulnerabilities

These issues formed a chain that allowed an attacker to escalate from basic authentication bypass to full decryption of protected messages and complete administrative control.

---

# **Initial Attacker Model**
The attacker begins with the following capabilities:
- Ability to create arbitrary user accounts
- Ability to exploit SQL injection in the login flow
- Ability to post messages visible to other users
- Ability to inject persistent JavaScript into victims’ browsers

No privileged access is assumed. All escalations arise directly from the system’s flawed trust boundaries.

---

# **Layer 1 — Authentication Compromise via SQL Injection**

## **Objective**
Obtain authenticated access as arbitrary users to enable deeper interaction with encrypted messaging and administrative endpoints.

## **Root Cause**
The authentication workflow concatenates user input into SQL queries without parameterization.

## **Impact**
This enables:
- Immediate login as any existing user
- Arbitrary user enumeration
- Forced access to chat interfaces required for later exploit stages

SQL injection establishes a reliable foothold for all subsequent layers.

---

# **Layer 2 — Diffie–Hellman Parameter Manipulation via Stored Script Injection**

## **Objective**
Control the symmetric key derived during the secure chat key exchange between users.

## **Technical Root Cause**
The system encrypts chat records using **AES-ECB**. Several dangerous design choices expose encrypted content and create a powerful decryption oracle:
- User-controlled fields (usernames) pass directly through the system’s encryption routine.
- The resulting ciphertext is exposed through a separate endpoint.
- **SQL injection in the `/user/{username}/modify` endpoint leaks raw encrypted chat records**, including the ciphertext of the target protected message.
- AES-ECB is deterministic: identical plaintext blocks produce identical ciphertext blocks.
The secure chat protocol relies on Alice’s browser to automatically:
1. Parse incoming messages
2. Extract Diffie–Hellman public parameters
3. Respond with its own DH value

Because user-controlled messages are inserted directly into the DOM without sanitization, a stored script injection vulnerability allows the attacker to execute JavaScript inside Alice’s browser. This includes the power to alter **Diffie–Hellman public parameters before they are processed**.

## **Attack Strategy**
The injected script forces Alice to send:
```
A = 1
```
to the peer. Since the server performs no DH parameter validation, the final shared secret becomes:
```
1^x mod p = 1
```
Thus the AES session key derived from the DH output becomes fully predictable.

## **Impact**
This does not break Diffie–Hellman cryptographically; it exploits its **lack of authentication** and the system’s unsafe reliance on the browser as a security-critical component.

With the predictable key, secure messages can be decrypted passively.

---

# **Layer 3 — ECB Block-Matching Plaintext Recovery via Attacker-Controlled Input**

## **Objective**
Recover a sensitive encrypted message stored server-side, despite encryption.

## **Technical Root Cause**
The system encrypts chat records using **AES-ECB**. Several dangerous design choices create a powerful decryption oracle:
- User-controlled fields (usernames) pass directly through the system’s encryption routine.
- The resulting ciphertext is exposed through a separate endpoint.
- SQL injection leaks the ciphertext of the target record.
- AES-ECB is deterministic: identical plaintext blocks produce identical ciphertext blocks.

## **Attack Strategy**
This attack is **not** a classical CBC padding oracle. Instead, it is a:

### **Deterministic ECB Block-Matching Oracle**
leveraging controlled plaintext alignment.

Steps:
1. The attacker **renames controlled accounts** to construct arbitrary plaintext.
2. Each rename operation results in a new ciphertext block exposed to the attacker.
3. The attacker aligns the controlled plaintext block with the target ciphertext block using PKCS#7 padding effects.
4. For each candidate character, the attacker:
   - Encrypts a crafted username
   - Extracts the ciphertext block
   - Compares it to the corresponding block from the target message
5. Matching blocks reveal plaintext **one byte at a time**.

## **Impact**
The encrypted message is fully recovered. This attack demonstrates how ECB mode, when combined with attacker-influenced plaintext and ciphertext exposure, becomes completely reversible.

---

# **Layer 4 — Server-Side Admin PIN Bypass via Buffer Overflow (Delivered Through XSS)**

## **Objective**
Obtain administrative privileges without knowing the server-validated admin PIN.

## **Technical Root Cause**
Administrative operations require:
- Valid session of an admin user
- Submission of an `admin_pin` field to a **native binary** that performs validation

The binary fails to enforce proper bounds on input, allowing a buffer overflow that bypasses the PIN check.

### **How the Overflow is Delivered**
Stored script injection allows the attacker to run JavaScript inside the administrator’s browser. The script issues a request with:
- A malicious `admin_pin` byte sequence
- Valid credentials automatically included by the browser

This request is forwarded to the vulnerable native binary, which overflows and accepts the administrative action.

## **Impact**
The attacker gains:
- Full administrative control
- Ability to rename arbitrary users
- Ability to manipulate encrypted data paths
- Complete compromise of system integrity

This stage enables the final decryption process to execute reliably.

---

# **Full Attack Flow Summary**
A realistic, professional view of the attack sequence:

1. **SQL injection** → obtain sessions and interact with system internals.
2. **Stored XSS** → gain code execution inside the administrator’s browser.
3. **DH manipulation** → derive predictable AES session keys.
4. **Username-based ECB block matching** → iteratively decrypt sensitive ciphertext.
5. **Buffer overflow via XSS** → escalate to full administrative control.
6. **Final plaintext extraction** → reconstruct the protected server-side message.

Each layer depends on the next; the system collapses because early failures corrupt every security assumption later.

---

# **Cross-Layer Security Failures**

## **1. Browser Trusted as a Security Endpoint**
Critical cryptographic exchanges and administrative operations depend on untrusted client-side behavior.

## **2. Cryptographic Misuse**
- No authentication of Diffie–Hellman parameters
- Unsafe reliance on AES-ECB
- No message integrity checks

## **3. Server-Side Vulnerabilities**
- SQL injection in authentication
- Buffer overflow in native admin PIN validator

## **4. Unsafe Cross-Layer Assumptions**
Each hardening step added new assumptions instead of genuine defenses, enabling chained exploitation.

---

# **Conclusion**
This analysis demonstrates how layered defenses fail when the underlying architecture relies on:
- Unvalidated cryptographic parameters
- Client-side execution as part of trusted logic
- Insecure encryption modes
- Vulnerable native code
- Weak input validation across components

Once an attacker achieved script execution inside the administrator’s browser, the system’s security guarantees collapsed. The combination of predictable key derivation, ECB determinism, SQL injection, and a server-side overflow allowed a complete compromise of confidentiality and integrity.

---

