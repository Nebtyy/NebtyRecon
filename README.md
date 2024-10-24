### NebtyRecon

### **Installation:**
To install **NebtyRecon** on Kali Linux, follow these steps:

```bash
git clone https://github.com/Nebtyy/NebtyRecon.git
cd NebtyRecon
chmod +x ./*
./setup_and_run.sh
```

This will download the repository, give execute permissions to the necessary files, and run the setup script.

---

### **How to Use:**
Once installed, you can run the script with the following command:

```bash
./NebtyRecon.sh <target_domain> <mode> <search_pattern>
```

- `<target_domain>`: The domain or subdomain you want to test (e.g., `www.google.com`).
- `<mode>`: The mode of operation (`search`, `find`, `process`, or `all`).
- `<search_pattern>`: A specific pattern for filtering results (e.g., `.google.com`).

---

### **Modes:**
1. **Mode `search`**
   - Initiates a subdomain search using various tools (subfinder, sublist3r, crt.sh, amass, and assetfinder).
   - Combines results and removes duplicates.

2. **Mode `find`**
   - Checks the availability of the found subdomains.
   - Runs the **subzy** tool for further analysis.

3. **Mode `process`**
   - Collects URLs from subdomains using **waybackurls**, **gau**, and **katana**.
   - Checks URL availability using **httpx**.
   - Searches for secrets in JavaScript files with **SecretFinder**.
   - **linkchecker** is used to identify broken, insecure, or potentially hijackable second-order subdomains by checking external links. This can help pinpoint subdomains that are vulnerable to subdomain takeover.

4. **Mode `all`**
   - Runs all the above steps sequentially.

---

### **What This Script Can Find:**

1. **Subdomains and Exposed Hosts**:
   - The script uses multiple tools to find hidden or forgotten subdomains associated with a target domain, which can reveal overlooked parts of an application’s infrastructure.

2. **Unused or Vulnerable Subdomains**:
   - The **subzy** tool checks for subdomains that might be vulnerable to subdomain takeover, a critical security risk where attackers can gain control of unused subdomains.

3. **Second-Order Subdomain Hijacking**:
   - The **linkchecker** tool examines external links on available subdomains to detect broken or unsecured links. This includes checking for potential second-order subdomain takeover risks, where attackers could hijack external resources or subdomains linked from within a target domain.

4. **URL Discovery and Analysis**:
   - Collects URLs through **waybackurls**, **gau**, and **katana**, helping uncover endpoints, resources, or paths that may contain hidden or unsecured parts of a web application.

5. **Sensitive Information Exposure**:
   - The **SecretFinder** tool analyzes JavaScript files for secrets such as API keys, access tokens, or other sensitive data that could be exposed in public scripts.

6. **Potential Security Vulnerabilities in URLs**:
   - By filtering parameters and paths, it highlights possible attack vectors like:
     - **Open redirects**
     - **Parameter pollution**
     - **SQL injection points**
     - **File inclusion attacks**

7. **Broken or Insecure Links**:
   - **linkchecker** not only helps identify broken or outdated links, but also aids in finding links that may be exploitable for phishing, malicious redirects, or other attacks.

8. **DNS Zone Transfers:**
   - The script also uses **dnsrecon** to check for DNS zone transfers, a vulnerability where attackers can retrieve sensitive DNS records. If a successful zone transfer is identified, the vulnerability is flagged, allowing the tester to alert the target for immediate remediation.

---

### **Example Usage:**

1. **To test a specific domain, e.g., `www.google.com`:**
   ```bash
   ./NebtyRecon.sh www.google.com all www.google.com
   ```

2. **To test all subdomains of a domain (e.g., `*.google.com`):**
   ```bash
   ./NebtyRecon.sh www.google.com all .google.com
   ```

---

### **Overall Purpose:**
This script is designed to help penetration testers and security professionals actively search for vulnerabilities in web applications, focusing on:
- Subdomain discovery
- URL collection
- Identifying sensitive data exposure in JavaScript files
- Finding unused subdomains vulnerable to takeover
- Detecting broken or insecure external links with potential second-order subdomain hijacking risks
- Checking for DNS zone transfer vulnerabilities using dnsrecon

By automating these processes, **NebtyRecon** allows you to quickly identify key weaknesses in a target's web infrastructure.
