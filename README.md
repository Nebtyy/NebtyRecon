### NebtyRecon

### **Installation:**
To install **NebtyRecon** on Kali Linux, follow these steps:

```bash
git clone https://github.com/Nebtyy/NebtyRecon.git
sudo apt install python3-venv
python3 -m venv myenv
source myenv/bin/activate
cd NebtyRecon
chmod +x ./*
./setup_and_run.sh
```

This will download the repository, give execute permissions to the necessary files, and run the setup script.

---

### **How to Use:**
Once installed, you can run the script with the following command:

```bash
./NebtyRecon.sh <target_domain> <mode> <search_pattern> <sudo_password>
```

- `<target_domain>`: The domain or subdomain you want to test (e.g., `www.google.com`).
- `<mode>`: The mode of operation (`search`, `find`, `process`, or `all`).
- `<search_pattern>`: A specific pattern for filtering results (e.g., `.google.com`).
-  <sudo_password> : To use advanced commands

---

### **Modes:**
1. **Mode `search`**
   - Initiates a subdomain search using various tools (subfinder, sublist3r, crt.sh, amass, and assetfinder).
   - Combines results and removes duplicates.

2. **Mode `find`**
   - Checks the availability of the found subdomains.
   - Generating an **Nmap report** to identify open ports and services.
   - Taking domain screenshots using **Aquatone**.
   - Testing for open redirects in subdomains
   - Runs the **subzy** tool for further analysis.

3. **Mode `process`**
   - Collects URLs from subdomains using **waybackurls**, **gau**, and **katana**.
   - Checks URL availability using **httpx**.
   - Searches for secrets in JavaScript files with **SecretFinder**.
   - **linkchecker** is used to identify broken, insecure, or potentially hijackable second-order subdomains by checking external links. This can help pinpoint subdomains that are vulnerable to subdomain takeover.
   - Sorting and categorizing potentially vulnerable endpoints based on parameters and file extensions.
4. **Mode `all`**
   - Runs all the above steps sequentially.

---

### **What This Script Can Find:**

1. Subdomains and Exposed Hosts:

2. The script uses multiple tools to find hidden or forgotten subdomains associated with a target domain, which can reveal overlooked parts of an application’s infrastructure.
Unused or Vulnerable Subdomains:

3. The subzy tool checks for subdomains that might be vulnerable to subdomain takeover, a critical security risk where attackers can gain control of unused subdomains.
Second-Order Subdomain Hijacking:

4. The linkchecker tool examines external links on available subdomains to detect broken or unsecured links. This includes checking for potential second-order subdomain takeover risks, where attackers could hijack external resources or subdomains linked from within a target domain.
URL Discovery and Analysis:

5. Collects URLs through waybackurls, gau, and katana, helping uncover endpoints, resources, or paths that may contain hidden or unsecured parts of a web application.
Sensitive Information Exposure:

6. The SecretFinder tool analyzes JavaScript files for secrets such as API keys, access tokens, or other sensitive data that could be exposed in public scripts.
Potential Security Vulnerabilities in URLs:

7. By filtering parameters and paths, it highlights possible attack vectors like:
   - Open redirects
   - Parameter pollution
   - SQL injection points
   - File inclusion attacks
   - Broken or Insecure Links:

8. linkchecker not only helps identify broken or outdated links, but also aids in finding links that may be exploitable for phishing, malicious redirects, or other attacks.
DNS Zone Transfers:

9. The script also uses dnsrecon to check for DNS zone transfers, a vulnerability where attackers can retrieve sensitive DNS records. If a successful zone transfer is identified, the vulnerability is flagged, allowing the tester to alert the target for immediate remediation.
Open Redirects:

10. Checks subdomains for potential open redirect vulnerabilities by appending common redirect patterns and verifying if the redirect is possible.
Categorization of Vulnerable Endpoints:

11. Extracts potentially vulnerable endpoints by analyzing URL parameters and file extensions, categorizing endpoints based on patterns associated with vulnerabilities such as SQL injection, SSRF, LFI, XSS, and sensitive file disclosures.

---

### **Example Usage:**

1. **To test a specific domain, e.g., `www.google.com`:**
   ```bash
   ./NebtyRecon.sh www.google.com all www.google.com sudo_password
   ```

2. **To test all subdomains of a domain (e.g., `*.google.com`):**
   ```bash
   ./NebtyRecon.sh www.google.com all .google.com sudo_password
   ```

---
### **Directory_structure:**
```
TARGET
├── domain_screens
│   ├── aquatone_report.html
│   ├── aquatone_session.json
│   ├── aquatone_urls.txt
│   ├── headers
│   │   ├── http__TARGET.txt
│   │   └── https__TARGET.txt
│   ├── html
│   │   ├── http__TARGET.html
│   │   └── https__TARGET.html
│   └── screenshots
│       └── https__TARGET.png
├── for_debugging
│   ├── domain_out_gau.txt
│   ├── domain_out_httpx.txt
│   ├── domain_out.txt
│   ├── domain_out_uro.txt
│   ├── katanaUrls.txt
│   ├── sorturls.txt
│   └── unique_urls.txt
├── potential_vulnerable_urls
│   ├── lfi.txt
│   ├── open_redirect.txt
│   ├── sensitive_docs.txt
│   ├── sql_injections.txt
│   ├── ssrf.txt
│   └── xss.txt
├── reports
│   ├── bbnmap_scan.html
│   ├── dns_vulnerabilities.txt
│   ├── dns_zone_transfer.txt
│   ├── linkchecker_output.txt
│   ├── open_redirect_results.txt
│   └── subdomain_takeover.txt
├── secrets
│   └── secret_findings.txt
├── subdomains
│   ├── all_subdomains.txt
│   └── available_subdomains.txt
└── urls
    ├── all_filtered_url.txt
    ├── available_urls.txt
    ├── possible_parameters_without_value.txt
    ├── possible_param.txt
    └── possible_path.txt
```
##### More about the structure in: Directory_structure_EN.md / Directory_structure_RU.md

---

### **Overall Purpose:**
This script is designed to help penetration testers and security professionals actively search for vulnerabilities in web applications, focusing on:
- Subdomain discovery
- URL collection
- Identifying sensitive data exposure in JavaScript files
- Finding unused subdomains vulnerable to takeover
- Detecting broken or insecure external links with potential second-order subdomain hijacking risks
- Checking for DNS zone transfer vulnerabilities using dnsrecon
- Generating Nmap reports for open ports and services
- Capturing screenshots of discovered domains
- Testing for open redirects and categorizing potentially vulnerable endpoints

By automating these processes, **NebtyRecon** allows you to quickly identify key weaknesses in a target's web infrastructure.
