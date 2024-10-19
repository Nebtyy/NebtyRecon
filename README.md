# NebtyRecon


### **Installation:**
To install **NebtyRecon** on Kali Linux, follow these steps:

```bash
git clone https://github.com/Nebtyy/NebtyRecon.git
cd NebtyRecon
chmod +x ./*
./setup_and_run.sh
```

This will download the repository, give execute permissions to the necessary files, and run the setup script.

### **How to Use:**
Once installed, you can run the script with the following command:

```bash
./NebtyRecon.sh <target_domain> <mode> <search_pattern>
```

- `<target_domain>`: The domain or subdomain you want to test (e.g., `www.google.com`).
- `<mode>`: The mode of operation (`search`, `find`, `process`, or `all`).
- `<search_pattern>`: A specific pattern for filtering results (e.g., `.google.com`).

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

4. **Mode `all`**
   - Runs all the above steps sequentially.

### **What This Script Can Find:**

1. **Subdomains and Exposed Hosts**:
   - The script uses multiple tools to find hidden or forgotten subdomains associated with a target domain, which can reveal overlooked parts of an application’s infrastructure.

2. **Unused or Vulnerable Subdomains**:
   - The **subzy** tool checks for subdomains that might be vulnerable to subdomain takeover, a critical security risk where attackers can gain control of unused subdomains.

3. **URL Discovery and Analysis**:
   - Collects URLs through **waybackurls**, **gau**, and **katana**, helping uncover endpoints, resources, or paths that may contain hidden or unsecured parts of a web application.

4. **Sensitive Information Exposure**:
   - The **SecretFinder** tool analyzes JavaScript files for secrets such as API keys, access tokens, or other sensitive data that could be exposed in public scripts.

5. **Potential Security Vulnerabilities in URLs**:
   - By filtering parameters and paths, it highlights possible attack vectors like:
     - **Open redirects**
     - **Parameter pollution**
     - **SQL injection points**
     - **File inclusion attacks**

6. **Broken or Insecure Links**:
   - The script checks URL availability and may identify broken or outdated links that could be exploited for phishing, malicious redirects, or other attacks.

### **Example Usage:**

1. **To test a specific domain, e.g., `www.google.com`:**
   ```bash
   ./NebtyRecon.sh www.google.com all www.google.com
   ```

2. **To test all subdomains of a domain (e.g., `*.google.com`):**
   ```bash
   ./NebtyRecon.sh www.google.com all .google.com
   ```

### **Overall Purpose:**
This script is designed to help penetration testers and security professionals actively search for vulnerabilities in web applications, focusing on:
- Subdomain discovery
- URL collection
- Identifying sensitive data exposure in JavaScript files
- Finding unused subdomains vulnerable to takeover

By automating these processes, **NebtyRecon** allows you to quickly identify key weaknesses in a target's web infrastructure.
