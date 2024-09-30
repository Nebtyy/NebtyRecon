#Installing Kali Linux
--------------------------------------------------
`git clone https://github.com/Nebtyy/NebtyRecon.git`

`cd NebtyRecon`

`chmod +x ./*`

`./setup_and_run.sh`

`./NebtyRecon.sh <target> <mode> <pattern>`

--------------------------------------------------
#Mods:
--------------------------------------------------
### 1. **Mode "search"**
- **What it does:** 
  - Initiates a subdomain search for the specified domain using several tools (subfinder, sublist3r, crt.sh, amass, and assetfinder).
  - Combines the results from all tools and removes duplicates, saving them to a file.

### 2. **Mode "find"**
- **What it does:** 
  - Checks the availability of the subdomains found in the previous step.
  - Runs the **subzy** tool for further processing and analysis of the subdomains.

### 3. **Mode "process"**
- **What it does:** 
  - Finds and collects URLs from the subdomains using the waybackurls and gau tools.
  - Checks the availability of the collected URLs using httpx.
  - Removes duplicate parameters from URLs and saves unique URLs.
  - Searches for sensitive data in JavaScript files extracted from the collected URLs using SecretFinder.

### 4. **Mode "all"**
- **What it does:** 
  - Executes all actions from the previous modes sequentially:
    - Searches for subdomains.
    - Combines results.
    - Checks the availability of subdomains.
    - Runs subzy for subdomain processing.
    - Searches for and processes URLs.
    - Looks for secrets in JavaScript files.

### Overall Purpose of the Script
The script is designed for actively searching and analyzing subdomains, collecting URLs, and finding sensitive information, which can be useful for testing the security of web applications.

#Example of use:
--------------------------------------------------
If, for example, you test www.google.com:
`./NebtyRecon.sh www.google.com all www.google.com`

If, for example, you test *.google.com:
`./NebtyRecon.sh www.google.com all .google.com`






#You can also use RECON-Cheat-Sheat.txt
