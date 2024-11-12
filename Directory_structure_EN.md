### Directory and file structure in `TARGET`

This structure is organized by functional categories, making it easy to find analysis results and reports for the target domain (`TARGET`).

---

#### 1. `domain_screens/` - Screenshots and HTTP/HTTPS headers analysis
(You'll probably only need **aquatone_report.html** here)

- **aquatone_report.html**: Aquatone HTML report summarizing the results of the domain scan.
- **aquatone_session.json**: Aquatone session file storing information about the scan.
- **aquatone_urls.txt**: List of URLs that were processed by Aquatone.
- **headers/**:
- **http__TARGET.txt**: HTTP headers for the scanned domain when accessed via HTTP.
- **https__TARGET.txt**: HTTP headers for the scanned domain when accessing via HTTPS.
- **html/**:
- **http__TARGET.html**: HTML representation of the HTTP response for the domain.
- **https__TARGET.html**: HTML representation of the HTTPS response for the domain.
- **screenshots/**:
- **https__TARGET.png**: Screenshot of the HTTPS page of the target domain.

---

#### 2. `for_debugging/` - Intermediate files for debugging URLs

- **domain_out_gau.txt**: URLs collected with the `gau` tool.
- **domain_out_httpx.txt**: Available URLs after checking `httpx`.
- **domain_out.txt**: All collected URLs for the domain before filtering.
- **domain_out_uro.txt**: URLs after filtering with `uro`.
- **katanaUrls.txt**: URLs obtained with the `katana` tool.
- **sorturls.txt**: Sorted list of unique URLs.
- **unique_urls.txt**: Final unique list of URLs.

---

#### 3. `potential_vulnerable_urls/` - URLs with potential vulnerabilities, classified by type

- **lfi.txt**: URLs vulnerable to Local File Injection (LFI).
- **open_redirect.txt**: URLs vulnerable to Open Redirect vulnerability.
- **sensitive_docs.txt**: Links to sensitive documents (e.g. `.sql`, `.json` files) that may have been exposed.
- **sql_injections.txt**: URLs containing parameters that may be vulnerable to SQL injection.
- **ssrf.txt**: URLs that may be susceptible to server-side request forgery (SSRF) attacks.
- **xss.txt**: URLs potentially vulnerable to cross-site scripting (XSS).

---

#### 4. `reports/` - Basic target domain analysis reports

- **bbnmap_scan.html**: HTML Nmap scan report showing information about open ports and services.
- **dns_vulnerabilities.txt**: Outputs DNS vulnerabilities such as transfer zones.
- **dns_zone_transfer.txt**: Results of zone transfer attempt via `dnsrecon`.
- **linkchecker_output.txt**: `linkchecker` report with results of external links check.
- **open_redirect_results.txt**: Results of open redirect check.
- **subdomain_takeover.txt**: Report of `subzy` subdomain takeover check.

---

#### 5. `secrets/` - Sensitive data found in JavaScript

- **secret_findings.txt**: Results of JavaScript file analysis via `SecretFinder`, including API keys, tokens, and other sensitive data found.

---

#### 6. `subdomains/` - Files related to subdomains of the target domain

- **all_subdomains.txt**: Full list of detected subdomains.
- **available_subdomains.txt**: List of subdomains that are available for connection (response).

--

#### 7. `urls/` - URL and parameter filtering and classification

- **all_filtered_url.txt**: Final filtered list of all URLs for analysis.
- **available_urls.txt**: List of available URLs after filtering and availability check.
- **possible_parameters_without_value.txt**: Parameters without values ​​that can be used in URLs for potential attacks.
- **possible_param.txt**: Filtered parameters that may be related to vulnerabilities.
- **possible_path.txt**: Various paths extracted from URLs that may point to sensitive resources or directories.

---
