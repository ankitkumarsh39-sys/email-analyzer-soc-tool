# Email Threat Analysis

A local-first SOC triage tool for inspecting `.eml` files. It extracts message, sender, attachment, URL, and IOC evidence; enriches indicators with configured threat-intelligence providers; and produces analyst-readable reports through a Streamlit dashboard or command line.

## Benefits

- Keeps the original `.eml` file unchanged during analysis.
- Combines email headers, authentication results, sender infrastructure, attachments, and IOC evidence in one investigation.
- Labels unavailable intelligence as unknown instead of treating a missing lookup as clean.
- Supports analyst comments and response actions without rerunning external lookups when final reports are submitted.

## Architecture

| Path | Purpose |
|---|---|
| `app.py` | Streamlit dashboard, upload/reanalysis actions, investigation workflow, and downloads |
| `email_analyzer/analyzer.py` | EML parsing, header/body/attachment analysis, URL wrapper decoding, IOC and sender analysis |
| `email_analyzer/mail_reporter.py` | TXT, JSON, DOCX, and blocklist report generation |
| `email_analyzer/main.py` | Command-line analysis entry point and logging setup |
| `email_analyzer/watcher.py` | Folder watcher and scheduled inbox-cycle processing |
| `email_analyzer/ui_runner.py` | Optional Tkinter interface for the folder watcher |
| `email_analyzer/utils/whois_utils.py` | WHOISJSON domain registration lookup |
| `ioc_lib/ioc_analyzer.py` | IOC extraction, enrichment, scoring, cache integration, and list matching |
| `ioc_lib/ioc_validator.py` | IOC extraction, defanging normalization, and text sanitation |
| `config/` | Runtime whitelist/blocklist Excel files; the dashboard creates missing files |
| `data/Sample Email/` | Sample or analyst-provided EML files |
| `reports/` | Generated reports, IOC cache, and report log |
| `logging/` | Application log |
| `requirements.txt` | Runtime dependencies |

## Features

- Parses EML headers, focused header values, authentication results, and Received hops.
- Compares From, Reply-To, Return-Path, and Sender domains for mismatches.
- Analyzes subject and body content, including hidden HTML indicators.
- Extracts and normalizes IPs, domains, URLs, and MD5/SHA1/SHA256 hashes; removes HTML tags and NUL bytes from IOC input.
- Decodes supported URL wrappers and records both the wrapper evidence and `final_ioc_url`.
- Calculates IOC and email risk information, reasons, campaigns, and alerts.
- Extracts attachment names, sizes, and SHA-256 hashes.
- Adds sender-domain and sender-IP intelligence, including DNS, MX, SPF/DMARC records, WHOIS/RDAP references, resolved-IP reputation, and whitelist/blocklist matches.
- Shows VirusTotal, AbuseIPDB, Talos, and URLScan evidence where available.
- Uses searchable provider links for analyst review; Talos and ICANN RDAP are reference links, not API reputation results.
- Supports whitelist and blocklist review and spreadsheet downloads.
- Includes Summary, IOC Results, Attachments, Header Details, Raw/JSON, Analyst Comments, Response Actions, and Whitelist/Blocklist tabs.
- Supports regular analysis, whole-email force reanalysis, TXT/JSON/DOCX reporting, and a folder watcher.

## Requirements and installation

Use Python 3.10 or later. The project has been exercised with Python 3.14.

### Windows PowerShell

```powershell
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

If PowerShell blocks activation, run commands directly with `.\.venv\Scripts\python.exe`.

### Dependencies

`requirements.txt` installs Streamlit, pandas, requests, mail-parser, BeautifulSoup, iocextract, python-dotenv, openpyxl, and python-docx. The project does not currently include a maintained automated test suite.

## Configuration

### API keys

Create a local `.env` file in the project root if you want to enable keyed providers. Keep it private and do not commit real keys.

```dotenv
VT_API_KEY=replace_with_your_own_key
URLSCAN_API_KEY=
ABUSEIPDB_API_KEY=
WHOISJSON_API_KEY=
```

Keys are optional, but provider coverage will be reduced without them. Talos and ICANN links are analyst lookup references and do not use API keys.

### Whitelist and blocklist

The active analysis uses `config/whitelist.xlsx` and `config/blocklist.xlsx`. The dashboard creates missing files with `type`, `value`, and `description` columns. Other supported metadata columns include `score`, `confidence`, `severity`, `source`, `category`, `status`, `first_seen`, `last_analyzed`, `tags`, `campaign`, `action`, `whois_age`, and `reputation`.

Use one IOC per row. Supported `type` values are `ip`, `domain`, `url`, and `hash`. List matches are added as evidence; blocklist matches affect scoring. Do not treat a whitelist match as a substitute for provider evidence.

### Cache and logs

- IOC enrichment results are stored in `reports/ioc_cache.json` for up to 48 hours.
- Whole-email reanalysis bypasses cached IOC results.
- WHOIS results use an in-memory cache for the current process.
- Logs are written to `logging/email.log` and `reports/email_analysis.log`.

## Run the application

### Streamlit dashboard

```powershell
.\.venv\Scripts\python.exe -m streamlit run app.py
```

Upload an EML file, select **Run Analysis**, and use the tabs to review findings and download reports. **Reanalyze Whole Email** uses the saved uploaded EML and forces fresh IOC enrichment. A normal analysis can reuse unexpired IOC cache entries.

### Command line

```powershell
.\.venv\Scripts\python.exe -m email_analyzer.main "data\Sample Email\sample_phishing.eml"
```

Pass a folder to analyze its newest `.eml`. Set a custom reports folder with:

```powershell
.\.venv\Scripts\python.exe -m email_analyzer.main "data\Sample Email" --reports "reports"
```

### Folder watcher and desktop runner

The watcher monitors `data/Sample Email` and creates reports for new EML files:

```powershell
.\.venv\Scripts\python.exe -m email_analyzer.watcher
```

The optional Tkinter runner can be started with:

```powershell
.\.venv\Scripts\python.exe -m email_analyzer.ui_runner
```

## Analysis workflow

1. Parse the EML and extract its headers, body parts, URLs, and attachments.
2. Record authentication results found in message headers and inspect Received hops and sender-domain mismatches.
3. Decode supported URL wrappers and use recovered destinations as IOC input.
4. Extract and normalize IOCs, check whitelist/blocklist files, and enrich indicators using configured providers and cached results.
5. Analyze sender domains and sender IPs. Sender URLScan checks search existing domain/IP scan records only.
6. Combine evidence into IOC/email risk information, reasons, campaign/alert findings, and sender verdict.
7. Generate TXT and JSON analysis reports. The dashboard can also submit analyst findings and generate final TXT, JSON, and DOCX reports from the saved analysis without rerunning OSINT.

### URL wrapper support and limitations

The decoder includes Microsoft Safe Links, Proofpoint, Mimecast, and Barracuda patterns. Wrapper formats change, and unrecognized or encrypted links may remain wrapped. The tool records the decoded destination when it can recover one; it does not guarantee that every redirect chain or final destination is known.

### Sender intelligence

Sender domains are collected from From, Reply-To, Return-Path, and Sender. Sender IPs are collected from Received and related originating-IP/authentication headers. Results include DNS A/AAAA/MX/TXT and DMARC TXT lookups, SPF/DMARC indicators, WHOIS age when WHOISJSON returns it, RDAP/ICANN and Talos lookup links, resolved-IP intelligence, and list matches.

DNS and external provider results can be unavailable or rate-limited. Authentication values are parsed from the message; this tool does not independently cryptographically verify DKIM signatures. ASN/hosting data depends on available provider response fields.

### IOC and provider behavior

| Provider/source | Behavior |
|---|---|
| VirusTotal | Looks up extracted IOC values and attachment hashes when configured |
| URLScan | Existing domain/IP scan search is used for sender intelligence. URL IOC enrichment may submit the URL for scanning when `URLSCAN_API_KEY` is configured. |
| AbuseIPDB | IP lookup when configured |
| WHOISJSON | Domain registration and age lookup when configured |
| RDAP/ICANN | Manual lookup link; not a direct RDAP API query |
| Talos | Manual reputation-center lookup link; not an automated Talos API lookup |
| DNS | Public DNS-over-HTTPS queries used for sender records |

An attachment is submitted to VirusTotal only when its hash lookup returns exactly `0 hits` and a VirusTotal API key is configured. A lookup error or missing API key does not trigger an upload. Use these integrations only when your organization authorizes sending the relevant indicators or files to the provider.

## Analyst comments and response actions

The Analyst Comments and Response Actions tabs are separate. The final submission stores the analyst comment, finding, action taken, recommendation, final verdict, selected response actions, response notes, and submission time in the existing email data. Submission regenerates reports from those stored results; it does not rerun EML parsing, IOC enrichment, or OSINT lookups.

## Reports

- **TXT**: readable analysis sections, sender intelligence, analyst comments, and final response actions when submitted.
- **JSON**: structured analysis data, sender intelligence, and investigation submission fields.
- **DOCX**: professional report generated from current email data, including available analysis and investigation fields.
- **Blocklist spreadsheet**: generated/exported IOC blocklist data.

Initial and whole-email reanalysis produce fresh TXT and JSON reports. The final investigation submission generates new TXT, JSON, and DOCX reports. Report generation itself does not call external analysis providers.

## Sample EML validation

To try the included samples, run the Streamlit app or:

```powershell
.\.venv\Scripts\python.exe -m email_analyzer.main "data\Sample Email\sample_phishing.eml"
```

For safe local tests, use a test harness that mocks external DNS/provider calls and VirusTotal attachment uploads. The project's sample emails may contain real indicators or attachment content; do not send them to public providers without authorization.

### Local validation

```powershell
.\.venv\Scripts\python.exe -m compileall app.py email_analyzer ioc_lib
.\.venv\Scripts\python.exe -m pip check
```

This checkout has no maintained automated test suite. Keep provider requests and file submissions mocked when adding local regression tests.

## Troubleshooting

| Symptom | Check |
|---|---|
| Provider fields show unavailable/unknown | Confirm the relevant API key, provider quota, and outbound network access. Missing results are not clean verdicts. |
| No EML appears in the dashboard | Confirm the file is a valid `.eml`; retry upload if its saved temporary copy was removed. |
| Excel list data is not loaded | Check that `config/whitelist.xlsx` or `config/blocklist.xlsx` has `type` and `value` columns. |
| A report is missing | Check write access to `reports/` and review `reports/email_analysis.log`. |
| Cached results look old | Use whole-email force reanalysis to bypass the IOC cache. |
| DOCX generation fails | Reinstall dependencies from `requirements.txt` in the active virtual environment. |

## Privacy and security

- EML bodies and attachments are processed locally, but configured provider lookups disclose the corresponding indicators to external services.
- URLScan URL scans and VirusTotal attachment uploads can send submitted content to a third party as described above.
- Keep `.env`, reports, logs, and sample EMLs out of public repositories; they may contain sensitive data or indicators.
- Do not use public provider submission features on confidential or regulated content without approval.
- The analyzer is a triage aid, not a substitute for analyst validation or incident-response procedures.

## Known limitations

- Provider coverage depends on API keys, quotas, DNS availability, and provider response shapes.
- WHOISJSON and DNS results may be incomplete; RDAP and Talos are lookup links rather than automated reputation feeds.
- URL wrapper decoding is pattern-based and cannot resolve every redirect or encrypted destination.
- SPF/DKIM/DMARC are reported from available headers and DNS records; DKIM signature verification is not implemented.
- No production deployment, authentication, role-based access control, or automated test suite is included.

## Roadmap

- Add a maintained automated test suite with mocked provider integrations.
- Add explicit per-investigation controls for external URL and attachment submissions.
- Improve structured DKIM verification and provider-independent ASN/hosting coverage.
- Add configurable retention and access controls for generated reports and logs.
