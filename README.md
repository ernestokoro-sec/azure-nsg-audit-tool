# Azure NSG Audit Tool

Python-based Azure Network Security Group (NSG) audit tool that detects risky inbound rules, identifies public management exposure, and exports findings for cloud security assessments.

---

## Overview

This project audits Azure Network Security Groups using Python and Azure CLI to identify risky configurations that may expose cloud resources unnecessarily.

The tool scans custom NSG rules and flags:

- Public RDP exposure
- Public SSH exposure
- Broad inbound access from `*`
- Public access to all ports
- Risky inbound rules requiring review

The goal is to automate common network security checks and provide security findings in a structured format.

---

## Features

✅ Detect public RDP exposure (TCP 3389)  
✅ Detect public SSH exposure (TCP 22)  
✅ Identify overly permissive source rules (`*`, `0.0.0.0/0`)  
✅ Classify findings by risk level  
✅ Export findings to CSV  
✅ Generate audit evidence for security reviews  

---

## Technologies Used

- Python 3
- Azure CLI
- Azure Network Security Groups (NSG)
- JSON parsing
- CSV reporting

---

## Project Structure

```text
azure-nsg-audit-tool/
│
├── nsg_audit.py
├── README.md
├── sample-output.txt
├── nsg-findings-sample.csv
└── .gitignore
```

---

## Security Problem

Misconfigured NSGs can expose cloud environments to unnecessary risk.

Examples include:

```text
Allow-RDP
Source: *
Port: 3389
```

or:

```text
Allow-SSH
Source: 0.0.0.0/0
Port: 22
```

Public management ports are common targets for:

- Brute-force attacks
- Credential attacks
- Internet scanning
- Unauthorized access attempts

This tool helps identify these risks early.

---

## Prerequisites

Install:

### Python

Verify:

```powershell
python --version
```

### Azure CLI

Verify:

```powershell
az --version
```

Login to Azure:

```powershell
az login
```

---

## How to Run

Navigate to the project folder:

```powershell
cd C:\Users\Administrator\azure-nsg-audit-tool
```

Run:

```powershell
python nsg_audit.py
```

Enter your resource group when prompted:

```text
tf-prod-style-rg
```

---

## Example Output

```text
Azure NSG Security Audit
==================================================

NSG:            web-nsg
Rule:           Allow-HTTPS
Priority:       1010
Risk:           Review
Issue:          Inbound allow from public source
Source:         *
Port:           443
Protocol:       Tcp
Recommendation: Validate business justification and restrict source where possible.

--------------------------------------------------

NSG:            web-nsg
Rule:           Allow-HTTP
Priority:       1000
Risk:           Review
Issue:          Inbound allow from public source
Source:         *
Port:           80
Protocol:       Tcp
Recommendation: Validate business justification and restrict source where possible.
```

---

## CSV Report Output

The tool automatically creates:

```text
nsg_findings.csv
```

Example:

| NSG | Rule | Risk | Port |
|------|-------|-------|------|
| web-nsg | Allow-HTTP | Review | 80 |
| web-nsg | Allow-HTTPS | Review | 443 |

---

## Risk Classification Logic

| Risk Level | Condition |
|------------|------------|
| High | Public RDP exposure |
| High | Public SSH exposure |
| High | Public inbound access to all ports |
| Review | Public inbound access to specific ports |
| Informational | No risky exposure found |

---

## Future Enhancements

Planned improvements:

- Export JSON reports
- Generate PDF audit reports
- Email findings automatically
- Add Azure subscription-wide scanning
- Integrate with GitHub Actions
- Add severity scoring

---

## Security Note

Do not upload real production audit outputs to public repositories.

Only upload sanitized sample findings.

---

## Author

Ernest Okoro

Cloud Security | Terraform | Azure | Python | Network Security
