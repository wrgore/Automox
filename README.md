# Automox
Python for interacting with Automox API.

**automover.py**

Primary Function - Create and Upload CSV to Automox Remediation Tool: 
1. Queries Automox for list of devices and checks the list of devices for vulnerabilities against DefenderTVM.
2. Creates csv file in Automox Remediation format.
3. Uploads the file to Automox.

Secondary Function - Get Vulnerability Stats:
1. Queries Automox for list of devices and checks them agaisnt DefenderTVM.
2. Returns list of statistics which includes: total systems, count of vulnerabilities by severity, and count of vulnerabilities by severity which are past due for remediation.

_Requires Automox organization ID if you have more than one organization within your tenant.
Requires Automox API key.
Requires Registered Application in Azure Tenant_

**automover.py Known Issues**

1. Input checking for 3 vulnerabilities has error where it does not check third list item against validInput list.
2. Input checking for 4 vulnerabilities or All does not check validInput list.

------------------------------------------------------------------------------------------------------------------------------------------------------------
**device-list.py**

Queries Automox API for device information, takes the devices name from the returned JSON, and prints in CSV format to a file called devices.txt.

_Requires Automox organization ID if you have more than one organization within your tenant.
Requires Automox API key.<br>_

------------------------------------------------------------------------------------------------------------------------------------------------------------
# KQL
