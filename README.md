# Automover

**automover.py**

Written in Python3.

Primary Function - Create and Upload CSV to Automox Remediation Tool: 
1. Queries Automox for list of devices and checks the list of devices for vulnerabilities against DefenderTVM.
2. Creates csv file in Automox Remediation format.
3. Uploads the file to Automox.

Secondary Function - Get Vulnerability Stats:
1. Queries Automox for list of devices and checks them agaisnt DefenderTVM.
2. Returns list of statistics which includes: total systems, count of vulnerabilities by severity, and count of vulnerabilities by severity which are past due for remediation.

**Requirements Documentation**

Requires Automox organization ID if you have more than one organization within your tenant.<br>
Requires Automox API key.

Requires import of MultipartEncoder from requests_toolbelt to handle multipart form data for Automox CSV upload.<br>
https://toolbelt.readthedocs.io/en/latest/uploading-data.html

Other Packages Used
<li>requests</li>
<li>json</li>
<li>urlib.request</li>
<li>urllib.parse</li>
<li>csv</li>
<li>datetime, date</li>
<li>os</li>

Requires Registered Application in Azure Tenant<br>
https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/exposed-apis-create-app-nativeapp?view=o365-worldwide

**Troubleshooting Help**

Automox API Documentation
   <li>https://developer.automox.com/</li>
   <br>
Curl Converter  
   <li>https://curlconverter.com/</li>
   <br>
Decode JWT:
    <li>https://jwt.io/</li>
    <br>
KQL and Defender API Documentation
    <li>https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/run-advanced-query-sample-python?view=o365-worldwide</li>
    <li>https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/get-all-vulnerabilities?view=o365-worldwide</li>
    <li>https://stackoverflow.com/questions/55415534/why-is-azure-storage-api-permission-not-listed-in-azure-portal</li>
    


------------------------------------------------------------------------------------------------------------------------------------------------------------
# Automox

**device-list.py**

Queries Automox API for device information, takes the devices name from the returned JSON, and prints in CSV format to a file called devices.txt.

_Requires Automox organization ID if you have more than one organization within your tenant.
Requires Automox API key.<br>_

------------------------------------------------------------------------------------------------------------------------------------------------------------
# Metroid

**metroid.py**

Written in Python3.

Metroid is a tool built for querying DefenderTVM to provide vulnerability reporting and metrics. To utilize Metroid, you will need the following:
1) Access to an active Microsoft 365 Defender account and Azure tenant.
2) An API key that allows for querying https://api.securitycenter.microsoft.com
   https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/exposed-apis-create-app-nativeapp?view=o365-worldwide
3) A list of systems in CSV format. If using excel, the format should be CSV MS-DOS to prevent ingestion errors.

**Troubleshooting Help**

KQL and Defender API Documentation
    <li>https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/run-advanced-query-sample-python?view=o365-worldwide</li>
    <li>https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/get-all-vulnerabilities?view=o365-worldwide</li>
    <li>https://stackoverflow.com/questions/55415534/why-is-azure-storage-api-permission-not-listed-in-azure-portal</li>
