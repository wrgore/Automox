# Automox
Python for interacting with Automox API.

**automover.py**
1. Queries Automox API for device information, takes the device names from the returned JSON.<br>
_Requires Automox organization ID if you have more than one organization within your tenant.<br>
Requires Automox API key.<br>_
2. Takes input for desired vulnerability levels (Critical, High, Medium, Low, All, or a combination of those).
3. Formats a KQL Query based on the input. The KQL Query will automatically output in the format that Automox expects in its Remediation tool.

Note: Future additions currently scheduled include Automated interaction with Defender Threat Hunting via KQL API, Automated output of  CSV of vulnerabilities, Automated upload of vulnerability CSV into Automox Remediation tool, and Automatic gathering and reporting of relevant vulnerability metrics.

**device-list.py**<br>
Queries Automox API for device information, takes the devices name from the returned JSON, and prints in CSV format to a file called devices.txt.<br>
_Requires Automox organization ID if you have more than one organization within your tenant.<br>
Requires Automox API key.<br>_
