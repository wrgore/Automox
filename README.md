# Automox
Python for interacting with Automox API.

**automover.py**
1. Queries Automox API for device information, takes the device names from the returned JSON.<br>
_Requires Automox organization ID if you have more than one organization within your tenant.<br>
Requires Automox API key.<br>_
2. Takes input for desired vulnerability levels (Critical, High, Medium, Low, All, or a combination of those).
3. Formats a KQL Query based on the input. The KQL Query will automatically output in the format that Automox expects in its Remediation tool.

**Known Issues**
1. Input checking for 1 vulnerability does not check validInput list.
2. Input checking for 3 vulnerabilities has error where it does not check third list item against validInput list.
3. Input checking for 4 vulnerabilities or All does not check validInput list.

**device-list.py**<br>
Queries Automox API for device information, takes the devices name from the returned JSON, and prints in CSV format to a file called devices.txt.<br>
_Requires Automox organization ID if you have more than one organization within your tenant.<br>
Requires Automox API key.<br>_
