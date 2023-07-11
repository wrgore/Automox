import pip._vendor.requests

#Logo and Welcome
def logo():
    print("   _         _                                   ")
    print("  /_\  _   _| |_ ___   /\/\   _____   _____ _ __ ")
    print(" //_ \| | | | __/ _ \ /    \ / _ \ \ / / _ \ '__|")
    print("/  _  \ |_| | || (_) / /\/\ \ (_) \ V /  __/ |   ")
    print("\_/ \_/\__,_|\__\___/\/    \/\___/ \_/ \___|_|   by rg")

#Help Function for KQL Build
def kqlHelp():
    print("----------------------------------------------------------------------------------------------------------------")
    print("| \n| AutoMover User's Guide\n|")
    print("| \n| Vulnerability Severity Options: Critical, High, Medium, Low")
    print("| To select all vulnerabilities use 'All'\n|")
    print("| To select some, but not all vulnerabilities, use the following format: VulnLevel + VulnLevel\n| As an example, to get High and Low vulnerabilities only you would input: 'High + Low' when prompted.\n|")
    print("| IMPORTANT: This program is case sensitive. Critical does not equal critical.\n|")
    print("----------------------------------------------------------------------------------------------------------------\n")
    queryBuilder()
                                                 
#Automox Device List Export
def automoxExport():
    url = "https://console.automox.com/api/servers"

    query = {
        "o": "YOUR-AUTOMOX-ORG-ID-GOES-HERE",
    }

    headers = {"Authorization": "Bearer YOUR-AUTOMOX-API-KEY-GOES-HERE"}

    print("Connecting to Automox API...")    
    response = pip._vendor.requests.get(url, headers=headers, params=query)
    data = response.json()

    for item in data:
        deviceList.append(item['name'])
    print("Successfully captured Automox device list.")

    queryBuilder()

#Build the KQL Query Based on Input
def queryBuilder():
    validInput = ['Critical', 'High', 'Medium', 'Low', 'All']
    severity = input("Please indicate the vulnerability severity level(s) for the report (For help use -h.) >  ")
    severityList = severity.split(" + ")
    if severity == '-h' or severity == 'help':
        kqlHelp()
    elif severity  == 'Critical' or severity == 'High' or severity == 'Medium' or severity == 'Low':
        query = (f"let automoxDevices = dynamic({deviceList}); DeviceTvmSoftwareVulnerabilities | where DeviceName in~ (automoxDevices) | where VulnerabilitySeverityLevel =~ \"{severity}\" | summarize by DeviceName, CveID, VulnerabilitySeverityLevel")
        print(query)
    elif len(severityList) == 2:
         if severityList[0] and severityList[1] in validInput:
            query = (f"let automoxDevices = dynamic({deviceList}); DeviceTvmSoftwareVulnerabilities | where DeviceName in~ (automoxDevices) | where VulnerabilitySeverityLevel =~ \"{severityList[0]}\" or  VulnerabilitySeverityLevel =~ \"{severityList[1]}\"| summarize by DeviceName, CveID, VulnerabilitySeverityLevel")
            print(query)
         else:
            print("Invalid input. Please see the usage page and try again.")
            kqlHelp()
    elif len(severityList) == 3:
         if severityList[0] and severityList[1] in validInput:
            query = (f"let automoxDevices = dynamic({deviceList}); DeviceTvmSoftwareVulnerabilities | where DeviceName in~ (automoxDevices) | where VulnerabilitySeverityLevel =~ \"{severityList[0]}\" or  VulnerabilitySeverityLevel =~ \"{severityList[1]}\" or  VulnerabilitySeverityLevel =~ \"{severityList[2]}\"| summarize by DeviceName, CveID, VulnerabilitySeverityLevel")
            print(query)
         else:
            print("Invalid input. Please see the usage page and try again.")
            kqlHelp()
    elif len(severityList) == 4 or severity == "All":
        query = (f"let automoxDevices = dynamic({deviceList}); DeviceTvmSoftwareVulnerabilities | where DeviceName in~ (automoxDevices) | summarize by DeviceName, CveID, VulnerabilitySeverityLevel")
        print(query)
    else:
        print("Invalid input. Please refer to the help page for proper usage.")
        kqlHelp()

    #pass to api query from here

#Function to loop if another report is desired.
def continueWorking():
   newQuery = input('Would you like to export another vulnerability severity level? (Y/N) > ')
   if newQuery == "Y":
    queryBuilder()
    print ("\nJob completed successfully. Please review new vulnerabilities in Automox Remediations.\n")
    continueWorking()
   elif newQuery == "N":
    print("Program closed successfully.")
   else:
    ("Invalid input. Please enter Y or N.")
    continueWorking()
    
#Main
if __name__ == '__main__':
    deviceList = []
    logo()
    automoxExport()
    print ("\nJob completed successfully. Please review new vulnerabilities in Automox Remediations.\n")
    continueWorking()
