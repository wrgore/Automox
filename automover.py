import requests
from requests_toolbelt import MultipartEncoder
import json
import urllib.request
import urllib.parse
import csv
from datetime import date
import os

#Logo and Welcome
def logo():
    print("   _         _                                   ")
    print("  /_\  _   _| |_ ___   /\/\   _____   _____ _ __ ")
    print(" //_ \| | | | __/ _ \ /    \ / _ \ \ / / _ \ '__|")
    print("/  _  \ |_| | || (_) / /\/\ \ (_) \ V /  __/ |   ")
    print("\_/ \_/\__,_|\__\___/\/    \/\___/ \_/ \___|_|   by rg\n")
    print("                                         v1.2\n")

#Main User's Guide - Contains All Product Guidance
def help():
    print("----------------------------------------------------------------------------------------------------------------")
    print("| AUTOMOVER OVERVIEW")
    print("| \n| 1. MAIN MENU COMMANDS\n|")
    print("| Get Current Vulnerability Statistics")
    print("| Command: \'status\'\n|")
    print("| Run Automox Remediation Builder")
    print("| Command: \'remediation\'\n|")
    print("| \n| 2. REMEDIATION BUILDER COMMANDS")
    print("| \n| Vulnerability Severity Options: Critical, High, Medium, Low")
    print("| To select all vulnerabilities use 'All'\n|")
    print("| To select some, but not all vulnerabilities, use the following format: VulnLevel + VulnLevel\n| As an example, to get High and Low vulnerabilities only you would input: 'High + Low' when prompted.\n|")
    print("| IMPORTANT: This program is case sensitive. Critical does not equal critical.\n|")
    print("----------------------------------------------------------------------------------------------------------------\n")

#Help Function for KQL Build
def kqlHelp():
    print("----------------------------------------------------------------------------------------------------------------")
    print("| \n| AutoMover Vulnerability Query Guide\n|")
    print("| \n| Vulnerability Severity Options: Critical, High, Medium, Low")
    print("| To select all vulnerabilities use 'All'\n|")
    print("| To select some, but not all vulnerabilities, use the following format: VulnLevel + VulnLevel\n| As an example, to get High and Low vulnerabilities only you would input: 'High + Low' when prompted.\n|")
    print("| IMPORTANT: This program is case sensitive. Critical does not equal critical.\n|")
    print("----------------------------------------------------------------------------------------------------------------\n")
    queryBuilder()

#Obtain OAuth Token for Microsoft Defender API and Pass it Back to Originating Caller
def defenderAuth():
    tenantId = 'Tenant-ID' # SENSITIVE - Paste your own tenant ID here
    appId = 'App-ID' # SENSITIVE - Paste your own app ID here
    appSecret = 'App-Secret' # HIGHLY SENSITIVE - Paste your own app secret here

    url = "https://login.microsoftonline.com/%s/oauth2/token" % (tenantId)

    resourceAppIdUri = 'https://api.securitycenter.microsoft.com'

    body = {
        'resource' : resourceAppIdUri,
        'client_id' : appId,
        'client_secret' : appSecret,
        'grant_type' : 'client_credentials'
    }

    data = urllib.parse.urlencode(body).encode("utf-8")
    req = urllib.request.Request(url, data)
    response = urllib.request.urlopen(req)
    jsonResponse = json.loads(response.read())
    aadToken = jsonResponse["access_token"]

    return aadToken
                                                 
#Automox Device List Export
def automoxExport():
    url = "https://console.automox.com/api/servers"

    query = {
        "o": "Automox-OrgID", #SENSITIVE - Automox Organization ID Goes Here
    }

    headers = {"Authorization": "Bearer Automox-API-Key"} #HIGHLY SENSITIVE - Automox API Key Goes Here

    print("Connecting to Automox API...")    
    response = requests.get(url, headers=headers, params=query)
    data = response.json()

    for item in data:
        deviceList.append(item['name'])
    print("Successfully imported Automox device list.")

#Build the KQL Query Based on Input
def queryBuilder():
    validInput = ['Critical', 'High', 'Medium', 'Low', 'All']
    severity = input("Please indicate the vulnerability severity level(s) for the report (For help use -h.):  ")
    severityList = severity.split(" + ")
    if severity == '-h' or severity == 'help':
        kqlHelp()
    elif severity == "quit" or severity == "q" or severity == "-q" or severity == "exit":
        exit()
    elif severity  == 'Critical' or severity == 'High' or severity == 'Medium' or severity == 'Low':
        kql = (f"let automoxDevices = dynamic({deviceList}); DeviceTvmSoftwareVulnerabilities | where DeviceName in~ (automoxDevices) | where VulnerabilitySeverityLevel =~ '{severity}' | summarize by DeviceName, CveId, VulnerabilitySeverityLevel")
    elif len(severityList) == 2:
         if severityList[0] and severityList[1] in validInput:
            kql = (f"let automoxDevices = dynamic({deviceList}); DeviceTvmSoftwareVulnerabilities | where DeviceName in~ (automoxDevices) | where VulnerabilitySeverityLevel =~ '{severityList[0]}' or  VulnerabilitySeverityLevel =~ '{severityList[1]}'| summarize by DeviceName, CveId, VulnerabilitySeverityLevel")
         else:
            print("\n[!] Invalid input. Please refer to the help page for proper usage by typing -h.\n\nRe-initializing program...")
            main()
    elif len(severityList) == 3:
         if severityList[0] and severityList[1] and severityList[2] in validInput:
            kql = (f"let automoxDevices = dynamic({deviceList}); DeviceTvmSoftwareVulnerabilities | where DeviceName in~ (automoxDevices) | where VulnerabilitySeverityLevel =~ '{severityList[0]}' or  VulnerabilitySeverityLevel =~ '{severityList[1]}' or  VulnerabilitySeverityLevel =~ '{severityList[2]}'| summarize by DeviceName, CveId, VulnerabilitySeverityLevel")
         else:
            print("\n[!] Invalid input. Please refer to the help page for proper usage by typing -h.\n\nRe-initializing program...")
            main()
    elif len(severityList) == 4 or severity == "All":
        if severityList[0] == "All":
            kql = (f"let automoxDevices = dynamic({deviceList}); DeviceTvmSoftwareVulnerabilities | where DeviceName in~ (automoxDevices) | summarize by DeviceName, CveId, VulnerabilitySeverityLevel")
        elif severityList[0] and severityList[1] and severityList[2] and severityList[3] in validInput:
            kql = (f"let automoxDevices = dynamic({deviceList}); DeviceTvmSoftwareVulnerabilities | where DeviceName in~ (automoxDevices) | summarize by DeviceName, CveId, VulnerabilitySeverityLevel")
        else:
            print("\n[!] Invalid input. Please refer to the help page for proper usage by typing -h.\n\nRe-initializing program...")
            main()
    else:
        print("[!] Invalid input. Please refer to the help page for proper usage by typing -h.\n\nRe-initializing program...")
        main()

    defenderQuery(kql, severity)

#Connects to and Queries securitycenter API; Writes Response to CSV
def defenderQuery(kql, severity):
    aadToken = defenderAuth()

    query = kql

    url = "https://api.securitycenter.microsoft.com/api/advancedqueries/run"
    headers = { 
        'Content-Type' : 'application/json',
        'Accept' : 'application/json',
        'Authorization' : "Bearer " + aadToken
    }

    data = json.dumps({ 'Query' : query }).encode("utf-8")

    req = urllib.request.Request(url, data, headers)
    response = urllib.request.urlopen(req)
    jsonResponse = json.loads(response.read())
    #schema = jsonResponse["Schema"]
    results = jsonResponse["Results"]

    #Write CSV File with Requested Severity Name and Current Date Information
    dateInfo = date.today()
    dateStamp = (f"{dateInfo.year}{dateInfo.month}{dateInfo.day}")
    fileName = (f"{severity}_{dateStamp}.csv")
    curdir = os.getcwd()
    if os.path.exists(f'{curdir}\\{fileName}'):
       print('\n[!] A File with this name already exists. Please remove the file from the directory or choose a different query.\nRe-initiating program...\n')
       main()
    else:
        vulnFile = open(f"{fileName}", 'w')
        vulns = csv.writer(vulnFile)
        vulns.writerow(results[0].keys())
        for result in results:
            vulns.writerow(result.values())
        vulnFile.close()

    #Checks That File Was Created Before Continuing
    if os.path.exists(f'{curdir}\\{fileName}'):
       transformer(fileName)
    else:
       print('\n[!] Something went wrong. Please try again or close the program.\n')
       kqlHelp()

#Transforms Column Headers to Correct Format and Passes to Automox Upload Function
def transformer(fileName):
   with open(fileName) as f:
      columnName = f.read().replace('DeviceName', 'Hostname*')
   with open(fileName, 'w') as f:
      f.write(columnName)
      f.close()
   with open(fileName) as f:
      columnName = f.read().replace('CveId', 'CVE ID*')
   with open(fileName, 'w') as f:
      f.write(columnName)
      f.close()
   with open(fileName) as f:
      columnName = f.read().replace('VulnerabilitySeverityLevel', 'Severity')
   with open(fileName, 'w') as f:
      f.write(columnName)
      f.close()
    
   autoLoader(fileName)

#Connects to Automox API and Uploads the CSV
def autoLoader(fileName):
    org_id = "Automox-OrgID" #SENSITIVE - Paste your Automox orgID here
    type = "patch"
    url = "https://console.automox.com/api/orgs/" + org_id + "/tasks/" + type + "/batches/upload"

    m = MultipartEncoder(
        fields={'file': (fileName, open(fileName, 'rb'), 'text/plain')} #, 'format': (None, "Generic Report")} //Does not work.
    )

    headers = {
    "Content-Type": m.content_type,
    "Authorization": "Bearer Automox-API-Key", #HIGHLY SENSITIVE - Paste your Automox API Key Here
    }

    response = requests.post(url, headers=headers, data=m)

    responseData = response.json()
    print("\nJSON Results returned from the server can be found below.\n")
    print(responseData)

#Function to Get Vulnerability Metrics from Defender and Append to Local Spreadsheet
def vulnStats():
    print("Running authentication sequence...")
    aadToken = defenderAuth()
    
    print("Building metrics...")
    statQuery = []
    stats = []

    totalSystems = len(deviceList) #Get Total Systems

    #Count Total Vulnerable Systems [0]
    statQuery.append(f"let automoxDevices = dynamic({deviceList}); DeviceTvmSoftwareVulnerabilities | where DeviceName in~ (automoxDevices) | summarize Total = count_distinct(DeviceId)")
    #Count of all Vulnerabilities by Severity [0]
    statQuery.append(f"let automoxDevices = dynamic({deviceList}); DeviceTvmSoftwareVulnerabilities | where DeviceName in~ (automoxDevices) | summarize Vulns=count() by VulnerabilitySeverityLevel |sort by VulnerabilitySeverityLevel asc")
    #Count of Vulnerabilities Outside of Acceptable Remediation Timeline by Severity [1]
    statQuery.append(f"let automoxDevices = dynamic({deviceList}); DeviceTvmSoftwareVulnerabilitiesKB | join DeviceTvmSoftwareVulnerabilities on CveId | where DeviceName in~ (automoxDevices) | where (VulnerabilitySeverityLevel =~ 'Critical' and PublishedDate < ago(14d)) or (VulnerabilitySeverityLevel =~ 'High' and PublishedDate < ago(45d)) or (VulnerabilitySeverityLevel =~ 'Medium' and PublishedDate < ago(90d)) or (VulnerabilitySeverityLevel =~ 'Low' and PublishedDate < ago(90d)) | summarize Total = count() by VulnerabilitySeverityLevel | sort by VulnerabilitySeverityLevel asc")
    #Count of Systems with Vulnerabilities by Severity [2]
    statQuery.append(f"let automoxDevices = dynamic({deviceList}); DeviceTvmSoftwareVulnerabilities | where DeviceName in~ (automoxDevices) | summarize Total = count_distinct(DeviceId) by VulnerabilitySeverityLevel | sort by VulnerabilitySeverityLevel asc")
    #Count of Systems with Vulnerabilities Outside of Acceptable Remediation Timeline by Severity [3]
    statQuery.append(f"let automoxDevices = dynamic({deviceList}); DeviceTvmSoftwareVulnerabilitiesKB | join DeviceTvmSoftwareVulnerabilities on CveId | where DeviceName in~ (automoxDevices) | where (VulnerabilitySeverityLevel =~ 'Critical' and PublishedDate < ago(14d)) or (VulnerabilitySeverityLevel =~ 'High' and PublishedDate < ago(45d)) or (VulnerabilitySeverityLevel =~ 'Medium' and PublishedDate < ago(90d)) or (VulnerabilitySeverityLevel =~ 'Low' and PublishedDate < ago(90d)) | summarize Total = count_distinct(DeviceId) by VulnerabilitySeverityLevel | sort by VulnerabilitySeverityLevel asc")
    #Percent of Devices with Critical Vulnerabilities Outside of 14 Days [4]
    statQuery.append(f"let automoxDevices = dynamic({deviceList}); DeviceTvmSoftwareVulnerabilitiesKB | join DeviceTvmSoftwareVulnerabilities on CveId | where DeviceName in~ (automoxDevices) | where (VulnerabilitySeverityLevel =~ 'Critical' and PublishedDate < ago(14d)) | summarize Metric = (count_distinct(DeviceId) * 100) / {totalSystems} ")
    #Percent of Devices with High Vulnerabilities Outside of 45 Days [5]
    statQuery.append(f"let automoxDevices = dynamic({deviceList}); DeviceTvmSoftwareVulnerabilitiesKB | join DeviceTvmSoftwareVulnerabilities on CveId | where DeviceName in~ (automoxDevices) | where (VulnerabilitySeverityLevel =~ 'High' and PublishedDate < ago(45d)) | summarize Metric = (count_distinct(DeviceId) * 100) / {totalSystems} ")
    #Percent of Devices with Critical Vulnerabilities Outside of 14 Days [6]
    statQuery.append(f"let automoxDevices = dynamic({deviceList}); DeviceTvmSoftwareVulnerabilitiesKB | join DeviceTvmSoftwareVulnerabilities on CveId | where DeviceName in~ (automoxDevices) | where (VulnerabilitySeverityLevel =~ 'Medium' or VulnerabilitySeverityLevel =~ 'Low' and PublishedDate < ago(90d)) | summarize Metric = (count_distinct(DeviceId) * 100) / {totalSystems} ")
    
    url = "https://api.securitycenter.microsoft.com/api/advancedqueries/run"
    headers = { 
        'Content-Type' : 'application/json',
        'Accept' : 'application/json',
        'Authorization' : "Bearer " + aadToken
    }

    for query in statQuery:
        data = json.dumps({ 'Query' : query }).encode("utf-8")

        req = urllib.request.Request(url, data, headers)
        response = urllib.request.urlopen(req)
        jsonResponse = json.loads(response.read())
        #schema = jsonResponse["Schema"]
        results = jsonResponse["Results"]
        stats.append(results)

    #Print Vulnerability Report. Index Postion [0] is Total vulnerable Systems. Index Postion [1][X] is Total Vulnerabilities. Index Postion [2][X] is Past Due. Index Postion [3][X] is Total Vulnerable Systems. Index Postion [4][X] is Total Vulnerable Systems Past Due. Index Postions [5 - 7][0] Are Specific KRI Percentages.
    print("\n----------------------------------------------------------------------------------------------------------------")

    print(f"\nTotal Systems: {totalSystems}")

    print(f"\nTotal Vulnerable Systems:" + str(stats[0]).replace("[{'Total':","").replace("}]",""))

    print(f"\nTotal Vulnerabilities\n")
    print(str(stats[1][0]).replace("{'VulnerabilitySeverityLevel': ", "").replace("'", "").replace("Vulns:", "").replace(","," - ").replace("}", ""))
    print(str(stats[1][1]).replace("{'VulnerabilitySeverityLevel': ", "").replace("'", "").replace("Vulns:", "").replace(","," - ").replace("}", ""))
    print(str(stats[1][3]).replace("{'VulnerabilitySeverityLevel': ", "").replace("'", "").replace("Vulns:", "").replace(","," - ").replace("}", ""))
    print(str(stats[1][2]).replace("{'VulnerabilitySeverityLevel': ", "").replace("'", "").replace("Vulns:", "").replace(","," - ").replace("}", ""))

    print(f"\nVulnerabilities Past Due Date\n")
    print(str(stats[2][0]).replace("{'VulnerabilitySeverityLevel': ", "").replace("'", "").replace("Total:", "").replace(","," - ").replace("}", ""))
    print(str(stats[2][1]).replace("{'VulnerabilitySeverityLevel': ", "").replace("'", "").replace("Total:", "").replace(","," - ").replace("}", ""))
    print(str(stats[2][3]).replace("{'VulnerabilitySeverityLevel': ", "").replace("'", "").replace("Total:", "").replace(","," - ").replace("}", ""))
    print(str(stats[2][2]).replace("{'VulnerabilitySeverityLevel': ", "").replace("'", "").replace("Total:", "").replace(","," - ").replace("}", ""))

    print(f"\nTotal Vulnerable Systems\n")
    print(str(stats[3][0]).replace("{'VulnerabilitySeverityLevel': ", "").replace("'", "").replace("Total:", "").replace(","," - ").replace("}", ""))
    print(str(stats[3][1]).replace("{'VulnerabilitySeverityLevel': ", "").replace("'", "").replace("Total:", "").replace(","," - ").replace("}", ""))
    print(str(stats[3][3]).replace("{'VulnerabilitySeverityLevel': ", "").replace("'", "").replace("Total:", "").replace(","," - ").replace("}", ""))
    print(str(stats[3][2]).replace("{'VulnerabilitySeverityLevel': ", "").replace("'", "").replace("Total:", "").replace(","," - ").replace("}", ""))

    print(f"\nTotal Vulnerable Systems Past Due\n")
    print(str(stats[4][0]).replace("{'VulnerabilitySeverityLevel': ", "").replace("'", "").replace("Total:", "").replace(","," - ").replace("}", ""))
    print(str(stats[4][1]).replace("{'VulnerabilitySeverityLevel': ", "").replace("'", "").replace("Total:", "").replace(","," - ").replace("}", ""))
    print(str(stats[4][3]).replace("{'VulnerabilitySeverityLevel': ", "").replace("'", "").replace("Total:", "").replace(","," - ").replace("}", ""))
    print(str(stats[4][2]).replace("{'VulnerabilitySeverityLevel': ", "").replace("'", "").replace("Total:", "").replace(","," - ").replace("}", ""))

    print(f"\nKey Performance Indicators\n")
    print(f"Percent of Assets with Critical Vulnerabilities Older than 14 Days: " + str(stats[5]).replace("[{'Metric': ", "").replace("}]", "%"))
    print(f"Percent of Assets with High Vulnerabilities Older than 45 Days: " + str(stats[6]).replace("[{'Metric': ", "").replace("}]", "%"))
    print(f"Percent of Assets with Low or Medium Vulnerabilities Older than 90 Days: " + str(stats[7]).replace("[{'Metric': ", "").replace("}]", "%"))
    print("----------------------------------------------------------------------------------------------------------------\n")
    
#Primary Flow Control Function
def main():
    print('\nSystem initialization complete. Waiting for task...\n')
    while True:
            try:
                command = input('Command: ')
                if command == "-h" or command == "help":
                    help()
                if command == "remediation":
                    queryBuilder()
                    print ("\nJob completed successfully. Please review new vulnerabilities in Automox Remediations.\n")
                if command == "status":
                    vulnStats()
                if command == "quit" or command == "q" or command == "-q" or command == "exit":
                    exit()
            except KeyboardInterrupt:
                print("[!] Keyboard interrupt issued. Program will be closed")
                exit()

#Main
if __name__ == '__main__':
    deviceList = []
    logo()
    automoxExport()
    main()
