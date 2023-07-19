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
    tenantId = 'TENANT-ID-GOES-HERE' # SENSITIVE - Paste your own tenant ID here
    appId = 'APP-ID-GOES-HERE' # SENSITIVE - Paste your own app ID here
    appSecret = 'APP-SECRET-GOES-HERE' # HIGHLY SENSITIVE - Paste your own app secret here

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
        "o": "AUTOMOX-ORG-ID-GOES-HERE", #SENSITIVE - Automox Organization ID Goes Here
    }

    headers = {"Authorization": "Bearer AUTOMOX-API-KEY-GOES-HERE"} #HIGHLY SENSITIVE - Automox API Key Goes Here

    print("Connecting to Automox API...")    
    response = requests.get(url, headers=headers, params=query)
    data = response.json()

    for item in data:
        deviceList.append(item['name'])
    print("Successfully imported Automox device list.")

#Build the KQL Query Based on Input
def queryBuilder():
    validInput = ['Critical', 'High', 'Medium', 'Low', 'All']
    severity = input("Please indicate the vulnerability severity level(s) for the report (For help use -h.) >  ")
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
            print("Invalid input. Please see the usage page and try again.")
            kqlHelp()
    elif len(severityList) == 3:
         if severityList[0] and severityList[1] in validInput:
            kql = (f"let automoxDevices = dynamic({deviceList}); DeviceTvmSoftwareVulnerabilities | where DeviceName in~ (automoxDevices) | where VulnerabilitySeverityLevel =~ '{severityList[0]}' or  VulnerabilitySeverityLevel =~ '{severityList[1]}' or  VulnerabilitySeverityLevel =~ '{severityList[2]}'| summarize by DeviceName, CveId, VulnerabilitySeverityLevel")
         else:
            print("Invalid input. Please see the usage page and try again.")
            kqlHelp()
    elif len(severityList) == 4 or severity == "All":
        kql = (f"let automoxDevices = dynamic({deviceList}); DeviceTvmSoftwareVulnerabilities | where DeviceName in~ (automoxDevices) | summarize by DeviceName, CveId, VulnerabilitySeverityLevel")
    else:
        print("Invalid input. Please refer to the help page for proper usage.")
        kqlHelp()

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
    org_id = "AUTOMOX-ORG-ID-GOES-HERE" #SENSITIVE - Paste your Automox orgID here
    type = "patch"
    url = "https://console.automox.com/api/orgs/" + org_id + "/tasks/" + type + "/batches/upload"

    m = MultipartEncoder(
        fields={'file': (fileName, open(fileName, 'rb'), 'text/plain')} #, 'format': (None, "Generic Report")} //Does not work.
    )

    headers = {
    "Content-Type": m.content_type,
    "Authorization": "Bearer AUTOMOX-API-KEY-GOES-HERE", #HIGHLY SENSITIVE - Paste your Automox API Key Here
    }

    response = requests.post(url, headers=headers, data=m)

    responseData = response.json()
    print("\nJSON Results returned from the server can be found below.\n")
    print(responseData)

#Function to Get Vulnerability Metrics from Defender and Append to Local Spreadsheet
def vulnStats():
    aadToken = defenderAuth()

    statQuery = []
    stats = []

    #Count of Devices with Vulnerabilities Outside of Acceptable Remediation Timeline by Severity
    statQuery.append(f"let automoxDevices = dynamic({deviceList}); DeviceTvmSoftwareVulnerabilitiesKB | join DeviceTvmSoftwareVulnerabilities on CveId | where DeviceName in~ (automoxDevices) | where (VulnerabilitySeverityLevel =~ 'Critical' and PublishedDate < ago(14d)) or (VulnerabilitySeverityLevel =~ 'High' and PublishedDate < ago(45d)) or (VulnerabilitySeverityLevel =~ 'Medium' and PublishedDate < ago(90d)) or (VulnerabilitySeverityLevel =~ 'Low' and PublishedDate < ago(90d)) | summarize Total = count() by VulnerabilitySeverityLevel | sort by VulnerabilitySeverityLevel asc")
    #Count of all Vulnerabilities by Severity
    statQuery.append(f"let automoxDevices = dynamic({deviceList}); DeviceTvmSoftwareVulnerabilities | where DeviceName in~ (automoxDevices) | summarize Vulns=count() by VulnerabilitySeverityLevel |sort by VulnerabilitySeverityLevel asc")

    for query in statQuery:
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
        stats.append(results)
    
    totalSystems = len(deviceList) #Get Total Systems

    #Print Vulnerability Report. Index Postion [0][X] is Past Due. Index Postion [1][X] is Total.
    print("\n----------------------------------------------------------------------------------------------------------------")
    print(f"\nTotal Systems: {totalSystems}")
    print(f"\nVULNERABILITIES PAST DUE DATE\n")
    print(f"{stats[0][0]}")
    print(f"{stats[0][1]}")
    print(f"{stats[0][3]}")
    print(f"{stats[0][2]}")
    print(f"\nTOTAL VULNERABILITIES\n")
    print(f"{stats[1][0]}")
    print(f"{stats[1][1]}")
    print(f"{stats[1][3]}")
    print(f"{stats[1][2]}")
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
