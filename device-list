import pip._vendor.requests

url = "https://console.automox.com/api/servers"

query = {
  "o": "YOUR-AUTOMOX-ORGANIZATION-NUMBER",
}

headers = {"Authorization": "Bearer YOUR-AUTOMOX-API-KEY"}

response = pip._vendor.requests.get(url, headers=headers, params=query)
data = response.json()

with open ("devices.txt","a") as deviceList:
    for item in data:
        print(item['name'] + ',', end = " ", file = deviceList)
