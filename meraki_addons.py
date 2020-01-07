import requests


"""
###############################################################################
These functions are all covering gaps in the legacy Meraki SDK
###############################################################################
"""


def get_api_http_servers(api_key, net_id):
    headers = {'X-Cisco-Meraki-API-Key': api_key}
    response = requests.get("https://api.meraki.com/api/v0/networks/" + net_id + "/httpServers", headers=headers)

    if response.ok:
        return response.json()
    else:
        print(response.content)
        return None


def add_api_http_servers(api_key, net_id, wh_name, wh_url):
    headers = {'X-Cisco-Meraki-API-Key': api_key}
    data = {"name": wh_name, "url": wh_url}
    response = requests.post("https://api.meraki.com/api/v0/networks/" + net_id + "/httpServers", data=data, headers=headers)

    if response.ok:
        return response.json()
    else:
        return None


def update_api_http_servers(api_key, net_id, wh_id, wh_name, wh_url):
    headers = {'X-Cisco-Meraki-API-Key': api_key}
    data = {"name": wh_name, "url": wh_url}
    response = requests.post("https://api.meraki.com/api/v0/networks/" + net_id + "/httpServers/" + wh_id, data=data, headers=headers)

    if response.ok:
        return response.json()
    else:
        return None


def get_alert_settings(api_key, net_id):
    headers = {'X-Cisco-Meraki-API-Key': api_key}
    response = requests.get("https://api.meraki.com/api/v0/networks/" + net_id + "/alertSettings", headers=headers)
    if response.ok:
        return response.json()
    else:
        return None


def update_alert_settings(api_key, net_id, wh_id):
    cur_alert = get_alert_settings(api_key, net_id)
    new_alert = []
    servers = cur_alert["defaultDestinations"]["httpServerIds"]
    servers.append(wh_id)

    for c in cur_alert["alerts"]:
        c["enabled"] = True
        new_alert.append(c)

    headers = {'X-Cisco-Meraki-API-Key': api_key, 'content-type': 'application/json'}
    data = {
        "defaultDestinations": {
            "emails": [],
            "snmp": False,
            "allAdmins": False,
            "httpServerIds": servers
        },
        "alerts": new_alert
    }
    url = "https://api.meraki.com/api/v0/networks/" + net_id + "/alertSettings"
    # print(url, data, headers)
    response = requests.put(url, json=data, headers=headers)
    # print(response.content.decode("utf-8"))

    if response.ok:
        return response.json()
    else:
        return None


def del_api_http_servers(api_key, net_id, wh_id):
    headers = {'X-Cisco-Meraki-API-Key': api_key}
    response = requests.delete("https://api.meraki.com/api/v0/networks/" + net_id + "/httpServers/" + wh_id, headers=headers)

    if response.ok:
        return response
    else:
        return None