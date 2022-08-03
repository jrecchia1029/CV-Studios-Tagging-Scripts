import argparse
import csv
from getpass import getpass
import random
import requests
import ssl
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
from cvprac.cvp_client import CvpClient
from cloudvision.Connector.grpc_client import GRPCClient, create_query
from cloudvision.Connector.codec.custom_types import FrozenDict


def get_auth_requirements(server, username, password):
    r = requests.post('https://' + server + '/cvpservice/login/authenticate.do',
                      auth=(username, password), verify=True is False)

    r.json()['sessionId']
    token = r.json()['sessionId']
    with open("cvp.crt", "w") as f:
        f.write(ssl.get_server_certificate((server, 443)))
    return token


def unfreeze(o):
    ''' Used to unfreeze Frozen dictionaries'''
    if isinstance(o, (dict, FrozenDict)):
        return dict({k: unfreeze(v) for k, v in o.items()})

    if isinstance(o, (str)):
        return o

    try:
        return [unfreeze(i) for i in o]
    except TypeError:
        pass

    return o


def get_switches(cv_client):
    ''' Get active devices '''
    dev_url = '/api/resources/inventory/v1/Device/all'
    devices_data = cv_client.get(dev_url)
    inventory = {}
    for device in devices_data['data']:
        try:
            inventory[device['result']['value']['key']['deviceId']] = device["result"]["value"]["hostname"]
        # pass on archived datasets
        except KeyError as e:
            continue
    return inventory


def get_bgp_as_value(apiserverAddr, device_id, token=None, certs=None, key=None, ca=None):
    '''/Sysdb/routing/bgp/config/asNumber'''
    pathElts = [
        "Sysdb",
        "routing",
        "bgp",
        "config"
    ]
    query = [
        create_query([(pathElts, ["asNumber"])], device_id)
    ]
    try:
        with GRPCClient(apiserverAddr, tokenValue=token, key=key,
                        ca=ca, certs=certs) as client:
            for batch in client.get(query):
                for notif in batch["notifications"]:
                    return unfreeze(notif["updates"]["asNumber"])["value"]
    except:
        return
    return


def get_router_id_value(apiserverAddr, device_id, token=None, certs=None, key=None, ca=None):
    '''/Sysdb/routing/bgp/config/routerId'''
    pathElts = [
        "Sysdb",
        "routing",
        "bgp",
        "config"
    ]
    query = [
        create_query([(pathElts, ["routerId"])], device_id)
    ]
    try:
        with GRPCClient(apiserverAddr, tokenValue=token, key=key,
                        ca=ca, certs=certs) as client:
            for batch in client.get(query):
                for notif in batch["notifications"]:
                    return notif["updates"]["routerId"]
    except:
        return
    return


def get_mlag_peer_link_value(apiserverAddr, device_id, token=None, certs=None, key=None, ca=None):
    '''/Sysdb/mlag/status/peerLinkIntf/ gives value of other path 
    /Sysdb/lag/input/interface/lag/intfStatus/<port-channel-id>/intfId'''
    pathElts = [
        "Sysdb",
        "mlag",
        "status"
    ]
    query = [
        create_query([(pathElts, ["peerLinkIntf"])], device_id)
    ]
    try:
        with GRPCClient(apiserverAddr, tokenValue=token, key=key,
                        ca=ca, certs=certs) as client:
            for batch in client.get(query):
                for notif in batch["notifications"]:
                    return notif["updates"]["peerLinkIntf"]._keys[-1]
    except:
        return
    return


def get_all_tag_values(cvp_client, workspace_id):
    '''
    Leverage cvprac get_all_tags() method
    '''
    all_tag_values = {}
    workspace_ids = [workspace_id]
    # Add Main workspace (None) if you want to get all tags
    # workspace_ids.append(None)
    for ws_id in workspace_ids:
        resp = cvp_client.api.get_all_tags("ELEMENT_TYPE_DEVICE", ws_id)["data"]
        for tag_info in resp:
            label = tag_info["result"]["value"]["key"]["label"]
            value = tag_info["result"]["value"]["key"]["value"]
            if label not in all_tag_values.keys():
                all_tag_values[label] = [value]
            else:
                if value not in all_tag_values[label]:
                    all_tag_values[label].append(value)
    return all_tag_values

def create_tag(cvp_client, workspace_id, label, value):
    '''
    Leverage cvprac tag_config() method
    '''
    return cvp_client.api.tag_config("ELEMENT_TYPE_DEVICE", workspace_id, label, value)


def delete_tag(cvp_client, workspace_id, label, value):
    '''
    Leverage cvprac tag_config() method
    '''
    return cvp_client.api.tag_config("ELEMENT_TYPE_DEVICE", workspace_id, label, value, remove=True)


def apply_tag(cvp_client, workspace_id, label, value, device_id):
    '''
    Leverage cvprac tag_assignment_config() method
    '''
    return cvp_client.api.tag_assignment_config(
        "ELEMENT_TYPE_DEVICE", workspace_id,
        label, value, device_id, "")


def remove_tag(cvp_client, workspace_id, label, value, device_id):
    '''
    Leverage cvprac tag_assignment_config() method
    '''
    return cvp_client.api.tag_assignment_config(
        "ELEMENT_TYPE_DEVICE", workspace_id,
        label, value, device_id, "", remove=True)


def main():
    parser = argparse.ArgumentParser(description="This script will create/apply or remove " \
                                    "the tags required for CloudVision's L3 Leaf-Spine studio " \
                                    "to generate configuration for a switch")
    parser.add_argument("--csv-file", type=str, required=True, help="Path to csv file")
    parser.add_argument("--cvp", type=str, required=True, help="IP address or fqdn of CVP (use 'www.arista.io' for CVaaS.")
    parser.add_argument("--username", required=False, type=str, help="Username of CVP account. Required when using on-prem CVP.")
    parser.add_argument("--password", required=False, type=str, help="Password of CVP account. Required when using on-prem CVP.")
    parser.add_argument("--api-token", required=False, type=str, help="Path to CVP service account token")
    parser.add_argument("--workspace-id", type=str, required=False, help="The workspace id of the workspace to modify. " \
                        "If no value is provided, a new workspace will be created with the name l3ls-<ws-id>.")
    parser.add_argument("--action", type=str, required=False, help="Action script should perform. Valid options are 'apply' or 'remove'. " \
                        "Applying will create and assign tags the tags listed in the csv file. "\
                        "Removing will remove the tags applied to the devices.  The default action is 'apply'.")
    args = parser.parse_args()
    # Set csv file path
    fn = args.csv_file
    # Set CV variables
    cvp_ip = args.cvp
    username = args.username
    password = args.password
    if username is not None and password is None:
        password = getpass("Password: ")

    if "arista.io" not in cvp_ip:
        token = get_auth_requirements(cvp_ip, username, password)

    # Set api token to what was retrieved if it was not input by user
    api_token = open(args.api_token).read() if args.api_token is not None else token
    # Set CV config variables
    workspace_id = args.workspace_id
    tag_action = args.action if args.action is not None else "apply"

    # For testing
    # fn = "tags.csv"
    # username = None
    # password = None
    # username = "cvpadmin"
    # password = "nynjlab"
    # cvp_ip = "www.cv-staging.corp.arista.io"
    # api_token = "../cvaas_staging_token.txt"
    # cvp_ip = "10.20.30.186"
    # api_token = "../on_prem_token.txt"
    # workspace_id = "7687717"
    
    # Read tag,values from csv file and put them in dictionary
    device_tags = {}

    with open(fn) as csv_file:
        csv_reader = csv.reader(csv_file, delimiter=',')
        fields = next(csv_reader)
        for row in csv_reader:
            device_tags[row[0]] = {
                fields[1]: row[1],
                fields[2]: row[2],
                fields[3]: row[3],
                fields[4]: row[4]
            }

    # Login to CVP
    cvp_ips = [ip.strip() for ip in cvp_ip.split(",")]
    cvp_client = CvpClient()
    if "arista.io" in cvp_ip:
        cvp_client.connect(cvp_ips, username='', password='', api_token=api_token, is_cvaas=True)
    else:
        cvp_client.connect(cvp_ips, username=username, password=password, api_token=api_token)

    # Get serial number for switches listed in csv file and make that the key
    device_inventory = get_switches(cvp_client)
    for sn, hostname in device_inventory.items():
        if hostname in device_tags.keys():
            device_tags[sn] = device_tags[hostname]
            del device_tags[hostname]

    # Get bgp_as, router_id, and mlag_peer_link values
    for sn in device_tags.keys():
        if "arista.io" in cvp_ip:
            device_tags[sn]["router_bgp.as"] = str(get_bgp_as_value(f"{cvp_ips[0]}:443", sn, token=api_token))
            device_tags[sn]["router_bgp.router_id"] = get_router_id_value(f"{cvp_ips[0]}:443", sn, token=api_token)
            device_tags[sn]["mlag_configuration.peer_link"] = get_mlag_peer_link_value(f"{cvp_ips[0]}:443", sn, token=api_token)
        else:
            device_tags[sn]["router_bgp.as"] = str(get_bgp_as_value(f"{cvp_ips[0]}:443", sn, token=api_token, ca="cvp.crt"))
            device_tags[sn]["router_bgp.router_id"] = get_router_id_value(f"{cvp_ips[0]}:443", sn, token=api_token, ca="cvp.crt")
            device_tags[sn]["mlag_configuration.peer_link"] = get_mlag_peer_link_value(f"{cvp_ips[0]}:443", sn, token=api_token, ca="cvp.crt")

    # Create workspace
    if workspace_id is None:
        workspace_id = str(random.randint(1000000,9999999))
        workspace_name = f"evpn-tags-{workspace_id}"
        resp = cvp_client.api.workspace_config(workspace_id, workspace_name)

    # print(json.dumps(device_tags, indent=2))
    # Get all tags so old tag values can be removed after the new value is applied
    tag_labels_with_one_value = [
        "node_id",
        "DC",
        "DC-Pod",
        "Leaf-Domain",
        "router_bgp.as",
        "router_bgp.router_id",
        "mlag_configuration.peer_link"
    ]

    all_tag_values = get_all_tag_values(cvp_client, workspace_id)
    # Create and apply tags
    for sn, tags in device_tags.items():
        for label, value in tags.items():
            if value is None or value.strip() == "":
                continue
            if tag_action == "apply":
                create_tag(cvp_client, workspace_id, label, value)
                apply_tag(cvp_client, workspace_id, label, value, sn)
                # Remove other tags with same label but different value
                if label in tag_labels_with_one_value:
                    for potential_value in all_tag_values[label]:
                        if value != potential_value:
                            remove_tag(cvp_client, workspace_id, label, potential_value, sn)
            elif tag_action == "remove":
                remove_tag(cvp_client, workspace_id, label, value, sn)
            elif tag_action == "delete":
                delete_tag(cvp_client, workspace_id, label, value)

    # This part assumes all devices in csv file are L3 Leafs
    # Add network services tags
    for sn in device_tags.keys():
        if tag_action == "apply":
            create_tag(cvp_client, workspace_id, "network_services", "L2")
            apply_tag(cvp_client, workspace_id, "network_services", "L2", sn)
            create_tag(cvp_client, workspace_id, "network_services", "L3")
            apply_tag(cvp_client, workspace_id, "network_services", "L3", sn)
        elif tag_action == "remove":
            remove_tag(cvp_client, workspace_id, "network_services", "L2", sn)
            remove_tag(cvp_client, workspace_id, "network_services", "L3", sn)            


if __name__ == "__main__":
    main()
