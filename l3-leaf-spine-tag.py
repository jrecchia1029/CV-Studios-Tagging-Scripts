import argparse
import csv
from getpass import getpass
import random
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
from cvprac.cvp_client import CvpClient


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
    parser.add_argument("--cvp", type=str, required=True, help="IP address or fqdn of CVP")
    parser.add_argument("--username", required=False, type=str, help="Username of CVP account")
    parser.add_argument("--password", required=False, type=str, help="Password of CVP account")
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
    api_token = args.api_token
    # Set CV config variables
    workspace_id = args.workspace_id
    tag_action = args.action if args.action is not None else "apply"
    
    # For testing
    fn = "tags.csv"
    username = None
    password = None
    username = "cvpadmin"
    password = "nynjlab"
    cvp_ip = "www.cv-staging.corp.arista.io"
    api_token = "../cvaas_staging_token.txt"
    # cvp_ip = "10.20.30.186"
    # api_token = "../on_prem_token.txt"
    workspace_id = "7687717"

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
    api_token = open(api_token).read() if api_token is not None else None
    cvp_ips = [ip.strip() for ip in cvp_ip.split(",")]
    cvp_client = CvpClient()
    if "arista.io" in cvp_ip:
        cvp_client.connect(cvp_ips, username='', password='', api_token=api_token, is_cvaas=True)
    else:
        cvp_client.connect(cvp_ips, username=username, password=password, api_token=api_token)

    # print(cvp_client.api.get_cvp_info())
    # Get serial number for switches listed in csv file and make that the key
    device_inventory = get_switches(cvp_client)
    for sn, hostname in device_inventory.items():
        if hostname in device_tags.keys():
            device_tags[sn] = device_tags[hostname]
            del device_tags[hostname]

    # Create workspace
    if workspace_id is None:
        workspace_id = str(random.randint(1000000,9999999))
        workspace_name = f"l3ls-tags-{workspace_id}"
        resp = cvp_client.api.workspace_config(workspace_id, workspace_name)

    # Get all tags so old tag values can be removed after the new value is applied
    tag_labels_with_one_value = [
        "node_id",
        "DC",
        "DC-Pod",
        "Leaf-Domain",
        "L2-Leaf-Domain",
        "Super-Spine-Plane"
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


if __name__ == "__main__":
    main()
