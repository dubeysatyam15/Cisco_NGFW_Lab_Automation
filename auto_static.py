# Get and Post Static Route

# EXT-B01


import re
import getpass
import json
import sys
import requests
import time
import warnings
import os
from sys import getsizeof

# Current BUILD STATUS
# 1. Get all the static IPv4 routes and write to json
# 2. Bulk post all the static IPv4 routes

# Next Build
# 1. Inclusion of IPv6
# 2. Check if HOST/NETWORK object exists before posting the routes to target FMC and remove those objects before bulk post

warnings.filterwarnings('ignore', message='Unverified HTTPS request')


def chunkIt(seq, num):
    avg = len(seq) / float(num)
    out = []
    last = 0.0

    while last < len(seq):
        out.append(seq[int(last):int(last + avg)])
        last += avg

    return out

def get(route_url, param=dict()):

    param['offset'] = '0'
    param['limit'] = '1000'
    param['expanded'] = 'true'

    responses = list()
    r = get_request(route_url, param)
    responses.append(r)
    payload = r.json()
    if 'paging' in payload.keys():

        while 'items' in payload.keys() and 'next' in payload['paging']:

            param['offset'] = str(int(param['offset']) + 1000)
            response_page = get_request(route_url, param)
            payload = response_page.json()
            responses.append(response_page)
    return responses

def get_request(route_url, param):

    r = requests.get(route_url, headers=headers, params=param, verify=False)
    rj = r.json()

    if r.status_code == 401:
        if 'Access token invalid' in str(r.json()):
            refresh()
            return get_request(route_url, param)
    return r

#=================================================================
# Section to take the device details and credentials from the user
#=================================================================


device = input("Enter the device IP address: ")
username = input(
    "Enter the username of the FMC( recommended to have a seperate API User):")
password = getpass.getpass("Enter the password of the FMC: ")


#================================================================
# Authenticate and domain selection
#================================================================


headers = {'Content-Type': 'application/json'}

def authenticate():

    r = None
    api_auth_path = "/api/fmc_platform/v1/auth/generatetoken"
    auth_url = "https://" + device + api_auth_path

    try:

        r = requests.post(auth_url, headers=headers, auth=requests.auth.HTTPBasicAuth(
            username, password), verify=False)
        auth_headers = r.headers
        auth_token = auth_headers.get('X-auth-access-token', default=None)
        refresh_token = auth_headers.get('X-auth-refresh-token', default=None)
        if auth_token == None:
            print("Authentication not found. Exiting...")
            print(r.reason)
            sys.exit()
        else:
            return(auth_headers, auth_token, refresh_token)
    except Exception as err:
        print("Error in generating Authentication token --> " + str(err))
        sys.exit()


auth_headers, auth_token, refresh_token = authenticate()

refresh_headers = {}
refresh_headers['X-auth-refresh-token'] = auth_headers.get(
    'X-auth-refresh-token')
refresh_headers['X-auth-access-token'] = auth_headers.get(
    'X-auth-access-token')

def refresh():

    global refresh_counter
    refresh_counter = 1

    print('###########################################################')

    refresh_url = "https://" + device + "/api/fmc_platform/v1/auth/refreshtoken"
    if refresh_counter > 3:
        print('Authentication token has already been used 3 times, API re-authentication will be performed')
        authenticate()

    try:
        refresh_counter += 1
        r = requests.post(refresh_url, headers=refresh_headers, verify=False)
        auth_token = r.headers.get('X-auth-access-token', default=None)
        refresh_token = r.headers.get('X-auth-refresh-token', default=None)
        print('auth token-->', auth_token)
        print('refresh token-->', refresh_token)
        if not auth_token or not refresh_token:
            print('Could not refresh tokens')
            sys.exit()
        headers['X-auth-access-token'] = auth_token
        headers['X-auth-refresh-token'] = refresh_token
    except ConnectionError:
        print('Could not connect. Max retries exceeded with url')
    except Exception as err:
        print("Refresh Function Error  --> " + str(err))
    print('Successfully refreshed authorization token')


headers['X-auth-access-token'] = auth_token
domain = auth_headers['DOMAIN_UUID']

name_list = []
uuid_list = []

new_list = json.loads(auth_headers['DOMAINS'])
domain_len = len(new_list)

if domain_len > 1:
    for dict_item in new_list:
        name_list.append(dict_item["name"])
        uuid_list.append(dict_item["uuid"])
    i = 0
    while i < domain_len:

        print(i + 1, name_list[i], uuid_list[i])
        i = i + 1
    user_domain = int(
        input("Choose the domain from which Device has to be listed (numeric value):"))
    domain = uuid_list[user_domain - 1]

#===============================================================
# Get the list of Device and Device selection
#===============================================================

api_path = "/api/fmc_config/v1/domain/" + \
    domain + "/devices/devicerecords"    # param
url = "https://" + device + api_path
if (url[-1] == '/'):
    url = url[:-1]

allEntries = []
device_name = []
device_id = []

print('###########################################################')
print('#                       DEVICE LIST                       #')
print('###########################################################')


try:

    url = "https://" + device + api_path;
    r = requests.get(url, headers=headers, verify=False)
    status_code = r.status_code
    resp = r.text
    if (status_code == 200):
        json_resp = json.loads(resp)
        iterate = 1
        for counter in json_resp['items']:
            device_name.append(counter['name'])
            device_id.append(counter['id'])

            print(iterate, counter['name'])
            iterate = iterate + 1

        print('###########################################################')
        policy_id_1 = input("Choose the Device (integer value):")
        print('###########################################################')
        policy_id_1 = int(policy_id_1)

        ac_policy_1 = device_name[policy_id_1 - 1]
        device_id_1 = device_id[policy_id_1 - 1]

except requests.exceptions.HTTPError as err:
    print("Error in connection --> " + str(err))

finally:
    if r:
        r.close()

print('\n###########################################################')
print('1. Get Route')
print('2. Post Route')
r_choice = input("Choose the Device (integer value):")
print('###########################################################')

route_id = []


if r_choice == "1":

    #=====================================================================================
    # Read all routes from selected device
    #=====================================================================================

    routes_url = "https://" + device + "/api/fmc_config/v1/domain/" + domain + \
        "/devices/devicerecords/" + \
        device_id[policy_id_1 - 1] + "/routing/ipv4staticroutes"

    print('Retrieving all routes,\nPlease Wait...! ')
    r = None
    device_routes = get(routes_url)
    print('Retrieving all routes from Device')

    bulk_route_list = []
    int_name = []
    route_counter = 0
    dup_route_counter = 0
    if len(device_routes) == 1 and device_routes[0].json()['paging'].get('count') == 0:

        print('No routes present in Device')
        sys.exit()
    else:
        for response in device_routes:

            for route in response.json()['items']:

                route.pop('metadata')
                route.pop('links')
                route_id.append(route['id'])
                route.pop('id')
                int_name.append(route['interfaceName'])
                bulk_route_list.append(route)
                route_counter = route_counter + 1

    print("Number of routes in Device: ", route_counter)

    print("Ensure that the below interface names are created before posting.")

    for q in set(int_name):
        print("> ", q)
    with open('Mod_Routes.json', 'w') as file_1:
        json.dump(bulk_route_list, file_1, indent=4)

    # print(type(data))
    # print(data)

elif r_choice == "2":

    #=====================================================================================
    # Bulk post routes
    #=====================================================================================

    post_filename = input("Enter the input JSON file :")

    if (os.path.exists(post_filename)) is False:
        print("File not found!")
        sys.exit()

    with open(post_filename) as file_2:
        bulk_route_list = json.load(file_2)

    bulk_route_list_size = len(bulk_route_list)

    print('\n###########################################################')

    post_url = "https://" + device + "/api/fmc_config/v1/domain/" + domain + \
        "/devices/devicerecords/" + \
        device_id[policy_id_1 - 1] + "/routing/ipv4staticroutes?bulk=true"

    try:

        print("Posting routes, please wait!")

        bulk_route_list_size = len(bulk_route_list)

        if bulk_route_list_size > 500:

            for not_so_bulk_list in chunkIt(bulk_route_list, int((bulk_route_list_size) / 500) + 1):
                print('\nNumber of routes being posted is ',
                      len(not_so_bulk_list))

                print('Size of data being posted ',
                      getsizeof(not_so_bulk_list), ' Bytes')
                time.sleep(2)
                r = requests.post(post_url, data=json.dumps(
                    not_so_bulk_list), headers=headers, verify=False)
                status_code = r.status_code
                reason = r.reason

            if (status_code == 200 or status_code == 201):
                print("Post was successful!")

            elif status_code == 401:
                if 'Access token invalid' in str(resp):
                    refresh()

            else:
                print("Status code : Reason -->", status_code, ' : ', reason)
                sys.exit()

        else:

            r = requests.post(post_url, data=json.dumps(
                bulk_route_list), headers=headers, verify=False)
            status_code = r.status_code
            resp = r.text
            reason = r.text

            if (status_code == 200 or status_code == 201):
                print("Post was successful!")

            elif status_code == 401:
                if 'Access token invalid' in str(resp):
                    refresh()

            else:
                print("Status code : Reason -->", status_code, ' : ', reason)
                sys.exit()

    except requests.exceptions.HTTPError as err:
        print("POST_ROUTE : Error in connection ")
    finally:
        if r:
            r.close()
    print('###########################################################')
