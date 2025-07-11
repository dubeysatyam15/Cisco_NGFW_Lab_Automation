#!/usr/bin/python
import json
import sys
import requests
#Surpress HTTPS insecure errors for cleaner output
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

#define fuction to connect to the FMC API and generate authentication token
def connect (host, username, password):
        headers = {'Content-Type': 'application/json'}
        path = "/api/fmc_platform/v1/auth/generatetoken"
        server = "https://"+host
        url = server + path
        try:
                r = requests.post(url, headers=headers, auth=requests.auth.HTTPBasicAuth(username,password), verify=False)
                auth_headers = r.headers
                token = auth_headers.get('X-auth-access-token', default=None)
                uuid = auth_headers.get('DOMAIN_UUID', default=None)
                if token == None:
                        print("No Token found, I'll be back terminating....")
                        sys.exit()
        except Exception as err:
                print ("Error in generating token --> "+ str(err))
                sys.exit()
        headers['X-auth-access-token'] = token

        return headers,uuid,server


def devicePOST (headers, uuid, server, post_data):
        api_path= "/api/fmc_config/v1/domain/" + uuid + "/devices/devicerecords"
        url = server+api_path
        try:
                r = requests.post(url, data=post_data, headers=headers, verify=False)
                status_code = r.status_code
                resp = r.text
                json_response = json.loads(resp)
                print("status code is: "+ str(status_code))
                if status_code == 201 or status_code == 202:
                        print("Post was sucessfull...")
                else:
                        r.raise_for_status()
                        print("error occured in POST -->"+resp)
        except requests.exceptions.HTTPError as err:
                print ("Error in connection --> "+str(err))
        finally:
                if r: r.close()
        return json_response



def deviceGET (headers, uuid, server):
        api_path= "/api/fmc_config/v1/domain/" + uuid + "/devices/devicerecords"
        url = server+api_path
        try:
                r = requests.get(url, headers=headers, verify=False)
                status_code = r.status_code
                resp = r.text
                json_response = json.loads(resp)
                print("status code is: "+ str(status_code))
                if status_code == 200:
                        print("GET was sucessfull...")
                else:
                        r.raise_for_status()
                        print("error occured in POST -->"+resp)
        except requests.exceptions.HTTPError as err:
                print ("Error in connection --> "+str(err))
        finally:
                if r: r.close()
        return json_response


def interfaceGET (headers, uuid, server, device_id):
        api_path= "/api/fmc_config/v1/domain/" + uuid + "/devices/devicerecords/"+device_id+"/physicalinterfaces"
        url = server+api_path
        try:
                r = requests.get(url, headers=headers, verify=False)
                status_code = r.status_code
                resp = r.text
                json_response = json.loads(resp)
                print("status code is: "+ str(status_code))
                if status_code == 200:
                        print("GET was sucessfull...")
                else:
                        r.raise_for_status()
                        print("error occured in POST -->"+resp)
        except requests.exceptions.HTTPError as err:
                print ("Error in connection --> "+str(err))
        finally:
                if r: r.close()
        return json_response



def interfacePUT (headers, uuid, server, put_data,device_id, interface_id):
        api_path= "/api/fmc_config/v1/domain/" + uuid + "/devices/devicerecords/"+device_id+"/physicalinterfaces/"+interface_id
        url = server+api_path
        try:
                r = requests.put(url, data=put_data, headers=headers, verify=False)
                status_code = r.status_code
                resp = r.text
                json_response = json.loads(resp)
                print("status code is: "+ str(status_code))
                if status_code == 200 :
                        print("Put was sucessfull...")
                else:
                        r.raise_for_status()
                        print("error occured in POST -->"+resp)
        except requests.exceptions.HTTPError as err:
                print ("Error in connection --> "+str(err))
        finally:
                if r: r.close()
        return json_response

def accesspolicyPOST (headers, uuid, server, post_data):
	api_path= "/api/fmc_config/v1/domain/" + uuid + "/policy/accesspolicies"
	url = server+api_path
	try:
		r = requests.post(url, data=json.dumps(post_data), headers=headers, verify=False)
		status_code = r.status_code
		resp = r.text
		json_response = json.loads(resp)
		print("status code is: "+ str(status_code))
		if status_code == 201 or status_code == 202:
			print("Post was sucessfull...")
		else:
			r.raise_for_status()
			print("error occured in POST -->"+resp)
	except requests.exceptions.HTTPError as err:
		print ("Error in connection --> "+str(err))
	finally:
		if r: r.close()
	return json_response
