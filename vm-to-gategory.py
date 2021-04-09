#!/bin/python
# Import modules and set context
import json
import getpass
import argparse
import requests
from requests.auth import HTTPBasicAuth
from urllib3 import disable_warnings
from urllib3.exceptions import InsecureRequestWarning
# Self-signed certificate trust handling
disable_warnings(InsecureRequestWarning)

# Add handling for API reply errors
def apiCall(apiurl, apiauth, apipayload, method):
    try:
        if method == 'POST':
            urlData = requests.post(url = apiurl, auth=apiauth, headers=headers, data=apipayload ,verify=False)
        elif method == 'PUT':
            urlData = requests.put(url = apiurl, auth=apiauth, headers=headers, data=apipayload ,verify=False)
        elif method == 'GET':
            urlData = requests.get(url = apiurl, auth=apiauth, headers=headers, verify=False)
        else:
            print('no method supplied. quitting...')
            quit()
    except Exception as err:
        print(err)
    
    if not urlData.status_code in [200,202]:
        print('Error code:', urlData.status_code)
        try:
            errContent = json.loads(urlData.content)
            print('''Details:\n
            Reason: {0}\n
            Message: {1}\n
            '''.format(errContent['message_list'][0]['reason'],errContent['message_list'][0]['message']))
        except:
            print('No Details retrieved')
        quit()
    return urlData

# Compare list of current values to new values
def categoryValuesCompare(curValues, newValues):
    diffValues = list(set(newValues) - set(curValues)) + list(set(curValues) - set(newValues))
    return diffValues

parser = argparse.ArgumentParser(description='''Script to add category and values to VM''', 
                                 usage='''new.py -u user_with_admin_permissions_here -n vmname_here -i 'PC_IP_or_FQDN_here' -c category_name_here -k category_values_here\n
                                 Category values can be supplied with \",\" as delimiter''')
parser.add_argument('-n', '--vmName', type=str, help='Name of VM', required=True)
parser.add_argument('-c', '--category',type=str, help='Category to add.', required=True)
parser.add_argument('-k', '--category_values',type=str, help='Category values to add.', required=True)
parser.add_argument('-i', '--ip', type=str, help='Server ip or FQDN', required=True)
parser.add_argument('-u', '--user', type=str, help='User with Cluster Admin Role Mapping', required=True)
args = parser.parse_args()

ipAddr = args.ip
vmName = args.vmName
user = args.user
categoryKey = args.category
categoryValues = (args.category_values).split(',')

apiBase = 'https://%s:9440/' % ipAddr
headers = {'Accept': 'application/json','content-type': 'application/json',}
auth = HTTPBasicAuth(user, getpass.getpass('Enter password for user '))

# Get VM list based on VM name - in case we have multiple VMs with same name
endpointVMs = '/api/nutanix/v3/vms/list'
listVMsPayload = '''{
  "kind": "vm",
  "filter": "vm_name==%s"
}''' % vmName
jsData = json.loads(apiCall(apiBase + endpointVMs, auth, listVMsPayload, 'POST').content)

# If more than one VM found build menu to pick VM based on UUID
menuEntries = list()
menuIndx = list()
selectedId = 0
if len(jsData['entities']) > 1:
    for i in range(len(jsData['entities'])):
        menuEntries.append((i, jsData['entities'][i]))
        menuIndx.append(i)
    for i,j in menuEntries:
        print(i, j['metadata']['uuid'],j['spec']['name'])
    selectedId = None
    while selectedId not in menuIndx:
        selectedId = int(input('Confirm VM UUID '))

vmUuid = jsData['entities'][selectedId]['metadata']['uuid']

# Get VM spec from PC
endpointVM = 'api/nutanix/v3/vms/'
jsData2 = json.loads(apiCall(apiBase + endpointVM + vmUuid, auth, None, 'GET').content)
print('Processing VM: \n',jsData2['spec']['name'],jsData2['metadata']['uuid'])


# Check if category exists and create if not
endpointCategory = 'api/nutanix/v3/categories/'+categoryKey
categoryPayload = '''{
  "kind": "category"
}'''
categoryData = json.loads(apiCall(apiBase + endpointCategory + '/list', auth, categoryPayload, 'POST').content)


if not categoryData['entities'] and categoryData['metadata']['length'] ==0:
    print('Creating missing category Key and Values')
    categoryDefinitionPayload = '''{
    "api_version": "3.1.0",
    "description": "created with script",
    "name": "%s"
    }''' % categoryKey
    json.loads(apiCall(apiBase + endpointCategory, auth, categoryDefinitionPayload, 'PUT').content)
    for i in categoryValues:
        categoryValueDefinitionPayload = '''{
        "value": "%s",
        "api_version": "3.1.0"
        }''' % i
        json.loads(apiCall(apiBase+endpointCategory + '/' + i, auth, categoryValueDefinitionPayload, 'PUT').content)
else:
    existingCatVal = list()
    for i in categoryData['entities']:
        existingCatVal.append(i['value'])
    for i in categoryValues:
        if not i in existingCatVal:
            print('Creating missing category Value')
            print(i)
            categoryValueDefinitionPayload = '''{
            "value": "%s",
            "api_version": "3.1.0"
            }''' % i
            json.loads(apiCall(apiBase + endpointCategory + '/' + i, auth, categoryValueDefinitionPayload, 'PUT').content)

# Creating payload for categories
newPayload = dict()
newPayload['spec'] = jsData2['spec']
newPayload['metadata'] = jsData2['metadata']
newPayload["api_version"] = jsData2['api_version']
newPayload['metadata']["use_categories_mapping"] = True
curVMCategories = newPayload['metadata']['categories_mapping']

# Modify/Add categories
if len(curVMCategories) > 0 and (categoryKey in curVMCategories.keys()):
    freshValues = categoryValuesCompare(curVMCategories[categoryKey],categoryValues)
    if not len(freshValues) == 0:
        for i in categoryValuesCompare(curVMCategories[categoryKey],categoryValues):
            (curVMCategories[categoryKey]).append(i)
    else:
        print('nothing to add')
        quit()
else:
    curVMCategories[categoryKey] = categoryValues

jsData3 = json.loads(apiCall(apiBase + endpointVM + vmUuid, auth, json.dumps(newPayload), 'PUT').content)
print('Task status: ', jsData3['status']['state'], '\n', 'Task uuid: ', jsData3['status']['execution_context']['task_uuid'])