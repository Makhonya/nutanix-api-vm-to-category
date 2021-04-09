# Add new category and category values for VM.

## Introduction

This script is example of REST API call way to add VM a category and category values on Prism Central.

## Requirements
```
Python 3
requests
urllib3
argparser
```
## How to use

To add VM a category with category values please use following format

```vm-to-gategory.py -u user_with_admin_permissions_here -n vmname1,vmname2 -i 'PC_IP_or_FQDN_here' -c category_name_here -k category_values_here```

Multiple VMs can be provided with "," as delimiter.
Category values can be supplied with "," as delimiter

Script will check if category or values already present on Prism Central and create missing category and values.
Script will check current VM category values and add/update new categiry and values.

## License
[MIT](https://choosealicense.com/licenses/mit/)
