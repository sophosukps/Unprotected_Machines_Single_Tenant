# Copyright 2019-2020 Sophos Limited
#
# Licensed under the GNU General Public License v3.0(the "License"); you may
# not use this file except in compliance with the License.
#
# You may obtain a copy of the License at:
# https://www.gnu.org/licenses/gpl-3.0.en.html
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied. See the License for the specific language governing permissions and
# limitations under the License.
#
#
# Console_Unprotected_Machines_v1.5.py
#
# Compares machines in Active Directory to machines in Sophos Central
# Machines NOT in Sophos Central will be exported to a csv report
#
#
# By: Michael Curtis and Robert Prechtel
# Date: 29/5/2020
# Version 1.5
# README: This script is an unsupported solution provided by
#           Sophos Professional Services

import requests
import csv
import configparser
# Import datetime modules
from datetime import date
from datetime import datetime
from datetime import timedelta
#Import OS to allow to check which OS the script is being run on
import os
# From the LDAP module import required objects
# https://ldap3.readthedocs.io/searches.html
from ldap3 import Server, Connection, SIMPLE, SYNC, ALL, SASL, NTLM, SUBTREE
# This list will hold all the computers
list_of_machines_in_central = []
# This list will hold all the computers not in Central
list_of_ad_computers_not_in_central = []
# This dictionary will hold all the computers in AD
dictionary_of_ad_computers = {}

# Get today's date and time
today = date.today()
now = datetime.now()
timestamp = str(now.strftime("%d%m%Y_%H-%M-%S"))

#######################
# Sophos Central Code #
#######################

# Get Access Token - JWT in the documentation
def get_bearer_token(client, secret, url):
    d = {
                'grant_type': 'client_credentials',
                'client_id': client,
                'client_secret': secret,
                'scope': 'token'
            }
    request_token = requests.post(url, auth=(client, secret), data=d)
    json_token = request_token.json()
    headers = {'Authorization': str('Bearer ' + json_token['access_token'])}
    return headers

def get_whoami():
    # We now have our JWT Access Token. We now need to find out if we are a Partner or Organization
    # Partner = MSP
    # Organization = Sophos Central Enterprise Dashboard
    # The whoami URL
    whoami_url = 'https://api.central.sophos.com/whoami/v1'
    request_whoami = requests.get(whoami_url, headers=headers)
    whoami = request_whoami.json()
    # MSP or Sophos Central Enterprise Dashboard
    # We don't use this variable in this script. It returns the organization type
    # Oraganization_Type = whoami["idType"]
    organizationID = whoami["id"]
    # Get the tennant Region
    regionURL = whoami['apiHosts']["dataRegion"]
    return organizationID, regionURL

def get_all_computers(tenant_token, url, name):
    # Get all Computers from the console
    print('Retrieving machines from Sophos Central')
    computers_url = url
    # Loop while the page_count is not equal to 0. We have more computers to query
    page_count = 1
    while page_count != 0:
        #Tenant to be searched
        tenant_id = tenant_token
        #Add X-Tenant-ID to the headers dictionary
        headers['X-Tenant-ID'] = tenant_id
        #Request all Computers
        request_computers = requests.get(computers_url, headers=headers)
        #Convert to JSON
        computers_json = request_computers.json()
        #Set the keys you want in the list
        computer_keys = ('hostname')
        #Add the computers to the computers list
        for all_computers in computers_json["items"]:
            # Make a temporary Dictionary to be added to the list_of_machines_in_central_list
            computer_dictionary = {key:value for key, value in all_computers.items() if key in computer_keys}
            #Get the hostname from the computer_dictionary
            central_computer_name = computer_dictionary['hostname']
            # Make Computer Name Upper Case for consistancy
            central_computer_name = central_computer_name.upper()
            list_of_machines_in_central.append(central_computer_name)
        # Check to see if you have more than 50 machines by checking if nextKey exists
        # We need to check if we need to page through lots of computers
        if 'nextKey' in computers_json['pages']:
            next_page = computers_json['pages']['nextKey']
            # Change URL to get the next page of computers
            # Example https://api-us01.central.sophos.com/endpoint/v1/endpoints?pageFromKey=<next-key>
            computers_url = url + '?pageFromKey=' + next_page
        else:
            # If we don't get another nextKey set page_count to 0 to stop looping
            page_count = 0

#########################
# Active Directory Code #
#########################

# Procedure to get AD computers
def get_ad_computers(search_domain, search_user, search_password, domain_controller, ldap_port):
    total_computers_in_ad = 0
    total_computers_in_central_and_ad = 0
    if ldap_port == 636:
        ldap_server = Server(domain_controller, port=ldap_port, use_ssl=True, get_info=SUBTREE)
        print('LDAPS is being used over port 636')
    else:
        ldap_server = Server(domain_controller, port=ldap_port, use_ssl=False, get_info=SUBTREE)
        print('LDAP is being used over port 389')
    server_query = Connection(ldap_server, search_user, search_password, auto_bind=True, authentication=NTLM)
    computers = server_query.extend.standard.paged_search(search_base=search_domain,
                                                              search_filter='(&(objectCategory=computer)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))',
                                                              search_scope=SUBTREE,
                                                              # Sets the search attributes to the name and lastLogonTimestamp
                                                              attributes=['cn', 'lastLogonTimestamp',
                                                                          'operatingSystem','dn'],
                                                              paged_size=5,
                                                              generator=False)
    print('Comparing Sophos Central machines to Active Directory')
    for entry in computers:
        if 'attributes' in entry:
            #Sets computer attributes to the Computer Name, OS, lastLogonTimestamp and DN
            computer_attributes = str(entry['attributes'])
            #Characters to be removed
            remove_characters_from_computer_attributes = ['[', '{', "'", "}", "]"," "]
            for remove_each_character in remove_characters_from_computer_attributes:
                computer_attributes = computer_attributes.replace(remove_each_character , '')
            cn_only = computer_attributes.split(',')[0]
            cn_only = cn_only.split(':')[1]
            timestamp_only = computer_attributes.split(',')[2]
            timestamp_only = timestamp_only.split(':')[1]
            os_only = computer_attributes.split(',')[1]
            os_only = os_only.split(':')[1]
            #Checks to see if the os_only contains just numbers. If so, it is the timestamp and should changed
            if os_only.isdecimal():
                timestamp_only = os_only
                os_only ="Unknown"
            if os_only == "":
                os_only = 'Unknown'
            #Adds computer_attribures to a Dictionary. Making the key at the : and splitting at the comma
            #dictionary_of_computers = dict(x.split(":") for x in computer_attributes.split(","))
            dictionary_of_computers = {}
            dictionary_of_computers['cn'] = cn_only
            dictionary_of_computers['operatingSystem'] = os_only
            dictionary_of_computers['lastLogonTimestamp'] = timestamp_only
            total_computers_in_ad += 1
            # This line allows you to debug on a certain computer. Add computer name
            if 'mcwsa' == cn_only:
                print('Add breakpoint here')
            #Get number of day since last logon. Check to see if lastLogonTimestamp is present
            if dictionary_of_computers.get('lastLogonTimestamp') != "":
                dictionary_of_computers['LastSeen'] = get_days_since_last_seen(dictionary_of_computers.get('lastLogonTimestamp'))
            else:
                # Machines with no time stamp are set to 1000 days for better sorting later
                dictionary_of_computers['LastSeen'] = 1000
            ad_computer_name = dictionary_of_computers.get('cn')
            # Make Computer Name Upper Case for consistancy
            ad_computer_name = ad_computer_name.upper()
            #If the computer is not in Central add it to list_of_ad_computers_not_in_central
            if ad_computer_name not in set_of_machines_in_central:
                #Add dictionary_of_computers to list_of_ad_computers
                #Changes the CN value to upper case to help the sort later
                dictionary_of_computers['cn'] = ad_computer_name
                #Remove the computer name from the DN
                dn_only = entry['dn'].split(',', 1)[-1]
                dictionary_of_computers['dn'] = dn_only
                list_of_ad_computers_not_in_central.append(dictionary_of_computers)
                print("a", end='')
            else:
                print("c", end='')
                total_computers_in_central_and_ad += 1
    return total_computers_in_ad, total_computers_in_central_and_ad


def get_days_since_last_seen(last_logon_date):
    # https://gist.github.com/caot/f57fbf419d6b37d53f6f4a525942cafc
    # https://www.programiz.com/python-programming/datetime/strptime
    # Converts report_date from a string into a DataTime
    convert_last_logon_date_to_int = int(last_logon_date)
    if convert_last_logon_date_to_int == 0:
        return None
    epoch_start = datetime(year=1601, month=1, day=1)
    seconds_since_epoch = convert_last_logon_date_to_int / 10 ** 7
    converted_timestamp = epoch_start + timedelta(seconds=seconds_since_epoch)
    # Remove the time from convert_last_seen_to_a_date
    converted_timestamp = datetime.date(converted_timestamp)
    days = (today - converted_timestamp).days
    return days

def print_report():
    #Customise the column headers
    fieldnames = ['Unprotected Machine', 'Operating System', 'Last AD Login (Days)', 'Microsoft Timestamp', 'DN']
    with open(full_report_path, 'w', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(['Percentage Protected', unprotected_percentage])
        writer.writerow(fieldnames)
    #Sets the column order
    order = ['cn', 'operatingSystem', 'LastSeen', 'lastLogonTimestamp','dn']
    with open(full_report_path, 'a+', encoding='utf-8', newline='') as output_file:
            dict_writer = csv.DictWriter(output_file, order)
            dict_writer.writerows(list_of_ad_computers_not_in_central)

def read_config():
    config = configparser.ConfigParser()
    config.read('console_config.config')
    config.sections()
    ClientID = config['DEFAULT']['ClientID']
    ClientSecret = config['DEFAULT']['ClientSecret']
    ReportName = config['REPORT']['ReportName']
    ReportFilePath = config['REPORT']['ReportFilePath']
    ConsoleName = config['REPORT']['ConsoleName']
    SearchDomain = config['DOMAIN']['SearchDomain']
    SearchUser= config['DOMAIN']['SearchUser']
    SearchUserPassword = config['DOMAIN']['SearchUserPassword']
    DomainController = config['DOMAIN']['DomainController']
    LDAPPort = config['DOMAIN']['LDAPPort']
    LDAPPort = int(LDAPPort)
    #Checks if the last character of the file path contanins a \ or / if not add one
    if ReportFilePath[-1].isalpha():
         if os.name != "posix":
             ReportFilePath = ReportFilePath + "\\"
         else:
             ReportFilePath = ReportFilePath + "/"
    return(ClientID,ClientSecret,ReportName,ReportFilePath,ConsoleName,SearchDomain,SearchUser,SearchUserPassword,DomainController, LDAPPort)




clientID, clientSecret, report_name, report_file_path, console_name, search_domain, search_user, search_user_password, domain_controller, ldap_port = read_config()
full_report_path = report_file_path + report_name + timestamp + '.csv'

token_url = 'https://id.sophos.com/api/v2/oauth2/token'
headers = get_bearer_token(clientID, clientSecret, token_url)
# Get the tenantID
tenantID, tenant_url = get_whoami()
tenant_endpoint_url = tenant_url + '/endpoint/v1/endpoints'


get_all_computers(tenantID, tenant_endpoint_url, console_name)
set_of_machines_in_central = set(list_of_machines_in_central)
number_of_machines_in_central = len(list_of_machines_in_central)

# get list of ad_computers
number_of_machines_in_ad, number_of_machines_in_central_and_ad = get_ad_computers(search_domain,search_user,search_user_password,domain_controller, ldap_port)
number_of_machines_in_central = len(list_of_machines_in_central)
unprotected_percentage = int((number_of_machines_in_central_and_ad / number_of_machines_in_ad) *100)

print('\n' + 'Number of machines not protected:', len(list_of_ad_computers_not_in_central))
print('Number of machines in AD', number_of_machines_in_ad)
print('Number of machines in Central', number_of_machines_in_central)
print('Number of machines in Central and AD', number_of_machines_in_central_and_ad)
print('Percentage Protected is', unprotected_percentage,'%')
# Sort the machines. cn for name or LastSeen for day
list_of_ad_computers_not_in_central.sort(key=lambda item: item.get("LastSeen"))
print_report()
