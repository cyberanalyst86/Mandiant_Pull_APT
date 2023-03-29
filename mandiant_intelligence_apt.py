import requests
import json
import os
import yaml
from yaml.loader import SafeLoader
from requests.auth import HTTPBasicAuth
import pandas as pd
from get_threat_actor_details import *

output_filepath = "C:\\Users\\Admin\\Downloads\\mandiant\\threat_actor.xlsx"

#----------------------------Mandiant API Credentials-----------------------------#

with open('cred.yaml') as f:
    conf = yaml.load(f, Loader=SafeLoader)

publickey = conf['mandiant_user']['publickey']
privatekey = conf['mandiant_user']['privatekey']

APIv3_key= publickey
APIv3_secret= privatekey

#----------------------------Get Mandiant API Token-----------------------------#

API_URL = 'https://api.intelligence.fireeye.com/token'
headers = {
    'grant_type': 'client_credentials'
    }
r = requests.post(API_URL, auth=HTTPBasicAuth(APIv3_key, APIv3_secret), data=headers)
data = r.json()
auth_token = data.get('access_token')

#----------------------------Mandiant Query Header - List Threat Actors-----------------------------#

url = "https://api.intelligence.mandiant.com/v4/actor"

headers = {
 "Authorization": f"Bearer {auth_token}",
 "Accept": "application/json",
 "X-App-Name": "insert your app name"
}

params = {
 "limit": 1000,
 "offset": 0,
}
#----------------------------Query Mandiant Threat Actor-----------------------------#

resp = requests.get(url=url, headers=headers, params=params)
#print(resp.url)
#print(json.dumps(resp.json(), indent=True))

df = pd.DataFrame(resp.json()["threat-actors"])

df_final = get_threat_actor_details(df, auth_token)

#df_final.to_excel(output_filepath, index=False)



