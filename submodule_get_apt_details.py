import requests
import json
import os
import pandas as pd
from yaml.loader import SafeLoader
from requests.auth import HTTPBasicAuth

def get_threat_actor_details(df, auth_token):

    # ----------------------------declare variables----------------------------#
    industries_list = []
    suspected_attribution_list = []
    source_list = []
    id_list = []
    name_list = []
    description_list = []
    # type_list = []
    last_activity_time_list = []
    audience_list = []
    is_publishable_list = []
    intel_free_list = []
    counts_list = []
    last_updated_list = []
    aliases_list = []
    malware_list = []
    motivations_list = []
    associated_uncs_list = []
    cve_list = []
    observed_list = []
    tools_list = []
    is_it_publishable_list = []
    target_list = []

    for index , row in df.iterrows():

        print(row["name"])
        print(row["id"])

        # ----------------------------Check Directory Folder-----------------------------#

        file_directory = "C:\\Users\\Admin\\Downloads\\mandiant\\"

        file_path = file_directory + str(row["name"])

        isExist = os.path.exists(file_path)

        if isExist == False:

            os.mkdir(file_path)

        else:

            error = "error"

        url = "https://api.intelligence.mandiant.com/v4/actor/" + str(row["id"])

        headers = {
            "Authorization": f"Bearer {auth_token}",
            "Accept": "application/json",
            "X-App-Name": "insert your app name"
        }

        params = None

        resp = requests.get(url=url, headers=headers, params=params)

        dict = resp.json()

        # ----------------------------get mandiant threat actor basic information----------------------------#

        name_list.append(dict["name"])
        id_list.append(dict["id"])

        try:
            last_activity_time_list.append(dict["last_activity_time"])
        except KeyError:
            last_activity_time_list.append("NIL")

        try:
            last_updated_list.append(dict["last_updated"])
        except KeyError:
            last_updated_list.append("NIL")

        try:
            description_list.append(dict["description"])
        except KeyError:
            description_list.append("NIL")

        try:
            is_publishable_list.append(dict["is_publishable"])
        except KeyError:
            is_publishable_list.append("NIL")

        try:
            intel_free_list.append(dict["intel_free"])
        except KeyError:
            intel_free_list.append("NIL")

        try:
            counts_list.append(dict["counts"])
        except KeyError:
            counts_list.append("NIL")



        # ----------------------------get mandiant threat actor detailed information----------------------------#
        try:
            df_aliases = pd.DataFrame(resp.json()["aliases"])
            df_aliases.to_excel(file_path + "\\" + "aliases.xlsx")
            aliases_list.append(df_aliases["alias"].values.tolist())
        except KeyError:
            aliases_list.append("NIL")

        try:
            df_associated_uncs = pd.DataFrame(resp.json()["associated_uncs"])
            df_associated_uncs.to_excel(file_path + "\\" + "associated_uncs.xlsx")
            associated_uncs_list.append(df_associated_uncs["name"].values.tolist())
        except KeyError:
            associated_uncs_list.append("NIL")

        try:
            df_industries = pd.DataFrame(resp.json()["industries"])
            df_industries.to_excel(file_path + "\\" + "industries.xlsx")
            industries_list.append(df_industries["name"].values.tolist())
        except KeyError:
            industries_list.append("NIL")

        try:
            df_motivations = pd.DataFrame(resp.json()["motivations"])
            df_motivations.to_excel(file_path + "\\" + "motivations.xlsx")
            motivations_list.append(df_motivations["name"].values.tolist())
        except KeyError:
            motivations_list.append("NIL")

        try:
            df_malware = pd.DataFrame(resp.json()["malware"])
            df_malware.to_excel(file_path + "\\" + "malware.xlsx")
            malware_list.append(df_malware["name"].values.tolist())
        except KeyError:
            malware_list.append("NIL")

        try:
            df_tools = pd.DataFrame(resp.json()["tools"])
            df_tools.to_excel(file_path + "\\" + "tools.xlsx")
            tools_list.append(df_tools["name"].values.tolist())
        except KeyError:
            tools_list.append("NIL")

        try:
            df_cve = pd.DataFrame(resp.json()["cve"])
            df_cve.to_excel(file_path + "\\" + "cve.xlsx")
            cve_list.append(df_cve["cve_id"].values.tolist())
        except KeyError:
            cve_list.append("NIL")

        try:
            df_source = pd.DataFrame(resp.json()["locations"]["source"])
            df_source.to_excel(file_path + "\\" + "source.xlsx")
            source_list.append((dict["locations"]["source"])[0]["country"]["name"])
        except KeyError:
            source_list.append("NIL")

        try:
            df_target = pd.DataFrame(resp.json()["locations"]["target"])
            df_target.to_excel(file_path + "\\" + "target.xlsx")
            target_list.append(df_target["name"].values.tolist())
        except KeyError:
            target_list.append("NIL")

        try:
            df_observed = pd.DataFrame(resp.json()["observed"])
            df_observed.to_excel(file_path + "\\" + "observed.xlsx")
            observed_list.append(df_observed.values.tolist())
        except KeyError:
            observed_list.append("NIL")

        try:
            df_suspected_attribution = pd.DataFrame(resp.json()["suspected_attribution"])
            df_suspected_attribution.to_excel(file_path + "\\" + "suspected.xlsx")
            suspected_attribution_list.append(df_suspected_attribution.values.tolist())
        except KeyError:
            suspected_attribution_list.append("NIL")

        try:
            df_audience = pd.DataFrame(resp.json()["audience"])
            df_audience.to_excel(file_path + "\\" + "audience.xlsx")
            audience_list.append(df_audience["name"].values.tolist())
        except KeyError:
            audience_list.append("NIL")

        # ------------------------------Create Overall Dataframe------------------------------#
        df_data = {
            'name': name_list,
            'id': id_list,
            'last_activity_time': last_activity_time_list,
            'last_updated': last_updated_list,
            'description': description_list,
            'aliases': aliases_list,
            'associated_uncs': associated_uncs_list,
            'industries': industries_list,
            'motivations': motivations_list,
            'malware': malware_list,
            'tools': tools_list,
            'cve': cve_list,
            'source': source_list,
            'target': target_list,
            'audience': audience_list,
            'is_publishable': is_publishable_list,
            'intel_free': intel_free_list,
            'observed': observed_list,
            'counts': counts_list,
            'suspected_attribution': suspected_attribution_list
        }

        df = pd.DataFrame(df_data)

        df.to_excel("C:\\Users\\Admin\\Downloads\\mandiant\\mandiant_threat_actor.xlsx")
