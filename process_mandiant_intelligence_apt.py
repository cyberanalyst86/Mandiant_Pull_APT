import pandas as pd

input_filepath = "C:\\Users\\Admin\\Downloads\\mandiant\\mandiant_aerospace_transport_apt.xlsx"

output_filepath_tools = "C:\\Users\\Admin\\Downloads\\mandiant\\tools.xlsx"
output_filepath_malware = "C:\\Users\\Admin\\Downloads\\mandiant\\malware.xlsx"
output_filepath_cve = "C:\\Users\\Admin\\Downloads\\mandiant\\cve.xlsx"
output_filepath_target = "C:\\Users\\Admin\\Downloads\\mandiant\\target.xlsx"

df = pd.read_excel(input_filepath)
print(df.columns)

tool_list = []
malware_list = []
cve_list = []
target_list = []


df_tool = pd.DataFrame()
df_malware = pd.DataFrame()
df_cve = pd.DataFrame()
df_target = pd.DataFrame()

#-------------------------------tools------------------------------#

for index, row in df.iterrows():

    if row["tools"] != "NIL":

        row = list(row["tools"].replace("[\"","").replace("['","").replace("']","").replace("'","").split(", "))

        for tool in row:

            tool_list.append(tool)

df_tool["tools"] = tool_list
df_tool.to_excel(output_filepath_tools, index=False)

#-------------------------------malware------------------------------#

for index, row in df.iterrows():

    if row["malware"] != "NIL":

        row = list(row["malware"].replace("[\"","").replace("['","").replace("']","").replace("'","").split(", "))

        for malware in row:

            malware_list.append(malware)

df_malware["malware"] = malware_list
df_malware.to_excel(output_filepath_malware, index=False)
#-------------------------------cve------------------------------#

for index, row in df.iterrows():

    if row["cve"] != "NIL":

        row = list(row["cve"].replace("[\"","").replace("['","").replace("']","").replace("'","").split(", "))

        print(row)

        for cve in row:

            cve_list.append(cve)

df_cve["cve"] = cve_list
df_cve.to_excel(output_filepath_cve, index=False)


#-------------------------------target------------------------------#

for index, row in df.iterrows():

    if row["target"] != "NIL":

        row = list(row["target"].replace("[\"","").replace("['","").replace("']","").replace("'","").split(", "))

        for target in row:

            target_list.append(target)

df_target["target"] = target_list
df_target.to_excel(output_filepath_target, index=False)
