import streamlit as st
import pandas as pd
#import matplotlib.pyplot as plt
from datetime import date, timedelta

st.set_page_config(layout="wide")

my_titles = ["Home","Semgrep SAST","Semgrep SCA", "AWS Inspector","AWS Inventory"]

# Initialize session state for the active page
if "active_page" not in st.session_state:
    st.session_state.active_page = my_titles[0]

if "uploaded_files" not in st.session_state:
    st.session_state.uploaded_files = {}

# Find todays date and 30 days prior
today = date.today()
default_start = today - timedelta(days=30)

# Define a function for each section
def home():
    st.title(my_titles[0])
    st.write("Welcome to the Home Page! Use the buttons above to crunch a report on the type of data you're working with.")

def flatten_columns(json_data, parent_key="", sep="."):
    """
    Flattens columns in a JSON object, supporting nested dictionaries and lists.
    Args:
        json_data: The JSON object (dict or list) to flatten
        parent_key: The base key for nested elements (used internally)
        sep: Separator for nested keys in the flattened result
    Returns:
        A flattened dictionary
    """
    flattened = {}
    for k, v in json_data.items():
        new_key = f"{parent_key}{sep}{k}" if parent_key else k
        if isinstance(v, dict):
            # Recursively flatten the dictionary
            flattened.update(flatten_columns(v, new_key, sep=sep))
        elif isinstance(v, list):
            # Convert list to a dot-separated string if it contains non-dict values
            if all(isinstance(item, (str, int, float)) for item in v):
                flattened[new_key] = ".".join(map(str, v))
            else:
                # Handle lists with dictionaries or nested structures
                for i, item in enumerate(v):
                    flattened.update(flatten_columns(item, f"{new_key}[{i}]", sep=sep))
        else:
            # For scalar values, simply add to the flattened dictionary
            flattened[new_key] = v
    return flattened

def sast():
    st.title(my_titles[1])
    if st.session_state.active_page == my_titles[1]:
        sast_uploaded_file = st.file_uploader("Upload a SAST file for analysis:",type=["json"])
        if "sast" in st.session_state.uploaded_files:
            st.write(f"Utilizing previously uploaded file: {st.session_state.uploaded_files['sast'].name}")
            sast_file=st.session_state.uploaded_files['sast']
            sast_file.seek(0)
            df = pd.read_json(sast_file)
        if sast_uploaded_file:
            st.success(f"File uploaded: {sast_uploaded_file.name}")
            st.session_state.uploaded_files['sast']=sast_uploaded_file
            df = pd.read_json(sast_uploaded_file)
    try:
        #st.dataframe(df,hide_index=True)
        if not df.empty:   
            # Strip timezone
            df['created_at'] = pd.to_datetime(df['created_at'],format='%Y-%m-%d %H:%M:%S').dt.tz_convert(None)
            
            # Flatten the columns that contain JSON structures
            df=pd.json_normalize(df.apply(flatten_columns,axis=1))
            df['rule.vulnerability_classes']=df['rule.vulnerability_classes'].apply(lambda x: x[0] if isinstance(x,list) and len(x)==1 else x)
            df['rule.cwe_names']=df['rule.cwe_names'].apply(lambda x: x[0] if isinstance(x,list) and len(x)==1 else x)

            st.subheader("Choose a date range:")
            d1,d2 = st.columns(2)
            with d1:
                og_start_date = st.date_input("Start Date",default_start)
                start_date = pd.to_datetime(og_start_date)
            with d2: 
                og_end_date = st.date_input("End Date",today)
                end_date = pd.to_datetime(og_end_date)

            # Filter out based on date range entered
            df_filtered = df[(df['created_at'] >= start_date) & (df['created_at'] <= end_date)]
            if len(df_filtered)> 0:
                # Change display columns based on what you need. 
                display_columns = ["created_at","rule_name","severity","rule_message","repository.name","line_of_code_url","rule.category","rule.subcategories","rule.owasp_names","rule.cwe_names","rule.vulnerability_classes"]

                # Define all severity levels in case some are missing
                all_severity = ["high", "medium", "low"]

                # Create pivot table and reindex to include all severities
                df_pivot = (
                    pd.pivot_table(
                        df_filtered,
                        index="severity",
                        columns="status",
                        values="created_at",
                        aggfunc="count",
                        fill_value=0
                    )
                    .reindex(all_severity, fill_value=0)
                    .reset_index()
                )

                # Calculate fix rate and format
                df_pivot["Fix Rate"] = (
                    (df_pivot["fixed"] / (df_pivot["fixed"] + df_pivot["open"]))
                    .fillna(0)
                    .mul(100)
                    .round(2)
                    .astype(str) + "%"
                )
                        
                #Calculate CWE, Vuln Class
                df_cwe_pivot = (
                    pd.pivot_table(
                        df_filtered,
                        index='rule.cwe_names',
                        aggfunc='size',
                        fill_value=0
                        )
                )
                
                df_cwe_pivot = df_cwe_pivot.rename("Count").reset_index().sort_values(by="Count",ascending=False)
                df_cwe_pivot.columns = ['CWE Names','Count']


                #Calculate CWE, Vuln Class
                df_vclass_pivot = (
                    pd.pivot_table(
                        df_filtered,
                        index='rule.vulnerability_classes',
                        aggfunc='size',
                        fill_value=0
                        )
                )
                df_vclass_pivot = df_vclass_pivot.rename("Count").reset_index().sort_values(by="Count",ascending=False)
                df_vclass_pivot.columns = ['Vuln Class','Count']

                st.subheader(f"Severity / Fix Rate Breakdown")
                
                pv1, pv2 = st.columns(2)
                with pv1: 
                    # Display pivot table with fix rate
                    st.dataframe(df_pivot,hide_index=True)
                with pv2:
                    chart_data= df_pivot.set_index("severity")[["open","fixed"]]
                    colors = ["#1f77b4", "#ff7f0e"]
                    st.bar_chart(chart_data,color=colors)

                st.subheader(f"Findings by CWE")
                cwe1, cwe2 = st.columns(2)
                with cwe1:
                    st.dataframe(df_cwe_pivot,hide_index=True)
                with cwe2:
                    chart_data = df_cwe_pivot.set_index('CWE Names')['Count']
                    st.bar_chart(chart_data,horizontal=True)

                st.subheader(f"Findings by Vulnerability Class")
                vuln1,vuln2 = st.columns(2)
                with vuln1:
                    st.dataframe(df_vclass_pivot,hide_index=True)
                with vuln2: 
                    chart_data = df_vclass_pivot.set_index('Vuln Class')['Count']
                    st.bar_chart(chart_data,horizontal=True)

                st.subheader("Filtered Data")
                st.dataframe(df_filtered[display_columns],hide_index=True)
            else:
                st.write("No data found, please adjust your data range.")
    except NameError:
        st.write("Waiting for file.")

def sca():
    st.title(my_titles[2])
    if st.session_state.active_page == my_titles[2]:
        sca_uploaded_file = st.file_uploader("Upload a SCA file for analysis:",type=["json"])
        if "sca" in st.session_state.uploaded_files :
            st.write(f"Utilizing previously uploaded file: {st.session_state.uploaded_files['sca'].name}")
            sca_file=st.session_state.uploaded_files['sca']
            sca_file.seek(0)
            df = pd.read_json(sca_file)
        if sca_uploaded_file:
            st.success(f"File uploaded: {sca_uploaded_file.name}")
            st.session_state.uploaded_files['sca']=sca_uploaded_file
            df = pd.read_json(sca_uploaded_file)
    
    try:
        #st.dataframe(df,hide_index=True)
        if not df.empty:   
            # Strip timezone
            df['created_at'] = pd.to_datetime(df['created_at'],format='%Y-%m-%d %H:%M:%S').dt.tz_convert(None)
            
            
            # Flatten the columns that contain JSON structures
            df=pd.json_normalize(df.apply(flatten_columns,axis=1))
            
            df['rule.vulnerability_classes']=df['rule.vulnerability_classes'].apply(lambda x: x[0] if isinstance(x,list) and len(x)==1 else x)
            df['rule.cwe_names']=df['rule.cwe_names'].apply(lambda x: x[0] if isinstance(x,list) and len(x)==1 else x)
            
            st.subheader("Choose a date range:")
            d1,d2 = st.columns(2)
            with d1:
                og_start_date = st.date_input("Start Date",default_start)
                start_date = pd.to_datetime(og_start_date)
            with d2: 
                og_end_date = st.date_input("End Date",today)
                end_date = pd.to_datetime(og_end_date)

            # Filter out based on date range entered
            df_filtered = df[(df['created_at'] >= start_date) & (df['created_at'] <= end_date)]
           
            if len(df_filtered)> 0:
                # Change display columns based on what you need. 
                display_columns = ["created_at","severity","rule_message","repository.name","found_dependency.ecosystem","found_dependency.package","line_of_code_url","rule.category","vulnerability_identifier","rule.owasp_names","rule.cwe_names","rule.vulnerability_classes"]

                # Define all severity levels in case some are missing
                all_severity = ["high", "medium", "low"]
                all_status=["fixed","open","reviewing"]
                
                # Create pivot table and reindex to include all severities
                df_pivot = (
                    pd.pivot_table(
                        df_filtered,
                        index="severity",
                        columns="status",
                        values="created_at",
                        aggfunc="count",
                        fill_value=0
                    )
                    .reindex(all_severity, fill_value=0)
                    .reindex(columns=all_status,fill_value=0)
                    .reset_index()
                )

                # Calculate fix rate and format
                df_pivot["Fix Rate"] = (
                    (df_pivot["fixed"] / (df_pivot["fixed"] + df_pivot["open"]+df_pivot['reviewing']))
                    .fillna(0)
                    .mul(100)
                    .round(2)
                    .astype(str) + "%"
                )
                

                #Calculate CVE Pivot
                df_cve_pivot = (
                    pd.pivot_table(
                        df_filtered,
                        index='vulnerability_identifier',
                        aggfunc='size',
                        fill_value=0
                        )
                )
                
                df_cve_pivot = df_cve_pivot.rename("Count").reset_index().sort_values(by="Count",ascending=False)
                df_cve_pivot.columns = ['CVE','Count']
                #Calculate CWE, Vuln Class
                df_cwe_pivot = (
                    pd.pivot_table(
                        df_filtered,
                        index='rule.cwe_names',
                        aggfunc='size',
                        fill_value=0
                        )
                )
                
                df_cwe_pivot = df_cwe_pivot.rename("Count").reset_index().sort_values(by="Count",ascending=False)
                df_cwe_pivot.columns = ['CWE Names','Count']


                #Calculate Vuln Class
                df_vclass_pivot = (
                    pd.pivot_table(
                        df_filtered,
                        index='rule.vulnerability_classes',
                        aggfunc='size',
                        fill_value=0
                        )
                )
                df_vclass_pivot = df_vclass_pivot.rename("Count").reset_index().sort_values(by="Count",ascending=False)
                df_vclass_pivot.columns = ['Vuln Class','Count']

                st.subheader(f"Severity / Fix Rate Breakdown")
                
                pv1, pv2 = st.columns(2)
                with pv1: 
                    # Display pivot table with fix rate
                    st.dataframe(df_pivot,hide_index=True)
                with pv2:
                    chart_data= df_pivot.set_index("severity")[["open","fixed"]]
                    colors = ["#1f77b4", "#ff7f0e"]
                    st.bar_chart(chart_data,color=colors)

                st.subheader(f"Findings by CVE")
                cve1, cve2 = st.columns(2)
                with cve1:
                    st.dataframe(df_cve_pivot,hide_index=True)
                with cve2:
                    chart_data = df_cve_pivot.set_index('CVE')['Count']
                    st.bar_chart(chart_data,horizontal=True)
                st.subheader(f"Findings by CWE")
                cwe1, cwe2 = st.columns(2)
                with cwe1:
                    st.dataframe(df_cwe_pivot,hide_index=True)
                with cwe2:
                    chart_data = df_cwe_pivot.set_index('CWE Names')['Count']
                    st.bar_chart(chart_data,horizontal=True)

                st.subheader(f"Findings by Vulnerability Class")
                vuln1,vuln2 = st.columns(2)
                with vuln1:
                    st.dataframe(df_vclass_pivot,hide_index=True)
                with vuln2: 
                    chart_data = df_vclass_pivot.set_index('Vuln Class')['Count']
                    st.bar_chart(chart_data,horizontal=True)

                st.subheader("Filtered Data")
                st.dataframe(df_filtered[display_columns],hide_index=True)
            else:
                st.write("No data found, please adjust your data range.")
    except NameError:
        st.write("Waiting for file.")

def inspector():
    st.title(my_titles[3])
    if st.session_state.active_page == my_titles[3]:
        inspector_uploaded_file = st.file_uploader("Upload an Inspector file for analysis:",type=["json"])
        if "ins" in st.session_state.uploaded_files:
            st.write("Previously uploaded file:")
            st.write(st.session_state.uploaded_files['ins'].name)
            inspector_file=st.session_state.uploaded_files['ins']
            inspector_file.seek(0)
            df = pd.read_json(inspector_file)
        if inspector_uploaded_file:
            st.success(f"File uploaded: {inspector_uploaded_file.name}")
            st.session_state.uploaded_files['ins']=inspector_uploaded_file
            df = pd.read_json(inspector_uploaded_file)
            st.write(df)
    try:
        df
    
    except NameError:
        st.write("Waiting for data file.")
def inventory():
    st.title(my_titles[4])
    if st.session_state.active_page == my_titles[4]:
        inventory_uploaded_file = st.file_uploader("Upload an AWS Inventory file for analysis:",type=["csv"])
        if "inv" in st.session_state.uploaded_files:
            st.write(f"Utilizing previously uploaded file: {st.session_state.uploaded_files['inv'].name}")
            inv_file=st.session_state.uploaded_files['inv']
            inv_file.seek(0)
            df = pd.read_csv(inv_file)
        if inventory_uploaded_file:
            st.success(f"File uploaded: {inventory_uploaded_file.name}")
            st.session_state.uploaded_files['inv']=inventory_uploaded_file
            df = pd.read_csv(inventory_uploaded_file)
    try:
        #st.dataframe(df,hide_index=True)
        if not df.empty:
            type_pivot = pd.pivot_table(
                df,
                index="Resource type",
                aggfunc="size",
                fill_value=0
            )
            type_pivot=type_pivot.rename("Count").reset_index().sort_values(by="Count",ascending=False)
            type_pivot.columns = ["Resource Type","Count"]

            region_pivot = pd.pivot_table(
                df,
                index="Region",
                aggfunc="size",
                fill_value=0
            )
            region_pivot=region_pivot.rename("Count").reset_index().sort_values(by="Count",ascending=False)
            region_pivot.columns = ["Region","Count"]
            

            st.subheader("Pivot by Resource Type")
            type1,type2 = st.columns(2)
            with type1: 
                st.dataframe(type_pivot,hide_index=True)
            with type2:
                chart_data = type_pivot.set_index('Resource Type')['Count']
                st.bar_chart(chart_data,horizontal=True)
            
            st.subheader("Pivot by Region")
            region1,region2 = st.columns(2)
            with region1: 
                st.dataframe(region_pivot,hide_index=True)
            with region2:
                chart_data = region_pivot.set_index('Region')['Count']
                st.bar_chart(chart_data,horizontal=True)

            st.subheader("Filtered Data")
            df["AWS Account"]=df["AWS Account"].astype(str)
            st.dataframe(df,hide_index=True)
    
    except NameError:
        st.write("Waiting for data file.")

# Navigation handler to update session state
def set_active_page(page_name):
    st.session_state.active_page = page_name

# Create the top navigation bar using buttons
st.markdown(
    """
    <style>
    .button-container {
        display: flex;
        justify-content: space-around;
        margin-bottom: 20px;
    }
    .stButton button {
        width: 125px;
        height: 50px;
        font-size: 16px;
    }
    </style>
    """,
    unsafe_allow_html=True,
)

st.markdown('<div class="button-container">', unsafe_allow_html=True)

col1, col2, col3, col4, col5 = st.columns(5)

with col1:
    if st.button(my_titles[0]):
        set_active_page(my_titles[0])
with col2:
    if st.button(my_titles[1]):
        set_active_page(my_titles[1])
with col3:
    if st.button(my_titles[2]):
        set_active_page(my_titles[2])
with col4:
    if st.button(my_titles[3]):
        set_active_page(my_titles[3])
with col5:
    if st.button(my_titles[4]):
        set_active_page(my_titles[4])

st.markdown('</div>', unsafe_allow_html=True)

# Page routing based on session state
if st.session_state.active_page == my_titles[0]:
    home()
elif st.session_state.active_page == my_titles[1]:
    sast()
elif st.session_state.active_page == my_titles[2]:
    sca()
elif st.session_state.active_page == my_titles[3]:
    inspector()
elif st.session_state.active_page == my_titles[4]:
    inventory()
