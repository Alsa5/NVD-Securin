import requests
import mysql.connector
import re
from dotenv import load_dotenv
import os

load_dotenv()

# Get credentials from environment variables
db_host = os.getenv('DB_HOST')
db_user = os.getenv('DB_USER')
db_password = os.getenv('DB_PASSWORD')
db_database = os.getenv('DB_DATABASE')


def fetch():
    api_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    response = requests.get(api_url)
    if response.status_code == 200:
        return response.json()["vulnerabilities"]
    else:
        print("Failed to retrieve data from the API")
        return None

def clean_html_tags(text):
    # Remove HTML tags using regex
    clean_text = re.sub(r'<[^>]*>', '', text)
    return clean_text

def deduplicate(data):
    # Function to remove duplicates based on the 'id' field
    unique_data = {d['cve']['id']: d for d in data}.values()
    return list(unique_data)

def dbconnection():
    try:
        con = mysql.connector.connect(host=db_host,user=db_user,password=db_password,database=db_database)
        cur = con.cursor()
        cur.execute('create table if not exists vuln_details (id varchar(255) primary key,published varchar(255),last_modified varchar(255),description text,cvss_vector_string varchar(255),base_score float,url text,source_identifier varchar(255), status varchar(255), severity varchar(255), score_vector_string varchar(255), access_vector varchar(255), access_complexity varchar(255), authentication varchar(255), confidentiality_impact varchar(255), integrity_impact varchar(255), availability_impact varchar(255), exploitability_score float, impact_score float, criteria varchar(255), match_criteria_id varchar(255), vulnerable varchar(150))')
        con.commit()
        print("Database connection established and table created successfully.")
        return con, cur
    except mysql.connector.Error as error:
        print("Error while connecting to the database:", error)
        return None, None

def insert(con, cur, vul):
    for cve in vul:
        cve_id = cve["cve"]["id"]
        published = cve["cve"]["published"]
        last_modified = cve["cve"]["lastModified"]
        description = cve["cve"]["descriptions"][0]["value"]
        description = clean_html_tags(description)  #RemovingHTMLtags
        cvss_v2_metrics = cve["cve"].get("metrics", {}).get("cvssMetricV2", [])
        if cvss_v2_metrics:
            cvss_vector_string = cvss_v2_metrics[0]["cvssData"]["vectorString"]
            base_score = cvss_v2_metrics[0]["cvssData"]["baseScore"]
        else:
            cvss_vector_string = None
            base_score = None
        severity = cvss_v2_metrics[0]["baseSeverity"] if cvss_v2_metrics else None
        access_vector = cvss_v2_metrics[0]["cvssData"]["accessVector"] if cvss_v2_metrics else None
        access_complexity = cvss_v2_metrics[0]["cvssData"]["accessComplexity"] if cvss_v2_metrics else None
        authentication = cvss_v2_metrics[0]["cvssData"]["authentication"] if cvss_v2_metrics else None
        confidentiality_impact = cvss_v2_metrics[0]["cvssData"]["confidentialityImpact"] if cvss_v2_metrics else None
        integrity_impact = cvss_v2_metrics[0]["cvssData"]["integrityImpact"] if cvss_v2_metrics else None
        availability_impact = cvss_v2_metrics[0]["cvssData"]["availabilityImpact"] if cvss_v2_metrics else None
        exploitability_score = cvss_v2_metrics[0]["exploitabilityScore"] if cvss_v2_metrics else None
        impact_score = cvss_v2_metrics[0]["impactScore"] if cvss_v2_metrics else None

        configurations = cve["cve"].get("configurations", [])
        if configurations:
            configuration = configurations[0]["nodes"][0]["cpeMatch"][0]
            criteria = configuration.get("criteria")
            match_criteria_id = configuration.get("matchCriteriaId")
            vulnerable = configuration.get("vulnerable")
        else:
            criteria = None
            match_criteria_id = None
            vulnerable = None

        references = cve["cve"].get("references", [])
        if references:
            url = references[0].get("url")
        else:
            url = None

        try:
            vulnerable_text = "YES" if vulnerable else "NO"
            cur.execute("insert into vuln_details values (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)", 
                        (cve_id, published, last_modified, description, cvss_vector_string, base_score, url, 
                         cve["cve"]["sourceIdentifier"], cve["cve"]["vulnStatus"], severity, cvss_vector_string, 
                         access_vector, access_complexity, authentication, confidentiality_impact, integrity_impact, 
                         availability_impact, exploitability_score, impact_score, criteria, match_criteria_id, vulnerable_text))
        except mysql.connector.Error as error:
            print("Error while inserting data:", error)
    con.commit()
    print("Data inserted into the database successfully.")


def main():
    vul = fetch()
    if vul:
        # De-duplication
        vul = deduplicate(vul)
        con, cur = dbconnection()
        if con and cur:
            insert(con, cur, vul)
            cur.close()
            con.close()
        else:
            print("Failed to establish database connection.")
    else:
        print("Failed to fetch data from the API.")
if __name__ == "__main__":
    main()