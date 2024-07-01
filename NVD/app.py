from flask import Flask, render_template, request
import mysql.connector
from flask import jsonify
from dotenv import load_dotenv
import os

load_dotenv()

db_host = os.getenv('DB_HOST')
db_user = os.getenv('DB_USER')
db_password = os.getenv('DB_PASSWORD')
db_database = os.getenv('DB_DATABASE')

app = Flask(__name__)
db=mysql.connector.connect(host=db_host,user=db_user,password=db_password,database=db_database)

def display_cves(page=1, sort_by='id', per_page=10):
    cursor = db.cursor(dictionary=True)
    cursor.execute(f"SELECT * FROM vuln_details ORDER BY {sort_by}")
    cves = cursor.fetchall()
    cursor.close()

    total_count = len(cves)
    total_pages = (total_count + per_page - 1) // per_page

    page = max(1, min(page, total_pages))

    start_record = (page - 1) * per_page + 1
    end_record = min(start_record + per_page - 1, total_count)

    max_display_pages = 5
    half_max_display_pages = max_display_pages // 2
    start_page = max(1, page - half_max_display_pages)
    end_page = min(total_pages, start_page + max_display_pages - 1)
    if end_page - start_page + 1 < max_display_pages:
        start_page = max(1, end_page - max_display_pages + 1)

    start_index = (page - 1) * per_page
    end_index = min(start_index + per_page, total_count)
    cves_on_page = cves[start_index:end_index]

    return render_template('index.html', cves=cves_on_page, page=page, total_pages=total_pages, total_count=total_count, start_record=start_record, end_record=end_record, start_page=start_page, end_page=end_page, per_page=per_page)

@app.route('/cves/list')
def index():
    page = request.args.get('page', 1, type=int)
    sort_by = request.args.get('sort', 'id')
    per_page = request.args.get('per_page', 10, type=int)  # Retrieve per_page from request parameters
    return display_cves(page, sort_by, per_page)

@app.route('/cves/<cve_id>')
def cve_details(cve_id):
    cursor = db.cursor(dictionary=True)
    cursor.execute("SELECT * FROM vuln_details WHERE id = %s", (cve_id,))
    cve_data = cursor.fetchone()
    cursor.close()
    return render_template('details.html', cve_data=cve_data)

@app.route('/filter_cves', methods=['GET'])
def filter_cves():
    cve_id = request.args.get('cve_id')
    specific_year = request.args.get('specific_year')
    min_score = request.args.get('min_score')
    max_score = request.args.get('max_score')
    last_modified_days = request.args.get('last_modified_days')

    # Construct the SQL query based on the provided parameters
    sql_query = "SELECT * FROM vuln_details WHERE 1=1"
    params = []

    if cve_id:
        sql_query += " AND id = %s"
        params.append(cve_id)

    if specific_year:
        sql_query += " AND YEAR(published) = %s"
        params.append(specific_year)

    if min_score:
        sql_query += " AND base_score >= %s"
        params.append(min_score)

    if max_score:
        sql_query += " AND base_score <= %s"
        params.append(max_score)

    if last_modified_days:
        sql_query += " AND DATEDIFF(NOW(), last_modified) <= %s"
        params.append(last_modified_days)

    # Execute the query
    cursor = db.cursor(dictionary=True)
    cursor.execute(sql_query, tuple(params))
    cves = cursor.fetchall()
    cursor.close()

    return jsonify(cves)

if __name__ == '__main__':
    app.run(debug=True)

