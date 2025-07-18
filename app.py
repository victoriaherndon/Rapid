from flask import Flask, render_template, request, url_for, session, redirect
import psycopg2
from dotenv import load_dotenv # Remove this line if needed, this is for practice hide database passwords
import os # Remove this line if needed as well, this is just for the passwords

app = Flask(__name__)

load_dotenv() # Remove this line if needed

psql_password = os.getenv("PSQL_PASSWORD") # Remove this line if need

conn = psycopg2.connect(database="rapid_db", user="postgres",
password=psql_password, host="localhost")  # Replace psql_password with the password for your psql user
cur = conn.cursor()

cur.execute(
    '''CREATE TABLE IF NOT EXISTS incidents( \
        county VARCHAR(30), address VARCHAR(120),\
        occurrence VARCHAR(10), description TEXT);'''
)

conn.commit()
cur.close()
conn.close()


@app.route('/')
def index():
    return render_template('index.html')
    

@app.route('/admin')
def admin():
    return render_template('admin.html')


@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():

    county = None
    address = None
    occurrence = None
    description = None

    if request.method == 'POST':
        county = request.form.get('county')
        address = request.form['address']
        occurrence = request.form['occurrence']
        description = request.form['description']

    conn = psycopg2.connect(database="rapid_db", user="postgres",
    password=psql_password, host="localhost")  # Replace psql_password with the password for your psql user

    cur = conn.cursor()

    cur.execute(
        '''INSERT INTO incidents (county, address, occurrence, description)
           VALUES (%s, %s, %s, %s);''',
        (county, address, occurrence, description)
    )

    conn.commit()
    cur.close()
    conn.close()
    return render_template('dashboard.html')

@app.route('/resources')
def resources():
    return render_template('resources.html')

@app.route('/create_account', methods=['GET', 'POST'])
def create_account():
    if request.method == 'POST':
        pass  
    return render_template('create_account.html')

@app.route('/admin/city_reports')
def city_reports():
        return render_template('admin/city_reports.html')

@app.route('/submitted_reports')
def submitted_reports():
    return render_template('submitted_reports.html')

@app.route('/demographics')
def demographics():
    return render_template('demographics.html')

@app.route('/admin/county_reports')
def county_reports():
        return render_template('admin/county_reports.html')

@app.route("/admin/anticipated_costs")
def anticipated_costs():
    return render_template("admin/anticipated_costs.html")

@app.route("/admin/mock-approval")
def mock_approval():
    return render_template("admin/mock_approval.html")


if __name__ == '__main__':
   app.run(debug = True)
