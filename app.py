from flask import Flask, render_template, request, url_for
import psycopg2
from dotenv import load_dotenv # Remove this line if needed, this is for practice hide database passwords
import os # Remove this line if needed as well, this is just for the passwords
from scrapers import get_gas_prices

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
def login():
    return render_template('login.html')

    

@app.route('/admin')
def admin():
    return render_template('admin.html')


@app.route('/index', methods=['GET', 'POST'])
def index():

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
    return render_template('index.html')

@app.route('/resources')
def resources():
    return render_template('resources.html')

@app.route('/submit_resources', methods=['POST'])
def submit_resources():
    flat_cost = 0
    man_hour_cost = 0
    gas_price, diesel_price = get_gas_prices()
    prices = {
        'sandbags': 2.5,
        'helicopters': 3000,
        'gasoline': gas_price,
        'diesel': diesel_price,
    }
    for item, price in prices.items():
        quantity = request.form.get(item)
        if quantity and quantity.isdigit():
            flat_cost += int(quantity) * price
    responders = {
        'medical_responders': 50,
        'police_responders': 45,
        'fire_responders': 55
    }
    for role, hourly_rate in responders.items():
        num = request.form.get(role)
        if num and num.isdigit():
            man_hour_cost += int(num) * hourly_rate
    message = f"Your estimated request costs ${flat_cost:.2f} flat, ${man_hour_cost:.2f} per first responder man-hour. Additionally, helicopters cost $600 per hour of flight. Custom resources are not included in this estimate."
    return render_template('summary.html', message=message)

if __name__ == '__main__':
   app.run(debug = True)
