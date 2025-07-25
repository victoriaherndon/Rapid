from flask import Flask, render_template, request, url_for, session, redirect, flash
import psycopg2
from dotenv import load_dotenv # Remove this line if needed, this is for practice hide database passwords
import os # Remove this line if needed as well, this is just for the passwords
from scrapers import get_gas_prices
from functools import wraps

app = Flask(__name__)

load_dotenv() # Remove this line if needed

app.secret_key = os.getenv("FLASK_SECRET_KEY", "default_secret_key")
psql_password = os.getenv("PSQL_PASSWORD") # Remove this line if need

conn = psycopg2.connect(database="rapid_db", user="postgres",
password=psql_password, host="localhost", port="5432")  # Replace psql_password with the password for your psql user

cur = conn.cursor()

cur.execute("""
    CREATE TABLE IF NOT EXISTS incidents (
        incident_id SERIAL PRIMARY KEY,
        userid INT NOT NULL REFERENCES users(userid),
        county VARCHAR(30) NOT NULL,
        address VARCHAR(120) NOT NULL,
        occurrence VARCHAR(10) NOT NULL,
        description TEXT NOT NULL,
        date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        status VARCHAR(20) DEFAULT 'Under Review'
    );
""")
# ensure userid column exists in incidents
cur.execute("""
    DO $$
    BEGIN
        IF NOT EXISTS (
            SELECT 1
            FROM information_schema.columns
            WHERE table_name = 'incidents'
              AND column_name = 'userid'
        ) THEN
            ALTER TABLE incidents ADD COLUMN userid INT REFERENCES users(userid);
        END IF;
    END
    $$;
""")

# add date column if it doesn't already exist in incidents
cur.execute("""
    DO $$
    BEGIN
        IF NOT EXISTS (
            SELECT 1
            FROM information_schema.columns
            WHERE table_name='incidents' AND column_name='date'
        ) THEN
            ALTER TABLE incidents ADD COLUMN date TIMESTAMP DEFAULT CURRENT_TIMESTAMP;
        END IF;
    END
    $$;
""")

# status column for incidents table
cur.execute("""
    DO $$
    BEGIN
        IF NOT EXISTS (
            SELECT 1
            FROM information_schema.columns
            WHERE table_name='incidents' AND column_name='status'
        ) THEN
            ALTER TABLE incidents ADD COLUMN status VARCHAR(20) DEFAULT 'Under Review';
        END IF;
    END
    $$;
""")

# create users table if it doesnt already exist
# for storing account credentials and role info
cur.execute("""
CREATE TABLE IF NOT EXISTS users(
    userid SERIAL PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    email VARCHAR(100) UNIQUE NOT NULL,
    password VARCHAR(300) NOT NULL,
    role VARCHAR(20) DEFAULT 'user'
);
""")

conn.commit()
cur.close()
conn.close()

# added decorator for updating routes w/ admin access 
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            return redirect(url_for('index'))
        if session.get('role') != 'admin':
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

# added decorator for updating header routes w/ admin access
@app.context_processor
def inject_user():
    return dict(username=session.get('username'))


@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
    if session.get('role') == 'admin':
        return redirect(url_for('all_submitted_reports'))
    
    userid = session.get('user_id')

    if request.method == 'POST':
        county = request.form.get('county')
        address = request.form['address']
        occurrence = request.form['occurrence']
        description = request.form['description']
        

        conn = psycopg2.connect(database="rapid_db", user="postgres",
                                password=psql_password, host="localhost")
        cur = conn.cursor()
        cur.execute('''
            INSERT INTO incidents (userid, county, address, occurrence, description)
            VALUES (%s, %s, %s, %s, %s);
        ''', (userid, county, address, occurrence, description))  

        conn.commit()
        cur.close()
        conn.close()

    conn = psycopg2.connect(database="rapid_db", user="postgres",
                            password=psql_password, host="localhost")
    cur = conn.cursor()
    cur.execute("SELECT * FROM incidents WHERE userid = %s ORDER BY date DESC;", (userid,))
    incidents = cur.fetchall()
    cur.close()
    conn.close()

    return render_template('dashboard.html', username=session.get('username'), incidents=incidents)

@app.route('/resources')
def resources():
    if session.get('role') == 'admin':
        return redirect(url_for('all_submitted_reports'))
    return render_template('resources.html')

@app.route('/submit_resources', methods=['POST'])
def submit_resources():
    # get the amount of each resource to insert in the db later and to do math
    county = request.form.get('county')
    # address is currently useless, should discuss whether we want this added to the db or just removed from here
    address = request.form.get('address')
    incident_id = request.form.get('IncidentID')
    sandbags = request.form.get('sandbags') or '0'
    helicopters = request.form.get('helicopters') or '0'
    gasoline = request.form.get('gasoline') or '0'
    diesel = request.form.get('diesel') or '0'
    medical_responders = request.form.get('medical_responders') or '0'
    police_responders = request.form.get('police_responders') or '0'
    fire_responders = request.form.get('fire_responders') or '0'
    # store the chunks of comments as a list of strings + store resource_comments as a dictionary for easier management and lookup of strings later
    # all of the chunks will be appended to list_of_comments and then that will be checked and submitted to the db
    comments_chunks = []
    list_of_comments = []
    resource_comments = {
        'sandbags': request.form.get('sandbags_comment', '').strip(),
        'helicopters': request.form.get('helicopters_comment', '').strip(),
        'gasoline': request.form.get('gasoline_comment', '').strip(),
        'diesel': request.form.get('diesel_comment', '').strip(),
        'medical responders': request.form.get('medical_responders_comment', '').strip(),
        'police responders': request.form.get('police_responders_comment', '').strip(),
        'fire responders': request.form.get('fire_responders_comment', '').strip()
    }
    for resource, comment in resource_comments.items():
        if comment:
            list_of_comments.append(f"{resource}: {comment}")
    # will format comments as
    # COMMENTS:
    # sandbags: (comment); helicopters: (comment); etc. if they exist
    if list_of_comments:
        comments_line = "COMMENTS: " + "; ".join(list_of_comments)
        comments_chunks.append(comments_line)
    custom_resource_names = request.form.getlist('resource_name[]')
    custom_resource_number = request.form.getlist('resource_quantity[]')
    custom_resource_specs = request.form.getlist('resource_specs[]')
    custom_resources = []
    for i in range(len(custom_resource_names)):
        # THIS DOES NOT FUNCTION AS INTENDED!
        # TODO: implement a better method that can deal with misaligned input numbers
        # if custom resource[0] has no specs but custom resource[1] does, custom resource[0]
        # will be assigned custom resource[1]'s specs
        name = custom_resource_names[i].strip() if i < len(custom_resource_names) else ''
        if name:
            quantity = custom_resource_number[i].strip() if i < len(custom_resource_number) else '0'
            specs = custom_resource_specs[i].strip() if i < len(custom_resource_specs) else ''
            # must be kept as a '0', flask sends info as strings, not ints
            if quantity != '0':
                custom_resource_line = f"{name}: {quantity}"
            else:
                custom_resource_line = f"{name}: Not specified"
            if specs:
                custom_resource_line += f" (specs: {specs})"
            custom_resources.append(custom_resource_line)
    if custom_resources:
        if comments_chunks:
            comments_chunks.append("")
        custom_resource_line = "CUSTOM RESOURCES: " + "; ".join(custom_resources)
        comments_chunks.append(custom_resource_line)
    comments_string = "\n".join(comments_chunks) if comments_chunks else ""
    # below is the old logic for the submission form, the only difference is that they now get inserted into the table
    flat_cost = 0
    man_hour_cost = 0
    gas_price, diesel_price = get_gas_prices()
    prices = {
        'sandbags': 2.5,
        'helicopters': 3000,
        'gasoline': gas_price,
        'diesel': diesel_price,
    }
    flat_cost += sandbags * prices['sandbags']
    flat_cost += helicopters * prices['helicopters']
    flat_cost += gasoline * prices['gasoline']
    flat_cost += diesel * prices['diesel']
    responders = {
        'medical_responders': 50,
        'police_responders': 45,
        'fire_responders': 55
    }
    man_hour_cost += medical_responders * responders['medical_responders']
    man_hour_cost += police_responders * responders['police_responders']
    man_hour_cost += fire_responders * responders['fire_responders']
    estimated_cost = flat_cost + man_hour_cost * 20
    conn = psycopg2.connect(database="rapid_db", user="postgres",
                            password=psql_password, host="localhost", port="5432")
    cur = conn.cursor()
    cur.execute('''
        INSERT INTO resource_req (
            IncidentID, County, Helicopter, Gasoline, Diesel, Sandbags,
            Medical_Responders, Police_Responders, Fire_Responders, 
            Funds_Approved, Comments, Estimated_Cost
        ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
    ''', (
        incident_id, county, helicopters, gasoline, diesel, sandbags,
        medical_responders, police_responders, fire_responders, 
        0, comments_string, estimated_cost
    ))
    conn.commit()
    cur.close()
    conn.close()
    message = f"Your estimated request costs ${flat_cost:.2f} flat, ${man_hour_cost:.2f} per first responder man-hour. Additionally, helicopters cost $600 per hour of flight. Custom resources are not included in this estimate."
    return render_template('summary.html', message=message)

@app.route('/submitted_reports')
def submitted_reports():
    user_id = session.get('user_id')
    conn = psycopg2.connect(database="rapid_db", user="postgres",
                            password=psql_password, host="localhost")
    cur = conn.cursor()
    cur.execute("SELECT * FROM incidents WHERE userid = %s ORDER BY date DESC;", (user_id,))
    incidents = cur.fetchall()
    cur.close()
    conn.close()

    return render_template('submitted_reports.html', incidents=incidents)


@app.route('/admin/demographics')
def demographics():
    return render_template('admin/demographics.html')


@app.route('/admin/city_reports')
@admin_required
def city_reports():
    return render_template('admin/city_reports.html')


@app.route('/admin/county_reports')
@admin_required
def county_reports():
    return render_template('admin/county_reports.html')


@app.route("/admin/anticipated_costs")
@admin_required
def anticipated_costs():
    return render_template("admin/anticipated_costs.html")


@app.route("/admin/mock-approval")
@admin_required
# this should connect to the database, list out all resource requests, and then subtract the estimated cost from the db
# if approved
# TODO: implement warning system/flash message if request would go negative
def mock_approval():
    conn = psycopg2.connect(database="rapid_db", user="postgres", password=psql_password, host="localhost", port="5432")
    cur = conn.cursor()
    if request.method == 'POST':
        request_id = request.form.get('request_id')
        status = request.form.get('status')
        is_rejected = (status == 'denied')
        cur.execute("""
            UPDATE resource_req
            SET Is_Rejected = %s
            WHERE ReportID = %s
        """, (is_rejected, request_id))
        if status == 'approved':
            cur.execute("""
                SELECT Estimated_Cost, County
                FROM resource_req
                WHERE ReportID = %s
            """, (request_id,))
            result = cur.fetchone()
            if result:
                estimated_cost, county = result
                cur.execute("""
                    UPDATE county
                    SET Budget = Budget - %s
                    WHERE Name = %s
                """, (estimated_cost, county))
        conn.commit()
    cur.execute("""
        SELECT ReportID, County, Estimated_Cost, Is_Rejected
        FROM resource_req
        ORDER BY ReportID DESC
    """)
    requests = cur.fetchall()
    cur.close()
    conn.close()
    return render_template('admin/mock_approval.html', requests=requests)

from werkzeug.security import generate_password_hash

@app.route('/create_account', methods=['GET', 'POST'])
def create_account():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']

        hashed_password = generate_password_hash(password)

        conn = psycopg2.connect(database="rapid_db", user="postgres",
            password=psql_password, host="localhost", port="5432")
        cur = conn.cursor()

        cur.execute("SELECT username FROM users WHERE username = %s", (username,))
        existing_user = cur.fetchone()

        if existing_user:
            cur.close()
            conn.close()
            error = "Username already exists. Please choose another one."
            return render_template('create_account.html', error=error)
        
        # insert new user here if username is unique
        cur.execute(
            '''INSERT INTO users (username, email, password)
            VALUES (%s, %s, %s);''',
            (username, email, hashed_password)
        )

        conn.commit()
        cur.close()
        conn.close()
        
        return redirect(url_for('index')) 
    return render_template('create_account.html')

from werkzeug.security import check_password_hash

@app.route('/', methods=['GET', 'POST'])
def index():
    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        conn = psycopg2.connect(database="rapid_db", user="postgres",
            password=psql_password, host="localhost", port="5432")
        cur = conn.cursor()
        cur.execute("SELECT userid, password, role FROM users WHERE username = %s", (username,))
        result = cur.fetchone()
        print("Fetched from DB:", result)#debug
        print("Password entered:", password)#debug
        if result: #debug
            print("Hash from DB:", result[0])
            print("Check passed:", check_password_hash(result[1], password))
        cur.close()
        conn.close()

        if result and check_password_hash(result[1], password):
            session['user_id'] = result[0]
            session['role'] = result[2]
            session['username'] = username

            if result[2] == 'admin':  # result[2] is the role
                return redirect(url_for('all_submitted_reports'))
            return redirect(url_for('dashboard'))
        else:
            error = "Invalid username or password"

    return render_template('index.html', error=error)

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

@app.route('/admin/all_submitted_reports')
@admin_required
def all_submitted_reports():
    conn = psycopg2.connect(database="rapid_db", user="postgres",
                            password=psql_password, host="localhost")
    cur = conn.cursor()
    cur.execute("SELECT * FROM incidents ORDER BY date DESC;")
    incidents = cur.fetchall()
    cur.close()
    conn.close()
    return render_template(
    'admin/all_submitted_reports.html',
    incidents=incidents,
    username=session.get('username')
)


if __name__ == '__main__':
   app.run(debug = True)
