from flask import Flask, render_template, request, url_for, session, redirect, flash
import psycopg2
from psycopg2 import OperationalError # idk what's wrong w/ this but pycharm kept throwing an error unless i manually included it lol
import os # Remove this line if needed as well, this is just for the passwords
from scrapers import get_gas_prices
from functools import wraps
from create_tables import create_tables
from dotenv import load_dotenv

app = Flask(__name__)
def db_connect():
    return psycopg2.connect(
        "postgresql://neondb_owner:npg_l6GvQO3zVwfC@ep-summer-truth-aehrsnkz-pooler.c-2.us-east-2.aws.neon.tech/neondb?sslmode=require&channel_binding=require"
    )
load_dotenv()
load_dotenv()
app.secret_key = os.getenv("FLASK_SECRET_KEY", "default_secret_key")
psql_password = os.getenv("PSQL_PASSWORD") # Remove this line if need

conn = db_connect()

# Just create a function that would connect to the postgres application
create_tables(conn)
cur = conn.cursor()

# Create a function that gets the user's specified role in postgres, so get the role that is not the username
def get_user_role(username, conn):
    cur = conn.cursor()
    try:
        cur.execute(
            '''
            SELECT rolname FROM pg_roles
            WHERE oid IN (
                SELECT roleid
                FROM pg_auth_members
                WHERE member = (
                    SELECT oid FROM pg_roles WHERE rolname = %s
                )
            )
            AND rolname IN ('community_member', 'city_manager', 'state_official', 'admin')
            ''', (username, )
        )

        roles = cur.fetchall()

        # Debugging
        print(f"Roles for user {username}: {roles}")
        
        # Turn the roles into a list
        role_names = [role[0] for role in roles]
        
        # Order everything by roles
        if 'admin' in role_names:
            return 'admin'
        elif 'state_official' in role_names:
            return 'state_official'
        elif 'city_manager' in role_names:
            return 'city_manager'
        elif 'community_member' in role_names:
            return 'community_member'
        else:
            return 'user'
    finally:
        cur.close()


# create users table if it doesnt already exist
# for storing account credentials and role info
# For the users, the password will be handled by postgres no need to manually encrypt, password
# Additional information about the user will be stored in the table
cur.execute("""
CREATE TABLE IF NOT EXISTS users(
    userid SERIAL PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    email VARCHAR(100) UNIQUE NOT NULL
);
""")

# Create the incidents tables, so it references things that are there
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

# We need to create the roles for the users in the database, community members, city managers, and state/federal officials
cur.execute(
    '''
    DO
    $do$
    BEGIN
        IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'community_member') THEN
            CREATE ROLE community_member;
        END IF;
        IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'city_manager') THEN
            CREATE ROLE city_manager;
        END IF;
        IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'state_official') THEN
            CREATE ROLE state_official;
        END IF;
        IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'admin') THEN
            CREATE ROLE admin;
        END IF;
    END
    $do$;
    '''
)



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

# Now we can grant the permissions to the roles
cur.execute(
    '''
    GRANT SELECT, INSERT ON TABLE incidents TO community_member;
    GRANT SELECT, UPDATE, DELETE ON TABLE incidents TO city_manager;
    GRANT SELECT, INSERT ON TABLE resource_req TO city_manager;
    GRANT SELECT, UPDATE ON TABLE incidents TO state_official;
    GRANT SELECT, UPDATE, DELETE ON TABLE resource_req TO state_official;
    GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO admin;
    '''
)

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
        

        conn = db_connect()
        cur = conn.cursor()
        cur.execute('''
            INSERT INTO incidents (userid, county, address, occurrence, description)
            VALUES (%s, %s, %s, %s, %s);
        ''', (userid, county, address, occurrence, description))  

        conn.commit()
        cur.close()
        conn.close()

    conn = db_connect()
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
    conn = db_connect()
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
    conn = db_connect()
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
    conn = db_connect()
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

@app.route('/create_account', methods=['GET', 'POST'])
def create_account():
    if request.method == 'POST':
        username = request.form['username'] # Lets have a psql role and a flask role, so flask is the app based logic
        email = request.form['email']
        password = request.form['password']

        conn = db_connect()
        cur = conn.cursor()

        # Check if the username already exists in the database
        try:
            cur.execute("SELECT 1 FROM pg_roles WHERE rolname = %s", (username,))
            existing_role = cur.fetchone()

            # LOOK AT THIS, THE USERNAME HAS TO BE SAFE FOR THE USER TO BE CREATED
            if not existing_role: # If the user does not exist, create user for the database
                if not username.isalnum(): # This meant to be safe for SQL to inject the username into SQL
                    error = "Username must contain only alphanumeric characters"

                # Use string formatting for creating user and granting roles to the specific user
                cur.execute(f"CREATE USER \"{username}\" WITH PASSWORD %s;", (password,))

                # Automatically grants community member role to whoever signs up
                cur.execute(f"GRANT community_member TO \"{username}\";")
        except Exception as e:
            error = f"User creation failed: {e}"

        
        # insert new user here if username if everything is good on the postgres side
        # We really only need the username and emails here, the password is stored safely in postgres
        # We do not need the email
        cur.execute(
            '''INSERT INTO users (username, email)
            VALUES (%s, %s)
            ON CONFLICT (username) DO NOTHING;''',
            (username, email)
        )

        conn.commit()
        cur.close()
        conn.close()
        
        return redirect(url_for('index')) 
    return render_template('create_account.html')


@app.route('/', methods=['GET', 'POST'])
def index():
    error = None
    # This is where the userid for the session will be stored, this is where it will be remembered
    user_id_test = 0

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # If the user exists within the postgres authentication
        conn = db_connect()

        cur = conn.cursor()

        # Validate if the user exists from the table so I can get the userid
        cur.execute("SELECT username FROM users WHERE username = %s", (username,))
        existing_user = cur.fetchone()

        if existing_user:
            # This is to get the user_id so it can be used throughout the session so yeah, get that in your head gang
            cur.execute("SELECT userid FROM users WHERE username=%s", (username,))
            user_id_cookin = cur.fetchone()

            # Debugging
            print(user_id_cookin[0])
            user_id_test = user_id_cookin[0]

        else:
            error="Cannot get user id of a user that does not exist"

        # This checks from the database selection if the user already exists for the database
        cur.execute("SELECT 1 FROM pg_roles WHERE rolname = %s", (username,)) # Checks the users that are in the roles list in psql
        existing_user = cur.fetchone()

        if existing_user:
            # If the user is able to login into the database, the database will have specific permissions
            # By the user
            try:
                conn =  db_connect()
                session['username'] = username
                session['role'] = get_user_role(username, conn) # Get the role of the user from the database, maybe this could work?
                session['user_id'] = user_id_test

                if get_user_role(username, conn) == 'admin':
                    return redirect(url_for('all_submitted_reports'))
                return redirect(url_for('dashboard'))
            except OperationalError as e:
                error = "Invalid username or password"
        else:
            error = "User does not exist"

    return render_template('index.html', error=error)

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

@app.route('/admin/all_submitted_reports')
@admin_required
def all_submitted_reports():
    conn = db_connect()
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
