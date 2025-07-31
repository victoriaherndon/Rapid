from flask import Flask, render_template, request, url_for, session, redirect, flash
import psycopg2
from psycopg2 import OperationalError
from dotenv import load_dotenv # Remove this line if needed, this is for practice hide database passwords
import os # Remove this line if needed as well, this is just for the passwords
from scrapers import get_gas_prices
from functools import wraps
from create_tables import create_tables

app = Flask(__name__)

load_dotenv() # Remove this line if needed

app.secret_key = os.getenv("FLASK_SECRET_KEY", "default_secret_key")
psql_password = os.getenv("PSQL_PASSWORD") # Remove this line if need

conn = psycopg2.connect(database="rapid_db", user="postgres",
password=psql_password, host="localhost", port="5432")  # Replace psql_password with the password for your psql user

# Just create a function that would connect to the postgres application
create_tables(conn)
cur = conn.cursor()

# Create a function that gets the user's specified role in postgres, so get the role that is not the username
def get_user_role(username, conn):
    cur = conn.cursor()
    try:
        # Check the role column in the users table
        cur.execute("SELECT role FROM users WHERE username = %s", (username,))
        result = cur.fetchone()
        
        if result:
            role = result[0]
            # Debugging
            print(f"Role for user {username}: {role}")
            return role
        else:
            return 'community_member'  # Default to community_member instead of 'user'
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
    email VARCHAR(100) UNIQUE NOT NULL,
    role VARCHAR(15) DEFAULT 'community_member'
);
""")

# Create the incidents table to match the schema
cur.execute("""
    CREATE TABLE IF NOT EXISTS incident_rep (
        EventID SERIAL PRIMARY KEY,
        County VARCHAR(15),
        Address TEXT,
        Status VARCHAR(15) DEFAULT 'Under Review',
        Submitted_At TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        Description TEXT,
        userid INT REFERENCES users(userid),
        occurrence VARCHAR(10)
    );
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





# Now we can grant the permissions to the roles
cur.execute(
    '''
    GRANT SELECT, INSERT ON TABLE incident_rep TO community_member;
    GRANT SELECT, UPDATE, DELETE ON TABLE incident_rep TO city_manager;
    GRANT SELECT, INSERT ON TABLE resource_req TO city_manager;
    GRANT SELECT, UPDATE ON TABLE incident_rep TO state_official;
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

# Decorator for city manager access
def city_manager_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            return redirect(url_for('index'))
        if session.get('role') not in ['admin', 'city_manager']:
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

# Decorator for state official access
def state_official_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            return redirect(url_for('index'))
        if session.get('role') not in ['admin', 'state_official']:
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

# added decorator for updating header routes w/ admin access
@app.context_processor
def inject_user():
    return dict(username=session.get('username'))

def process_incidents_for_template(incidents):
    """Convert date strings to datetime objects for template rendering"""
    from datetime import datetime
    processed_incidents = []
    for incident in incidents:
        incident_list = list(incident)
        if incident_list[4]:  # Submitted_At field (index 4)
            try:
                # Parse the date string to datetime object
                if isinstance(incident_list[4], str):
                    incident_list[4] = datetime.fromisoformat(incident_list[4].replace('Z', '+00:00'))
                else:
                    incident_list[4] = incident_list[4]  # Already a datetime object
            except (ValueError, TypeError):
                incident_list[4] = None
        processed_incidents.append(incident_list)
    return processed_incidents


@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
    # Check if user is logged in
    if 'user_id' not in session or not session.get('user_id'):
        return redirect(url_for('index'))
    
    # Redirect based on role
    role = session.get('role')
    if role == 'admin':
        return redirect(url_for('all_submitted_reports'))
    elif role == 'city_manager':
        return redirect(url_for('city_manager_dashboard'))
    elif role == 'state_official':
        return redirect(url_for('state_official_dashboard'))
    
    # Default: community_member dashboard
    userid = session.get('user_id')

    if request.method == 'POST':
        county = request.form.get('county')
        address = request.form['address']
        occurrence = request.form['occurrence']
        description = request.form['description']
        
        # Validate that userid is not 0 or None
        if not userid or userid == 0:
            flash('Invalid user session. Please log in again.')
            return redirect(url_for('index'))

        conn = psycopg2.connect(database="rapid_db", user="postgres",
                                password=psql_password, host="localhost")
        cur = conn.cursor()
        cur.execute('''
            INSERT INTO incident_rep (userid, County, Address, occurrence, Description, Status)
            VALUES (%s, %s, %s, %s, %s, 'Under Review');
        ''', (userid, county, address, occurrence, description))  

        conn.commit()
        cur.close()
        conn.close()

    conn = psycopg2.connect(database="rapid_db", user="postgres",
                            password=psql_password, host="localhost")
    cur = conn.cursor()
    cur.execute("SELECT * FROM incident_rep WHERE userid = %s ORDER BY Submitted_At DESC;", (userid,))
    incidents = cur.fetchall()
    cur.close()
    conn.close()

    return render_template('dashboard.html', username=session.get('username'), incidents=process_incidents_for_template(incidents))

@app.route('/resources')
def resources():
    # Check if user is logged in
    if 'user_id' not in session or not session.get('user_id'):
        return redirect(url_for('index'))
    
    if session.get('role') == 'admin':
        return redirect(url_for('all_submitted_reports'))
    
    # Get user's incidents for the dropdown
    user_id = session.get('user_id')
    conn = psycopg2.connect(database="rapid_db", user="postgres",
                            password=psql_password, host="localhost")
    cur = conn.cursor()
    cur.execute("SELECT EventID, County, Address, occurrence, Description FROM incident_rep WHERE userid = %s ORDER BY Submitted_At DESC;", (user_id,))
    incidents = cur.fetchall()
    cur.close()
    conn.close()
    
    return render_template('resources.html', incidents=incidents)

@app.route('/submit_resources', methods=['POST'])
def submit_resources():
    # Check if user is logged in
    if 'user_id' not in session or not session.get('user_id'):
        return redirect(url_for('index'))
    
    # get the incident ID and fetch incident details from database
    incident_id = request.form.get('IncidentID')
    
    # Get incident details from database
    conn = psycopg2.connect(database="rapid_db", user="postgres",
                            password=psql_password, host="localhost", port="5432")
    cur = conn.cursor()
    cur.execute("SELECT County, Address, occurrence FROM incident_rep WHERE EventID = %s", (incident_id,))
    incident_result = cur.fetchone()
    
    if not incident_result:
        flash('Invalid incident ID selected.')
        return redirect(url_for('resources'))
    
    county = incident_result[0]
    address = incident_result[1]
    occurrence = incident_result[2]
    cur.close()
    conn.close()
    
    # Convert form values to integers/floats for calculations
    sandbags = int(request.form.get('sandbags') or 0)
    helicopters = int(request.form.get('helicopters') or 0)
    gasoline = int(request.form.get('gasoline') or 0)
    diesel = int(request.form.get('diesel') or 0)
    medical_responders = int(request.form.get('medical_responders') or 0)
    police_responders = int(request.form.get('police_responders') or 0)
    fire_responders = int(request.form.get('fire_responders') or 0)
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
            Funds_Approved, Comments, Estimated_Cost, Status
        ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
    ''', (
        incident_id, county, str(helicopters), str(gasoline), str(diesel), str(sandbags),
        str(medical_responders), str(police_responders), str(fire_responders), 
        0, comments_string, estimated_cost, 'Under Review'
    ))
    conn.commit()
    cur.close()
    conn.close()
    message = f"Your estimated request costs ${flat_cost:.2f} flat, ${man_hour_cost:.2f} per first responder man-hour. Additionally, helicopters cost $600 per hour of flight. Custom resources are not included in this estimate."
    return render_template('summary.html', message=message)

@app.route('/submitted_reports')
def submitted_reports():
    # Check if user is logged in
    if 'user_id' not in session or not session.get('user_id'):
        return redirect(url_for('index'))
    
    user_id = session.get('user_id')
    
    # Validate that userid is not 0 or None
    if not user_id or user_id == 0:
        flash('Invalid user session. Please log in again.')
        return redirect(url_for('index'))
    
    conn = psycopg2.connect(database="rapid_db", user="postgres",
                            password=psql_password, host="localhost")
    cur = conn.cursor()
    cur.execute("SELECT * FROM incident_rep WHERE userid = %s ORDER BY Submitted_At DESC;", (user_id,))
    incidents = cur.fetchall()
    cur.close()
    conn.close()

    return render_template('submitted_reports.html', incidents=process_incidents_for_template(incidents))

@app.route('/my_resource_requests')
def my_resource_requests():
    # Check if user is logged in
    if 'user_id' not in session or not session.get('user_id'):
        return redirect(url_for('index'))
    
    user_id = session.get('user_id')
    
    conn = psycopg2.connect(database="rapid_db", user="postgres",
                            password=psql_password, host="localhost")
    cur = conn.cursor()
    
    # Get user's resource requests with incident details
    cur.execute("""
        SELECT rr.ReportID, rr.County, rr.Estimated_Cost, rr.Status, rr.Funds_Approved,
               ir.EventID, ir.occurrence, ir.Address, ir.Description,
               rr.Helicopter, rr.Gasoline, rr.Diesel, rr.Sandbags,
               rr.Medical_Responders, rr.Police_Responders, rr.Fire_Responders,
               rr.Comments, rr.IncidentID
        FROM resource_req rr
        LEFT JOIN incident_rep ir ON rr.IncidentID = ir.EventID
        WHERE ir.userid = %s
        ORDER BY rr.ReportID DESC
    """, (user_id,))
    requests = cur.fetchall()
    cur.close()
    conn.close()

    return render_template('my_resource_requests.html', requests=requests)


@app.route('/admin/demographics')
def demographics():
    return render_template('admin/demographics.html')


# Removed city_reports route


@app.route('/admin/county_reports')
@admin_required
def county_reports():
    conn = psycopg2.connect(database="rapid_db", user="postgres",
                            password=psql_password, host="localhost")
    cur = conn.cursor()
    
    # Get all counties with their incident counts and budgets
    cur.execute("""
        SELECT 
            c.Name,
            c.Population,
            c.Budget,
            COUNT(ir.EventID) as incident_count,
            COUNT(CASE WHEN ir.Status = 'Under Review' THEN 1 END) as pending_incidents,
            COUNT(CASE WHEN ir.Status = 'Approved' THEN 1 END) as approved_incidents
        FROM county c
        LEFT JOIN incident_rep ir ON c.Name = ir.County
        GROUP BY c.Name, c.Population, c.Budget
        ORDER BY c.Name
    """)
    counties = cur.fetchall()
    
    # Get recent incidents by county
    cur.execute("""
        SELECT 
            ir.EventID,
            ir.County,
            ir.Address,
            ir.occurrence,
            ir.Description,
            ir.Submitted_At,
            ir.Status,
            u.username
        FROM incident_rep ir
        LEFT JOIN users u ON ir.userid = u.userid
        ORDER BY ir.Submitted_At DESC
        LIMIT 10
    """)
    recent_incidents = cur.fetchall()
    
    cur.close()
    conn.close()
    
    return render_template('admin/county_reports.html', 
                         counties=counties, 
                         recent_incidents=process_incidents_for_template(recent_incidents))


# Removed anticipated_costs route

@app.route('/admin/resource_approval', methods=['GET', 'POST'])
@admin_required
def resource_approval():
    conn = psycopg2.connect(database="rapid_db", user="postgres",
                            password=psql_password, host="localhost")
    cur = conn.cursor()
    
    if request.method == 'POST':
        action = request.form.get('action')
        report_id = request.form.get('report_id')
        
        if action and report_id:
            # Get the resource request details
            cur.execute("""
                SELECT Estimated_Cost, County, IncidentID 
                FROM resource_req 
                WHERE ReportID = %s
            """, (report_id,))
            request_data = cur.fetchone()
            
            if request_data:
                estimated_cost, county, incident_id = request_data
                
                if action == 'approve':
                    # Check county budget
                    cur.execute("SELECT Budget FROM county WHERE Name = %s", (county,))
                    budget_result = cur.fetchone()
                    
                    if budget_result:
                        current_budget = budget_result[0]
                        new_budget = current_budget - estimated_cost
                        
                        # Approve the resource request
                        cur.execute("""
                            UPDATE resource_req 
                            SET Status = 'Approved', Funds_Approved = %s 
                            WHERE ReportID = %s
                        """, (estimated_cost, report_id))
                        
                        # Update county budget (can go negative)
                        cur.execute("""
                            UPDATE county 
                            SET Budget = Budget - %s 
                            WHERE Name = %s
                        """, (estimated_cost, county))
                        
                        # Update incident status to Approved
                        cur.execute("""
                            UPDATE incident_rep 
                            SET Status = 'Approved' 
                            WHERE EventID = %s
                        """, (incident_id,))
                        
                        conn.commit()
                        
                        if new_budget < 0:
                            flash(f'Resource request approved! County budget is now ${new_budget:,.2f} (negative).', 'success')
                        else:
                            flash('Resource request approved successfully!', 'success')
                    else:
                        flash('County not found.', 'error')
                        
                elif action == 'deny':
                    # Deny the resource request
                    cur.execute("""
                        UPDATE resource_req 
                        SET Status = 'Denied', Funds_Approved = 0 
                        WHERE ReportID = %s
                    """, (report_id,))
                    
                    # Update incident status to Denied
                    cur.execute("""
                        UPDATE incident_rep 
                        SET Status = 'Denied' 
                        WHERE EventID = %s
                    """, (incident_id,))
                    
                    conn.commit()
                    flash('Resource request denied.', 'success')
    
    # Fetch all resource requests with incident details
    cur.execute("""
        SELECT rr.ReportID, rr.County, rr.Estimated_Cost, rr.Status, rr.Funds_Approved,
               ir.EventID, ir.occurrence, ir.Address, ir.Description,
               rr.Helicopter, rr.Gasoline, rr.Diesel, rr.Sandbags,
               rr.Medical_Responders, rr.Police_Responders, rr.Fire_Responders,
               rr.Comments, rr.IncidentID
        FROM resource_req rr
        LEFT JOIN incident_rep ir ON rr.IncidentID = ir.EventID
        ORDER BY rr.ReportID DESC
    """)
    resource_requests = cur.fetchall()
    
    # Fetch county budgets
    cur.execute("SELECT Name, Budget FROM county ORDER BY Name")
    counties = cur.fetchall()
    
    cur.close()
    conn.close()
    
    return render_template('admin/resource_approval.html',
                         resource_requests=resource_requests,
                         counties=counties)

@app.route('/create_account', methods=['GET', 'POST'])
def create_account():
    error = None
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']

        # Validate username format
        if not username.isalnum():
            error = "Username must contain only alphanumeric characters"
            return render_template('create_account.html', error=error)

        conn = psycopg2.connect(database="rapid_db", user="postgres",
            password=psql_password, host="localhost", port="5432")
        cur = conn.cursor()

        try:
            # Check if the username already exists in the users table
            cur.execute("SELECT username FROM users WHERE username = %s", (username,))
            existing_user = cur.fetchone()
            
            if existing_user:
                error = "Username already taken. Please choose a different username."
                cur.close()
                conn.close()
                return render_template('create_account.html', error=error)
            
            # Check if the username already exists as a PostgreSQL role
            cur.execute("SELECT 1 FROM pg_roles WHERE rolname = %s", (username,))
            existing_role = cur.fetchone()

            if not existing_role:
                # Create PostgreSQL role
                cur.execute(f"CREATE USER \"{username}\" WITH PASSWORD %s;", (password,))
                # Grant community member role
                cur.execute(f"GRANT community_member TO \"{username}\";")

            # Insert user into the users table
            cur.execute(
                '''INSERT INTO users (username, email, role)
                VALUES (%s, %s, 'community_member');''',
                (username, email)
            )

            conn.commit()
            cur.close()
            conn.close()
            
            flash('Account created successfully! Please log in.')
            return redirect(url_for('index')) 
                
        except Exception as e:
            error = f"Account creation failed: {e}"
            conn.rollback()
            cur.close()
            conn.close()
            return render_template('create_account.html', error=error)

    return render_template('create_account.html', error=error)


@app.route('/', methods=['GET', 'POST'])
def index():
    error = None

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Connect to database as postgres user to check user existence
        conn = psycopg2.connect(database="rapid_db", user="postgres",
            password=psql_password, host="localhost", port="5432")

        cur = conn.cursor()

        # First, check if the user exists in the users table and get their userid
        cur.execute("SELECT userid FROM users WHERE username = %s", (username,))
        user_result = cur.fetchone()
        
        if not user_result:
            error = "Invalid username or password"
            cur.close()
            conn.close()
            return render_template('index.html', error=error)
        
        user_id = user_result[0]
        
        # Check if the user exists as a PostgreSQL role
        cur.execute("SELECT 1 FROM pg_roles WHERE rolname = %s", (username,))
        existing_role = cur.fetchone()

        if not existing_role:
            error = "Invalid username or password"
            cur.close()
            conn.close()
            return render_template('index.html', error=error)

        # Try to authenticate the user
        try:
            # Test the user's credentials by connecting as the user
            test_conn = psycopg2.connect(database="rapid_db", user=username,
                password=password, host="localhost", port="5432")
            
            # If we get here, authentication was successful
            session['username'] = username
            session['user_id'] = user_id
            session['role'] = get_user_role(username, conn)  # Use postgres connection instead of user connection
            
            test_conn.close()
            cur.close()
            conn.close()
            
            # Redirect based on role
            if session['role'] == 'admin':
                return redirect(url_for('all_submitted_reports'))
            elif session['role'] == 'city_manager':
                return redirect(url_for('city_manager_dashboard'))
            elif session['role'] == 'state_official':
                return redirect(url_for('state_official_dashboard'))
            else:
                return redirect(url_for('dashboard'))
                
        except psycopg2.OperationalError:
            # Authentication failed
            error = "Invalid username or password"
            cur.close()
            conn.close()
            return render_template('index.html', error=error)

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
    cur.execute("SELECT * FROM incident_rep ORDER BY Submitted_At DESC;")
    incidents = cur.fetchall()
    cur.close()
    conn.close()
    
    return render_template(
    'admin/all_submitted_reports.html',
    incidents=process_incidents_for_template(incidents),
    username=session.get('username')
)

# Remove the incident approval routes
# @app.route('/admin/incident-approval')
# @app.route('/city_manager/incident-approval')

@app.route('/city_manager/dashboard')
@city_manager_required
def city_manager_dashboard():
    conn = psycopg2.connect(database="rapid_db", user="postgres",
                            password=psql_password, host="localhost")
    cur = conn.cursor()
    
    # Get incidents in the city manager's area (all incidents for now)
    cur.execute("SELECT * FROM incident_rep ORDER BY Submitted_At DESC;")
    incidents = cur.fetchall()
    
    # Get resource requests for their area
    cur.execute("""
        SELECT rr.ReportID, rr.County, rr.Estimated_Cost, rr.Status, rr.Funds_Approved,
               ir.EventID, ir.occurrence, ir.Address, ir.Description,
               rr.Helicopter, rr.Gasoline, rr.Diesel, rr.Sandbags,
               rr.Medical_Responders, rr.Police_Responders, rr.Fire_Responders,
               rr.Comments, rr.IncidentID
        FROM resource_req rr
        LEFT JOIN incident_rep ir ON rr.IncidentID = ir.EventID
        ORDER BY rr.ReportID DESC
    """)
    resource_requests = cur.fetchall()
    
    cur.close()
    conn.close()
    
    return render_template(
        'city_manager/dashboard.html',
        incidents=process_incidents_for_template(incidents),
        resource_requests=resource_requests,
        username=session.get('username')
    )

# Remove the incident approval routes
# @app.route('/city_manager/incident-approval')

@app.route('/state_official/dashboard')
@state_official_required
def state_official_dashboard():
    conn = psycopg2.connect(database="rapid_db", user="postgres",
                            password=psql_password, host="localhost")
    cur = conn.cursor()
    
    # Get all incidents for state overview
    cur.execute("SELECT * FROM incident_rep ORDER BY Submitted_At DESC;")
    incidents = cur.fetchall()
    
    # Get all resource requests for state oversight
    cur.execute("""
        SELECT rr.ReportID, rr.County, rr.Estimated_Cost, rr.Status, rr.Funds_Approved,
               ir.EventID, ir.occurrence, ir.Address, ir.Description,
               rr.Helicopter, rr.Gasoline, rr.Diesel, rr.Sandbags,
               rr.Medical_Responders, rr.Police_Responders, rr.Fire_Responders,
               rr.Comments, rr.IncidentID
        FROM resource_req rr
        LEFT JOIN incident_rep ir ON rr.IncidentID = ir.EventID
        ORDER BY rr.ReportID DESC
    """)
    resource_requests = cur.fetchall()
    
    # Get county statistics
    cur.execute("""
        SELECT 
            c.Name,
            c.Population,
            c.Budget,
            COUNT(ir.EventID) as incident_count
        FROM county c
        LEFT JOIN incident_rep ir ON c.Name = ir.County
        GROUP BY c.Name, c.Population, c.Budget
        ORDER BY c.Name
    """)
    counties = cur.fetchall()
    
    cur.close()
    conn.close()
    
    return render_template(
        'state_official/dashboard.html',
        incidents=process_incidents_for_template(incidents),
        resource_requests=resource_requests,
        counties=counties,
    username=session.get('username')
)


if __name__ == '__main__':
   app.run(debug = True)
