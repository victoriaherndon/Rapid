import psycopg2

def create_tables(connection):
    # function that takes the connection as an argument then creates the tables according to our DBML (can be adjusted of course)
    # stores all of the tables as strings in a list and then uses uses the connection to execute each command, rolling back if necessary
    # please do not declare a column as NOT NULL without thorough code review; values like Is_Rejected will be null to indicate a pending status and
    # will be initialized when adjudicated 

    create_tables_sql = [
        """
        CREATE TABLE IF NOT EXISTS users (
            userid SERIAL PRIMARY KEY,
            name VARCHAR(30),
            role VARCHAR(15) DEFAULT 'user',
            username VARCHAR(15) UNIQUE NOT NULL,
            email VARCHAR(255) UNIQUE NOT NULL
            --, password VARCHAR(512) NOT NULL --
        );
        """,
        """
        CREATE TABLE IF NOT EXISTS county (
            CountyID INTEGER PRIMARY KEY,
            Population INTEGER,
            Name VARCHAR(15) UNIQUE,
            Number_Sheltered INTEGER,
            Budget INTEGER
        );
        """,
        """
        CREATE TABLE IF NOT EXISTS incident_rep (
            EventID SERIAL PRIMARY KEY,
            County VARCHAR(15) REFERENCES county(Name),
            Address TEXT,
            Status VARCHAR(15),
            Submitted_At TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            Description TEXT,
            userid INT REFERENCES users(userid),
            occurrence VARCHAR(10)
        );
        """,
        """
        CREATE TABLE IF NOT EXISTS resource_req (
            ReportID SERIAL PRIMARY KEY,
            IncidentID INTEGER REFERENCES incident_rep(EventID),
            County VARCHAR(15) REFERENCES county(Name),
            Helicopter INTEGER,
            Gasoline INTEGER,
            Diesel INTEGER,
            Sandbags INTEGER,
            Medical_Responders INTEGER,
            Police_Responders INTEGER,
            Fire_Responders INTEGER,
            Funds_Approved INTEGER,
            Is_Rejected BOOL,
            Comments TEXT,
            Estimated_Cost INTEGER,
            Status VARCHAR(20) DEFAULT 'Under Review'
        );
        """
    ]

    try:
        cursor = connection.cursor()
        for statement in create_tables_sql:
            cursor.execute(statement)
        connection.commit()
        print("All tables created successfully!")

    except psycopg2.Error as e:
        print(f"Error creating tables: {e}")
        connection.rollback()

    finally:
        cursor.close()
