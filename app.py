import os
from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_bcrypt import Bcrypt
from dotenv import load_dotenv
import pymysql
import uuid 

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY")
bcrypt = Bcrypt(app)

# Secure Database Connection
def get_db():
    return pymysql.connect(
        host="localhost",
        user="root",
        password="", # Force it to be empty string, not None
        database="egov_secure_db",
        cursorclass=pymysql.cursors.DictCursor
    )

@app.route("/")
def index():
    return render_template("login.html")

# Secure Registration with Password Hashing
@app.route("/register", methods=["POST"])
def register():
    name = request.form['name']
    email = request.form['email']
    password = request.form['password']
    
    # Encrypt the password before saving
    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
    
    db = get_db()
    cur = db.cursor(pymysql.cursors.DictCursor) 
    try:
        cur.execute("INSERT INTO users (name, email, password) VALUES (%s, %s, %s)", 
                    (name, email, hashed_password))
        db.commit()
        return redirect("/")
    except:
        return "Email already exists!"
    finally:
        db.close()

# Route to show the Registration Page
@app.route("/register")
def register_page():
    return render_template("register.html")

# Logic to save the user to MySQL with Encryption
@app.route("/register_user", methods=["POST"])
def register_user():
    name = request.form['name']
    email = request.form['email']
    password = request.form['password']
    
    # Scramble the password using Bcrypt
    hashed_pw = bcrypt.generate_password_hash(password).decode('utf-8')
    
    db = get_db()
    cur = db.cursor(pymysql.cursors.DictCursor) 
    try:
        # Ensure name, email, and hashed_pw are in ONE set of parentheses
        cur.execute("INSERT INTO users (name, email, password) VALUES (%s, %s, %s)",(name, email, hashed_pw))
        db.commit()
        return redirect("/")
    except Exception as e:
        print(f"Error: {e}") # This will show the real error in terminal
        return f"Registration error: {e}"
    finally:
        db.close()

@app.route("/login_user", methods=["POST"])
def login_user():
    email = request.form["email"]
    password_candidate = request.form["password"]
    db = get_db()
    cur = db.cursor(pymysql.cursors.DictCursor)
    cur.execute("SELECT * FROM users WHERE email = %s", (email,))
    user = cur.fetchone()
    db.close()
    if user:
        # 1. First, check if it's your manual 'staff' account with plain text password
        if user['role'] == 'staff' and password_candidate == user['password']:
            is_valid = True
        else:
            # 2. Otherwise, use bcrypt for secure hashed passwords
            try:
                is_valid = bcrypt.check_password_hash(user['password'], password_candidate)
            except ValueError:
                is_valid = False
        if is_valid:
            session['logged_in'] = True
            session['user_id'] = user['id']
            session['user_name'] = user['name']
            session['role'] = user['role'] # This will be 'staff'
            # 3. Redirect to Admin Dashboard because role is 'staff'
            if user['role'] == 'staff':
                return redirect("/admin/dashboard")
            else:
                return redirect("/dashboard")
        else:
            return "Invalid Password"        
    return "User not found"

@app.route("/dashboard")
def dashboard():
    if not session.get("logged_in"):
        return redirect("/")   
    user_id = session.get("user_id")
    db = get_db()  
    # CHANGE THIS LINE: Add dictionary=True
    cur = db.cursor(pymysql.cursors.DictCursor)    
    # Keep your query fetching the columns you need
    cur.execute("SELECT service_name, status, ref_id FROM applications WHERE user_id = %s", (user_id,))
    user_apps = cur.fetchall()
    
    db.close()
    return render_template("dashboard.html", applications=user_apps)

from flask import Response # Ensure this is in your imports at the top

@app.route('/download_receipt/<ref_id>')
def download_receipt(ref_id):
    if not session.get("logged_in"):
        return redirect("/")
    db = get_db()
    # Use DictCursor here as well so we can use column names
    cur = db.cursor(pymysql.cursors.DictCursor)   
    # Search for the application by its unique ref_id
    cur.execute("SELECT service_name, status, created_at FROM applications WHERE ref_id = %s", (ref_id,))
    app_data = cur.fetchone()
    db.close()
    if app_data:
        # Create a clean text receipt using the dictionary keys
        receipt_text = f"""
        ------------------------------------------
        GOV-SECURE PORTAL OFFICIAL RECEIPT
        ------------------------------------------
        Application ID : {ref_id}
        Service Name   : {app_data['service_name']}
        Current Status : {app_data['status']}
        Applied On     : {app_data['created_at']}
        
        Note: This is a computer-generated receipt.
        ------------------------------------------
        """      
        # This triggers the automatic download in the browser
        return Response(
            receipt_text,
            mimetype="text/plain",
            headers={"Content-disposition": f"attachment; filename=Receipt_{ref_id}.txt"}
        )
    else:
        return "Application Not Found", 404

@app.route("/admin/dashboard")
def admin_dashboard():
    # Basic security check: ensure only admins can enter
    if not session.get("logged_in") or session.get("role") != "staff":
        return redirect("/")
    db = get_db()
    cur = db.cursor(pymysql.cursors.DictCursor)
    # Fetch all applications and the names of the users who submitted them
    query = """
    SELECT a.id, a.ref_id, a.service_name, a.status, u.name as user_name 
    FROM applications a 
    JOIN users u ON a.user_id = u.id
    """
    cur.execute(query)
    all_apps = cur.fetchall()
    db.close()

    return render_template("admin_dashboard.html", applications=all_apps)

@app.route("/admin/approve/<int:app_id>")
def approve_application(app_id):
    db = get_db()
    cur = db.cursor()
    # Update the status in the database
    cur.execute("UPDATE applications SET status = 'Approved' WHERE id = %s", (app_id,))
    db.commit()
    db.close()
    return redirect("/admin/dashboard")

import random

# STEP 1: Send OTP and show verification page
@app.route("/admin/send_otp/<int:app_id>")
def send_otp(app_id):
    otp = str(random.randint(100000, 999999))
    session['current_otp'] = otp
    session['target_app_id'] = app_id   
    # Check your terminal/console to see this OTP
    print(f"OTP for App {app_id} is: {otp}")    
    return render_template("admin_verify.html", app_id=app_id)
# STEP 2: Verify the OTP and mark as 'Verified'
@app.route("/admin/confirm_verify", methods=["POST"])
def confirm_verify():
    entered_otp = request.form.get("otp")
    app_id = session.get('target_app_id')   
    if entered_otp == session.get('current_otp'):
        db = get_db()
        cur = db.cursor()
        # Move status from 'Pending' to 'Verified'
        cur.execute("UPDATE applications SET status = 'Verified' WHERE id = %s", (app_id,))
        db.commit()
        db.close()
        return redirect("/admin/dashboard")
    return "Invalid OTP. Verification failed."
# STEP 3: Final manual approval by Admin
@app.route("/admin/final_approve/<int:app_id>")
def final_approve(app_id):
    db = get_db()
    cur = db.cursor()
    # Finalize the status to 'Approved'
    cur.execute("UPDATE applications SET status = 'Approved' WHERE id = %s", (app_id,))
    db.commit()
    db.close()
    return redirect("/admin/dashboard")

@app.route("/admin_login")
def admin_login_page():
    return render_template("admin_login.html")

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")

@app.route("/submit_application", methods=["POST"])
def submit_application():
    service = request.form.get("service_name")
    user_id = session.get("user_id") # Identify who is applying
    
    db = get_db()
    cur = db.cursor(pymysql.cursors.DictCursor) 
    # Save selection to the database
    cur.execute("INSERT INTO applications (user_id, service_name) VALUES (%s, %s)", (user_id, service))
    db.commit()
    db.close()
    return redirect("/dashboard")

@app.route("/submit_detailed_app", methods=["POST"])
def submit_detailed_app():
    if not session.get("logged_in"):
        return redirect("/")   
    service = request.form.get("service_name")
    user_id = session.get("user_id")  
    # 1. Capture Universal Fields (Required for all services)
    aadhar_val = request.form.get("aadhar_number") 
    contact_val = request.form.get("contact")
    ref_id = f"GOV-{service[:3].upper()}-{str(uuid.uuid4())[:4].upper()}"  
    # 2. Build Specific Details
    if service == "Income Certificate":
        income = request.form.get("income_val")
        reason = request.form.get("reason")
        full_details = f"Annual Income: ₹{income} | Reason: {reason}"
    else:
        # Defaults for Aadhar Update
        new_name = request.form.get("new_name")
        new_addr = request.form.get("new_address")
        full_details = f"New Name: {new_name} | New Address: {new_addr}"
    # 3. Insert into Local Database
    db = get_db()
    cur = db.cursor(pymysql.cursors.DictCursor)
    sql = """INSERT INTO applications 
             (user_id, service_name, details, aadhar_num, contact_number, ref_id, status) 
             VALUES (%s, %s, %s, %s, %s, %s, 'Pending')"""
    cur.execute(sql, (user_id, service, full_details, aadhar_val, contact_val, ref_id))
    db.commit()
    db.close()  
    return render_template("confirmation.html", service=service, ref_no=ref_id)

# Route to show the list of all available services
@app.route("/apply")
def apply():
    if not session.get("logged_in"):
        return redirect("/")
    return render_template("apply.html")

# Route to decide which specific form to open
@app.route("/select_service/<service_type>")
def select_service(service_type):
    if not session.get("logged_in"):
        return redirect("/")
    
    if service_type == "aadhar":
        return render_template("form_aadhar.html")
    elif service_type == "scholarship":
        return render_template("scholarship.html")
    elif service_type == "caste":
        return render_template("form_caste.html")
    elif service_type == "income":
        return render_template("form_income.html")   
    
 # External "Safe Bridge" redirects
    elif service_type == "voter":
        return render_template("external_viewer.html", 
                               url="https://voters.eci.gov.in/", 
                               name="Voter ID Registration")
    elif service_type == "ration":
        return render_template("external_viewer.html", 
                               url="https://nfsa.gov.in/", 
                               name="Ration Card")
    
    return redirect("/dashboard")
    # External Government Redirects
  #  elif service_type == "voter":
        # You could add a DB entry here to log the attempt if you wish
   #     return redirect("https://voters.eci.gov.in/")  

@app.route("/handle_selection", methods=["POST"])
def handle_selection():
    choice = request.form.get("service_name")
    # Redirects the user to the specific page for that service
    return redirect(f"/select_service/{choice}")


@app.route("/download_aadhar/<ref_id>")
def download_aadhar(ref_id):
    if not session.get("logged_in"):
        return redirect("/")
    
    # We pass the ref_id and the user's name to the template
    # 'name' comes from the session you created during login
    return render_template("digital_aadhar.html", ref_no=ref_id, name=session.get("name"))
if __name__ == "__main__":
    app.run(debug=True)