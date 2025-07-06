import os
from flask import Flask, render_template, request, redirect, flash, session, url_for, jsonify
from flask_sqlalchemy import SQLAlchemy
from dotenv import load_dotenv
import random
import string
import smtplib
from email.message import EmailMessage
from datetime import datetime, timedelta, date
import re
import io
import csv

# Load environment variables from .env
load_dotenv()

app = Flask(__name__)
app.secret_key = os.environ.get('FLASK_SECRET_KEY')

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///appointments.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

EMAIL_ADDRESS = os.environ.get('EMAIL_ADDRESS')
EMAIL_PASSWORD = os.environ.get('EMAIL_APP_PASSWORD')

# Helper function for sending emails

def generate_captcha(length=5):
    letters = string.ascii_uppercase + string.digits
    return ''.join(random.choices(letters, k=length))

def send_email(to_email, subject, message, appointment=None):
    msg = EmailMessage()
    msg['Subject'] = subject
    msg['From'] = EMAIL_ADDRESS
    msg['To'] = to_email
    msg.set_content(message)

    # If appointment is provided, add CSV attachment
    if appointment:
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(['Field', 'Value'])
        writer.writerow(['Name', appointment.name])
        writer.writerow(['Email', appointment.email])
        writer.writerow(['Phone Number', appointment.phone_number])
        writer.writerow(['Aadhar', appointment.aadhar])
        writer.writerow(['Purpose', appointment.purpose])
        writer.writerow(['Appointment ID', appointment.appointment_id])
        writer.writerow(['Status', appointment.status])
        if hasattr(appointment, 'organiser_email_id'):
            writer.writerow(['Organiser Email', appointment.organiser_email_id])
        if appointment.date and appointment.date != '':
            writer.writerow(['Date', appointment.date])
        if appointment.time and appointment.time != '':
            writer.writerow(['Time', appointment.time])

        msg.add_attachment(
            output.getvalue().encode('utf-8'),
            maintype='text',
            subtype='csv',
            filename='appointment_details.csv'
        )

    try:
        with smtplib.SMTP_SSL('smtp.gmail.com', 465) as smtp:
            smtp.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
            smtp.send_message(msg)
        print(f"Email sent successfully to {to_email}")
        return True
    except Exception as e:
        print(f"Failed to send email to {to_email}: {e}")
        return False


# MODELS
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False) # In a real app, use hashed passwords!

class Appointment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), nullable=False)
    aadhar = db.Column(db.String(20), nullable=False) # This is where the ID number goes
    purpose = db.Column(db.String(200), nullable=False)
    appointment_id = db.Column(db.String(20), unique=True, nullable=False)
    status = db.Column(db.String(20), default='pending')
    date = db.Column(db.String(20), nullable=True) # Stored as string 'YYYY-MM-DD'
    time = db.Column(db.String(20), nullable=True) # Stored as string 'HH:MM'
    phone_number = db.Column(db.String(20), nullable=False) # Ensure this is nullable=False as it's typically required
    phone_last4 = db.Column(db.String(4), nullable=False) # Ensure this is nullable=False if always present
    id_type = db.Column(db.String(50))
    organiser_personal_number = db.Column(db.String(20), nullable=True)
    # NEW COLUMN ADDED: to store the email of the organizer for this appointment
    organiser_email_id = db.Column(db.String(100), nullable=True) # Make nullable=True if not always required, otherwise False
    #created_at = db.Column(db.DateTime, default=datetime.utcnow)
    #updated_at = db.Column(db.DateTime, default=datetime.utcnow, onuodate=datetime.utcnow)

class OTPStore(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), nullable=False)
    otp = db.Column(db.String(6), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

# THIS IS YOUR 'ORGANISER' TABLE - ADDING joining_date here
class Organiser(db.Model):
    __tablename__ = 'organiser' # Explicitly setting table name as per your previous traceback
    id = db.Column(db.Integer, primary_key=True)
    personal_number = db.Column(db.String(50), unique=True, nullable=True) # Making nullable=True for flexibility
    name = db.Column(db.String(100), nullable=False)
    department = db.Column(db.String(100), nullable=True) # Making nullable=True for flexibility
    designation = db.Column(db.String(100), nullable=True) # Making nullable=True for flexibility
    contact_no = db.Column(db.String(20), nullable=False) # Making nullable=True for flexibility
    email = db.Column(db.String(100), unique=True, nullable=False)
    joining_date = db.Column(db.Date, nullable=False) # ADDED: joining_date to Organiser

# AUTH ROUTES (Re-included and consolidated from previous versions)
@app.route('/register', methods=['GET', 'POST'])
def register():
    email = None
    if request.method == 'POST':
        if 'send_otp' in request.form:
            email = request.form['email']
            if User.query.filter_by(email=email).first():
                flash("This email is already registered!", "warning")
            else:
                otp = str(random.randint(1000, 9999))
                session['reg_email'] = email
                session['reg_otp'] = otp
                session['otp_verified'] = False

                if send_email(email, "Your OTP", f"Your 4-digit OTP is: {otp}"):
                    flash("OTP sent to your email.", "info")
                else:
                    flash("Failed to send OTP. Please check your email settings or try again.", "danger")

        elif 'register_user' in request.form:
            email = session.get('reg_email')
            entered_otp = request.form['otp']
            password = request.form['password']
            confirm_password = request.form['confirm_password']

            if entered_otp != session.get('reg_otp'):
                flash("Incorrect OTP!", "danger")
            elif password != confirm_password:
                flash("Passwords do not match!", "danger")
            elif User.query.filter_by(email=email).first():
                flash("Email already registered!", "warning")
            else:
                # Assuming this registration is for a regular user, not an organiser
                db.session.add(User(email=email, password=password)) # Remember to hash passwords in production!
                db.session.commit()
                session.pop('reg_email', None)
                session.pop('reg_otp', None)
                flash("Registered successfully! Please login.", "success")
                return redirect(url_for('login'))

    return render_template("register.html", email=session.get('reg_email'))

@app.route('/verify-register-otp', methods=['POST'])
def verify_register_otp():
    user_otp = request.json.get('otp')
    if user_otp == session.get('register_otp'):
        return jsonify({'status': 'success'})
    return jsonify({'status': 'error', 'message': 'Invalid OTP'}), 400

@app.route('/send-register-otp', methods=['POST'])
def send_register_otp():
    email = request.json.get('email')
    if not email:
        return jsonify({'status': 'error', 'message': 'Email is required'}), 400

    otp = str(random.randint(1000, 9999))
    session['register_otp'] = otp
    session['register_email'] = email

    if send_email(email, "Your Registration OTP", f"Your OTP is: {otp}\nIt is valid for 2 minutes."):
        return jsonify({'status': 'success', 'message': 'OTP sent to your email'})
    else:
        return jsonify({'status': 'error', 'message': 'Failed to send OTP. Please try again.'}), 500


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email, password=password).first() # Again, use hashed passwords!
        if user:
            session['user'] = email # Set session for regular user
            flash("Logged in successfully!", "success")
            return redirect(url_for('dashboard')) # Redirect to the main user dashboard
        else:
            flash("Invalid credentials.", "danger")
    return render_template('login.html')


@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        if 'send_otp' in request.form:
            email = request.form['email']
            user = User.query.filter_by(email=email).first()
            if user:
                otp = str(random.randint(1000, 9999))
                session['fp_email'] = email
                session['fp_otp'] = otp
                session['fp_otp_sent'] = True
                if send_email(email, "Your OTP", f"Your 4-digit password reset OTP is: {otp}"):
                    flash("OTP sent to your email.", "info")
                else:
                    flash("Failed to send OTP. Please try again.", "danger")
            else:
                flash("No account found with this email.", "danger")

        elif 'reset_password' in request.form:
            entered_otp = request.form['otp']
            new_password = request.form['new_password']
            confirm_password = request.form['confirm_password']
            actual_otp = session.get('fp_otp')
            email = session.get('fp_email')

            if entered_otp != actual_otp:
                flash("Incorrect OTP.", "danger")
            elif new_password != confirm_password:
                flash("Passwords do not match!", "danger")
            else:
                user = User.query.filter_by(email=email).first()
                if user:
                    user.password = new_password  # Consider hashing!
                    db.session.commit()
                    session.pop('fp_email', None)
                    session.pop('fp_otp', None)
                    session.pop('fp_otp_sent', None)
                    flash("Password reset successfully. Please log in.", "success")
                    return redirect(url_for('login'))
    return render_template("forgot_password.html")

@app.route('/logout')
def user_logout():
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for('login'))

# HOME / DASHBOARD ROUTES
@app.route('/')
def root():
    # If a regular user is logged in, redirect to their dashboard
    if 'user' in session:
        return redirect(url_for('dashboard'))
    # If an employee/organiser is logged in, redirect to their dashboard
    if 'employee_logged_in' in session:
        return redirect(url_for('employee_dashboard'))
    # Otherwise, redirect to login page
    return redirect(url_for('login'))

@app.route('/dashboard') # This is the regular user dashboard endpoint
def dashboard():
    if 'user' not in session:
        flash("Please login to access the user dashboard.", "warning")
        return redirect(url_for('login'))
    return render_template('index.html')


@app.route('/book-appointment', methods=['GET', 'POST'])
def book_appointment():
    if request.method == 'POST':
        appointment_id_gen = ''.join(random.choices(string.ascii_uppercase + string.digits, k=8))
        while Appointment.query.filter_by(appointment_id=appointment_id_gen).first():
            appointment_id_gen = ''.join(random.choices(string.ascii_uppercase + string.digits, k=8))

        name = request.form['name']
        email = request.form['email']
        id_type = request.form['id_type']
        id_number = request.form['id_number']
        phone_number = request.form['phone_number']
        phone_last4 = request.form['phone_last4']
        purpose = request.form['purpose']
        
        # Retrieve the desired datetime from the form
        desired_datetime_str = request.form.get('desired_datetime')
        appointment_date = None
        appointment_time = None
        if desired_datetime_str:
            try:
                dt_obj = datetime.strptime(desired_datetime_str, '%Y-%m-%dT%H:%M')
                appointment_date = dt_obj.strftime('%Y-%m-%d')
                appointment_time = dt_obj.strftime('%H:%M')
            except ValueError:
                flash("Invalid desired date/time format. Please use a valid date and time.", "danger")
                return redirect(url_for('book_appointment'))


        # Get the organiser's email from the hidden field populated by JavaScript
        organiser_email_id = request.form.get('organiser_email_hidden')
        
        # Ensure that organiser_email_id is not empty if it's supposed to be present
        if not organiser_email_id:
            flash("Organiser details are missing. Please ensure you clicked 'Get Details' for the organiser.", "danger")
            return redirect(url_for('book_appointment'))

        new_appointment = Appointment(
            name=name,
            email=email,
            aadhar=id_number,
            phone_number=phone_number,
            phone_last4=phone_last4,
            purpose=purpose,
            appointment_id=appointment_id_gen,
            status='Pending',
            date=appointment_date, # Use the new date
            time=appointment_time, # Use the new time
            id_type=id_type,
            organiser_email_id=organiser_email_id # Storing the organiser's email
        )

        db.session.add(new_appointment)
        db.session.commit()

        # ✅ Send Confirmation Email with CSV here
        message = f"""
Dear {new_appointment.name},

Your appointment request has been submitted successfully.

Appointment ID: {new_appointment.appointment_id}
ID Type: {new_appointment.id_type}
ID Number: {new_appointment.aadhar}
Phone: {new_appointment.phone_number}
Purpose: {new_appointment.purpose}
Status: {new_appointment.status}
Organiser Email: {new_appointment.organiser_email_id}
Desired Date: {new_appointment.date if new_appointment.date else 'N/A'}
Desired Time: {new_appointment.time if new_appointment.time else 'N/A'}

You will be notified once your appointment is confirmed.

Regards,  
Tata Steel Appointment Team
""" 
        send_email(
            to_email=new_appointment.email,
            subject="Tata Steel Appointment Request Submitted",
            message=message,
            appointment=new_appointment  # Pass appointment object to attach CSV
        )

        flash(f"Appointment booked successfully! Your Appointment ID is: {appointment_id_gen}", "success")
        return redirect(url_for('track'))

    organisers = Organiser.query.all()
    return render_template('book_appointment.html', organisers=organisers)

@app.route('/verify-otp', methods=['GET', 'POST'])
def verify_otp():
    # This OTP verification is general. If specific to appointment, it needs pending_data logic.
    # Given the book_appointment now saves directly, this `verify_otp` is likely for general user flow (registration/forgot_password).
    flash("OTP verification logic is for general user flow (registration/forgot_password) here.", "info")
    return render_template('verify_otp.html')

@app.route('/resend-otp')
def resend_otp():
    flash("Resend OTP logic is for general user flow (registration/forgot_password) here.", "info")
    return redirect(url_for('verify_otp'))


@app.route('/track', methods=['GET', 'POST'])
def track():
    appointment_details = None
    if request.method == 'POST':
        appt_id = request.form['appointment_id'].strip()
        phone_last4 = request.form['phone_last4'].strip()

        # Change query to match appointment_id + last 4 digits of phone
        appointment = Appointment.query.filter_by(appointment_id=appt_id, phone_last4=phone_last4).first()

        if appointment:
            appointment_details = {
                'id': appointment.id,
                'name': appointment.name,
                'email': appointment.email,
                'phone_number': appointment.phone_number,
                'aadhar': appointment.aadhar,
                'purpose': appointment.purpose,
                'appointment_id': appointment.appointment_id,
                'status': appointment.status,
                'date': appointment.date,
                'time': appointment.time,
                'organiser_email_id': appointment.organiser_email_id, # Include this for tracking if needed
                'id_type': appointment.id_type # ADDED: Pass id_type to the template
            }
            return render_template('track_result.html', appt=appointment_details)
        else:
            flash("No appointment found with the provided details. Please check and try again.", "danger")

    return render_template('track.html')

@app.route('/verify_id_proof', methods=['POST'])
def verify_id_proof():
    data = request.json
    id_type = data.get('id_type')
    id_number = data.get('id_number')

    if not id_type or not id_number:
        return jsonify({"status": "error", "message": "ID type and ID number are required."}), 400

    # Validate based on format
    if id_type == "Aadhar":
        if re.fullmatch(r"\d{12}", id_number):
            return jsonify({"status": "success", "message": "Aadhar successfully verified!"}), 200
        else:
            return jsonify({"status": "error", "message": "Invalid Aadhar number format."}), 400

    elif id_type == "Pancard":
        if re.fullmatch(r"[A-Z]{5}[0-9]{4}[A-Z]", id_number):
            return jsonify({"status": "success", "message": "PAN Card successfully verified!"}), 200
        else:
            return jsonify({"status": "error", "message": "Invalid PAN number format."}), 400

    elif id_type == "Passport":
        if re.fullmatch(r"[A-Z][0-9]{7}", id_number):
            return jsonify({"status": "success", "message": "Passport successfully verified!"}), 200
        else:
            return jsonify({"status": "error", "message": "Invalid Passport number format."}), 400

    else:
        return jsonify({"status": "error", "message": "Unknown ID type."}), 400

# EMPLOYEE LOGIN (now uses Organiser model)
@app.route('/employee_login', methods=['GET', 'POST'])
def employee_login():
    if request.method == 'POST':
        organiser_email = request.form['employee_id'] # Using employee_id field for organiser email
        joining_date_str = request.form['joining_date'] # Using joining_date field
        
        try:
            joining_date_obj = datetime.strptime(joining_date_str, '%Y-%m-%d').date()
        except ValueError:
            flash("Invalid date format. Please use ISO (YYYY-MM-DD).", "danger")
            # Generate new captcha on error
            session['captcha_text'] = generate_captcha() 
            return render_template('employee_login.html', captcha_text=session['captcha_text'])

        # Authenticate against the Organiser model using email and joining_date
        organiser_record = Organiser.query.filter_by(email=organiser_email, joining_date=joining_date_obj).first()

        if organiser_record:
            session['employee_email'] = organiser_email # Store email in session as 'employee_email' for dashboard
            session['employee_logged_in'] = True # Mark as logged in
            
            # Generate and send OTP for organiser login
            otp = str(random.randint(100000, 999999))
            session['employee_otp'] = otp # Store OTP for verification
            session['captcha_text'] = generate_captcha() # Generate new captcha for OTP page
            
            if send_email(organiser_email, "Organiser Login OTP", f"Your OTP for login is: {otp}"):
                flash("OTP sent to your organiser email. Please verify to log in.", "info")
                return redirect(url_for('employ_otp')) # Correct endpoint for OTP verification
            else:
                flash("Failed to send OTP. Please contact support.", "danger")
        else:
            flash("Invalid Organiser Email ID or Joining Date.", "danger")
    
    # Generate new captcha on GET request or failed attempt
    captcha_text = generate_captcha()
    session['captcha_text'] = captcha_text
    return render_template('employee_login.html', captcha_text=captcha_text)


@app.route('/employ_otp', methods=['GET', 'POST']) # Endpoint name is 'employ_otp'
def employ_otp():
    # This route is for organiser (employee) OTP verification
    if not session.get('employee_email'): # Check if an organiser email is stored from previous login attempt
        flash("Please initiate organiser login first.", "warning")
        return redirect(url_for('employee_login'))

    if request.method == 'POST':
        user_otp = request.form['otp']
        entered_captcha = request.form['captcha_input'].strip().lower()
        session_captcha = session.get('captcha_text', '').lower()
        stored_otp = session.get('employee_otp')

        if entered_captcha != session_captcha:
            flash("Invalid CAPTCHA. Please try again.", "danger")
            session['captcha_text'] = generate_captcha() # Regenerate on failure
            return render_template('employ_otp.html', captcha_text=session['captcha_text'])

        if user_otp == stored_otp:
            session['employee_logged_in'] = True # Confirm login
            session.pop('employee_otp', None) # Clear OTP after use
            session.pop('captcha_text', None) # Clear captcha after use
            flash("Organiser login successful!", "success")
            return redirect(url_for('employee_dashboard')) # Redirect to organiser dashboard
        else:
            flash("Invalid OTP!", "danger")
            session['captcha_text'] = generate_captcha() # Regenerate on failure
            return render_template('employ_otp.html', captcha_text=captcha_text)

    # GET request - generate CAPTCHA
    captcha_text = generate_captcha()
    session['captcha_text'] = captcha_text
    return render_template('employ_otp.html', captcha_text=captcha_text)

@app.route('/resend_employee_otp', methods=['POST'])
def resend_employee_otp():
    organiser_email = session.get('employee_email') # Use the email stored from the login attempt
    if not organiser_email:
        return jsonify({"status": "error", "message": "Session expired. Please log in again."}), 400

    otp = str(random.randint(100000, 999999))
    session['employee_otp'] = otp # Update OTP in session

    if send_email(organiser_email, "Your new OTP", f"Your new OTP is: {otp}"):
        return jsonify({"status": "success", "message": "A new OTP has been sent to your email."}), 200
    else:
        return jsonify({"status": "error", "message": "Failed to send new OTP. Please try again."}), 500

@app.route('/employee-dashboard') # Endpoint name is 'employee_dashboard'
def employee_dashboard():
    if not session.get('employee_logged_in'):
        flash("Please login first.", "warning")
        return redirect(url_for('employee_login'))

    # Get the email of the currently logged-in employee (organiser)
    logged_in_organiser_email = session.get('employee_email')

    if logged_in_organiser_email:
        # Filter appointments to only show those requested with this organiser's email ID
        appointments = Appointment.query.filter_by(organiser_email_id=logged_in_organiser_email).all()
    else:
        # If for some reason the email isn't in session, show no appointments or redirect
        appointments = []
        flash("Could not retrieve organiser email. Please log in again.", "danger")
        return redirect(url_for('employee_login'))


    return render_template('employee_dashboard.html', appointments=appointments)

@app.route('/update_status', methods=['POST'])
def update_status():
    if not session.get('employee_logged_in'):
        return jsonify(status="error", message="Not logged in"), 401

    data = request.get_json()
    appointment_id = data.get('appointment_id')
    action = data.get('action')
    new_datetime = data.get('new_datetime')

    appointment = Appointment.query.get(appointment_id) # Assumes appointment_id is the primary key
    if not appointment:
        return jsonify(status="error", message="Appointment not found"), 404

    # Crucial security check: Ensure the logged-in organizer can only modify THEIR appointments
    logged_in_organiser_email = session.get('employee_email')
    if not logged_in_organiser_email or appointment.organiser_email_id != logged_in_organiser_email:
        return jsonify(status="error", message="Unauthorized: You can only update your own appointments."), 403 # Forbidden

    if action == 'decline':
        appointment.status = 'Declined'
        message = f"""
Dear {appointment.name},

Your appointment request (ID: {appointment.appointment_id}) has been DECLINED by the organizer.

Purpose of Meeting: {appointment.purpose}
Status: {appointment.status}
Organiser Email: {appointment.organiser_email_id}

Please contact the organizer or try booking another appointment if needed.

Regards,  
Tata Steel Appointment Team
"""
        send_email(
            to_email=appointment.email,
            subject="Tata Steel Appointment Declined",
            message=message,
            appointment=appointment
        )
        db.session.commit()
        return jsonify(status="success", message="Appointment declined.")
    elif action == 'accept' and new_datetime:
        try:
            # Parse the datetime string from the client
            dt_obj = datetime.strptime(new_datetime, '%Y-%m-%dT%H:%M')
            appointment.date = dt_obj.strftime('%Y-%m-%d')
            appointment.time = dt_obj.strftime('%H:%M')
            appointment.status = 'Accepted'
            
            message = f"""
Dear {appointment.name},

Good news! Your appointment request (ID: {appointment.appointment_id}) has been ACCEPTED by the organizer.

Date: {appointment.date}
Time: {appointment.time}
Purpose of Meeting: {appointment.purpose}
Status: {appointment.status}
Organiser Email: {appointment.organiser_email_id}

We look forward to your meeting.

Regards,  
Tata Steel Appointment Team
"""
            send_email(
                to_email=appointment.email,
                subject="Tata Steel Appointment Accepted",
                message=message,
                appointment=appointment
            )
            db.session.commit()
            return jsonify(status="success", message="Appointment accepted and scheduled.")
        except ValueError:
            return jsonify(status="error", message="Invalid datetime format. Use ISO (YYYY-MM-DDTHH:MM)"), 400
    return jsonify(status="error", message="Invalid action or missing datetime for accept action"), 400

# In your app.py, replace the placeholder for get_organiser_details
# Ensure 'request' and 'jsonify' are imported from flask

@app.route('/get_organiser_details', methods=['POST'])
def get_organiser_details():
    # It's a POST request, so get JSON data from the request body
    personal_number = request.json.get('personal_number')

    if not personal_number:
        return jsonify({"status": "error", "message": "Organiser Personal Number is required."}), 400

    # Query the Organiser model using the 'personal_number' column
    # This assumes 'personal_number' is unique and how you identify an organiser.
    organiser = Organiser.query.filter_by(personal_number=personal_number).first()

    if organiser:
        # If an organiser is found, return their details as a JSON object
        return jsonify({
            "status": "success",
            "name": organiser.name,
            "department": organiser.department,
            "designation": organiser.designation,
            "contact_no": organiser.contact_no,
            "email": organiser.email
        }), 200 # Return 200 OK for success
    else:
        # If no organiser is found
        return jsonify({"status": "error", "message": "Organiser not found with this personal number."}), 404 # Return 404 Not Found

# Initial data auto insert when app starts (only once)
with app.app_context():
    db.create_all()
    # Insert dummy Organiser data with joining_date
    if not Organiser.query.first():
        organisers = [
            Organiser(email='organiser1@tatasteel.com', joining_date=date(2022, 1, 15), name='David Lee', contact_no='1112223333', personal_number='ORG001', department='Security', designation='Guard'),
            Organiser(email='organiser2@tatasteel.com', joining_date=date(2023, 4, 10), name='Sarah Chen', contact_no='4445556666', personal_number='ORG002', department='HR', designation='Coordinator'),
            Organiser(email='organiser3@tatasteel.com', joining_date=date(2021, 7, 1), name='Michael Green', contact_no='7778889999', personal_number='ORG003', department='Admin', designation='Assistant')
        ]
        db.session.add_all(organisers)
        db.session.commit()
        print("Default organiser data inserted.")
    
    # Insert dummy User data (for regular user login)
    if not User.query.first():
        users = [
            User(email='user1@example.com', password='password1'),
            User(email='user2@example.com', password='password2')
        ]
        db.session.add_all(users)
        db.session.commit()
        print("Default user data added.")

    # Add dummy appointment data if the table is empty and no organiser_email_id is present
    # Check if any appointment already has organiser_email_id set (to avoid recreating on restart after first successful run)
    if not Appointment.query.filter(Appointment.organiser_email_id.isnot(None)).first():
        print("Inserting dummy appointment data for organizers...")
        app1 = Appointment(
            name='John Doe', email='john.doe@example.com', aadhar='123456789012',
            phone_number='9876543210', phone_last4='3210', purpose='Meeting about Project X',
            appointment_id='ABC12345', status='Pending', date='2025-07-15', time='10:00', id_type='Aadhar',
            organiser_personal_number='ORG001', organiser_email_id='organiser1@tatasteel.com'
        )
        app2 = Appointment(
            name='Jane Smith', email='jane.smith@example.com', aadhar='234567890123',
            phone_number='8765432109', phone_last4='2109', purpose='Discussion on new policy',
            appointment_id='DEF67890', status='Pending', date='2025-07-16', time='14:30', id_type='Pancard',
            organiser_personal_number='ORG002', organiser_email_id='organiser2@tatasteel.com'
        )
        app3 = Appointment(
            name='Alice Johnson', email='alice.j@example.com', aadhar='345678901234',
            phone_number='7654321098', phone_last4='1098', purpose='HR interview',
            appointment_id='GHI10111', status='Pending', date='2025-07-17', time='09:00', id_type='Passport',
            organiser_personal_number='ORG001', organiser_email_id='organiser1@tatasteel.com'
        )
        # Appointment for a third organizer (if you have one)
        app4 = Appointment(
            name='Bob Brown', email='bob.b@example.com', aadhar='456789012345',
            phone_number='6543210987', phone_last4='0987', purpose='Client meeting',
            appointment_id='JKL22334', status='Pending', date='2025-07-18', time='11:00', id_type='Aadhar',
            organiser_personal_number='ORG003', organiser_email_id='organiser3@tatasteel.com'
        )
        db.session.add_all([app1, app2, app3, app4])
        db.session.commit()
        print("Dummy appointment data inserted.")


if __name__ == '__main__':
    app.run(debug=True)
