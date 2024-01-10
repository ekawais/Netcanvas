from flask import Flask, render_template, redirect, url_for, session, flash, request
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email, ValidationError
import bcrypt 
from flask_mysqldb import MySQL
from scapy.all import rdpcap, IP
import re 
import os



app = Flask(__name__)

# MySQL Configuration
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = ''
app.config['MYSQL_DB'] = 'netcanvas'
app.secret_key = 'myFlaskNetCanvasApp'

mysql = MySQL(app)

class RegisterForm(FlaskForm):
    name = StringField("Name", validators=[DataRequired()])
    email = StringField("Email", validators=[DataRequired(), Email()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Register")

    def validate_email(self, field):
        cursor = mysql.connection.cursor()
        cursor.execute("SELECT * FROM admin where email=%s", (field.data,))
        admin = cursor.fetchone()
        cursor.close()
        if admin:
            raise ValidationError('Email Already Taken')
    

class LoginForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired(), Email()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Login")
    
class AdminLoginForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired(), Email()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Login")

class AdminRegisterForm(FlaskForm):
    name = StringField("Name", validators=[DataRequired()])
    email = StringField("Email", validators=[DataRequired(), Email()])
    password = PasswordField("Password", validators=[DataRequired()])
    license_key = StringField("License Key", validators=[DataRequired()])
    submit = SubmitField("Register")

    def validate_email(self, field):
        cursor = mysql.connection.cursor()
        cursor.execute("SELECT * FROM admin where email=%s", (field.data,))
        admin = cursor.fetchone()
        cursor.close()
        if admin:
            raise ValidationError('Email Already Taken')

    def validate_license_key(self, field):
        entered_key = field.data
        valid_license_key = 'A052-L140-H142'

        if entered_key != valid_license_key:
            raise ValidationError('Invalid License Key')

def password_checks(password):
    
    if len(password) < 8:
        return "Password contain at least 8 characters"
    if not any(char.isupper() for char in password):
        return "Password msut contain one Upper case character"
    if not re.search(r'[!@#$%^&*(),.?:{}<>|]',password):
        return "Password must contain one special character"
    else:
        return "Password is Valid"

@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    else:
        return redirect(url_for('login'))
@app.route('/admin')
def admin_index():
    if 'admin_id' in session:
        return redirect(url_for('admin_dashboard'))
    else:
        return redirect(url_for('admin_login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    form = LoginForm()
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data

        cursor = mysql.connection.cursor()
        cursor.execute("SELECT * FROM users WHERE email=%s", (email,))
        user = cursor.fetchone()
        cursor.close()
        if user and bcrypt.checkpw(password.encode('utf-8'), user[3].encode('utf-8')):
            session['user_id'] = user[0]
            return redirect(url_for('dashboard'))
        else:
            flash("Login failed. Please check your email and password",'danger')
            return redirect(url_for('login'))

    return render_template('login.html', form=form)
# Function to capture packets
def read_packets(path):
    packets = []
    pcap_file = path

    try:
        pkts = rdpcap(pcap_file)
        for packet in pkts:
            packet_details = {
                'source_ip': packet[IP].src,
                'destination_ip': packet[IP].dst,
                'protocol': packet[IP].proto,
                'packet_length': len(packet),
                'packet_info': repr(packet),
            }
            packets.append(packet_details)
    except Exception as e:
        print(f"An error occurred: {e}")
    
    return packets


@app.route('/start_capture', methods=['GET', 'POST'])
def start_capture():
    if 'user_id' in session:
        user_id = session['user_id']

        cursor = mysql.connection.cursor()
        cursor.execute("SELECT * FROM users where id=%s",(user_id,))
        user = cursor.fetchone()
        cursor.close()
        if request.method == 'POST':
            pcapFile = request.files['pcap_file']
            if pcapFile:
                capture_packet = read_packets(pcapFile)

                file_name = pcapFile.filename

                return render_template('captured_packets.html', packets=capture_packet)
            else:
                flash('PCAP FILE NOT FOUND','danger')
                return redirect(url_for('start_capture'))
        else:
            return render_template('captured_packets.html', user=user) 
    else:
        return redirect(url_for('login'))


@app.route('/dashboard')
def dashboard():
    if 'user_id' in session:
        user_id = session['user_id']
        cursor = mysql.connection.cursor()
        cursor.execute("SELECT * FROM users where id=%s",(user_id,))
        user = cursor.fetchone()
        cursor.close()
        print(user)

        if user:
            return render_template('dashboard.html',user=user)
    return redirect(url_for('login'))

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash("You have been logged out successfully.",'success')
    return redirect(url_for('login'))


@app.route('/admin/register', methods=['GET', 'POST'])
def admin_register():
    if 'admin_id' in session:
        return redirect(url_for('admin_dashboard'))

    form = AdminRegisterForm()
    if form.validate_on_submit():
        name = form.name.data
        email = form.email.data
        password = form.password.data

        password_check_validation = password_checks(password)

        if password_check_validation == "Password is Valid":
            hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

            cursor = mysql.connection.cursor()
            cursor.execute("INSERT INTO admin (name, email, password) VALUES (%s, %s, %s)", (name, email, hashed_password))
            mysql.connection.commit()
            cursor.close()
            flash('Admin register successfully!','success')
            return redirect(url_for('admin_login'))
        else:
            flash(password_check_validation,'danger')
            return render_template('admin_register.html', form=form)

    return render_template('admin_register.html', form=form)



@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if 'admin_id' in session:
        return redirect(url_for('admin_dashboard'))
    form = AdminLoginForm()
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data
        isAdmin= 1

        cursor = mysql.connection.cursor()
        cursor.execute("SELECT * FROM admin WHERE email=%s and isAdmin=%s", (email,isAdmin))
        admin = cursor.fetchone()
        cursor.close()

        print(f"Email and IsAdmin : {admin}")
        print(f"Password Admin : {bcrypt.checkpw(password.encode('utf-8'), admin[3].encode('utf-8'))}")

        functions_list = dir(bcrypt)
        print(functions_list)

        if admin and bcrypt.checkpw(password.encode('utf-8'), admin[3].encode('utf-8')):

            session['admin_id'] = admin[0]
            flash("Admin login successful!","success")
            return redirect(url_for('admin_dashboard'))
        else:
            flash("Admin login failed. Please check your email and password.",'danger')
            return redirect(url_for('admin_login'))

    return render_template('admin_login.html', form=form)

@app.route('/admin/dashboard')
def admin_dashboard():
    if 'admin_id' in session:
        admin_id = session['admin_id']
        # For admin
        cursor_admin = mysql.connection.cursor()
        cursor_admin.execute("SELECT * FROM admin WHERE id=%s",(admin_id,))
        admin = cursor_admin.fetchone()
        cursor_admin.close()
        # For User List
        cursor = mysql.connection.cursor()
        cursor.execute("SELECT * FROM users")
        users = cursor.fetchall()
        cursor.close()
        
      
        print(f"Admin Id and Data {admin}")
       
        return render_template('admin_dashboard.html', users=users, admin = admin)
    else:
        flash("Please log in as an admin.",'warning')
        return redirect(url_for('admin_login'))
    
@app.route('/admin/add_user', methods=['GET', 'POST'])
def admin_add_user():
    if 'admin_id' in session:

        cursor = mysql.connection.cursor()
        cursor.execute("SELECT * FROM admin WHERE id=%s", (session['admin_id'],))
        admin = cursor.fetchone()
        form = RegisterForm()

        if form.validate_on_submit():
            name = form.name.data
            email = form.email.data
            password = form.password.data

            password_check_validation = password_checks(password)

            if password_check_validation == "Password is Valid":
                # Check the email already exists in the database
                cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
                existing_user = cursor.fetchone()

                if existing_user:
                    flash("This email is already taken. Please use a different email.", 'danger')
                else:
                    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
                    cursor.execute("INSERT INTO users (name, email, password) VALUES (%s, %s, %s)", (name, email, hashed_password))
                    mysql.connection.commit()
                    flash("User added successfully!", 'success')
                    return redirect(url_for('admin_dashboard'))
            else:
                flash(password_check_validation , 'danger')
                return render_template('admin_add_user.html',form=form)

        cursor.close()
        return render_template('admin_add_user.html', form=form,admin = admin)
    flash("Please! login as Admin First!","danger")
    return redirect(url_for('admin_login'))

@app.route('/admin/delete_user/<int:user_id>', methods=['POST'])
def admin_delete_user(user_id):
    print("Attempting to delete user:", user_id)  # Check if the route is being accessed

    if 'admin_id' not in session:
        flash("Please log in as an admin.")
        return redirect(url_for('admin_login'))

    print("Admin ID in session:", session['admin_id'])  # Check the admin ID in the session

    cursor = mysql.connection.cursor()
    cursor.execute("SELECT * FROM admin WHERE id=%s", (session['admin_id'],))
    admin = cursor.fetchone()

    print("Admin from database:", admin)  # Check if the admin is retrieved properly

    

    cursor.execute("DELETE FROM users WHERE id=%s", (user_id,))
    mysql.connection.commit()
    cursor.close()

    flash("User deleted successfully!",'danger')
    return redirect(url_for('admin_dashboard'))


@app.route('/admin/logout')
def admin_logout():
    session.pop('admin_id', None)
    flash("You have been logout successfully!", "success")
    return redirect(url_for('admin_login'))
   

if __name__ == '__main__':
    app.run(debug=True)
