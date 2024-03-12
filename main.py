from flask import Flask, render_template, redirect, url_for, flash, request, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import RegisterForm, LoginForm, ForgotPasswordForm, PasswordResetForm
import smtplib
from datetime import datetime, timedelta
import time
import asyncio
import threading
import random
import string
import os

API_KEY = 'V2RNZOK9B0N58A8A'

app = Flask(__name__)


# Access environment variable
app.config['SECRET_KEY'] = os.environ['FLASK_KEY']
EMAIL = os.environ['FLASK_EMAIL']
PASSWORD = os.environ['FLASK_PASSWORD']


# CREATE DATABASE
app.config['SQLALCHEMY_DATABASE_URI'] = "postgres://investment_zqhr_user:zRdTvinwCZvQmyGIRqfT8DR0wbWq4TJ0@dpg-cnn7su021fec739a9lp0-a.oregon-postgres.render.com/investment_zqhr"
# app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///crypto_website.db'
# Optional: But it will silence the deprecation warning in the console.
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)


# CREATE TABLE
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(250), nullable=False)
    email = db.Column(db.String(250), unique=True, nullable=False)
    password = db.Column(db.String(250), nullable=False)
    balance = db.Column(db.Float, nullable=False, default=0.0)
    is_verified = db.Column(db.Boolean, default=False)
    verification_code = db.Column(db.String(10))
    reset_token = db.Column(db.String(20), nullable=True, unique=True)
    reset_token_expiration = db.Column(db.DateTime, nullable=True)
    deposits = db.relationship('Deposit', backref='user')
    investments = db.relationship('Investment', backref='user')
    # Add any other columns as needed for your requirements


class Deposit(db.Model):
    __tablename__ = "deposits"
    id = db.Column(db.Integer, primary_key=True)
    proposed_amount = db.Column(db.Float, nullable=False)
    amount = db.Column(db.Float, nullable=False, default=0.0)
    date = db.Column(db.Date, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))


class Investment(db.Model):
    __tablename__ = "investments"
    id = db.Column(db.Integer, primary_key=True)
    date = db.Column(db.Date, nullable=False)
    type = db.Column(db.String(250), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    profit = db.Column(db.Float, nullable=False, default=0.0)
    last_updated = db.Column(db.DateTime, nullable=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))


class Withdrawal(db.Model):
    __tablename__ = "withdrawals"
    id = db.Column(db.Integer, primary_key=True)
    date = db.Column(db.Date, nullable=False)
    amount = db.Column(db.Float, nullable=False, default=0.0)
    proposed_amount = db.Column(db.Float, nullable=False)
    wallet_address = db.Column(db.String(250), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))


db.init_app(app)

with app.app_context():
    db.create_all()

from datetime import date


def change_user_profit(email, new_profit):
    user_to_update = User.query.filter_by(email=email).first()
    if user_to_update:
        if not user_to_update.investments:  # Check if no investments exist
            new_investment = Investment(date=date.today(), type="placeholder", amount=0.0, profit=new_profit, user=user_to_update)
            db.session.add(new_investment)
        else:
            # Existing logic for updating profit for all investments
            for investment in user_to_update.investments:
                investment.profit = new_profit
        db.session.commit()
        print(f'User with email {email} investment profit updated successfully!')
    else:
        print(f'User with email {email} not found.')


# Example usage (replace with actual user ID and new email)
change_user_profit("mrevers02@yahoo.com",128000)


def calculate_profit(investment_id, start_time):
    with app.app_context():
        investment = Investment.query.get(investment_id)
        if investment:
            elapsed_time = time.time() - start_time

            # Check if 5 minutes have elapsed
            if elapsed_time >= 604800:
                # retrieve user associated with the investment
                user = User.query.get(investment.user_id)
                # Add the investment profit to the user's balance
                # user = investment.user_id  # Replace with the actual relationship to the User model
                user.balance += investment.profit
                user.balance += investment.amount
                investment.profit = 0
                db.session.commit()
                return

            if investment.type == 'Beginner Plan':
                profit = investment.amount * 0.08
            elif investment.type == 'Intermediate Plan':
                profit = investment.amount * 0.135
            elif investment.type == 'Manager Plan':
                profit = investment.amount * 0.28

            # profit = investment.amount * 0.08
            investment.profit += profit
            db.session.commit()

            # Start a new timer for the next profit calculation
            threading.Timer(86400, calculate_profit, args=[investment_id, start_time]).start()


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.route('/')
def home():
    year = datetime.now().year
    return render_template('index.html', date=year)


@app.route("/contact", methods=["GET", "POST"])
def contact():
    year = datetime.now().year
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        message = request.form['message']
        send_email(name, email, message, recipient_email=email)
        return render_template("contact.html", msg_sent=True, date=year)
    return render_template('contact.html', date=year)


def send_email(name, email, message, recipient_email):
    email_message = f"Subject: New Message\n\nName: {name}\nEmail: {email}\nMessage: {message}"
    threading.Thread(target=send_email_thread, args=(email_message, recipient_email)).start()


def send_email_thread(email_message, recipient_email):
    with smtplib.SMTP_SSL("mail.privateemail.com", 465) as connection:
        connection.login(EMAIL, PASSWORD)
        connection.sendmail(from_addr=EMAIL, to_addrs=recipient_email, msg=email_message)


@app.route('/login', methods=['GET', 'POST'])
def login():
    login_form = LoginForm()
    if login_form.validate_on_submit():
        email = request.form.get('email')
        password = request.form.get('password')

        # Find user by email entered.
        user = User.query.filter_by(email=email).first()
        if not user:
            flash("Email doesn't exist. Please check the email and try again.", 'error')
            return redirect(url_for('login'))
        else:
            if password == user.password:
                if user.is_verified:  # Check if the user is verified
                    login_user(user)
                    return redirect('dashboard')
                else:
                    verification_code = ''.join(random.choices(string.digits, k=6))

                    user.verification_code = verification_code
                    db.session.commit()

                    # Store the email in the session
                    session['email'] = email

                    # Send the verification code to the user's email
                    send_email('Verification Code', user.email, verification_code, recipient_email=email)

                    flash("Account not verified. Please verify your account.", 'error')
                    return render_template('register_verification.html', form=login_form, email=email)
            else:
                flash("Password is not correct", 'error')
                return redirect(url_for('login'))

    return render_template('login.html', form=login_form)


# Route for "Forgot Password" form
@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    form = ForgotPasswordForm()

    if form.validate_on_submit():
        email = form.email.data.lower()

        user = User.query.filter_by(email=email).first()

        if user:
            # Generate a random token (for simplicity, just using a random string)
            token = ''.join(random.choices(string.ascii_letters + string.digits, k=6))
            user.reset_token = token
            user.reset_token_expiration = datetime.utcnow() + timedelta(minutes=15)
            db.session.commit()

            # Send password reset email to user's email with token
            send_email('Password Reset',
                       f'Your OTP:{token}', user.email, recipient_email=email)
            flash(f"Password reset OTP has been sent to your {email}.")
            return redirect(url_for('reset_password'))
        else:
            flash('Email not found. Please check and try again', 'error')
            return redirect(url_for('forgot_password', form=form))

    return render_template('forgot_password.html', form=form)


@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    form = PasswordResetForm()
    if request.method == 'POST':
        if form.validate_on_submit():
            token = request.form.get('token')
            user = User.query.filter_by(reset_token=token).first()

            # Check if the user is found in the database
            if not user:
                flash('The password reset code is invalid', 'error')
                user.reset_token = None
                user.reset_token_expiration = None
                db.session.commit()
                return redirect(url_for('login'))

            # Check if the token has expired
            if user.reset_token_expiration and user.reset_token_expiration < datetime.utcnow():
                flash('The password reset code has expired.', 'error')
                user.reset_token = None
                user.reset_token_expiration = None
                db.session.commit()
                return redirect(url_for('login'))

            # Validate the OTP from the form
            if token and token != user.reset_token:
                flash('Invalid OTP. Please check and try again.', 'error')

            else:
                # Update the user's password
                user.password = form.password.data
                user.reset_token = None
                user.reset_token_expiration = None
                db.session.commit()

                send_email('Password Reset Successful',
                           f'Dear {user.name},\nYou have successfully reset your password.\n Please login with the new password',
                           user.email, recipient_email=user.email)
                flash('Your password has been reset. You can now log in with your new password.', 'success')
                return redirect(url_for('login'))
        else:
            flash('Your Passwords must match', 'error')

    return render_template('reset_password.html', form=form)


@app.route('/register', methods=['GET', 'POST'])
def register():
    register_form = RegisterForm()
    if register_form.validate_on_submit():
        email = request.form.get('email')
        name = request.form.get('name')
        password = request.form.get('password')
        user = User.query.filter_by(email=email).first()
        if user:
            flash(" You've already signed up with that email. Login instead")
            return redirect('login')
        elif register_form.password.data != register_form.confirm_password.data:
            flash(" Your passwords don't match")
            return redirect('register')
        else:
            # Generate a random verification code
            verification_code = ''.join(random.choices(string.digits, k=6))

            new_user = User()
            new_user.name = name
            new_user.email = email.lower()
            new_user.password = password
            new_user.verification_code = verification_code

            db.session.add(new_user)
            db.session.commit()

            # Store the email in the session
            session['email'] = email

            # Send the verification code to the user's email
            send_email('Verification Code', new_user.email, verification_code, recipient_email=email)

            return render_template('register_verification.html', form=register_form, email=email)
    return render_template('register.html', form=register_form)


@app.route('/register/verify', methods=['POST'])
def register_verify():
    register_form = RegisterForm()  # Use the same RegisterForm to handle the verification code input
    email = session.get('email')
    otp1 = str(request.form.get('otp1'))
    otp2 = str(request.form.get('otp2'))
    otp3 = str(request.form.get('otp3'))
    otp4 = str(request.form.get('otp4'))
    otp5 = str(request.form.get('otp5'))
    otp6 = str(request.form.get('otp6'))
    verification_code = otp1 + otp2 + otp3 + otp4 + otp5 + otp6
    user = User.query.filter_by(email=email).first()

    if user and verification_code == user.verification_code:
        if verification_code == user.verification_code:
            user.is_verified = True
            db.session.commit()
            flash("Account verified successfully. You can now log in.")
            return redirect(url_for('login'))

    flash("Invalid verification code. Please try again.")
    return render_template('register_verification.html', email=email, form=register_form)


@app.route('/dashboard')
@login_required
def dashboard():
    name = current_user.name
    balance = current_user.balance

    # Query all deposit amounts for the current user
    deposits = Deposit.query.filter_by(user_id=current_user.id).all()
    # Extract the deposit amounts
    deposit_amounts = [deposit.amount for deposit in deposits]
    last_deposit = next((amount for amount in reversed(deposit_amounts) if amount != 0.0), 0.0)

    # Query all withdrawal amounts for the current user
    withdrawals = Withdrawal.query.filter_by(user_id=current_user.id).all()
    # Extract the withdrawal amounts
    withdrawal_amounts = [withdrawal.amount for withdrawal in withdrawals]
    last_withdrawal = next((amount for amount in reversed(withdrawal_amounts) if amount != 0.0), 0.0)

    # Query all investments for the current user
    investments = Investment.query.filter_by(user_id=current_user.id).all()
    # Calculate the total profit from investments
    total_profit = sum(investment.profit for investment in investments)

    return render_template('dashboard.html', name=name.upper(), balance=balance, last_deposit=last_deposit,
                           last_withdrawal=last_withdrawal, total_profit=total_profit)


@app.route('/withdraw', methods=['GET', 'POST'])
@login_required
def withdraw():
    name = current_user.name
    if request.method == 'POST':
        proposed_amount = float(request.form['usdAmount'])
        wallet_address = request.form['wallet_address']

        if current_user.balance < proposed_amount:
            flash('Withdrawal amount exceeds available balance')
            return redirect(url_for('withdraw'))

        # Create a new withdraw instance
        new_withdrawal = Withdrawal(proposed_amount=proposed_amount, date=datetime.now(), wallet_address=wallet_address,
                                    user_id=current_user.id)

        # Add the deposit to the database
        db.session.add(new_withdrawal)
        db.session.commit()

        # Show a flash message for successful withdrawal
        flash('Withdrawal submitted successfully')

        # Redirect to a success page or perform any other necessary actions
        return redirect(url_for('dashboard'))
    return render_template('withdraw.html', name=name)


@app.route('/admin/confirm_withdrawal/<int:withdrawal_id>', methods=['POST'])
@login_required
def confirm_withdrawal(withdrawal_id):
    if current_user.id != 1:  # Only allow access to user with ID 1 (admin)
        return redirect(url_for('home'))

    # Retrieve the withdrawal from the database
    withdrawal = Withdrawal.query.get(withdrawal_id)

    # Check if the withdrawal has already been confirmed
    if withdrawal.amount == withdrawal.proposed_amount:
        flash('Withdrawal already confirmed')
        return redirect(url_for('admin_dashboard'))

    # retrieve user associated with the withdrawal
    user = User.query.get(withdrawal.user_id)

    # Check if the proposed amount exceeds the user's available balance
    if withdrawal.proposed_amount > user.balance:
        flash('Withdrawal amount exceeds available balance')
        return redirect(url_for('admin_dashboard'))

    # Update the amount in the withdrawal table
    withdrawal.amount = withdrawal.proposed_amount

    # Update the user's balance in the user table
    user.balance -= withdrawal.proposed_amount

    # Commit the changes to the database
    db.session.commit()

    flash('Withdrawal confirmed')
    # Redirect to the admin dashboard or any other desired page
    return redirect(url_for('admin_dashboard'))


@app.route('/deposit', methods=['GET', 'POST'])
@login_required
def deposit():
    name = current_user.name
    if request.method == 'POST':
        proposed_amount = float(request.form['usdAmount'])

        # Create a new deposit instance
        new_deposit = Deposit(proposed_amount=proposed_amount, date=datetime.now(), user_id=current_user.id)

        # Add the deposit to the database
        db.session.add(new_deposit)
        db.session.commit()

        # Redirect to a success page or perform any other necessary actions
        return redirect(url_for('wallets'))

    return render_template('deposit.html', name=name)


@app.route('/admin/confirm_deposit/<int:deposit_id>', methods=['POST'])
@login_required
def confirm_deposit(deposit_id):
    if current_user.id != 1:  # Only allow access to user with ID 1 (admin)
        return redirect(url_for('home'))

    # Retrieve the deposit from the database
    deposit = Deposit.query.get(deposit_id)

    # Check if the deposit has already been confirmed
    if deposit.amount == deposit.proposed_amount:
        flash('Deposit already confirmed')
        return redirect(url_for('admin_dashboard'))

    # Update the amount in the deposit table
    deposit.amount = deposit.proposed_amount

    # Update the user's balance in the user table
    user = User.query.get(deposit.user_id)
    user.balance += deposit.proposed_amount

    # Commit the changes to the database
    db.session.commit()

    flash('Deposit confirmed')
    # Redirect to the admin dashboard or any other desired page
    return redirect(url_for('admin_dashboard'))


@app.route('/wallets')
@login_required
def wallets():
    name = current_user.name

    # Query all deposit amounts for the current user
    deposits = Deposit.query.filter_by(user_id=current_user.id).all()
    # Extract the deposit amounts
    deposit_amounts = [deposit.proposed_amount for deposit in deposits]
    last_deposit = next((amount for amount in reversed(deposit_amounts) if amount != 0.0), 0.0)

    return render_template('wallets.html', name=name, amount=last_deposit)


@app.route('/profile')
@login_required
def profile():
    name = current_user.name
    return render_template('profile.html', name=name)


@app.route('/about')
def about():
    year = datetime.now().year
    return render_template('about.html', date=year)


@app.route('/services')
def services():
    year = datetime.now().year
    return render_template('services.html', date=year)


@app.route('/faqs')
def faqs():
    year = datetime.now().year
    return render_template('faqs.html', date=year)


@app.route('/invest', methods=['GET', 'POST'])
def invest():
    name = current_user.name
    if request.method == 'POST':
        start_time = time.time()
        investment_type = request.form['investment_type']
        amount = float(request.form['investment_amount'])

        # Check if the user has sufficient balance
        user = current_user  # Replace with the actual user ID
        if user.balance < amount:
            flash('Insufficient balance. Please deposit more funds.')
            return redirect(url_for('invest'))

        # Deduct the investment amount from the user's balance
        user.balance -= amount

        # if investment_type == 'Basic package':
        #     profit = amount * 0.06

        # Create a new investment
        new_investment = Investment(
            date=datetime.now(),
            user_id=user.id,
            type=investment_type,
            amount=amount,
            last_updated=datetime.now()
        )
        db.session.add(new_investment)
        db.session.commit()

        # Start calculating profit for the new investment
        threading.Timer(86400, calculate_profit, args=[new_investment.id, start_time]).start()

        flash('Investment successful')
        return redirect(url_for('invest'))

    return render_template('invest.html', name=name)


@app.route('/admin/dashboard')
@login_required
def admin_dashboard():
    user_id = current_user.id  # Implement a function to get the currently authenticated user ID
    if user_id == 1:  # Only allow access to user with ID 1 (admin)
        users = User.query.all()  # Retrieve all user data from the user table
        deposits = Deposit.query.all()  # Query all deposits from the database
        withdrawals = Withdrawal.query.all()
        investments = Investment.query.all()
        return render_template('admin.html', users=users, deposits=deposits, withdrawals=withdrawals,
                               investments=investments)
    else:
        return redirect(url_for('home'))  # Redirect to the home page or a restricted access page


@app.route('/admin/dashboard/<int:user_id>', methods=['POST'])
@login_required
def update_balance(user_id):
    # user_id = request.form.get('user_id')
    new_balance = request.form.get('balance')

    # Retrieve the user from the database based on the user_id
    user = User.query.get(user_id)

    if user:
        user.balance = new_balance
        # Save the updated user balance to the database
        db.session.commit()
        flash('Balance updated successfully!', 'success')
    else:
        flash('User not found!', 'error')

    return redirect(url_for('admin_dashboard'))


@app.route('/admin/delete/<int:user_id>', methods=['GET', 'POST'])
@login_required
def delete_user(user_id):
    user = User.query.get(user_id)  # Retrieve the user from the database
    if user:
        db.session.delete(user)  # Delete the user from the database
        db.session.commit()

    return redirect(url_for('admin_dashboard'))


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


def run_event_loop():
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    loop.run_forever()


if __name__ == '__main__':
    # Start the event loop in a separate thread
    event_loop_thread = threading.Thread(target=run_event_loop)
    event_loop_thread.start()

    app.run(debug=False)
