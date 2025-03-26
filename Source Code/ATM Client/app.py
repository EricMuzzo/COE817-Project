from flask import Flask, render_template, request, redirect, url_for, session

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'  # Replace with a strong secret key

# -------------------------
# Route: Home/Index
# -------------------------
@app.route('/')
def index():
    """
    If the user is logged in, redirect to the dashboard.
    Otherwise, send them to the login page.
    """
    if 'username' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

# -------------------------
# Route: Login Page (GET, POST)
# -------------------------
@app.route('/login', methods=['GET', 'POST'])
def login():
    """
    GET: Render the login page to allow the user to input their credentials.
    
    POST: Process the login form submission.
         - Collect the username and password from the submitted form.
         - TODO: Encrypt the credentials using the session keys after initiating the key distribution protocol.
         - TODO: Send the encrypted login data to the bank server via a secure WebSocket connection.
         - TODO: Receive and decrypt the response from the bank server.
         - If authentication is successful, store the user session and redirect to the dashboard.
         - If authentication fails, display an error message and reload the login page.
    
    Expected Server Behavior:
         - The server receives the encrypted credentials.
         - It decrypts them, authenticates the user, and sends back a confirmation message.
    """
    error = None
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        # TODO: Encrypt the credentials using the session's encryption key.
        # TODO: Initiate the authenticated key distribution protocol if not already done.
        # TODO: Send the encrypted login data to the bank server via WebSocket.
        # TODO: Receive and handle the server's response (authenticate or reject).
        
        # For now, simulate a successful login if both fields are provided.
        if username and password:
            session['username'] = username
            return redirect(url_for('dashboard'))
        else:
            error = "Invalid credentials. Please try again."
    
    return render_template('login.html', error=error)

# -------------------------
# Route: Dashboard / Transaction Page (GET)
# -------------------------
@app.route('/dashboard')
def dashboard():
    """
    Render the main dashboard where the user can perform transactions.
    
    This page should include:
         - Display of the user's current account details (to be retrieved via secure WebSocket).
         - Options for transaction actions such as deposits, withdrawals, and balance inquiries.
         - Embedded JavaScript to establish and manage the secure WebSocket connection to the bank server.
    
    Expected Server Behavior for Transactions:
         - The bank server will receive encrypted transaction requests,
           decrypt and process them, then send back encrypted responses.
         - The client will decrypt the response and update the display accordingly.
    """
    if 'username' not in session:
        return redirect(url_for('login'))
    
    return render_template('dashboard.html')

# -------------------------
# Route: Logout
# -------------------------
@app.route('/logout')
def logout():
    """
    Clears the current user session and redirects back to the login page.
    """
    session.clear()
    return redirect(url_for('login'))

# -------------------------
# Main Entry Point
# -------------------------
if __name__ == '__main__':
    # Run the Flask app with debugging enabled.
    app.run(debug=True)
