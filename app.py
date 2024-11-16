import sqlite3
import bcrypt
import re



# Function to hash the password using bcrypt
def hash_password(password):
    # Generate a salt
    salt = bcrypt.gensalt()
    # Hash the password using the salt
    password_hash = bcrypt.hashpw(password.encode('utf-8'), salt)
    return password_hash, salt

# Function to validate password
def check_password(stored_hash, salt, password):
    return bcrypt.checkpw(password.encode('utf-8'), stored_hash)

# Function to validate password strength
def validate_password_strength(password):
    """
    Validates the strength of the password based on length, uppercase letters, numbers, and special characters.
    """
    if len(password) < 8:
        print("Password must be at least 8 characters.")
        return False
    if not re.search(r'[A-Z]', password):
        print("Password must contain at least one uppercase letter.")
        return False
    if not re.search(r'[a-z]', password):
        print("Password must contain at least one lowercase letter.")
        return False
    if not re.search(r'[0-9]', password):
        print("Password must contain at least one number.")
        return False
    if not re.search(r'[@$!%*?&]', password):
        print("Password must contain at least one special character.")
        return False
    return True

# Store user email, hashed password, and salt into the database
def store_user(email, password):
    """
    This function stores the email, hashed password, and salt in the database.
    """
    email = email.lower().strip()
    # Check if the password is strong before proceeding
    if not validate_password_strength(password):
        print("Password does not meet the strength criteria. Please choose a stronger password.")
        return
    
    # Hash password using bcrypt (alternatively can use hash_password_argon2)
    password_hash, salt = hash_password(password)
    
    # Check if the email is already in the database
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute("SELECT COUNT(*) FROM users WHERE email=?", (email,))
    result = c.fetchone()  # Get the result (should return a tuple with the count)
    conn.close()

    if result and result[0] > 0:
        print("Email already registered. Please choose another email.")
        return

    # If the email is not already registered, store it
    try:
        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        c.execute("INSERT INTO users (email, password_hash, salt) VALUES (?, ?, ?)", 
                  (email, password_hash, salt))  # Store as byte strings
        conn.commit()
        print(f"User {email} registered successfully!")
    except sqlite3.DatabaseError as e:
        print(f"Database error: {e}")
    finally:
        conn.close()
        
# Validate the user's password during login
def validate_user(email, password):
    """
    This function validates the user's login credentials by checking if the password matches the stored hash.
    """
    email = email.lower().strip()
    
    try:
        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        c.execute("SELECT password_hash, salt FROM users WHERE email=?", (email,))
        result = c.fetchone()
        
        if result:
            stored_hash, salt = result
            # Check the password using bcrypt
            if bcrypt.checkpw(password.encode('utf-8'), stored_hash): 
                print("Login successful!")
            else:
                print("Incorrect password.")
        else:
            print("User not found.")
    except sqlite3.DatabaseError as e:
        print(f"Database error: {e}")
    finally:
        conn.close()



def create_table():
    try:
        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        c.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT UNIQUE NOT NULL,
                password_hash BLOB NOT NULL,
                salt BLOB NOT NULL
            )
        ''')
        conn.commit()
    except sqlite3.DatabaseError as e:
        print(f"Database error: {e}")
    finally:
        conn.close()
    

# Main function to run the program
def main():
    create_table() 
    
    # Register a new user (for testing purposes)
    email = input("Enter your email: ")
    password = input("Enter your password: ")

    if validate_password_strength(password):
        store_user(email, password)
        print(f"User {email} registered successfully!")
        
    # Validate user login (for testing purposes)
    login_email = input("Enter your email to login: ")
    login_password = input("Enter your password to login: ")
    
    validate_user(login_email, login_password)

if __name__ == '__main__':
    main()
