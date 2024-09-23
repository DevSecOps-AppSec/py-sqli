
# SQL Injection Demo Application

This application demonstrates SQL Injection vulnerabilities, improper access controls, and forced browsing attacks. The goal is to showcase how misconfigurations and insecure coding practices can lead to severe security breaches in web applications.

## Features

- **Login Functionality**: Users can log in using predefined credentials stored in a local SQLite database.
- **Admin-Only Search Functionality**: The admin user can search for users by their ID. However, due to improper access controls, all logged-in users can access this page through forced browsing.
- **SQL Injection Vulnerability**: The login and search fields are vulnerable to SQL Injection, allowing attackers to extract all user data.

## Vulnerabilities Demonstrated

- **Error-Based SQL Injection**: The search functionality is intentionally left vulnerable, allowing attackers to manipulate the SQL query and retrieve sensitive data.
- **Login Bypass via SQL Injection**: The login page can be exploited to bypass authentication and gain unauthorized access.
- **Forced Browsing**: Non-admin users can access restricted admin pages by directly navigating to the URL, demonstrating the consequences of improper access control.

## Prerequisites

- Python 3.x
- Flask (`pip install flask`)
- SQLite (comes pre-installed with Python)

## Installation and Setup

1. **Clone the Repository**:

   ```bash
   git clone <repository-url>
   cd <repository-directory>
   ```

2. **Install Required Packages**:

   Make sure Flask is installed. If not, install it using pip:

   ```bash
   pip install flask
   ```

3. **Run the Application**:

   Start the Flask application using:

   ```bash
   python3 app.py
   ```

4. **Access the Application**:

   Open your browser and navigate to:

   ```
   http://127.0.0.1:8080/
   ```

## Usage

### 1. Login

- Use any of the predefined credentials to log in:

  - **Admin User**:
    - Username: `admin`
    - Password: `password123`
  - **Regular Users**:
    - `user1 / pass1`
    - `user2 / pass2`
    - `john_doe / john123`
    - `jane_doe / jane123`
    - `guest / guestpass`
    - `testuser / testpass`

### SQL Injection Bypass for Login

To exploit the SQL injection vulnerability on the login page, use the following payloads:

- **Username**:  
  ```sql
  ' OR '1'='1
  ```
- **Password**:  
  Enter anything or leave it blank since it will be ignored.

These inputs manipulate the SQL query, allowing unauthorized access to the application.

### 2. Forced Browsing Vulnerability

- Non-admin users will not see the "Search User by ID" option on the home page.
- However, they can access the page by directly navigating to `/search-user`.

### 3. SQL Injection Exploit on Search Page

- Access the "Search User by ID" page and enter the following vulnerable input:

  **SQL Injection Payload**:

  ```sql
  1 OR 1=1 --
  ```

- This payload manipulates the SQL query to return all user data from the database.

## Security Considerations

- **Do Not Use in Production**: This application is intentionally insecure and should never be deployed in a real environment.
- **SQL Injection**: The application lacks input sanitization, making it vulnerable to SQL Injection attacks.
- **Access Control**: Proper access control mechanisms are missing, allowing unauthorized access to admin functionalities.

## Learning Outcomes

- Understand the risks associated with SQL Injection and forced browsing.
- Learn how improper input handling and lack of access controls can expose sensitive data.
- Explore ways to mitigate such vulnerabilities by using parameterized queries and robust access control mechanisms.

## Improvements and Mitigations

To secure the application, consider the following improvements:

1. **Use Parameterized Queries**: Prevent SQL Injection by using prepared statements with parameterized queries.
2. **Implement Proper Access Controls**: Ensure that sensitive functionalities are accessible only to authorized users.
3. **Input Validation and Sanitization**: Validate and sanitize all user inputs to prevent malicious data from being processed.

## License

This project is for educational purposes only. Use it to understand vulnerabilities and how to secure applications against such attacks.

---

**Disclaimer**: This application is intentionally insecure and should only be used in a controlled environment for educational purposes.
