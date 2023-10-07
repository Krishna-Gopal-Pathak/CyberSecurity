## OWASP TOP 10
- A01:2021-Broken Access Control 
- A02 Cryptographic Failures
- A03 Injection
- A04:2021-Insecure Design
- A05:2021-Security Misconfiguration 
- A06:2021-Vulnerable and Outdated Components
- A07:2021-Identification and Authentication Failures 
- A08:2021-Software and Data Integrity Failures 
- A09:2021-Security Logging and Monitoring Failures 
- A10:2021-Server-Side Request Forgery


## Broken Access Control
- Allow unauthorized users to gain access to sensitive data or systems.
- This can happen when controls such as authentication and authorization are not properly implemented

**Types of Broken Access Control Vulnerabilities**
- Insecure direct object references
- Lack of restriction on URL parameters
- Security misconfiguration
- Mass assignment

**Broken Access Control Attacks**
- Brute Force Attacks
- Session Hijacking
- Man-in-the-Middle Attacks
- Replay Attacks
- Privilege Escalation Attacks


**Prevention**
- Implement least privilege
- MFA
- Network segmentation 


## SQL Injection
- Attacker manipulate SQL queries by injecting malicious input.
- Gain unauthorized access to database.

**Vulnerability Include**
- Data Breaches
- Denial of Service Attacks
- Server Takeover

**Prevent**
- Proper validate all user input.
- Use secure Database Configuration.

1. Classic SQL Injection (SQLi)
2. Blind SQL Injection
4. Time-Based Blind SQL Injection
5. Boolean-Based Blind SQL Injection
6. Out-of-Band SQL Injection
7. Union-Based SQL Injection
8. Second-Order SQL Injection
9. Time-Based Blind Second-Order SQL Injection
10. Content-Based Blind Second-Order SQL Injection
11. Error-Based SQL Injection
12. Function-Based SQL Injection
13. Stored Procedure Injection
14. Inferential SQL Injection:Also known as "blind SQL injection,"

**1. Classic SQL Injection (SQLi)**
- Attacker manipulates an application's SQL query by injecting malicious SQL code into user-provided input fields or parameters.
   
Suppose you have a web application with a login form that uses the following SQL query to check user credentials:
```
SELECT * FROM users WHERE username = '$username' AND password = '$password';
```
- The application takes user inputs for username and password.
- An attacker enters the following as the username input: admin' OR '1'='1.
```
SELECT * FROM users WHERE username = 'admin' OR '1'='1' AND password = '$password';
```
In this case, because '1'='1' always evaluates to true, the query returns all rows from the users table, effectively granting unauthorized access to the application as the admin user.

**2. Blind SQL injection**
- Blind SQL injection is a type of SQL injection attack that exploits vulnerabilities in web applications to steal data by asking the database a series of true or false questions 


**3. Boolean-Based Blind SQL Injection**
- Boolean-Based Blind SQL Injection an attacker injects malicious SQL code to determine if their injected condition is true or false.
- They do this by observing the application's behavior or responses, as the application typically does not directly display database error messages or query results to the user.

**Prevention**
- Avoid displaying detailed error messages to users
- Input Validation

**4. Time-Based Blind SQL Injection**
- Time-Based Blind SQL Injection is a type of SQL injection attack where an attacker injects malicious SQL code into a vulnerable web application, introducing time delays in the application's responses. The attacker then measures the time it takes for the application to respond.

**5. Out-of-Band SQL Injection**
- Out-of-Band SQL Injection is a type of SQL injection attack where an attacker exploits a vulnerability in a web application to inject malicious SQL code that triggers external communication with a server controlled by the attacker


**6. Union-Based SQL Injection**
- Combines the results of multiple SELECT statements to fetch data from multiple tables as a single result set.

**7. Second-Order SQL Injection**
- Second-Order SQL Injection is a type of SQL injection attack where the attacker injects malicious SQL code into a web application, and the application stores the injected code in a database. The attack is executed later when the application retrieves and uses the stored data, leading to SQL injection vulnerabilities.

**8. Time-Based Blind Second-Order SQL Injection**
- In this attack, the attacker injects malicious SQL code that introduces time delays when executed, even though the results of the injection are not immediately visible. The delayed execution occurs at a later point in time when the application processes the injected data.

**9. Content-Based Blind Second-Order SQL Injection**
- In this attack, the attacker injects malicious SQL code into a web application, and the application stores the injected data in its database without immediate execution. The execution of the injected code occurs at a later point in time when the application retrieves and displays the stored data.

**10. Error-Based SQL Injection**
- The attacker intentionally injects malicious SQL code that causes the application to generate error messages containing valuable information.






## Insecure direct object references
This type of vulnerability occurs when an application exposes a direct reference to an internal object, such as a file or database record. By manipulating the reference, an attacker can gain unauthorized access to the object.

**Vulnerabilities**
- Information discloser

**Prevention**
- Use complex identifiers, such as GUIDs or random numbers.
- Do not expose identifiers in URLs or parameters unless absolutely necessary.
- Implement access control to restrict access to objects.
- WAF


## Security Misconfiguration
Poorly configured servers, frameworks, and libraries can leads to expose of sensitive data or allow unauthorized access.

**Vulnerability Include**
- Data Breaches
- Denial of Service Attacks
- Unauthorized Access

**Prevention**
- Disable unnecessary features.
- Monitor your application.

## File Inclusion

**Impact of File Inclusion**
- Code execution on server
- Code execution on client side
- Dos attack
- Information Disclosure

**LFI [Local file inclusion]**
- LFI stands for Local File Inclusion, which means an attacker can access files on your server through a vulnerable parameter or input in a web application. Allowing attackers to include and view local files on the server.

**RFI [Remote file inclusion]**
- RFI stands for remote file inclusion, which means an attacker can include a file from a remote server and execute it on your server.

## Cross-Site Request Forgery
- Attacker tricks victim to perform action that they do not intend to perform.<br/>
**Vulnerability Include:**
- Changing password.
- Delete Account.
- Transfer funds.<br/>
**How to Prevent**
- Use Firewall.
- Use CSRF Token
