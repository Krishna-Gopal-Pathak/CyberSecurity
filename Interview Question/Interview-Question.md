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
3. Blind SQL Injection
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

Attacker manipulates an application's SQL query by injecting malicious SQL code into user-provided input fields or parameters. 
Suppose you have a web application with a login form that uses the following SQL query to check user credentials:
```
SELECT * FROM users WHERE username = '$username' AND password = '$password';
```
- The application takes user inputs for username and password.
- An attacker enters the following as the username input: admin' OR '1'='1.
```
SELECT * FROM users WHERE username = 'admin' OR '1'='1' AND password = '$password';
```

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
