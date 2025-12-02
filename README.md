# OWASP-Top-10-Code-Fix
README.DOC 


## 1. Broken Access Control
Language: JavaScript
*Security Flaw*
The system is vulnerable to Insecure Direct Object Reference, which is a type of Broken Access Control (OWASP A01). The application trusts user input from the URL to access resources without checking permissions. Resulting in any logged-in user having access to other user’s profile or settings simply by changing the ID in the URL. 

*Fix*
Introduced ‘requireAuth’ middleware enforced authentication and ensure the user is logged in.
Added authorization checks to ensure users can only access their own data  unless they have an Admin role.
*OWASP Reference*
https://owasp.org/Top10/A01_2021-Broken_Access_Control/


##2. Broken Access Control
Language: Python
*Security Flaw*
The system is vulnerable to Insecure Direct Object Reference, a type of Broken Access Control (OWASP A01).  The application directly uses the user_id from the URL to retrieve data without checking authentication and authorization. This allows any logged-in user to access other user’s profile or settings simply by changing the ID in the URL. 

*Fix*
Fix by implementing two key controls, first, @login_required for authentication, ensuring only logged-in users can proceed. Second, an authorization check verifies the requested user_id matches log user, unless the user is an Admin. If failure occurs, system returns 403 Forbidden responses. 
*OWASP Reference*
https://owasp.org/Top10/A01_2021-Broken_Access_Control/


## 3. Cryptographic Failures 
Language:  Java
*Security Flaw*
The code uses MD5, which is a weak and outdated hashing algorithm that stores passwords. MD5 is fast, yet lacks salting and vulnerable to collision attacks and rainbow table attacks. Due to passwords insecurely hashed, attacker can gain access to database easily, recovering original passwords. 
*Fix*
Replacement of MD5 with BCrypt via Spring Security’s BCryptPasswordEncoder.  BCrypt is specific for security and intentionally slow to increase time, requiring attacker to take longer to guess password.
*OWASP Reference*
https://owasp.org/Top10/A02_2021-Cryptographic_Failures/


##4. Cryptographic Features
Language: Python
*Security Flaw*
The system uses the SHA-1 hashing algorithm for password storage. SHA-1 considered cryptographically broken and vulnerable to collision attacks. The lack of a unique salt for each password also leaves the system open to the rainbow table attacks.
*Fix*
 The fix implemented the Bcrypt algorithm, for password hashing. Gensalt() for automatic salting, to create unique random salt for each password. Additionally, (rounds=12) to intentionally slow down to make large-scale password attacks, making it harder for attackers to guess. 
*OWASP Reference*
https://owasp.org/Top10/A02_2021-Cryptographic_Failures/


##5. Injection
Language: Java
*Security Flaw*
The insecure code directly concatenates user input into the SQL query. An attacker can inject SQL such as: admin’ or ‘1’=’1
This exposes all users, bypass authentication, or manipulate the database.
*Fix*
Use PreparedStatement, which uses ? placeholders and safely escapes user input. This prevents SQL injection because the database treats the input as data not executable SQL.
*OWASP Reference*
https://owasp.org/Top10/A03_2021-Injection/


##6. Injection
Language: JavaScript
*Security Flaw*
This code is insecure as user-supplied input is passed directly into the MongoDb query, allowing attackers to inject NoSQL operators. Attackers can send /user?usernmame[$ne]=null, this will bypass checks and return unintended data. 
*Fix*
The secure version validates and sanitizes the username, removing dangerous   characters like $ and . . It ensures the data type is correct, prevents operator injection, hides sensitive fields (like passwords), and avoids server-side errors.
*OWASP Reference*
https://owasp.org/Top10/A03_2021-Injection/


##07 Insecure Design
Language: Python
*Security Flaw*
The code is insecure because it allows anyone to reset user’s password by simply knowing their email. There is no token or expiration check, and passwords may be stored in plaintext. This allows attackers to take over accounts without proper authorization.

*Fix*
Implemented a secure password reset workflow using tokens and password hashing. Passwords are hashed before storage, protecting against leaks. Only valid, unused, unexpired tokens can reset a password. Tokens are marked as used after a reset to prevent reuse. 
*OWASP Reference*
https://owasp.org/Top10/A04_2021-Insecure_Design/


##08 Software and Data Integrity Failures
Language: HTML
*Security Flaw*
The insecure code loads a script directly from an external CDN without verifying its integrity. If the external script is compromised, the browser will still execute it, allowing attackers to run malicious code on the site.
*Fix*
The fix enforces integrity by implementing Subresource Integrity (SRI). This requires adding the integrity attribute (containing a cryptographic hash, like SHA-384) to the script, along with the required crossorigin=”anonymous” attribute. The browser calculates the hash of downloaded script and will automatically block execution if the calculated hash does not match the value. 
*OWASP Reference*
https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/


##09 Server-Side Request Forgery
Language: Python
*Security Flaw*
The insecure code takes a user suppled URL and makes an HTTP request without validation. This allows attackers to force the server to connect the internal network addresses or cloud metadata services. Exploiting this can expose sensitive internal data, including cloud credentials and administrative interfaces. 
*Fix*
The secure code implements a strict allowlist first with a protocol  check. Only http and https are allowed, blocking dangerous protocols. Secondly, a domain allowlist, which limits requests to approved domains in ALLOWED_DOMAINS. The fix also  uses a timeout and disables redirects to prevent attackers from using features to bypass. 
*OWASP Reference*
https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery/


##10 Identification and Authentication Failures
Language: Java
*Security Flaw*
The insecure code is vulnerable to an Authentication Timing Attack. By using inputPassword.equals(user.getPassword()), the system compares passwords in non-constant time, meaning the operation takes longer if characters match. Additionally, passwords are weakly hashed or stored in plaintext. 
*Fix*
The secure code uses BCrypt for hashing and encoder.matches() for password comparison. The comparison is constant-time preventing timing attacks. The passwords are also salted and securely hashed, protecting them from compromise. 
*OWASP Reference*
https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/

Author: 
Estela Garcia
