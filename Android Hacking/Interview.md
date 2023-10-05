**1. Can you explain the difference between dynamic analysis and static analysis in Android app security testing?**
- <ins>Dynamic Analysis:</ins> It focuses on the app's runtime behavior, interactions with the device, and external services.
- <ins>Static Analysis:</ins> It focuses on identifying potential security vulnerabilities through code inspection and analysis.

**2. What recommendations would you give to developers to secure their Android apps against common penetration testing findings?**
- Recommendations include regular security testing, data encryption, secure coding practices, proper permissions management, and ongoing monitoring for vulnerabilities.

**3. What is Android Intent-based communication, and how can it be abused for security purposes?**
- Android Intents allow app components to communicate. They can be abused for malicious purposes, such as unauthorized data sharing or launching other apps.

**4. What is the role of API security in Android app penetration testing, and how do you test for insecure APIs?**
- APIs play a crucial role in data exchange. Test for insecure API endpoints, improper authentication, authorization issues, and data exposure.

**5. Can you explain how Android WebView can introduce security risks, and what measures can be taken to secure it?**
- WebView can execute untrusted code, introducing risks. Secure WebView by keeping it up-to-date, limiting JavaScript execution, and validating input. Implement a CSP that defines which sources of content are considered trusted.
