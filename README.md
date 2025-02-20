
# Python file vulnerability scan

Found out that git has 'hidden code' problemo with python files\
Wrote a quick script to scan python packages for vulnerabilities

Recursively loop all python files in a directory
Try to find very long lines with whitespace followed by some code and base64 encoded string.
Try to decode found b64
