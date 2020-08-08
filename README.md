# enum_ssl

## Description

Made for simple enumeration of CN and Subject Alternative Name (SAN) records in x509 certificates on webservers.

## Usage

**As a CLI tool**
```
usage: enum_ssl.py [-h] [-f FILE] [-i IP] [-o WRITEFILE] [hostname] [port]

Download and parse SSL certificates from servers

positional arguments:
  hostname              Hostname or IP of the target server
  port                  Port number

optional arguments:
  -h, --help            show this help message and exit
  -f FILE, --file FILE  Load PEM encoded certificate from a file
  -i IP, --ip IP        IP to connect to (can be different than the hostname)
  -o WRITEFILE, --writefile WRITEFILE
                        Write certificate to file
```

*Example*
```
> ./enum_ssl.py google.com
*.google.com
*.android.com
*.appengine.google.com
*.bdn.dev
*.cloud.google.com
```

**As a module**
```python
import enum_ssl

# Download an X509 certificate from an SSL/HTTPS connection
cert = enum_ssl.download('google.com', 443)

# Decode an X509 certificate and extract the CN and SNI hostnames
hosts = enum_ssl.get_hostnames(cert)
```
