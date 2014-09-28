shellshock-cgi
==============

A python script to enumerate CGI scripts vulnerable to CVE-2014-6271 on one specific server

## Usage
```
$ python testing.py --server 172.16.255.130 --listen 172.16.255.1
```


##Example Return:
```
[+] Testing if 172.16.255.130 is vulnerable to CVE-2014-6271 via CGI

[+] Listening for incoming connections on the following socket 172.16.255.1:4443

[!] The server is vulnerable at the following URL: http://172.16.255.130/cgi-bin/status

[!] The server is vulnerable at the following URI: http://172.16.255.130/cgi-bin/ax.cgi
```


## Contributors
Special thanks to https://github.com/Signus for general assitance with the threading and socket function

## Contact
Twitter: [@francisckrs](https://twitter.com/francisckrs "twitterhandle on twitter")
