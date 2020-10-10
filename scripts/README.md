# Scripts

This folder contains 2 scripts:
### 1. **analyze_csv_report.py**

In APM GUI you can generate .CSV report for any session-id. But looking through that report in Excel or in CLI is not convenient.

That script formats the .SCV report to the readable format:
 
**\<date/time\> \<Access Policy\> : \<session-id\> : \<log message\>**

Usage:
> analyze_csv_report.py  <.CSV report>

Example:
> analyze_csv_report.py  sessionReports_sessionDetails_xxxxxxxxxxxxxxxx.csv

Example output:
> 2020-01-01 00:00:31  /Common/test_Access_Policy : 65b9ac63 : Client_IP=192.168.1.168;State=;Country=;Continent=;Virtual_IP=10.1.110.1;Listener=/Common/test_virtual_server_https;Reputation=Unknown;

> 2020-01-01 00:00:31  /Common/test_Access_Policy : 65b9ac63 : User_Name=test_user;

> [...]

> Hostname: LabBIG-IP-01.example.local

> Virtual Server: /Common/test_virtual_server_https

> Access Policy: /Common/test_Access_Policy

> Session-id: 65b9ac63
