# Scripts

This folder contains 2 scripts:
### 1. **analyze_csv_report.py**

In APM GUI you can generate .CSV report for any session-id. But looking through that report in Excel or in CLI is not convenient.

That script formats the .SCV report to the readable format:<br/>
**\<date/time\> \<Access Policy\> : \<session-id\> : \<log message\>**

Usage:
> analyze_csv_report.py  <.CSV report>

Example:
> analyze_csv_report.py  sessionReports_sessionDetails_xxxxxxxxxxxxxxxx.csv

Example output:
> 2020-01-01 00:00:31  /Common/test_Access_Policy : 65b9ac63 : Client_IP=192.168.1.168;State=;Country=;Continent=;Virtual_IP=10.1.110.1;Listener=/Common/test_virtual_server_https;Reputation=Unknown;<br/>
> 2020-01-01 00:00:31  /Common/test_Access_Policy : 65b9ac63 : User_Name=test_user;<br/>
> [...]<br/>
> Hostname: LabBIG-IP-01.example.local<br/>
> Virtual Server: /Common/test_virtual_server_https<br/>
> Access Policy: /Common/test_Access_Policy<br/>
> Session-id: 65b9ac63<br/>
<br/>

### 2. **analyze_f5_report.py**

This script is used for F5 Edge Client report analysis. More information about Edge Client report could be found in [K00819308: Gathering F5 VPN client logs](https://support.f5.com/csp/article/K00819308)

This script uses colorama Python module so it should be installed in advance:
> pip install colorama

Usage:
> analyze_f5_report.py \<f5 report\>

Example:
> analyze_f5_report.py f5_report.html

This script analyzes 2 log sections:
- logterminal.txt
- f5TunnelServer.txt 

Short summary of events logged by the script:
* session establishment process is logged
* most important errors or critical events
* RASMAN errors
* errors in f5TunnelServer logs
* session-ids seen in the F5 report
* VPN destinations + NA resources user connected to
