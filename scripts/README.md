# Scripts

This folder contains 2 scripts:
1) analyze_csv_report.py

In APM GUI you can generate .CSV report for any session-id. But looking through that report in Excel or in CLI is not convenient.

That script formats the .SCV report to the readable format:\n 
**\<date/time\> \<Access Policy\> : \<session-id\> : \<log message\>**

Usage:
> analyze_csv_report.py  <.CSV report>

Example:
> analyze_csv_report.py  sessionReports_sessionDetails_xxxxxxxxxxxxxxxx.csv

