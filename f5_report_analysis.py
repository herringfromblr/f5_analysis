from colorama import Fore, Back, Style
from pprint import pprint
import re, argparse

parser = argparse.ArgumentParser(description='Analyze F5 Report')
parser.add_argument('-v', '--version', action='version', version='%(prog)s 1.0')
parser.add_argument('f5_report', type=str, help="path to F5 Report")
args = parser.parse_args()

print(f"filename: {args.f5_report}")
entries_to_look_in_logs = ["RAS error","A network error has happened",
"OnError event","Failed to connect for downloading a PAC file", "Http status code",
"Failed to prepare URL for fetching PAC file", "As this represents a potential security threat",
"Policy check failed", "Enumeration failed. error", "RasDeviceName is empty", "VPN device not found",
"Temporarily disconnecting","Open Session Failed"]

def analyze_f5_report(f5_report):
    session_ids = set() # Set for unique session ids
    timestamps = set() # Set for important timestamps
    vpn_fqdn_na_res = {} # Set dictionary for VPN fqdns and NA resources, client connects to
    date = False
    na_res = False
    """
    In below section I analyze only logterminal.txt. I looks for:
    - session start/stop/reconnect and etc...
    - any relevant errors in loterminal.txt
    - save all session-ids to 'session_ids' set
    """
    with open(f5_report, 'r', encoding='utf8', errors='ignore') as f:
        analyze_logterminal = True
        analyze_f5tunnel_server = False
        for line in f:
            line = line.rstrip()
            if analyze_logterminal:
                if "<A name=logterminal>" in line and "Table Of Contents" in line:
                    print(Fore.MAGENTA + "#"*40 + " Starting logterminal.txt logs initial analysis " + "#"*40, Style.RESET_ALL)
                elif "Starting pending session ID: " in line:
                    print(line)
                    session_id = re.search(r'^([\d-]+, *[\d:]{3,4}).*Starting pending session ID: *([\w]{8})', line)
                    if session_id:
                        timestamps.add(session_id.group(1))
                        session_ids.add(session_id.group(2))
                elif re.search('Session [0-9a-z]{8} (closed|established)', line):
                    print(line)
                    session_id = re.search(r'^([\d-]+, *[\d:]{3,4}).*Session *([\w]{8})', line)
                    if session_id:
                        timestamps.add(session_id.group(1))
                        session_ids.add(session_id.group(2))
                elif "User status" in line:
                    print(line)
                    user_status = re.search(r'^([\d-]+, *[\d:]{3,4}).*User status is: .*$', line)
                    if user_status:
                        timestamps.add(user_status.group(1))
                        #print("timestamp - ", user_status.group(1))
                        #print("user status: ", session_id.group(2))
                elif any(i for i in entries_to_look_in_logs if i in line):
                    entry = re.search(r'^([\d-]+, *[\d:]{3,4}).*', line)
                    if entry:
                        timestamps.add(entry.group(1))
                    if "FONT" in line:
                        m = re.sub(r'(<FONT COLOR="\w+" +>|</FONT>)', ' ',line)
                        if m:
                            print(Fore.RED + m, Style.RESET_ALL)
                    elif "Http status code" in line:
                        m = re.search(r'.* Http status code:([45]\d{2})', line)
                        if m:
                            print(line)
                    else:
                        print(Fore.RED + line, Style.RESET_ALL)
                elif 'name="tunnel_host0"' in line:
                    m = re.search(r'.*, +value="([\w.]+)"', line)
                    if m:
                        vpn_fqdn = m.group(1)
                        if date and na_res:
                            vpn_fqdn_na_res[date]= [vpn_fqdn, na_res]
                elif 'name="ur_name"' in line:
                    m = re.search(r'^([\d.-]+, *[\d:]+),.*, +value="([\w./-]+)"', line)
                    if m:
                        date = m.group(1)
                        na_res = m.group(2)
                elif "logterminal.txt.bak" in line and "Table Of Contents" in line:
                    print(Fore.MAGENTA + "#"*40 + " Finishing logterminal.txt logs initial analysis " + "#"*40, Style.RESET_ALL)
                    analyze_logterminal = False
            elif "<A name=f5TunnelServer>" in line and "Table Of Contents" in line:
                print(Fore.MAGENTA + "#"*40 + " Starting f5TunnelServer.txt logs initial analysis " + "#"*40, Style.RESET_ALL)
                analyze_f5tunnel_server = True

            elif analyze_f5tunnel_server:
                if "EXCEPTION" in line:
                    f5tun_log_time = re.search(r'^([\d-]+, *[\d:]{3,4}).*', line)
                    #print(f5tun_log_time.group(1))
                    if f5tun_log_time.group(1) in timestamps:
                        m = re.sub(r'(<FONT COLOR="\w+" +>|</FONT>)', ' ',line)
                        if m:
                            print(m)
                elif "read failed, -1" in line:
                    print(line)
                elif "<A name=f5TunnelServer_Low>" in line and "Table Of Contents" in line:
                    print(Fore.MAGENTA + "#"*40 + " Finishing f5TunnelServer.txt logs initial analysis " + "#"*40, Style.RESET_ALL)
                    analyze_f5tunnel_server = False

        print("Session-ids observed in logs: " + ", ".join(str(e) for e in session_ids))

        print()
        print("User connected to the following VPNs/Network Access Resources: ")
        for i,k in vpn_fqdn_na_res.items():
            print(i + ' - ' + 'VPN fqdn: ' + k[0] + ' ; NA resource: ' + k[1])

if __name__ == "__main__":
    analyze_f5_report(args.f5_report)
    #analyze_f5_report('C:/cases/C3177578/mar_03/F5DiagnosticsReport.html')