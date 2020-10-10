import csv, re, argparse

parser = argparse.ArgumentParser(description='Analyze CSV Report')
parser.add_argument('-v', '--version', action='version', version='%(prog)s 1.0')
parser.add_argument('csv_report', type=str, help="path to CSV Report")
args = parser.parse_args()

def analyze_csv_report(csv_report):
    with open(csv_report, encoding='utf8', errors='ignore', newline='') as f:
        reader = csv.reader(f)
        hostname = False
        session_id = False
        access_profile = False
        for row in reader:
            if any(row):
                time = row[3]
                last_column = row[-1].split(';')
                try:
                    if not hostname:
                        hostname = last_column[1]
                    if not session_id:
                        session_id = last_column[4].split('=')[-1]
                    if not access_profile:
                        access_profile = last_column[5].split('=')[-1]

                    #print(row[-1])
                    log_msg = re.search(r'.*;Session_I[dD]=[\w]{8};(.*)',row[-1])
                    if log_msg:
                        print(f"{time}  {access_profile} : {session_id} : {log_msg.group(1)}")
                        if "Listener" in log_msg.group(1):
                            virtual_server = re.search(r'.*;Listener=(.*?);.*', log_msg.group(1)).group(1)

                except IndexError:
                    continue
    print()
    print(f"Hostname: {hostname}")
    print(f"Virtual Server: {virtual_server}")
    print(f"Access Policy: {access_profile}")
    print(f"Session-id: {session_id}")



if __name__ == "__main__":
    analyze_csv_report(args.csv_report)