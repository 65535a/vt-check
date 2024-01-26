import vt
import os
import json
import datetime 

apikey = os.environ['VTAPI']
client = vt.Client(apikey)
hashes = []

with open("hashes.txt", 'r') as file:
	hashes = [line.strip() for line in file.readlines()]

def main():	
	for hash in hashes:
		try:
			current_datetime = datetime.datetime.now()
			formatted_datetime = current_datetime.strftime("[%d/%b/%Y:%H:%M:%S]")
			file = client.get_object("/files/"+hash)
			filename =  file.names[0]
			info = file.antiy_info
			results = file.last_analysis_stats
			log_entry = f"{formatted_datetime} {filename} - {info} - {hash} - Harmless: {results['harmless']}, Suspicious: {results['suspicious']}, Malicious: {results['malicious']}, Undetected: {results['undetected']}\n"
			with open("log.txt", 'r+') as log:
				if hash not in log.read():
					log.write(log_entry)
					print(log_entry)			
		except:
			print(f"{hash} not found")
	client.close()

if __name__ == "__main__":
	main()
