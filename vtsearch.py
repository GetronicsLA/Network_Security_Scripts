import urllib.request
import urllib.parse
import json
from netaddr import IPAddress, IPNetwork
import time
import sys
import csv


def dst_name(ip_address):
	"""
	Comprobacion de direcciones IP locales
	ya que se buscan ataques desde y hacia internet
	no se requiere busquedas de IP locales
	"""
	
	if IPAddress(ip_address) in IPNetwork("10.0.0.0/8"):
		return None 
	elif IPAddress(ip_address) in IPNetwork("172.16.0.0/12"):
		return None
	elif IPAddress(ip_address) in IPNetwork("192.168.0.0/16"):
		return None
	else:
		return ip_address


def malicious_info(detection_type):
	"""
	Extraccion de informacion una vez
	se identifique en VT la actividad maliciosa
	o posibles falñsos positivos.
	"""
	
	malware_counter = 0
	for sample_info in detection_type:
		date = sample_info["date"]
		sample_sha256 = sample_info["sha256"]
		print("\tDetection date: %s " %date)
		print("\tSample SHA256: %s" %sample_sha256)
        
		malware_counter += 1
		if malware_counter == 5:
			break
  

def virus_total_api(destination_address, source_address, search_type_vt, source_type):
	"""
	Conexion con la API de VT
	se envia la IP src o dst dependiendo
	de las opciones de usuarios y si se buscan
	ataques out->in o in->out, este ultimo para actividades
	C&C, shell_reverse, spyware.
	"""
	
	api_key = "PONGA SU LLAVE VT AQUI"
	url_data = urllib.parse.urlencode({"ip":search_type_vt,"apikey":api_key})
	url_search = "https://www.virustotal.com/vtapi/v2/ip-address/report?%s" %url_data

	scan_response = urllib.request.urlopen(url_search).read().decode("utf-8")
	
	try:
		formated_out = json.loads(scan_response)
		if formated_out["detected_urls"] and source_type == "source":
		
			url_malicious_detections = formated_out["detected_urls"][0]["positives"]
			url_malicious_date = formated_out["detected_urls"][0]["scan_date"]
			url_malurl = formated_out["detected_urls"][0]["url"]
			
			print("\n##### Suspicious activity found! #####\n")
			print("[+] Attacker: %s" %source_address)
			print("[+] Detections: %s/64" %url_malicious_detections)
			print("[+] Detection Date: %s" %url_malicious_date)
			print("[+] Associated URL: %s\n" %url_malurl)
		
		elif formated_out["detected_downloaded_samples"] and formated_out["undetected_downloaded_samples"]:

			print("\n##### Suspicious activity found! #####\n")
			print("[!] Detected malware:")
			malicious_info(formated_out["detected_downloaded_samples"])
			print("[!] Undetected malware:")
			malicious_info(formated_out["undetected_downloaded_samples"])

		elif formated_out["detected_downloaded_samples"]:

			print("\n##### Suspicious activity found! #####\n")
			print("[!] Detected malware:")
			malicious_info(formated_out["detected_downloaded_samples"])

		elif formated_out["undetected_downloaded_samples"]:
		
			print("\n##### Suspicious activity found! #####\n")
			print("[!] Undetected malware:")
			malicious_info(formated_out["undetected_downloaded_samples"])
			
		if formated_out["detected_downloaded_samples"] or formated_out["undetected_downloaded_samples"]:

			name_host = formated_out["resolutions"][0]["hostname"]
			last_scan = formated_out["resolutions"][0]["last_resolved"]
			malware_url = formated_out["detected_urls"]
			
			print("[+] Last URL Resolution: %s" %last_scan)
			print("[+] Hostname: %s" %name_host)
			print("[+] IP Source: %s" %source_address)
			print("[+] IP Dest: %s" %destination_address)
			print("[+] Last five malicious URL's hosted:")

			url_counter = 0

			for url_info in malware_url:
				print("\t-> %s : \n\t%s" %(url_info["scan_date"], url_info["url"]))
				url_counter += 1

				if url_counter == 5:
					break

			print()

	except: #KeyError:
		pass


def main():
	
	"""
	Mensaje de bienvenida, almacenamiento de 
	argumentos e interface simple de uso
	llamado de funciones y lectura de archivo
	de entrada.
	"""
	
	print (
	"-----------------------------------------------\n"
	"|        Virus Toatal Script API              |\n"
	"|        By Julian Ramirez Gomez              |\n"
	"| Contact: julian.ramirez@getronics-latam.com |\n"
	"|        @Getronics Colombia LTDA.            |\n"
	"-----------------------------------------------\n"
	)
	
	if len(sys.argv[0:]) < 3:
		print("USAGE %s FW_LOG_FILE[file.csv] SRC[source|destination]" %sys.argv[0])
		sys.exit(0)
	else:
		input_file = sys.argv[1]
		source_type = sys.argv[2]
				
	request_counter = 0
	analyzed_address = []

	with open(input_file, "r") as log_file:
		csv_reader = csv.DictReader(log_file)

		for addressing in csv_reader:
			destination_address = dst_name(addressing["Destination address"])
			source_address = addressing["Source address"]
			
			if source_type == "source":
				search_address_vt = source_address
			elif source_type == "destination":
				search_address_vt = destination_address
			else:
				print ("[!] source type not suppored.. must be [source|destination] ")
				sys.exit(0)
			
			if search_address_vt not in analyzed_address and destination_address != None :
				analyzed_address.append(search_address_vt)
				virus_total_api(destination_address, source_address, search_address_vt, source_type)
				request_counter += 1

				if request_counter%4 == 0:
					print("Limit search reached!... adding 60s delay")
					time.sleep(60)
		

if __name__ == "__main__":
	main()
