pcap_analyser: main.cpp
	g++ -o pcap_analyser main.cpp -lpcap

clean:
	rm -f pcap_analyser
