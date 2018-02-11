#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h> //For struct protoent *getprotobynumber(const char *name);. Removed from the program. 
#include <net/ethernet.h>

void ProcessPacket(unsigned char*, int);
void print_tcp_packet(unsigned char*, int);
void print_ip_header(unsigned char*, int);
void print_eth_header(unsigned char*,int);
void PrintData(unsigned char*, int);
void print_udp_packet(unsigned char*, int);

struct sockaddr_in source,destination; 
int total = 0,tcp=0,udp=0,icmp=0,igmp=0; //Keeps track of the total number of packets.
FILE *logfile;

int main()
{
	struct sockaddr saddr; 
	unsigned char * buffer = (unsigned char *) malloc(65536); 
	logfile = fopen("logfile.txt","w");

	int sockfd;
	/*	Socket descriptor for the raw socket. The type is SOCK_RAW, protocol is IPPROTO_TCP,
		hence it will capture only tcp packets. */
		
	sockfd = socket( AF_PACKET, SOCK_RAW ,htons(ETH_P_ALL) );
	// The family indicates it's a generic socket, and the protocol indicates 
	// that is should fetch all different kind of protocol packets. The type is 
	// self explanatory.
	if(sockfd < 0)
	{
		printf("Could not create socket. \n");
		exit(0);
	}
	// printf("the sockfd is %d\n",sockfd);
	while(1)
	{
		socklen_t data_size_var = sizeof(saddr);
		int data_size = recvfrom(sockfd,buffer,65536,0,&saddr,&data_size_var); // recvform is used to raw and datagram sockets. 
		// Use read and write for tcp connections, they work fine. 
		/* ssize_t recvfrom(int sockfd, void *buf, size_t len, int flags,
                 struct sockaddr *src_addr, socklen_t *addrlen); */
		if(data_size < 0)
		{
			printf("Could not receive.\n");
			exit(0);
		}
		ProcessPacket(buffer,data_size);
	}	
	printf("Done. Exiting.\n");


}

void ProcessPacket(unsigned char * buffer, int data_size)
{
	struct iphdr *ip_header = (struct iphdr *)(buffer+sizeof(struct ethhdr));
	// The adding is because we are using raw sockets, so we get the packet with the ethernet header.
	uint8_t protocol = ip_header->protocol;
	switch(protocol)
	{
		case 6:
			//printf("The protocol is tcp\n");

			print_tcp_packet(buffer,data_size);
			total++;
			tcp++;
			break;
		
		case 17:
			//printf("The protocol is udp\n");
			total++;
			udp++;
			print_udp_packet(buffer,data_size);
			break;

		case 2:
			total++;
			igmp++;
			//printf("The protocol is igmp\n");
			break;
			
		case 1:
			total++;
			icmp++;
			printf("The protocol is icmp\n");

		default:
			//printf("Other protocol\n");
			total++;
	}	
	printf("TCP: %d UDP: %d IGMP: %d ICMP: %d\r",tcp,udp,igmp,icmp);

}	

// Function for printing ethernet header.
void print_eth_header(unsigned char* buffer, int data_size)
{
	struct ethhdr *eth = (struct ethhdr *)buffer;
	fprintf(logfile,"\nETHERNET HEADER\n");

	fprintf(logfile,"Source addr: ");
	for(int i = 0; i < 5; i++)
	{
		fprintf(logfile,"%.2X-",eth->h_source[i]);
	}
	fprintf(logfile,"%.2X\n", eth->h_source[5]);

	fprintf(logfile,"Destination addr: ");
	for(int i = 0; i < 5; i++)
	{
		fprintf(logfile,"%.2X-",eth->h_dest[i]);
	}
	fprintf(logfile,"%.2X\n", eth->h_dest[5]);

	fprintf(logfile,"Protocol: %d\n", (uint16_t)eth->h_proto); // You can see the types in the header files. 

}

// Function for printing IP header.
void print_ip_header(unsigned char* buffer,int data_size)
{
	print_eth_header(buffer,data_size);
	struct iphdr *ip_header = (struct iphdr *)(buffer+sizeof(struct ethhdr));
	uint8_t protocol = ip_header->protocol;

	
	fprintf(logfile,"\nIP HEADER\n");
	memset(&source,0,sizeof(source));
	memset(&destination,0,sizeof(destination));

	source.sin_addr.s_addr = ip_header->saddr;
	destination.sin_addr.s_addr = ip_header->daddr;

	fprintf(logfile,"Version: %d\n",(uint8_t)ip_header->version);
	fprintf(logfile,"Header length: %d DWORDS or %d Bytes\n",ip_header->ihl,ip_header->ihl*4);
	fprintf(logfile,"Source address: %s\n",inet_ntoa(source.sin_addr));
	fprintf(logfile,"Destination address : %s\n",inet_ntoa(destination.sin_addr));
}

void print_tcp_packet(unsigned char* buffer, int data_size)
{
	fprintf(logfile,"\nPacket no : %d(tcp packet) **************\n", total);
	print_ip_header(buffer,data_size);
    struct iphdr * ip_header = (struct iphdr *)buffer;
    int ip_header_len = ip_header->ihl*4; // IP header length in words, convert to bytes. 
    //printf("IP header length: %d\n",ip_header_len);
    
    struct tcphdr * tcph= (struct tcphdr *)(buffer+ip_header_len+sizeof(struct ethhdr)); 
    // Extracting only the tcp header.
    fprintf(logfile,"TCP HEADER\n");
    fprintf(logfile,"Source port number: %d\n",ntohs(tcph->source));
    fprintf(logfile,"Destination port number: %d\n",ntohs(tcph->dest));
	int tcp_header_len = tcph->doff * 4;
	//printf("TCP header length: %d\n",tcp_header_len);

    fprintf(logfile,"**************DATA DUMP**********\n");
    int offset = tcp_header_len+ip_header_len;
    PrintData(buffer+offset,data_size-offset);

}

// Function for printing UDP packets.
void print_udp_packet(unsigned char * buffer, int data_size)
{
	fprintf(logfile,"\nPacket no : %d(udp packet) **************\n", total);
	print_ip_header(buffer,data_size);
    struct iphdr * ip_header = (struct iphdr *)buffer;
    int ip_header_len = ip_header->ihl*4;

	struct udphdr *udph = (struct udphdr *)(buffer + sizeof(struct ethhdr) + ip_header_len);
	fprintf(logfile,"UDP HEADER\n");
	fprintf(logfile,"Source port: %d\n",ntohs(udph->source));
	fprintf(logfile,"Destination port: %d\n", ntohs(udph->dest));
	fprintf(logfile,"Length: %d\n",ntohs(udph->len));
	fprintf(logfile,"Checksum: %d\n", ntohs(udph->check));
	
	fprintf(logfile,"**************DATA DUMP**********\n");
    int offset = ntohs(udph->len)*4+ip_header_len;
    PrintData(buffer+offset,data_size-offset);

}

// Fucntion for printing the data in proper format.
void PrintData(unsigned char * data,int data_size)
{
	//fprintf(logfile,"The total data size is %d\n",data_size);
	for(int i = 0; i < data_size; i++)
	{
		if(i != 0 && i%16 == 0)
		{
			fprintf(logfile,"      ");
			for(int j = i - 16; j < i; j++)
			{
				if(data[j] >= 32 && data[j] <= 128)
					fprintf(logfile,"%c",data[j]);
				else
					fprintf(logfile,".");
			}
			fprintf(logfile,"\n");
		}
		if(i%16 == 0)
			fprintf(logfile,"    ");
		fprintf(logfile," %02X",data[i]);
		if(i == data_size-1)
		{
			for(int j = 0; j < 15-i%16; j++) 
				fprintf(logfile,"   ");
			fprintf(logfile,"      ");
			for(int j = i - i%16; j <= i; j++)
				if(data[j] >= 32 && data[j] <= 128)
					fprintf(logfile,"%c",data[j]);
				else
					fprintf(logfile,".");
			fprintf(logfile,"\n");
				
		}
		

	}


}


