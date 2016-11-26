#ifndef CALLBACK_H
#define CALLBACK_H

#include <pcap.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define ETHERNET_HEADER_LENGTH 14
#define IP_HEADER_LENGTH 20
#define IMCP_HEADER_LENGTH 8

/*tls 头部定义*/
struct tls_header
{
  
};

/*UDP头部格式定义*/
struct udp_header
{
	u_int16_t udp_source_port; //源端口号
	u_int16_t udp_destination_port; //目的端口号
	u_int16_t udp_length; //长度
	u_int16_t udp_checksum ; //校验和
};

struct tcp_header
{
	u_int16_t tcp_source_port;
	u_int16_t tcp_destination_port;
	u_int32_t tcp_syn; //SYN number
	u_int32_t tcp_ack; //ACK number
	#ifdef WORDS_BEGENDIAN
  	u_int8_t 	tcp_offset:4,
  				tcp_reserved:4;
  	#else
  	u_int8_t 	tcp_reserved:4,
  				tcp_offset:4;
  	#endif

  	u_int8_t tcp_flags;
  	u_int16_t tcp_windows;
  	u_int16_t tcp_checksum;
  	u_int16_t tcp_urgent_pointer;
};

/*ICMP头部格式定义*/
struct icmp_header
{
	u_int8_t icmp_type;
	u_int8_t icmp_code;
	u_int16_t icmp_checksum;
	u_int16_t icmp_id;
	u_int16_t icmp_sequence;
};

/*IP协议头部格式*/
struct ip_header
{
  #ifdef WORDS_BEGENDIAN
  u_int8_t  ip_version:4,  //ip协议版本
            ip_header_length:4; //ip协议首部长度
  #else
  u_int8_t  ip_header_length:4, //ip协议首部长度
            ip_version:4;  //ip协议版本
  #endif
  u_int8_t ip_tos; /*TOS服务质量*/                    
  u_int16_t ip_length; //总长度
  u_int16_t ip_id; //标识
  u_int16_t ip_off;//偏移
  u_int8_t ip_ttl; /*生存时间*/
  u_int8_t ip_protocol; //协议类型
  u_int16_t ip_checksum; //校验和
  struct in_addr ip_source_address; //源ip地址
  struct in_addr ip_destination_address; //目的ip地址

};

/*arp protocol format*/
struct arp_header
{
  u_int16_t arp_hardware_type; /*硬件地址类型 Ethernet is 1*/
  u_int16_t arp_protocol_type; /*网络层协议类型 ipv4 0x0800*/
  u_int8_t arp_hardware_length; /*硬件地址长度*/
  u_int8_t arp_protocol_length; /*网络层协议地址长度*/
  u_int16_t arp_operation_code; /*操作类型 1 request 2 reply*/

  u_int8_t arp_source_ethernet_address[6]; /*源以太网地址*/
  u_int8_t arp_source_ip_address [4]; /*源ip地址*/
  u_int8_t arp_destination_ethernet_address[6]; /*目的以太网地址*/
  u_int8_t arp_destination_ip_address [4]; /*目的ip地址*/
};


//util to get ethernet packets
struct ether_header //data structure of ethernet protocol
{
  u_int8_t ether_dhost[6]; //Destination address 
  u_int8_t ether_shost[6]; //Source address
  u_int16_t ether_type; //Ethernet type
};


void arp_protocol_packet_callback(u_char *argument, 
          const struct pcap_pkthdr *packet_header,
          const u_char *packet_content);

void ethernet_protocol_packet_callback(u_char *argument, //arguments pass by user
          const struct pcap_pkthdr *packet_header,
          const u_char *packet_content);

void ip_protocol_packet_callback(u_char *argument, //arguments pass by user
          const struct pcap_pkthdr *packet_header,
          const u_char *packet_content);

void icmp_protocol_packet_callback(u_char *argument, //arguments pass by user
          const struct pcap_pkthdr *packet_header,
          const u_char *packet_content);


void udp_protocol_packet_callback(u_char *argument, //arguments pass by user
          const struct pcap_pkthdr *packet_header,
          const u_char *packet_content);

void tcp_protocol_packet_callback(u_char *argument, //arguments pass by user
          const struct pcap_pkthdr *packet_header,
          const u_char *packet_content);
#endif