#include "callback.h"

static int number = 0;

void tls_protocol_packet_callback(u_char *argument, //arguments pass by user
          const struct pcap_pkthdr *packet_header,
          const u_char *packet_content)
{

}

void tcp_protocol_packet_callback(u_char *argument, //arguments pass by user
          const struct pcap_pkthdr *packet_header,
          const u_char *packet_content)
{
  struct tcp_header *tcp_protocol;
  u_char flags;
  int header_length;
  u_short source_port;
  u_short destination_port;
  u_short windows;
  u_short urgent_pointer;
  u_int sequence;
  u_int acknowlegement;
  u_int16_t checksum;
  tcp_protocol=(struct tcp_protocol*)(packet_content+ETHERNET_HEADER_LENGTH+IP_HEADER_LENGTH);
  source_port = ntohs(tcp_protocol->tcp_source_port);
  destination_port = ntohs(tcp_protocol->tcp_destination_port);
  header_length = tcp_protocol->tcp_offset * 4;
  sequence = ntohs(tcp_protocol->tcp_syn);
  acknowlegement = ntohs(tcp_protocol->tcp_ack);
  windows = ntohs(tcp_protocol->tcp_windows);
  urgent_pointer = ntohs(tcp_protocol->tcp_windows);
  flags = tcp_protocol->tcp_flags;
  checksum = ntohs(tcp_protocol->tcp_checksum);
  printf("--------------------TCP Protocol (Transport Layer)--------------------------\n");
  printf("Source Port: %d\n",source_port );
  printf("Destination Port: %d\n",destination_port );
  switch(destination_port) //判断上层协议
  {
    case 80:printf("HTTP protocol \n");break;
    case 21:printf("FTP protocol \n");break;
    case 23:printf("Telnet protocol \n");break;
    case 25:printf("SMTP protocol \n");break;
    case 110:printf("POP3 protocol\n");break;
    case 443:printf("HTTPS protocol \n");break;
    default:break;

  }

  printf("Sequence Number: %u\n",sequence );
  printf("Acknowlegement Number: %u\n", acknowlegement ); //%u unsigned integer
  printf("Header Length: %d\n",header_length );
  printf("Reserve: %d\n",tcp_protocol->tcp_reserved );

  //提取标志位
  if (flags & 0x20)printf("URG");
  if (flags & 0x01)printf("FIN");
  if (flags & 0x04)printf("RST");
  if (flags & 0x08)printf("PSH");
  if (flags & 0x10)printf("ACK");
  if (flags & 0x02)printf("SYN");
  printf("\n");

  printf("Window Size: %d\n",windows );
  printf("Checksum: %d\n", checksum);
  printf("Urgent Pointer: %d\n",urgent_pointer );

  switch(destination_port) //判断上层协议
  {
    case 443:
      tls_protocol_packet_callback(argument,packet_header,packet_content);
      break;
    default:
      break;

  }
}

void udp_protocol_packet_callback(u_char *argument, //arguments pass by user
          const struct pcap_pkthdr *packet_header,
          const u_char *packet_content)
{
  struct udp_header *udp_protocol; //UDP协议变量
  u_short source_port; //源端口号
  u_short destination_port; //目的端口号
  u_short length; //长度
  /*获得ICMP协议数据内容，跳过以太网协议与ip协议部分*/
  udp_protocol = (struct udp_header *)(packet_content+ETHERNET_HEADER_LENGTH+IP_HEADER_LENGTH);
  source_port = ntohs(udp_protocol->udp_source_port);
  destination_port = ntohs(udp_protocol->udp_destination_port);
  length = ntohs(udp_protocol->udp_length);
  printf("-------------------------UDP Protocol (Transport Layer) ----------------------\n");
  printf("Source port: %d\n", source_port);
  printf("Destination port: %d\n", destination_port);
  switch(destination_port)
  {
    //NetBios数据报服务
    case 138: printf("NETBIOS Datagram Service\n"); break;
    case 137: printf("NETBIOS Name Service\n"); break;
    case 139: printf("NETBIOS Session Service\n"); break;
    case 53:printf("name-domain server \n");break;
    default:break;//其他端口号在此没有分析，后续版本会添加

  }
  printf("Length:%d \n", length );
  printf("Checksum: %d\n", ntohs(udp_protocol->udp_checksum)); //获得校验和

}



void icmp_protocol_packet_callback(u_char *argument, //arguments pass by user
          const struct pcap_pkthdr *packet_header,
          const u_char *packet_content)
{
  struct icmp_header *icmp_protocol;
  /*获得ICMP协议数据内容，跳过以太网协议与ip协议部分*/
  icmp_protocol = (struct icmp_header *) (packet_content+ETHERNET_HEADER_LENGTH+IP_HEADER_LENGTH);
  printf("---------------ICMP Protocol (Transport Layer)---------------------");
  printf("ICMP Type: %d\n",icmp_protocol->icmp_type );
  switch(icmp_protocol->icmp_type) //ICMP数据包类型较多，待扩展
  {
    case 8://回显请求ICMP数据包
    printf("ICMP Echo REquest Protocol \n");
    printf("ICMP Identifier: %s\n", icmp_protocol->icmp_id);
    printf("ICMP Sequence Number: %s\n", icmp_protocol->icmp_sequence);
    break;
    case 0://回显应答数据包
    printf("ICMP Echo Reply Protocol \n");
    printf("ICMP Identifier: %s\n", icmp_protocol->icmp_id);
    printf("ICMP Sequence Number: %s\n", icmp_protocol->icmp_sequence);
    break;
    default:
    printf("Header Data %s%s\n", icmp_protocol->icmp_id,icmp_protocol->icmp_sequence);

  }
  printf("ICMP Checksum:%d\n",ntohs(icmp_protocol->icmp_checksum) );
  printf("ICMP Payload: %s", packet_content+
    ETHERNET_HEADER_LENGTH+IP_HEADER_LENGTH+IMCP_HEADER_LENGTH);
}

/*arp协议分析回调函数*/
void arp_protocol_packet_callback(u_char *argument, 
          const struct pcap_pkthdr *packet_header,
          const u_char *packet_content)
{
  struct arp_header *arp_protocol; //协议头变量
  u_short protocol_type; //协议类型
  u_short hardware_type; //硬件协议类型
  u_short operation_code; //操作类型
  u_char *mac_string; //以太网地址
  struct in_addr source_ip_address; 
  struct in_addr destination_ip_address;

  u_char hardware_length; //硬件地址长度
  u_char protocol_length; //协议地址长度

  printf("----------  ARP Protocol (Network Layer) ---------------\n");
  /*获得arp协议数据。逐一在这里要跳过以太网数据部分*/
  arp_protocol = (struct arp_header *)(packet_content+ETHERNET_HEADER_LENGTH);

  /*使用ntohs函数将网络字节序转换为本机字节序*/
  hardware_type =  ntohs(arp_protocol->arp_hardware_type);
  protocol_type = ntohs(arp_protocol->arp_protocol_type);
  operation_code = ntohs(arp_protocol->arp_operation_code);

  hardware_length = arp_protocol->arp_hardware_length;
  protocol_length = arp_protocol->arp_protocol_length;

  printf("ARP Hardware Type: %d\n", hardware_type);
  printf("ARP Protocol Type: %d\n",protocol_type);
  printf("ARP Hardware Length: %d\n", hardware_length);
  printf("ARP Operation: %d\n", operation_code);
  switch(operation_code){
    case 1: printf("ARP Request Protocol\n"); break;
    case 2: printf("ARP Reply Protocol\n"); break;
    case 3: printf("RARP Request Protocol\n"); break;
    case 4: printf("RARP Reply Protocol\n"); break;
    default: break;
  }
  printf("Ethernet Source Address is : \n");
  mac_string = arp_protocol->arp_source_ethernet_address;
  printf("%02x:%02x:%02x:%02x:%02x:%02x:\n",*(mac_string),
  *(mac_string+1),*(mac_string+2),*(mac_string+3),*(mac_string+4),
  *(mac_string+5) );
  memcpy((void *) &source_ip_address, (void *) &arp_protocol->
      arp_source_ip_address, sizeof(struct in_addr));
  printf("Source IP Address: %s\n", inet_ntoa(source_ip_address));
  printf("Ethernet destination_ip_address Address is : \n");
  mac_string = arp_protocol->arp_destination_ethernet_address;
  printf("%02x:%02x:%02x:%02x:%02x:%02x\n",*(mac_string),
  *(mac_string+1),*(mac_string+2),*(mac_string+3),*(mac_string+4),
  *(mac_string+5) );
  memcpy((void *) &destination_ip_address, (void *) &arp_protocol->
      arp_destination_ip_address, sizeof(struct in_addr));
  printf("Destination IP Address: %s\n", inet_ntoa(destination_ip_address));

}


/*回调函数实现ip协议包分析*/
void ip_protocol_packet_callback(u_char *argument, //arguments pass by user
          const struct pcap_pkthdr *packet_header,
          const u_char *packet_content)
{
  struct ip_header *ip_protocol; 
  u_int header_length; 
  u_int offset;
  u_char tos;
  u_int16_t checksum;
  /*去掉以太网头部，获得ip协议数据内容*/
  ip_protocol = (struct ip_header *)(packet_content + ETHERNET_HEADER_LENGTH);
  checksum = ntohs(ip_protocol->ip_checksum);
  header_length = ip_protocol->ip_header_length*4;
  tos = ip_protocol->ip_tos;
  offset = ntohs(ip_protocol->ip_off);
  printf("------------------IP Protocol (Network Layer)----------------------\n");  
  printf("IP Version: %d\n",ip_protocol->ip_version);
  printf("Header_length: %d\n",header_length);
  printf("Tos:%d\n", tos);
  printf("Total length: %d\n", ntohs(ip_protocol->ip_length));
  printf("Identification: %d\n",ntohs(ip_protocol->ip_id) );
  printf("offset: %d\n",(offset & 0x1fff)*8 );
  printf("TTL: %d\n",ip_protocol->ip_ttl );
  printf("Protocol: %d\n",ip_protocol->ip_protocol );

  switch(ip_protocol->ip_protocol)
  {
    case 6: printf("The Transport Layer Protocol is TCP\n");break;
    case 17: printf("The Transport layer Protocol is UDP\n");break;
    case 1: printf("The Transport layer Protocol is ICMP\n");break;
    default: 
      break;
  }
  printf("Header checksum: %d\n", checksum);
  printf("Source address: %s\n",inet_ntoa(ip_protocol->ip_source_address));
  printf("Destination address: %s\n", inet_ntoa(ip_protocol->ip_destination_address));

  switch(ip_protocol->ip_protocol)
  {
    case 6: tcp_protocol_packet_callback(argument,packet_header,packet_content);break;
    case 17: udp_protocol_packet_callback(argument,packet_header,packet_content);break;
    case 1: icmp_protocol_packet_callback(argument,packet_header,packet_content);break;
    default: 
      break;
  }

}


/*回调函数实现以太网协议分析*/

void ethernet_protocol_packet_callback(u_char *argument, //arguments pass by user
          const struct pcap_pkthdr *packet_header,
          const u_char *packet_content){

  number++;
  printf("\n");
  printf("\n");
  printf("The num %d packets\n", number);

  u_short ethernet_type; //以太网类型
  struct ether_header *ethernet_protocol; //以太网协议类型
  u_char *mac_string; //以太网地址
  static int packet_number = 1;
  printf("--------------------Ethernet Protocol (Link Layer)-------------------\n");

  ethernet_protocol = (struct ethernet_header *)packet_content;

  /*获得以太网协议数据*/
  printf("Ethernet type is : \n");
  ethernet_type = ntohs(ethernet_protocol->ether_type);//获得以太网类型
  printf("%04x\n",ethernet_type );
  switch(ethernet_type)
  {
    case 0x0800: printf("The network layer is IP protocol\n");break;
    case 0x0806: printf("The network layer is ARP protocol\n");break;
    case 0x0835: printf("The network layer is RARP protocol\n");break;
  }
    /*获得源以太网地址*/
    printf("Mac Source Address is : \n");
    mac_string = ethernet_protocol->ether_shost;
    printf("%02x:%02x:%02x:%02x:%02x:%02x\n",*(mac_string),
  *(mac_string+1),*(mac_string+2),*(mac_string+3),*(mac_string+4),
  *(mac_string+5) );


    /*获得目的以太网地址*/
    printf("Mac Destination Address is : \n");
    mac_string = ethernet_protocol->ether_dhost;
    printf("%02x:%02x:%02x:%02x:%02x:%02x\n",*(mac_string),
  *(mac_string+1),*(mac_string+2),*(mac_string+3),*(mac_string+4),
  *(mac_string+5) );
     
     /*调用上层协议分析回调函数*/
    switch(ethernet_type)
    {
      case 0x0800: ip_protocol_packet_callback(argument,packet_header,packet_content);
                    break;
      case 0x0806: arp_protocol_packet_callback(argument,packet_header,packet_content);
                    break;
      case 0x0835: break;
      default: break;
    }
  

  printf("-------------------------------------------------------------------------\n");

}