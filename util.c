#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#include <pcap.h>
#include "util.h"
#include "callback.h"

/*List all devices*/
static int ifprint(pcap_if_t *d);
static char *iptos(bpf_u_int32 in);

int findalldevs(){
	pcap_if_t *alldevs;
	pcap_if_t *d;
	char *s;
	bpf_u_int32 net,mask;
	int exit_status = 0;

	char errbuf[PCAP_ERRBUF_SIZE+1];
	if (pcap_findalldevs(&alldevs, errbuf) == -1)
	{
		fprintf(stderr,"Error in pcap_findalldevs: %s\n",errbuf);
    	return 1;
	}
	for(d=alldevs;d;d=d->next)
  	{
    	if (!ifprint(d)){
    		return 1;
    	}

  	}
  	if ( (s = pcap_lookupdev(errbuf)) == NULL)
  	{
    	fprintf(stderr,"Error in pcap_lookupdev: %s\n",errbuf);
    	exit_status = 2;
  	}
  	else
  	{
    	printf("Preferred device name: %s\n",s);
 	}

 	 if (pcap_lookupnet(s, &net, &mask, errbuf) < 0)
  	{
   	 	fprintf(stderr,"Error in pcap_lookupnet: %s\n",errbuf);
   		exit_status = 2;
  	}
  	else
  	{
    	printf("Preferred device is on network: %s/%s\n",iptos(net), iptos(mask));
  	}
  	return exit_status;

}

static int ifprint(pcap_if_t *d)
{
  pcap_addr_t *a;
  int status = 1; /* success */

  printf("%s\n",d->name);
  if (d->description)
    printf("\tDescription: %s\n",d->description);
  printf("\tLoopback: %s\n",(d->flags & PCAP_IF_LOOPBACK)?"yes":"no");

  for(a=d->addresses;a;a=a->next) {
    if (a->addr != NULL)
      switch(a->addr->sa_family) {
      case AF_INET:
        printf("\tAddress Family: AF_INET\n");
        if (a->addr)
          printf("\t\tAddress: %s\n",
            inet_ntoa(((struct sockaddr_in *)(a->addr))->sin_addr));
        if (a->netmask)
          printf("\t\tNetmask: %s\n",
            inet_ntoa(((struct sockaddr_in *)(a->netmask))->sin_addr));
        if (a->broadaddr)
          printf("\t\tBroadcast Address: %s\n",
            inet_ntoa(((struct sockaddr_in *)(a->broadaddr))->sin_addr));
        if (a->dstaddr)
          printf("\t\tDestination Address: %s\n",
            inet_ntoa(((struct sockaddr_in *)(a->dstaddr))->sin_addr));
        break;

      default:
        printf("\tAddress Family: Unknown (%d)\n", a->addr->sa_family);
        break;
      }
    else
    {
      fprintf(stderr, "\tWarning: a->addr is NULL, skipping this address.\n");
      status = 0;
    }
  }
  printf("\n");
  return status;
}

/* From tcptraceroute */
#define IPTOSBUFFERS	12
static char *iptos(bpf_u_int32 in)
{
	static char output[IPTOSBUFFERS][3*4+3+1];
	static short which;
	u_char *p;

	p = (u_char *)&in;
	which = (which + 1 == IPTOSBUFFERS ? 0 : which + 1);
	sprintf(output[which], "%d.%d.%d.%d", p[0], p[1], p[2], p[3]);
	return output[which];
}




void capture_packets(struct filter_options *options){
  char error_content[PCAP_ERRBUF_SIZE];
  pcap_t *pcap_handle; 
  bpf_u_int32 net_mask; //netmask
  bpf_u_int32 net_ip; //net ip
  char *net_interface;

  struct bpf_program bpf_filter; //bpf过滤规则
  char *bpf_filter_string = options->filter; //bpf过滤规则

  //net_interface = pcap_lookupdev(error_content); /*获取网络接口*/
  net_interface = options->device;
  printf("net_interface :%s\n", net_interface);

  /*获取网络地址和掩码地址*/
  pcap_lookupnet(net_interface,
                &net_ip,
                &net_mask,
                error_content);
  /*打开网络接口*/
  pcap_handle = pcap_open_live(net_interface,
                                BUFSIZ,
                                1, /*混杂模式*/
                                0, /*等待实践*/
                                error_content);

  if (!pcap_handle)
  {
    printf("打开网络接口失败，请检查输入的网络接口是否存在，或者是否具有权限打开此网络接口。\n");
    return;
  }

  /*编译并设置bpf过滤规则*/
  if (pcap_compile(pcap_handle, &bpf_filter,bpf_filter_string,0,net_mask))
  {
      printf("请检查你的输入规则是否有误。\n");
      return;
  }
  
  pcap_setfilter(pcap_handle,&bpf_filter);

  if (pcap_datalink(pcap_handle) != DLT_EN10MB)
  {
    return;
  }

  pcap_dumper_t* out_pcap = NULL;
  out_pcap  = pcap_dump_open(pcap_handle,options->path);

  pcap_loop(pcap_handle,//回调函数
            30 //loop infinity
            ,ethernet_protocol_packet_callback //回调函数
            ,(u_char *)out_pcap); //pass arguments to callback
  pcap_close(pcap_handle);
  pcap_dump_close(out_pcap);
}

