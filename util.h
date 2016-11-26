#ifndef UTIL_H
#define UTIL_H

#include <pcap.h>
#define BUFFERSIZE 20

struct filter_options
{
	char filter[BUFFERSIZE];
	char device[BUFFERSIZE];
	char path[BUFFERSIZE];
};

typedef struct filter_options filter_options_t;

/*打印所有可用的网络接口信息*/
int findalldevs();

/*捕获报文*/
void capture_packets(struct filter_options *options);

#endif
