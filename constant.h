#include <stdio.h>
#include <pcap.h>
#include <string.h>
#include "util.h"

#define INTRODUCTION "Author hanbing nudt.\n\
Simple packet dump"

#define COMMAND_BUFFER_SIZE 50

/* Usage information to print */
#define USAGE "USAGE:show-device: Print validate devices on your computer.\n\
show-options: Print the option of setting a filter.\n\
select-devices : select a device to monitor.(option 'all' set to monitor all devices.)\n\
quit : Quit from mypacket_dump." 

/*Define some command identifier */

#define COMMAND_CODE_QUIT 1  /*command quit*/
#define COMMAND_QUIT "quit"	

#define COMMAND_CODE_LIST_ALL_DEVICE 2 /*list all valiable device*/
#define COMMAND_LIST_ALL_DEVICE "show-device"

#define COMMAND_CODE_SHOW_OPTIONS 3 /*show options of setting a filter*/
#define COMMAND_SHOW_OPTIONS "show-options"

#define COMMAND_CODE_SET 4
#define COMMAND_SET "set"
#define TOKEN " "

#define COMMAND_CODE_BEGIN 5
#define COMMAND_BEGIN "begin"