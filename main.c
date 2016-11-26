
#include "constant.h"

static char buffer[COMMAND_BUFFER_SIZE];
static int command_code;
static filter_options_t options;

void init_interpreter(){
	puts(INTRODUCTION);
}

void PrintUsage(){
	printf("%s\n", USAGE);
}

void show_options(){
	printf("过滤规则: %s\n", options.filter);
	printf("网络设备: %s\n",options.device);
}

int ParseCommandLine(char *command){

	if (strcmp(command,COMMAND_QUIT) == 0)
	{
		command_code = COMMAND_CODE_QUIT;
		return 0;
	}
	else if (strcmp(command,COMMAND_LIST_ALL_DEVICE) == 0)
	{
		command_code = COMMAND_CODE_LIST_ALL_DEVICE;
		return 0;
	}
	else if (strcmp(command,COMMAND_SHOW_OPTIONS) == 0)
	{
		command_code = COMMAND_CODE_SHOW_OPTIONS;
		return 0;
	}
	else if(strcmp(command,COMMAND_BEGIN) == 0){
		command_code = COMMAND_CODE_BEGIN;
		return 0;
	}
	else{
		char *tmp = NULL;
		tmp = strtok(command,TOKEN);
		if (strcmp(tmp,COMMAND_SET) == 0)
		{
			if(pares_option_setting()){
				command_code = COMMAND_CODE_SET;
				return 0;
			}
		}
	}
	command_code = 0;
	return 1;
}

int pares_option_setting(){
	char *tmp;
	char *option;
	tmp = strtok(NULL,TOKEN);
	if (!tmp)
	{
		return 0; //false
	}
	option = strtok(NULL,TOKEN);
	if (!option)
	{
		return 0; //false
	}
	if (strtok(NULL,TOKEN))
	{
		return 0;
	}

	if (!strcmp(tmp,"device"))
	{
		strcpy(options.device,option);
		return 1;
	}

	else if(!strcmp(tmp,"filter"))
	{
		strcpy(options.filter,option);
		return 1;
	}

	else if(!strcmp(tmp,"path"))
	{
		strcpy(options.path,option);
		return 1;
	}

	else
	{
		return 0;//false
	}


}

int CommandDispacther(){
	switch(command_code){
		case COMMAND_CODE_QUIT:
			return 0;  //return status code 0 when quit
		case COMMAND_CODE_LIST_ALL_DEVICE:
			findalldevs();
			return 1;
		case COMMAND_CODE_SHOW_OPTIONS:
			show_options();
			return 1;
		case COMMAND_CODE_SET:
			return 1;
		case COMMAND_CODE_BEGIN:
			capture_packets(&options);
			return 1;
		default:
			return 0;	//defalt retrun true
	}
}



int main(int argc, char const *argv[])
{
	int status = 1;

	init_interpreter();
	do{
		printf(">>");
		gets(buffer);
		
		/*Parse args options*/
		if (ParseCommandLine(buffer)){
			PrintUsage();
		}else{
			status = CommandDispacther();
		}
	} while (status);
	

	return 1;
}