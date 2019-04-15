#include "utils.h"
#include "client.h"
#include "server.h"


void print_app_usage()
{
	printf("App usage: pbproxy [-l port] -k keyfile destination port\n\n-l  Reverse-proxy mode: listen for inbound connections on <port> and relay\nthem to <destination>:<port>\n\n-k  Use the symmetric key contained in <keyfile> (as a hexadecimal string)\n");
	// puts("App usage: pbproxy [-l port] -k keyfile destination port");
}

int main(int argc, char* argv[])
{
	int run_as_server = 0, dest_port = 0;
	unsigned int server_port = 0;
	char ch, *dest_addr = NULL;
	char * key = NULL;

	while ((ch = getopt (argc, argv, ":l:k:h")) != -1)
	{

		switch (ch)
		{
			case 'l':
				run_as_server = 1;
				server_port = atoi(optarg);
				if (!server_port)
				{
					fprintf (stderr, "Port number not specified.\n");
					print_app_usage();
					exit(1);
				}	

				break;

			case 'k':
				if( optarg[0] == '-') 
				{
					fprintf(stderr ,"Key file name not given\n");
					print_app_usage();
					exit(1);
				}

				key = optarg;
				break;

			case 'h':
				print_app_usage();
				exit(1);

	      	case ':':
				if (optopt == 'k')
					fprintf (stderr, "Port Number not entered for -%c.\n", optopt);
				else if (optopt == 'l')
					fprintf (stderr, "Pass argument for -%c.\n", optopt);
					
				print_app_usage();
				return 1;
		
			default:
				print_app_usage();
				exit(1);
		}
	}

	if  (key == NULL)
	{
		puts("Key not given");
		print_app_usage();
		exit(1);
	}

	//check if destination ip and port are provided
	if (optind + 2 > argc)
	{
		fprintf(stderr,"Too few arguments\n");
		print_app_usage();
		exit(1);
	}

	dest_addr = argv[optind++];
	dest_port = atoi(argv[optind]);


	if (run_as_server)
	{
		start_server(server_port, dest_addr, dest_port, key);
		exit(0);
	}

    else
    {
		generate_client(dest_addr, dest_port, key);
		exit(0);
	}

    return 0;
}