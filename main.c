/********************************************************
aim is to create a script we are confident is stealth
no knocking clients off
router can log this 
********************************************************/

/********* header *********/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
typedef struct wlan_packet_s
{
    uint8_t hdr_version;             // radiotap protocol version - always zero?
    uint8_t hdr_padding1;            // padding
    uint16_t hdr_length;             // header length
    uint32_t hdr_pflags;             // header present flags
    uint8_t hdr_flags;               // header flags
    uint8_t hdr_data_rate;
} wlan_packet_t;
char wlan[10];
int monitor_mode();
int managed_mode();
int capture_packet();
void packet_handler(
    u_char *args,
    const struct pcap_pkthdr *packet_header,
    const u_char *packet_body
);
/**************************/

/* body */
int monitor_mode()
{
    /* CAN THIS BE REPLACED BY 'pcap_can_set_rfmon' and 'pcap_set_rfmon'? */
    printf("switching to monitor mode...\n");
    char command[50];
    snprintf(command, sizeof(command), "ip link set %s down", wlan);
    system(command);
    snprintf(command, sizeof(command), "iw %s set monitor none", wlan);
    system(command);
    snprintf(command, sizeof(command), "ip link set %s up", wlan);
    system(command);
    printf("done.\n");
    return 0;
}

int managed_mode()
{
    printf("switching to managed mode...\n");
    char command[50];
    snprintf(command, sizeof(command), "ip link set %s down", wlan);
    system(command);
    snprintf(command, sizeof(command), "iw %s set type managed", wlan);
    system(command);
    snprintf(command, sizeof(command), "ip link set %s up", wlan);
    system(command);
    printf("done.\n");
    return 0;
}

int capture_packet()
{
    pcap_t * handle;
    int packet_limit = 10;
    int timeout_limit = 10000; /* milliseconds */
    char error_buffer[PCAP_ERRBUF_SIZE];

    if((handle = pcap_open_live(
        wlan,
        BUFSIZ,
        packet_limit, /* change to 0 for unlimited but find a clean way to break loop - either ctrl+c or whatever */
        timeout_limit,
        error_buffer
    )) == NULL)
    {
        printf("main() : pcap_open_live() : failed to create handler");
        return 2;
    }

    pcap_loop(handle, 0, packet_handler, NULL);

    return 0;
}

void packet_handler(
    u_char *args,
    const struct pcap_pkthdr *packet_header,
    const u_char *packet_body
)
{    
    wlan_packet_t * packet;
    packet = (wlan_packet_t *) packet_body;
    printf("*************************\n");
    printf("version: %d\n", ntohs(packet->hdr_version));
    printf("length: %d\n", (packet->hdr_length));
    printf("data rate: %d Mb/s\n", (packet->hdr_data_rate));
    printf("*************************\n");
}

int main(int argc, char * argv[])
{
    printf("Welcome to tectagon's wifi enumerator\n");

    if(argc != 2)
    {
        printf("usage: ./main <interface>\n");
    } else 
    {
        strcpy(wlan, argv[1]);
        printf("interface: %s\n", wlan);
    }

    /* interface in monitor mode*/
    monitor_mode();
    capture_packet();
    managed_mode();

    return 0;
}