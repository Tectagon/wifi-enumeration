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
    // wireshark used to make this
    // radiotap header
    uint16_t hdr_pad1;      // version nb + pad
    uint16_t hdr_length;    // header length
    uint64_t hdr_pad2;      // flags + data rate + channel frequency
    uint16_t hdr_pad3;      // channel flags
    uint8_t hdr_signal;     // antenna signal (dBm)
    uint8_t hdr_pad4;       // antenna
    uint16_t hdr_pad5;      // wireshark says "frame with bad PLCP"
    // 802.11 body
    uint8_t bdy_subtype;    // packet type
    uint64_t bdy_pad1;      // fcorder + duration + destination hardware address 
    uint32_t bdy_pad2;      // destination address continued + source hardware address 
    uint16_t bdy_pad3;      // source hardware continued
    uint8_t bdy_pad4;       // source hardware end
    // BSSID
    uint8_t bdy_BSSID[6];
    //uint8_t bdy_BSSID1;
    //uint8_t bdy_BSSID2;
    //uint8_t bdy_BSSID3;
    //uint8_t bdy_BSSID4;
    //uint8_t bdy_BSSID5;
    //uint8_t bdy_BSSID6;
    // Padding
    //uint64_t bdy_pad5;      // wlan.seq + wlan.fixed.timestamp
    //uint32_t bdy_pad6;      // wlan.fixed.timestamp + wlan.fixed.beacon + wlan.fixed.capabilities.reserved6 + wlan.tag.number + wlan.tag.length
    //uint16_t bdy_pad7;
    //uint8_t bdy_pad8;
    // SSID - can we change this to something smaller ? using arrays changes bytes ordering...
    //uint8_t bdy_taglength;     // tag length
    //uint8_t * bdy_SSID;   // ssid

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
    int packet_limit = 30;
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

    pcap_loop(handle, packet_limit, packet_handler, NULL);

    return 0;
}

void packet_handler(
    u_char *args,
    const struct pcap_pkthdr *packet_header,
    const u_char *packet_body
)
{    
    wlan_packet_t * packet;
    char bssid[7];
    packet = (wlan_packet_t *) packet_body;

    // beacon has binary 1000 which is 255.
    if(packet->bdy_subtype != 255) return;

    // setup
    //sprintf(bssid, "%02X:%02X:%02X:%02X:%02X:%02X", packet->bdy_BSSID1, packet->bdy_BSSID2, packet->bdy_BSSID3, packet->bdy_BSSID4, packet->bdy_BSSID5, packet->bdy_BSSID6);

    //uint8_t *bdy_SSID = packet->bdy_SSID;
    //uint8_t bdy_taglength = (packet->bdy_taglength);

    printf("*************************\n");
    printf("length: %d\n", packet->hdr_length);
    printf("signal: -%d dBm\n", packet->hdr_signal);
    printf("type: %d\n", packet->bdy_subtype);
    printf("BSS ID: ");
    for (int i = 0; i < sizeof(packet->bdy_BSSID); i++) {
        printf("%02X", packet->bdy_BSSID[i]);
        if (i < sizeof(packet->bdy_BSSID) - 1) {
            printf(":");
        }
    }
    printf("\n");
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