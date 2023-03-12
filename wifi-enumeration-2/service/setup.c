#include "../header/setup.h"
#include "../header/error.h"

/* setup interface */
void setup_interface()
{
    char interface[6];

    /* get interface from user */
    {
        char errbuf[PCAP_ERRBUF_SIZE];
        pcap_if_t *interfaces;
        if (pcap_findalldevs(&interfaces,errbuf) < 0){
            error(strcat("setup_interface() : pcap_findalldevs() : ", errbuf));
            exit(1);
        }

        printf("Choose interface (usually wlan<number>):\n");
        pcap_if_t *temp;
        int i=1;
        for(temp=interfaces;temp;temp=temp->next)
        {
            printf("%d : %s\n", i++, temp->name);
        }

        char number[3];
        printf("Enter interface number : ");
        fgets(number, sizeof(number), stdin);
        int selection=0;
        if ((selection = atoi(number)) < 1){
            error("setup_interface() : atoi() ");
            exit(1);
        }
        if (selection < 1 || selection>(i-1))
        {
            error("setup_interface() : invalid selection ");
            exit(1);
        }
        i=1;
        for(temp=interfaces;temp;temp=temp->next)
        {
            if(i++==selection)
            {
                strcpy(interface, temp->name);
                interface[5]='\0';
                break;
            }
        }
    }

    printf("--%s--\n", interface);

    /* setup wifi monitor */
    {
        char errbuf[PCAP_ERRBUF_SIZE];
        pcap_t * pcap_h;
        if((pcap_h = pcap_create(interface, errbuf)) == NULL)
        {
            error(strcat("setup_interface() : pcap_create() : ", errbuf));
            exit(1);
        }
        if(pcap_set_rfmon(pcap_h, 1) != 0)
        {
            error("setup_interface() : pcap_set_rfmon()");
            exit(1);
        }

        /* failing - to fix */
        int status = pcap_activate(pcap_h);
        printf("%d\n", status);

        pcap_close(pcap_h);
    }
    
}