#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/ether.h>
#include <arpa/inet.h>
#include <linux/if_packet.h>

#define BUFFER_SIZE 1600
//#define ETHERTYPE 0x0FFF
#define ETHERTYPE 0x0806

int main(int argc, char *argv[])
{
	int fd;
	unsigned char buffer[BUFFER_SIZE];
	unsigned char *data;
	struct ifreq ifr;
	char ifname[IFNAMSIZ];
	unsigned char ip_Lista[255][4];
	unsigned char mac_Lista[255][6];

	if (argc != 2) {
		printf("Usage: %s iface\n", argv[0]);
		return 1;
	}
	strcpy(ifname, argv[1]);

	/* Cria um descritor de socket do tipo RAW */
	fd = socket(PF_PACKET,SOCK_RAW, htons(ETH_P_ALL));
	if(fd < 0) {
		perror("socket");
		exit(1);
	}

	/* Obtem o indice da interface de rede */
	strcpy(ifr.ifr_name, ifname);
	if(ioctl(fd, SIOCGIFINDEX, &ifr) < 0) {
		perror("ioctl");
		exit(1);
	}

	/* Obtem as flags da interface */
	if (ioctl(fd, SIOCGIFFLAGS, &ifr) < 0){
		perror("ioctl");
		exit(1);
	}

	/* Coloca a interface em modo promiscuo */
	ifr.ifr_flags |= IFF_PROMISC;
	if(ioctl(fd, SIOCSIFFLAGS, &ifr) < 0) {
		perror("ioctl");
		exit(1);
	}

	printf("Esperando pacotes ... \n");
	while (1) {
		unsigned char mac_dst[6];
		unsigned char mac_src[6];
		short int ethertype;
		int frame_len = 0;

		/* Recebe pacotes */
		if (recv(fd,(char *) &buffer, BUFFER_SIZE, 0) < 0) {
			perror("recv");
			close(fd);
			exit(1);
		}
        
		/* Copia o conteudo do cabecalho Ethernet */
		memcpy(mac_dst, buffer, sizeof(mac_dst));
		frame_len += sizeof(mac_dst);
		
		memcpy(mac_src, buffer+frame_len, sizeof(mac_src));
		frame_len += sizeof(mac_src);
		
		memcpy(&ethertype, buffer+frame_len, sizeof(ethertype));
		frame_len += sizeof(ethertype);
		
		ethertype = ntohs(ethertype);
		data = (buffer+frame_len);
		
		short int op;
		memcpy(&op, data+6, 2);
		op = ntohs(op);
		
		unsigned char ipARP[4];
		memcpy(&ipARP, data+14, 4);
		//ip = ntohs(ip);
		
		unsigned char macARP[6];
		memcpy(&macARP, data+8, 6);
		
		
		if (ethertype == ETHERTYPE && op == 0x0002) {
			//printf("IP %d.%d.%d.%d\n", 
			//ip_Lista[ipARP[3]][] = ipARP;
			memcpy(&ip_Lista[ipARP[3]], ipARP, 4);
			memcpy(&mac_Lista[ipARP[3]], macARP, 6);
			
			
			//printf("MAC destino: %02x:%02x:%02x:%02x:%02x:%02x\n", 
                        //mac_dst[0], mac_dst[1], mac_dst[2], mac_dst[3], mac_dst[4], mac_dst[5]);
			//printf("MAC origem:  %02x:%02x:%02x:%02x:%02x:%02x\n", 
                        //mac_src[0], mac_src[1], mac_src[2], mac_src[3], mac_src[4], mac_src[5]);
			//printf("EtherType: 0x%04x\n", ethertype);		
			short int conta=0;
			//printf("OP: 0x%04x\n",op);
			//printf("Dado: ");
			while(conta<255){
				//printf(" %02x", data[conta]);
				if (ip_Lista[conta][0]!=0){ // ip não está zerado
					memcpy(&ipARP, ip_Lista[conta],4);
					memcpy(&macARP,mac_Lista[conta],6);
					printf("IP %d.%d.%d.%d", 
								ipARP[0], ipARP[1], ipARP[2], ipARP[3]);
					printf(" está no MAC: %02x:%02x:%02x:%02x:%02x:%02x\n", 
								macARP[0], macARP[1], macARP[2], macARP[3], macARP[4], macARP[5]);				
				}
				conta++;
			}
			printf("\n");
		}
	}

	close(fd);
	return 0;
}
