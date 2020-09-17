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
#define ETHERTYPE 0x0806
#define REPLY 0X0002
//send
#define MAC_ADDR_LEN 6
#define MAX_DATA_SIZE 1500


int main(int argc, char *argv[])
{
	int fd;
	unsigned char buffer[BUFFER_SIZE];
	unsigned char *data2;
	struct ifreq ifr;
	char ifname[IFNAMSIZ];
	char orig_ip[] = {10, 0, 2, 20};

	//send
	struct ifreq if_idx;
	struct ifreq if_mac;
	struct sockaddr_ll socket_address;
	//char ifname[IFNAMSIZ];
	int frame_len = 0;
	//char buffer[BUFFER_SIZE];
	char data[MAX_DATA_SIZE];
	char dest_mac[] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}; //broadcast
	short int ethertype = htons(0x0806);
	short int hwtype = htons(0x0001);
	short int prottype = htons(0x0800);
	char hwsize = 0x06;
	char protsize = 0x04;
	short int op = htons(0x0001);
	char sender_ip[] = {10, 0, 2, 20};
	char target_eth[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
	char target_ip[] = {10, 0, 2, 1};
	char target_ip2[] = {10, 0, 2, 21};
	
	
	char mac_router[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
	char mac_host[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};


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

	


	//send
	/* Cria um descritor de socket do tipo RAW */
	if ((fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) == -1) {
		perror("socket");
		exit(1);
	}

	/* Obtem o indice da interface de rede */
	memset(&if_idx, 0, sizeof (struct ifreq));
	strncpy(if_idx.ifr_name, ifname, IFNAMSIZ - 1);
	if (ioctl(fd, SIOCGIFINDEX, &if_idx) < 0) {
		perror("SIOCGIFINDEX");
		exit(1);
	}

	/* Obtem o endereco MAC da interface local */
	memset(&if_mac, 0, sizeof (struct ifreq));
	strncpy(if_mac.ifr_name, ifname, IFNAMSIZ - 1);
	if (ioctl(fd, SIOCGIFHWADDR, &if_mac) < 0) {
		perror("SIOCGIFHWADDR");
		exit(1);
	}

	/* Indice da interface de rede */
	socket_address.sll_ifindex = if_idx.ifr_ifindex;

	/* Tamanho do endereco (ETH_ALEN = 6) */
	socket_address.sll_halen = ETH_ALEN;

	/* Endereco MAC de destino */
	memcpy(socket_address.sll_addr, dest_mac, MAC_ADDR_LEN);

	/* Preenche o buffer com 0s */
	memset(buffer, 0, BUFFER_SIZE);

	/* Monta o cabecalho Ethernet */

	/* Preenche o campo de endereco MAC de destino */	
	memcpy(buffer, dest_mac, MAC_ADDR_LEN);
	frame_len += MAC_ADDR_LEN;

	/* Preenche o campo de endereco MAC de origem */
	memcpy(buffer + frame_len, if_mac.ifr_hwaddr.sa_data, MAC_ADDR_LEN);
	frame_len += MAC_ADDR_LEN;

	/* Preenche o campo EtherType */
	memcpy(buffer + frame_len, &ethertype, sizeof(ethertype));
	frame_len += sizeof(ethertype);
	
	/* INICIO ARP */
	
	/* hwtype */
	memcpy(buffer + frame_len, &hwtype, sizeof(hwtype));
	frame_len += sizeof(hwtype);

	/* prottype */
	memcpy(buffer + frame_len, &prottype, sizeof(prottype));
	frame_len += sizeof(prottype);

	/* hwsize */
	memcpy(buffer + frame_len, &hwsize, sizeof(hwsize));
	frame_len += sizeof(hwsize);

	/* protsize */
	memcpy(buffer + frame_len, &protsize, sizeof(protsize));
	frame_len += sizeof(protsize);

	/* op */
	memcpy(buffer + frame_len, &op, sizeof(op));
	frame_len += sizeof(op);

	/* eth origem */
	memcpy(buffer + frame_len, if_mac.ifr_hwaddr.sa_data, MAC_ADDR_LEN);
	frame_len += MAC_ADDR_LEN;

	/* ip origem */
	memcpy(buffer + frame_len, &sender_ip, sizeof(sender_ip));
	frame_len += sizeof(sender_ip);

	/* eth destino */
	memcpy(buffer + frame_len, &dest_mac, sizeof(dest_mac));
	frame_len += sizeof(dest_mac);
	




int i = 1;
int j = 1;


		unsigned char *reply;	
		unsigned char mac_dst[6] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
		unsigned char mac_src[6] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
		unsigned char ip_src[4] = {0, 0, 0, 0};
		unsigned char ip_dst[4] = {0, 0, 0, 0};
		short int ethertype2 = 0;
		short int oprecieve = 0;
		
		//envia pacotes
		//printf("IP: %d.%d.%d.%d\t  1 \n", target_ip[0], target_ip[1], target_ip[2], target_ip[3]);
		memcpy(buffer + frame_len, target_ip, sizeof(target_ip));
		frame_len += sizeof(target_ip);
		//printf("IP: %d.%d.%d.%d\t  2 \n", target_ip[0], target_ip[1], target_ip[2], target_ip[3]);
		if (sendto(fd, buffer, frame_len, 0, (struct sockaddr *)&socket_address, sizeof(struct sockaddr_ll)) < 0)
		{
			perror("send");
			close(fd);
			exit(1);
		}

		frame_len -= sizeof(target_ip);
	printf("Pacote enviado3.\n \n \n");
	
	
	
		printf("Esperando pacotes ... \n");
		/* Recebe pacotes */
		if (recv(fd,(char *) &buffer, BUFFER_SIZE, 0) < 0) {
			perror("recv");
			close(fd);
			exit(1);
		}
        
		/* Copia o conteudo do cabecalho Ethernet */
		memcpy(mac_dst, buffer, sizeof(mac_dst));
		memcpy(mac_src, buffer+sizeof(mac_dst), sizeof(mac_src));
		memcpy(&ethertype2, buffer+sizeof(mac_dst)+sizeof(mac_src), sizeof(ethertype2));
		ethertype2 = ntohs(ethertype2);
		reply = (buffer+sizeof(mac_dst)+sizeof(mac_src)+sizeof(ethertype2));

		memcpy(&oprecieve,reply+6, sizeof(oprecieve));
		oprecieve = ntohs(oprecieve);
		
		memcpy(ip_src, reply+14, sizeof(ip_src));

		memcpy(ip_dst, reply+24, sizeof(ip_dst));
		
		if ((ethertype2 == ETHERTYPE && oprecieve == 2)
			&& (20 == ip_dst[3]))
			//&& (orig_ip[0] == ip_dst[0] && orig_ip[1] == ip_dst[1] && orig_ip[2] == ip_dst[2] && orig_ip[3] == ip_dst[3])) 
		{
			printf("IP: %d.%d.%d.%d\t", ip_src[0], ip_src[1], ip_src[2], ip_src[3]);
			printf("MAC origem:  %02x:%02x:%02x:%02x:%02x:%02x\n", 
                        mac_src[0], mac_src[1], mac_src[2], mac_src[3], mac_src[4], mac_src[5]);
			printf("\n");
			mac_router[0] = mac_src[0];
			mac_router[1] = mac_src[1];
			mac_router[2] = mac_src[2];
			mac_router[3] = mac_src[3];
			mac_router[4] = mac_src[4];
			mac_router[5] = mac_src[5];
		}
		


frame_len =0;


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






	//send
	/* Cria um descritor de socket do tipo RAW */
	if ((fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) == -1) {
		perror("socket");
		exit(1);
	}

	/* Obtem o indice da interface de rede */
	memset(&if_idx, 0, sizeof (struct ifreq));
	strncpy(if_idx.ifr_name, ifname, IFNAMSIZ - 1);
	if (ioctl(fd, SIOCGIFINDEX, &if_idx) < 0) {
		perror("SIOCGIFINDEX");
		exit(1);
	}

	/* Obtem o endereco MAC da interface local */
	memset(&if_mac, 0, sizeof (struct ifreq));
	strncpy(if_mac.ifr_name, ifname, IFNAMSIZ - 1);
	if (ioctl(fd, SIOCGIFHWADDR, &if_mac) < 0) {
		perror("SIOCGIFHWADDR");
		exit(1);
	}

	/* Indice da interface de rede */
	socket_address.sll_ifindex = if_idx.ifr_ifindex;

	/* Tamanho do endereco (ETH_ALEN = 6) */
	socket_address.sll_halen = ETH_ALEN;

	/* Endereco MAC de destino */
	memcpy(socket_address.sll_addr, dest_mac, MAC_ADDR_LEN);

	/* Preenche o buffer com 0s */
	memset(buffer, 0, BUFFER_SIZE);

	/* Monta o cabecalho Ethernet */

	/* Preenche o campo de endereco MAC de destino */	
	memcpy(buffer, dest_mac, MAC_ADDR_LEN);
	frame_len += MAC_ADDR_LEN;

	/* Preenche o campo de endereco MAC de origem */
	memcpy(buffer + frame_len, if_mac.ifr_hwaddr.sa_data, MAC_ADDR_LEN);
	frame_len += MAC_ADDR_LEN;

	/* Preenche o campo EtherType */
	memcpy(buffer + frame_len, &ethertype, sizeof(ethertype));
	frame_len += sizeof(ethertype);
	
	/* INICIO ARP */
	
	/* hwtype */
	memcpy(buffer + frame_len, &hwtype, sizeof(hwtype));
	frame_len += sizeof(hwtype);

	/* prottype */
	memcpy(buffer + frame_len, &prottype, sizeof(prottype));
	frame_len += sizeof(prottype);

	/* hwsize */
	memcpy(buffer + frame_len, &hwsize, sizeof(hwsize));
	frame_len += sizeof(hwsize);

	/* protsize */
	memcpy(buffer + frame_len, &protsize, sizeof(protsize));
	frame_len += sizeof(protsize);

	/* op */
	memcpy(buffer + frame_len, &op, sizeof(op));
	frame_len += sizeof(op);

	/* eth origem */
	memcpy(buffer + frame_len, if_mac.ifr_hwaddr.sa_data, MAC_ADDR_LEN);
	frame_len += MAC_ADDR_LEN;

	/* ip origem */
	memcpy(buffer + frame_len, &sender_ip, sizeof(sender_ip));
	frame_len += sizeof(sender_ip);

	/* eth destino */
	memcpy(buffer + frame_len, &dest_mac, sizeof(dest_mac));
	frame_len += sizeof(dest_mac);
	







		
		unsigned char *reply2;	
		unsigned char mac_dst2[6] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
		unsigned char mac_src2[6] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
		unsigned char ip_src2[4] = {0, 0, 0, 0};
		unsigned char ip_dst2[4] = {0, 0, 0, 0};
		short int ethertype3 = 0;
		short int oprecieve2 = 0;
		
		
		
		//envia pacotes
		//printf("IP: %d.%d.%d.%d\t  1 \n", target_ip[0], target_ip[1], target_ip[2], target_ip[3]);
		memcpy(buffer + frame_len, target_ip2, sizeof(target_ip2));
		frame_len += sizeof(target_ip2);
		//printf("IP: %d.%d.%d.%d\t  2 \n", target_ip[0], target_ip[1], target_ip[2], target_ip[3]);
		if (sendto(fd, buffer, frame_len, 0, (struct sockaddr *)&socket_address, sizeof(struct sockaddr_ll)) < 0)
		{
			perror("send");
			close(fd);
			exit(1);
		}

		frame_len -= sizeof(target_ip2);
	printf("Pacote enviado3.\n \n \n");
	
	
	
		printf("Esperando pacotes ... \n");
		/* Recebe pacotes */
		if (recv(fd,(char *) &buffer, BUFFER_SIZE, 0) < 0) {
			perror("recv");
			close(fd);
			exit(1);
		}
        printf("teste");
		/* Copia o conteudo do cabecalho Ethernet */
		memcpy(mac_dst2, buffer, sizeof(mac_dst2));
		memcpy(mac_src2, buffer+sizeof(mac_dst2), sizeof(mac_src2));
		memcpy(&ethertype3, buffer+sizeof(mac_dst2)+sizeof(mac_src2), sizeof(ethertype3));
		ethertype3 = ntohs(ethertype3);
		reply2 = (buffer+sizeof(mac_dst2)+sizeof(mac_src2)+sizeof(ethertype3));

		memcpy(&oprecieve2,reply2+6, sizeof(oprecieve2));
		oprecieve2 = ntohs(oprecieve2);
		
		memcpy(ip_src2, reply2+14, sizeof(ip_src2));

		memcpy(ip_dst2, reply2+24, sizeof(ip_dst2));
		
		if ((ethertype3 == ETHERTYPE && oprecieve2 == 2)
			&& (20 == ip_dst2[3]))
			//&& (orig_ip[0] == ip_dst[0] && orig_ip[1] == ip_dst[1] && orig_ip[2] == ip_dst[2] && orig_ip[3] == ip_dst[3])) 
		{
			printf("linha 286 \n");
			printf("IP: %d.%d.%d.%d\t", ip_src2[0], ip_src2[1], ip_src2[2], ip_src2[3]);
			printf("MAC origem:  %02x:%02x:%02x:%02x:%02x:%02x\n", 
                        mac_src2[0], mac_src2[1], mac_src2[2], mac_src2[3], mac_src2[4], mac_src2[5]);
			printf("\n");
			mac_host[0] = mac_src2[0];
			mac_host[1] = mac_src2[1];
			mac_host[2] = mac_src2[2];
			mac_host[3] = mac_src2[3];
			mac_host[4] = mac_src2[4];
			mac_host[5] = mac_src2[5];
		}
			
		/*target_ip[3] = 78;
		target_ip[2] = 15;
		target_ip[1] = 168;
		target_ip[0] = 192;
		printf("entrei \n");
		printf("IP: %d.%d.%d.%d\t  3 \n", target_ip[0], target_ip[1], target_ip[2], target_ip[3]);
		*/
		



printf("MAC Gateway:  %02x:%02x:%02x:%02x:%02x:%02x\n", 
                        mac_router[0], mac_router[1], mac_router[2], mac_router[3], mac_router[4], mac_router[5]);
printf("\n");

printf("MAC vitima:  %02x:%02x:%02x:%02x:%02x:%02x\n", 
                        mac_host[0], mac_host[1], mac_host[2], mac_host[3], mac_host[4], mac_host[5]);

printf("\n");
			







	close(fd);
	return 0;
}
