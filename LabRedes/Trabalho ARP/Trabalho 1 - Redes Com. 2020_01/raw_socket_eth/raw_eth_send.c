#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/ether.h>
#include <arpa/inet.h>
#include <linux/if_packet.h>

#define MAC_ADDR_LEN 6
#define BUFFER_SIZE 1600
#define MAX_DATA_SIZE 1500

int main(int argc, char *argv[])
{
	int fd;
	struct ifreq if_idx;
	struct ifreq if_mac;
	struct sockaddr_ll socket_address;
	char ifname[IFNAMSIZ];
	int frame_len = 0;
	char buffer[BUFFER_SIZE];
	//char data[MAX_DATA_SIZE];
	char dest_mac[] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}; //broadcast
	char dest_macARP[] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}; //broadcast
	short int ethertype = htons(0x0806);
	short int hwtype = htons(0x0001);
	short int prottype = htons(0x0800);
	char hlen = 0x06;
	char plen = 0x04;
	short int op = htons(0x0001);
	char sender_ip[] = {10.0.2.20};//{192,168,15,193};
	char dest_ip[] = {192,168,15,2};

	if (argc != 2) {
		printf("Usage: %s iface\n", argv[0]);
		return 1;
	}
	strcpy(ifname, argv[1]);

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

/*---*/

	/* Preenche o campo hardType */
	memcpy(buffer + frame_len, &hwtype, sizeof(hwtype));
	frame_len += sizeof(hwtype);
	
	/* Preenche o campo prottype */
	memcpy(buffer + frame_len, &prottype, sizeof(prottype));
	frame_len += sizeof(prottype);
	
	/* Preenche o campo HLEN */
	memcpy(buffer + frame_len, &hlen, sizeof(hlen));
	frame_len += sizeof(hlen);
	
	/* Preenche o campo PLEN */
	memcpy(buffer + frame_len, &plen, sizeof(plen));
	frame_len += sizeof(plen);

	/* Preenche o campo OP */
	memcpy(buffer + frame_len, &op, sizeof(op));
	frame_len += sizeof(op);
	
	/* Preenche o campo sender IP */
	memcpy(buffer + frame_len, if_mac.ifr_hwaddr.sa_data, MAC_ADDR_LEN);
	frame_len += MAC_ADDR_LEN;
	
	/* Preenche o campo sender IP */
	memcpy(buffer + frame_len, &sender_ip, sizeof(sender_ip));
	frame_len += sizeof(sender_ip);
	
	/* Preenche o campo sender IP */
	memcpy(buffer + frame_len, &dest_macARP, sizeof(dest_macARP));
	frame_len += sizeof(dest_macARP);

int soma=0;
while(soma<255){	
	dest_ip[3]=soma;
	soma++;
	/* Preenche o campo sender IP */
	memcpy(buffer + frame_len, &dest_ip, sizeof(dest_ip));
	frame_len += sizeof(dest_ip);

	/* Obtem uma mensagem do usuario */
	//printf("Digite a mensagem: ");
	//scanf("%[^\n]s", data);

	/* Preenche o campo de dados */
	//memcpy(buffer + frame_len, data, strlen(data));
	//frame_len += strlen(data) + 1;

	/* Envia pacote */
	if (sendto(fd, buffer, frame_len, 0, (struct sockaddr *) &socket_address, sizeof (struct sockaddr_ll)) < 0) {
		perror("send");
		close(fd);
		exit(1);
	}
	frame_len -= sizeof(dest_ip);
	
	printf("Pacote enviado.\n");
}
	close(fd);
	return 0;
}
