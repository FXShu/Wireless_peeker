#include"parse.h"

int parse_http_request(const u_char* data,http_resquest_payload* http){
	init_hashtable(&(http->header),25);
	if(!data || !http){
		log_printf(MSG_WARNING,"PARSE: packet payload is empty or buffer initialize fail\n");
		return -1;
	}
	u_char* data_buff = (u_char*)data;
	char *type_ptr, *header_ptr, *payload_ptr;
	char *buff;
	char *key,*value;
	char *http_type_tmp = strtok_r(data_buff,"\r\n",&payload_ptr);
	http->type.method = strtok_r(http_type_tmp," ",&type_ptr);
	http->type.URI = strtok_r(http_type_tmp," ",&type_ptr);
	http->type.version = strtok_r(http_type_tmp," ",&type_ptr);
	while((buff = strtok_r(data_buff,"\r\n",&payload_ptr)) != NULL){
		key = strtok_r(buff,": ",&header_ptr);
		value = strtok_r(buff,": ",&header_ptr);
		struct node* header_cont = create_node(key,value);
		if((http->header).insert(&(http->header),header_cont)<0) {
			log_printf(MSG_WARNING,"PARSE: http request header contect match fail\n");
			return -1;
		}
	}

	print_hashtable(&(http->header));
	return 0;
}

int parse_http_reply(const u_char* data, http_reply_payload* payload) {
	init_hashtable(&(payload->header),10);
	if(!data || !payload){
		log_printf(MSG_WARNING,"PARSE: packet payload is empty or buffer initialize fail\n");
		return -1;
	}
	u_char* data_buff = (u_char*)data;
	char* buff;
	char *type_ptr, *header_ptr, *payload_ptr;
	char *key,*value;
	char *http_type_tmp = strtok_r(data_buff,"\r\n",&payload_ptr);
	payload->type.version = strtok_r(http_type_tmp," ",&type_ptr);
	payload->type.status_code = atoi(strtok_r(http_type_tmp," ",&type_ptr));
	payload->type.phrase = strtok_r(http_type_tmp," ",&type_ptr);
	while((buff = strtok_r(data_buff,"\r\n",&payload_ptr)) != NULL){
		key = strtok_r(buff,": ",&header_ptr);
		value = strtok_r(buff,": ",&header_ptr);
		struct node* header_cont = create_node(key,value);
		if((payload->header).insert(&(payload->header),header_cont)<0){
			log_printf(MSG_WARNING,"PARSE: http reply header contect match fail\n");
			return -1;
		}
	}

	print_hashtable(&(payload->header));
	return 0;
}
