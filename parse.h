
#define unsigned char  u_char
#define unsigned short u_short

typedef struct{}

typedef struct{
	u_char* method;
	u_char* URI;
	u_char* version;
}http_type;

typedef struct{
	u_char* accept;
	u_char* accept_charset;
	u_char* accept_encoding;
	u_char* accept_language;
        u_char* authorization;
	u_char* cache_control;
	u_char* connection;
	u_char* cookie;
	u_char* content_length;
	u_char* content_type;	
}http_resq_header;

typedef struct{
	struct http_type type;
	struct http_header header;
}http_payload;
