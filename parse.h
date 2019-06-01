#include"hashtab.h"
#include"print.h"
struct http_resquest_type {
	u_char* method;
	u_char* URI;
	u_char* version;
};

struct http_reply_type {
	u_char* version;
	int     status_code;
	u_char* phrase;
};
/* request header :
 * accept  
 * accept_charset
 * accept_encoding
 * accept_language
 * authorization
 * expect
 * from
 * host
 * if-match
 * if-modified-since
 * if-none-match
 * if-range
 * if-unmodified-since
 * max-forwards
 * proxy-authorization
 * range
 * referer
 * TE
 * user-agent
 * cache_control
 * connection
 * cookie
 * content_length
 * content_type	
 */

typedef struct{
	struct http_resquest_type type;
	struct hash_table header;
}http_resquest_payload;

/* reply header
 * Accept_ranges
 * Age
 * ETag
 * Location
 * Proxy-Authenticate
 * Retry-After
 * Server
 * Vary
 * WWW-Authenticate
 */

typedef struct{
	struct http_reply_type type;
	struct hash_table header;
}http_reply_payload;

int parse_http_request(const u_char* data,http_resquest_payload* payload);

int parse_http_reply(const u_char* data,http_reply_payload* payload);
