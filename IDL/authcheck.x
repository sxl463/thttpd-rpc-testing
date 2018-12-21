
#include "idl_config.h"
/*
const MAXLEN = 1024;
typedef char filename[MAXLEN];
typedef int vtimestamp[5];
typedef int sender_id;
typedef int recv_id;

struct request {
    filename name;
    int start;
    vtimestamp ts;
    sender_id sid;
    recv_id rid;
};

typedef struct request request;

typedef opaque filepart[MAXLEN];

struct partreceive {
    filepart data;
    int bytes;
    vtimestamp ts;
    sender_id sid;
    recv_id rid;
};
typedef struct partreceive partreceive;

struct partsend {
    filename name;
    filepart data;
    int bytes;
    vtimestamp ts;
    sender_id sid;
    recv_id rid;
    int isStart;
    int source;
};
typedef struct partsend partsend;

union readfile_res switch (int errno) {
    case 0:
        partreceive part;
    default:
        void;
};

struct fileListing {
	filename list[MAXLEN];
	vtimestamp ts[MAXLEN];
	int len;
};
typedef struct fileListing fileListing;

union listfile_res switch (int errno) {
    case 0:
        fileListing fileListing;
    default:
        void;
};

*/
/*
program FTPROG {
    version FTVER {
        readfile_res retrieve_file(request *) = 1;
        int send_file(partsend *) = 2;
	listfile_res listfile(request *) = 3;
    } = 1;
} = 0x31240000;
*/

/* 
A simplified interface between auth_check and auth_check2. 
    if ( hc->hs->vhost && hc->hostdir[0] != '\0' )
    hc->status = status; send_mime
hc->hs->charset
*/
struct auth_check2_out {
	int ret;
};

struct shttpd_conn{
	string dirname<100>;
	string authorization<100>;
	string hostdir<100>;
	string remoteuser<100>;
	string encodedurl<100>; /* used in httpd_send_err*/
	string useragent<100>;
	string charset<100>;
	string protocol<100>;
	string p3p<100>;
	string response<500>;
	int global_passwd;
	int vhost;
	int maxremoteuser;
	int method;
	int should_linger;
	int status;
	int mime_flag; /*used in send_mime*/
	int max_age; /*hs->max_age*/
	int got_range;
	int maxresponse; /*size_t*/
	int responselen; /*size_t*/
	long first_byte_index;
	long last_byte_index;
	long bytes_to_send; /*off_t usuall long int*/
	long range_if; /*time_t*/
	/*long st_mtime; */
};
typedef struct shttpd_conn shttpd_conn;

program AUTHPROG {
    version AUTHVERSION {
        auth_check2_out auth_check2(shttpd_conn) = 1;
    } = 1;
} = 0x31240000;
/*
        int send_file(partsend *) = 2;
	listfile_res listfile(request *) = 3;
*/
