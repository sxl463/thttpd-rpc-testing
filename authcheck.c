/*
#2:
Sensitive partition (with names):
$str_alloc_count
$str_alloc_size
auth_check2
httpd_logstats

Replicated functions (with names):
$JunkClientData
$b64_decode_table
$expire_age
$sub_process
$terminate
add_response
b64_decode
defang
httpd_ntoa
httpd_realloc_str
shttpd_send_err
match
match_one
my_snprintf
send_authenticate
send_err_file
send_mime
send_response
send_response_tail
sockaddr_len

Static boundary: (383.4,8.0,1.0,9.30)
$str_alloc_count httpd_realloc_str
$str_alloc_size httpd_realloc_str
auth_check auth_check2
httpd_realloc_str $str_alloc_count
httpd_realloc_str $str_alloc_size
logstats httpd_logstats
*/

#include "config.h"
#include "version.h"

#ifdef SHOW_SERVER_VERSION
#define EXPOSED_SERVER_SOFTWARE SERVER_SOFTWARE
#else /* SHOW_SERVER_VERSION */
#define EXPOSED_SERVER_SOFTWARE "thttpd"
#endif /* SHOW_SERVER_VERSION */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/stat.h>

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <time.h>
#ifdef HAVE_MEMORY_H
#include <memory.h>
#endif /* HAVE_MEMORY_H */
#include <pwd.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>
#include <stdarg.h>

#ifdef HAVE_OSRELDATE_H
#include <osreldate.h>
#endif /* HAVE_OSRELDATE_H */

#ifdef HAVE_DIRENT_H
# include <dirent.h>
# define NAMLEN(dirent) strlen((dirent)->d_name)
#else
# define dirent direct
# define NAMLEN(dirent) (dirent)->d_namlen
# ifdef HAVE_SYS_NDIR_H
#  include <sys/ndir.h>
# endif
# ifdef HAVE_SYS_DIR_H
#  include <sys/dir.h>
# endif
# ifdef HAVE_NDIR_H
#  include <ndir.h>
# endif
#endif

#include "libhttpd.h"
#include "mmc.h"
#include "timers.h"
#include "match.h"
#include "tdate_parse.h"
//#include "socket.h"
#include "authcheck.h"

#ifndef STDIN_FILENO
#define STDIN_FILENO 0
#endif
#ifndef STDOUT_FILENO
#define STDOUT_FILENO 1
#endif
#ifndef STDERR_FILENO
#define STDERR_FILENO 2
#endif

#ifndef SHUT_WR
#define SHUT_WR 1
#endif

#ifndef HAVE_INT64T
//typedef long long int64_t;
#endif

#ifndef HAVE_SOCKLENT
//typedef int socklen_t;
#endif

#ifdef __CYGWIN__
#define timezone  _timezone
#endif

#ifndef MAX
#define MAX(a,b) ((a) > (b) ? (a) : (b))
#endif
#ifndef MIN
#define MIN(a,b) ((a) < (b) ? (a) : (b))
#endif

/**
 * Example echo server
 *
 * This is the server script
 */
#ifndef DEFAULT_EXPIRE_AGE
#define DEFAULT_EXPIRE_AGE 600
#endif

#ifdef EXPLICIT_ERROR_PAGES
#define ERROR_FORM(a,b) b
#else /* EXPLICIT_ERROR_PAGES */
#define ERROR_FORM(a,b) a
#endif /* EXPLICIT_ERROR_PAGES */


ClientData JunkClientData;
static time_t expire_age = DEFAULT_EXPIRE_AGE;
static int sub_process = 0; // may be assigned to 1
int terminate = 0; // may be assigned to 1
static int str_alloc_count = 0;
static size_t str_alloc_size = 0;

static int b64_decode_table[256] = {
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,  /* 00-0F */
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,  /* 10-1F */
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,62,-1,-1,-1,63,  /* 20-2F */
    52,53,54,55,56,57,58,59,60,61,-1,-1,-1,-1,-1,-1,  /* 30-3F */
    -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,  /* 40-4F */
    15,16,17,18,19,20,21,22,23,24,25,-1,-1,-1,-1,-1,  /* 50-5F */
    -1,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,  /* 60-6F */
    41,42,43,44,45,46,47,48,49,50,51,-1,-1,-1,-1,-1,  /* 70-7F */
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,  /* 80-8F */
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,  /* 90-9F */
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,  /* A0-AF */
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,  /* B0-BF */
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,  /* C0-CF */
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,  /* D0-DF */
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,  /* E0-EF */
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1   /* F0-FF */
    };

static char* ok206title = "Partial Content";
static char* err401title = "Unauthorized";
static char* err401form =
    "Authorization required for the URL '%.80s'.\n";

static char* err403title = "Forbidden";
static char* err403form =
    "You do not have permission to get URL '%.80s' from this server.\n";

// static int auth_check( httpd_conn* hc, char* dirname  ); // 88
static int auth_check2( shttpd_conn* hc, char* dirname  ); // 89
void httpd_logstats( long secs );
/*-----------------------------------------*/
static void send_authenticate( shttpd_conn* hc, char* realm ); // 91

char* httpd_ntoa( httpd_sockaddr* saP ); // 36

void httpd_realloc_str( char** strP, size_t* maxsizeP, size_t size ); // 43

void shttpd_send_err( shttpd_conn* hc, int status, char* title, char* extraheads, char* form, char* arg ); // 44

static size_t sockaddr_len( httpd_sockaddr* saP ); // 58

static int my_snprintf( char* str, size_t size, const char* format, ... ); // 59

static int send_err_file( shttpd_conn* hc, int status, char* title, char* extraheads, char* filename ); // 60

static void send_response( shttpd_conn* hc, int status, char* title, char* extraheads, char* form, char* arg ); // 61

static void send_mime( shttpd_conn* hc, int status, char* title, char* encodings, char* extraheads, char* type, off_t length, time_t mod ); // 70

static void add_response( shttpd_conn* hc, char* str ); // 71

static void send_response_tail( shttpd_conn* hc ); // 95

static void defang( char* str, char* dfstr, int dfsize ); // 96

int match( const char* pattern, const char* string ); // 135

static int match_one( const char* pattern, int patternlen, const char* string ); // 136




/* Generate debugging statistics syslog message. */
void
httpd_logstats( long secs )
    {
    if ( str_alloc_count > 0 )
	syslog( LOG_NOTICE,
	    "  libhttpd - %d strings allocated, %lu bytes (%g bytes/str)",
	    str_alloc_count, (unsigned long) str_alloc_size,
	    (float) str_alloc_size / str_alloc_count );
    }

static int
b64_decode( const char* str, unsigned char* space, int size )
    {
    const char* cp;
    int space_idx, phase;
    int d, prev_d = 0;
    unsigned char c;

    space_idx = 0;
    phase = 0;
    for ( cp = str; *cp != '\0'; ++cp )
	{
	d = b64_decode_table[(int) ((unsigned char) *cp)];
	if ( d != -1 )
	    {
	    switch ( phase )
		{
		case 0:
		++phase;
		break;
		case 1:
		c = ( ( prev_d << 2 ) | ( ( d & 0x30 ) >> 4 ) );
		if ( space_idx < size )
		    space[space_idx++] = c;
		++phase;
		break;
		case 2:
		c = ( ( ( prev_d & 0xf ) << 4 ) | ( ( d & 0x3c ) >> 2 ) );
		if ( space_idx < size )
		    space[space_idx++] = c;
		++phase;
		break;
		case 3:
		c = ( ( ( prev_d & 0x03 ) << 6 ) | d );
		if ( space_idx < size )
		    space[space_idx++] = c;
		phase = 0;
		break;
		}
	    prev_d = d;
	    }
	}
    return space_idx;
    }


/* Returns -1 == unauthorized, 0 == no auth file, 1 = authorized. */
/*
static int
auth_check( httpd_conn* hc, char* dirname  )
    {
	printf("Already in auth_check:\n");
	printf("hc->hs->global_passwd:%d\n", hc->hs->global_passwd);

    if ( hc->hs->global_passwd )
	{
	printf("in auth_check, LINE 236\n");
	char* topdir;
	if ( hc->hs->vhost && hc->hostdir[0] != '\0' )
	    topdir = hc->hostdir;
	else
	    topdir = ".";
	switch ( auth_check2( hc, topdir ) )
	    {
	    case -1:
	    return -1;
	    case 1:
	    return 1;
	    }
	}
    printf("Before return auth_check2:\n");
    return auth_check2( hc, dirname );
    }
*/

/* Returns -1 == unauthorized, 0 == no auth file, 1 = authorized. */
static int
auth_check2( shttpd_conn* hc, char* dirname  )
    {
    static char* authpath;
    static size_t maxauthpath = 0;
    struct stat sb;
    char authinfo[500];
    char* authpass;
    char* colon;
    int l;
    FILE* fp;
    char line[500];
    char* cryp;
    static char* prevauthpath;
    static size_t maxprevauthpath = 0;
    static time_t prevmtime;
    static char* prevuser;
    static size_t maxprevuser = 0;
    static char* prevcryp;
    static size_t maxprevcryp = 0;

	printf("DEBUG beginning in auth_check2:\n");
    /* Construct auth filename. */
    httpd_realloc_str(
	&authpath, &maxauthpath, strlen( dirname ) + 1 + sizeof(AUTH_FILE) );
    (void) my_snprintf( authpath, maxauthpath, "%s/%s", dirname, AUTH_FILE );

    /* Does this directory have an auth file? */
    if ( stat( authpath, &sb ) < 0 )
	/* Nope, let the request go through. */
	return 0;

    /* Does this request contain basic authorization info? */
    if ( hc->authorization[0] == '\0' ||
	 strncmp( hc->authorization, "Basic ", 6 ) != 0 )
	{
	/* Nope, return a 401 Unauthorized. */
	send_authenticate( hc, dirname );
	return -1;
	}
#if 1
    /* Decode it. */
    l = b64_decode(
	&(hc->authorization[6]), (unsigned char*) authinfo,
	sizeof(authinfo) - 1 );
#endif
    l = 100;

    authinfo[l] = '\0';
	printf("authinfo: %s\n", authinfo);
    /* Split into user and password. */
    authpass = strchr( authinfo, ':' );
    if ( authpass == (char*) 0 )
	{
	/* No colon?  Bogus auth info. */
	send_authenticate( hc, dirname );
	return -1;
	}
    *authpass++ = '\0';
    /* If there are more fields, cut them off. */
    colon = strchr( authpass, ':' );
    if ( colon != (char*) 0 )
	*colon = '\0';

    /* See if we have a cached entry and can use it. */
    if ( maxprevauthpath != 0 &&
	 strcmp( authpath, prevauthpath ) == 0 &&
	 sb.st_mtime == prevmtime &&
	 strcmp( authinfo, prevuser ) == 0 )
	{
	/* Yes.  Check against the cached encrypted password. */
	if ( strcmp( crypt( authpass, prevcryp ), prevcryp ) == 0 )
	    {
	    /* Ok! */

	    httpd_realloc_str(
		&hc->remoteuser, &hc->maxremoteuser, strlen( authinfo ) );

	    (void) strcpy( hc->remoteuser, authinfo );
	    return 1;
	    }
	else
	    {
	    /* No. */
	    send_authenticate( hc, dirname );
	    return -1;
	    }
	}

    printf("DEBUG 1: Before open the password file\n");
    /* Open the password file. */
    fp = fopen( authpath, "r" );
    if ( fp == (FILE*) 0 )
	{
	/* The file exists but we can't open it?  Disallow access. */
/*
	syslog(
	    LOG_ERR, "%.80s auth file %.80s could not be opened - %m",
	    httpd_ntoa( &hc->client_addr ), authpath );
*/
	shttpd_send_err(
	    hc, 403, err403title, "",
	    ERROR_FORM( err403form, "The requested URL '%.80s' is protected by an authentication file, but the authentication file cannot be opened.\n" ),
	    hc->encodedurl );

	return -1;
	}

    printf("DEBUG 2: read password file\n");
    /* Read it. */
    while ( fgets( line, sizeof(line), fp ) != (char*) 0 )
	{
	/* Nuke newline. */
	l = strlen( line );
	if ( line[l - 1] == '\n' )
	    line[l - 1] = '\0';
	/* Split into user and encrypted password. */
	cryp = strchr( line, ':' );
	if ( cryp == (char*) 0 )
	    continue;
	*cryp++ = '\0';
	/* Is this the right user? */
	if ( strcmp( line, authinfo ) == 0 )
	    {
	      printf("DEBUG 3: right user, do fclose()\n");
	    /* Yes. */
	    (void) fclose( fp );
	    /* So is the password right? */
	    if ( strcmp( crypt( authpass, cryp ), cryp ) == 0 )
		{
		  printf("DEBUG 4: right password, cache the user's information\n");
		/* Ok! */

		httpd_realloc_str(
		    &hc->remoteuser, &hc->maxremoteuser, strlen( line ) );

		(void) strcpy( hc->remoteuser, line );
		/* And cache this user's info for next time. */
		httpd_realloc_str(
		    &prevauthpath, &maxprevauthpath, strlen( authpath ) );
		(void) strcpy( prevauthpath, authpath );
		prevmtime = sb.st_mtime;
		httpd_realloc_str(
		    &prevuser, &maxprevuser, strlen( authinfo ) );
		(void) strcpy( prevuser, authinfo );
		httpd_realloc_str( &prevcryp, &maxprevcryp, strlen( cryp ) );
		(void) strcpy( prevcryp, cryp );
		return 1;
		}
	    else
		{
		/* No. */
		  printf("DEBUG 5: wrong password, send_authenticate\n");
		send_authenticate( hc, dirname );
		return -1;
		}
	    }
	}
    printf("DEBUG 6: Didn't find that user, access denied and do send_authenticate\n");

    /* Didn't find that user.  Access denied. */
    (void) fclose( fp );
    send_authenticate( hc, dirname );
    return -1;
    }

// 91
static void
send_authenticate( shttpd_conn* hc, char* realm )
    {
    static char* header;
    static size_t maxheader = 0;
    static char headstr[] = "WWW-Authenticate: Basic realm=\"";

    httpd_realloc_str(
	&header, &maxheader, sizeof(headstr) + strlen( realm ) + 3 );
    (void) my_snprintf( header, maxheader, "%s%s\"\015\012", headstr, realm );
    shttpd_send_err( hc, 401, err401title, header, err401form, hc->encodedurl );
    /* If the request was a POST then there might still be data to be read,
    ** so we need to do a lingering close.
    */
    if ( hc->method == METHOD_POST )
	hc->should_linger = 1;
    }

// 36
char*
httpd_ntoa( httpd_sockaddr* saP )
    {
#ifdef USE_IPV6
    static char str[200];

    if ( getnameinfo( &saP->sa, sockaddr_len( saP ), str, sizeof(str), 0, 0, NI_NUMERICHOST ) != 0 )
	{
	str[0] = '?';
	str[1] = '\0';
	}
    else if ( IN6_IS_ADDR_V4MAPPED( &saP->sa_in6.sin6_addr ) && strncmp( str, "::ffff:", 7 ) == 0 )
	/* Elide IPv6ish prefix for IPv4 addresses. */
	(void) ol_strcpy( str, &str[7] );

    return str;

#else /* USE_IPV6 */

    return inet_ntoa( saP->sa_in.sin_addr );

#endif /* USE_IPV6 */
    }

// 43
void
httpd_realloc_str( char** strP, size_t* maxsizeP, size_t size )
    {
    if ( *maxsizeP == 0 )
	{
	printf("In httpd_realloc_str, DEBUG 1(if *maxsizeP == 0)\n");
	printf("str_alloc_count:%d\n", str_alloc_count);
	printf("str_alloc_size:%d\n", str_alloc_size);
	*maxsizeP = MAX( 200, size + 100 );
	*strP = NEW( char, *maxsizeP + 1 );
	++str_alloc_count;
	str_alloc_size += *maxsizeP;
	}
    else if ( size > *maxsizeP )
	{
	printf("In httpd_realloc_str, DEBUG 2(if size > *maxsizeP)\n");
	printf("str_alloc_count:%d\n", str_alloc_count);
	printf("str_alloc_size:%d\n", str_alloc_size);

	str_alloc_size -= *maxsizeP;
	*maxsizeP = MAX( *maxsizeP * 2, size * 5 / 4 );
	*strP = RENEW( *strP, char, *maxsizeP + 1 );
	str_alloc_size += *maxsizeP;
	}
    else{
	printf("In httpd_realloc_str, DEBUG 3, return void directly\n");
	return;
	}
    if ( *strP == (char*) 0 )
	{
	printf("In httpd_realloc_str, DEBUG 4s, return void directly\n");
	syslog(
	    LOG_ERR, "out of memory reallocating a string to %ld bytes",
	    (long) *maxsizeP );
	exit( 1 );
	}
    }

// 44
void
shttpd_send_err( shttpd_conn* hc, int status, char* title, char* extraheads, char* form, char* arg )
    {
#ifdef ERR_DIR

    char filename[1000];

    /* Try virtual host error page. */
    if ( hc->vhost && hc->hostdir[0] != '\0' ) /*shen: hc->hs->vhost*/
	{
	(void) my_snprintf( filename, sizeof(filename),
	    "%s/%s/err%d.html", hc->hostdir, ERR_DIR, status );
	if ( send_err_file( hc, status, title, extraheads, filename ) )
	    return;
	}

    /* Try server-wide error page. */
    (void) my_snprintf( filename, sizeof(filename),
	"%s/err%d.html", ERR_DIR, status );
    if ( send_err_file( hc, status, title, extraheads, filename ) )
	return;

    /* Fall back on built-in error page. */
    send_response( hc, status, title, extraheads, form, arg );

#else /* ERR_DIR */

    send_response( hc, status, title, extraheads, form, arg );

#endif /* ERR_DIR */
    }


// 58
static size_t
sockaddr_len( httpd_sockaddr* saP )
    {
    switch ( saP->sa.sa_family )
	{
	case AF_INET: return sizeof(struct sockaddr_in);
#ifdef USE_IPV6
	case AF_INET6: return sizeof(struct sockaddr_in6);
#endif /* USE_IPV6 */
	default:
	return 0;	/* shouldn't happen */
	}
    }
// 59
static int
my_snprintf( char* str, size_t size, const char* format, ... )
    {
    va_list ap;
    int r;

    va_start( ap, format );
#ifdef HAVE_VSNPRINTF
    r = vsnprintf( str, size, format, ap );
#else /* HAVE_VSNPRINTF */
    r = vsprintf( str, format, ap );
#endif /* HAVE_VSNPRINTF */
    va_end( ap );
    return r;
    }

// 60
#ifdef ERR_DIR
static int
send_err_file( shttpd_conn* hc, int status, char* title, char* extraheads, char* filename )
    {
    FILE* fp;
    char buf[1000];
    size_t r;

    fp = fopen( filename, "r" );
    if ( fp == (FILE*) 0 )
	return 0;
    send_mime(
	hc, status, title, "", extraheads, "text/html; charset=%s", (off_t) -1,
	(time_t) 0 );
    for (;;)
	{
	r = fread( buf, 1, sizeof(buf) - 1, fp );
	if ( r == 0 )
	    break;
	buf[r] = '\0';
	add_response( hc, buf );
	}
    (void) fclose( fp );

#ifdef ERR_APPEND_SERVER_INFO
    send_response_tail( hc );
#endif /* ERR_APPEND_SERVER_INFO */

    return 1;
    }
#endif /* ERR_DIR */

// 61
static void
send_response( shttpd_conn* hc, int status, char* title, char* extraheads, char* form, char* arg )
    {
    char defanged_arg[1000], buf[2000];

    send_mime(
	hc, status, title, "", extraheads, "text/html; charset=%s", (off_t) -1,
	(time_t) 0 );
    (void) my_snprintf( buf, sizeof(buf), "\
<!DOCTYPE html PUBLIC \"-//W3C//DTD HTML 4.01 Transitional//EN\" \"http://www.w3.org/TR/html4/loose.dtd\">\n\
\n\
<html>\n\
\n\
  <head>\n\
    <meta http-equiv=\"Content-type\" content=\"text/html;charset=UTF-8\">\n\
    <title>%d %s</title>\n\
  </head>\n\
\n\
  <body bgcolor=\"#cc9999\" text=\"#000000\" link=\"#2020ff\" vlink=\"#4040cc\">\n\
\n\
    <h2>%d %s</h2>\n",
	status, title, status, title );
    add_response( hc, buf );
    defang( arg, defanged_arg, sizeof(defanged_arg) );
    (void) my_snprintf( buf, sizeof(buf), form, defanged_arg );
    add_response( hc, buf );
    if ( match( "**MSIE**", hc->useragent ) )
	{
	int n;
	add_response( hc, "<!--\n" );
	for ( n = 0; n < 6; ++n )
	    add_response( hc, "Padding so that MSIE deigns to show this error instead of its own canned one.\n");
	add_response( hc, "-->\n" );
	}
    send_response_tail( hc );
    }

// 70
static void
send_mime( shttpd_conn* hc, int status, char* title, char* encodings, char* extraheads, char* type, off_t length, time_t mod )
    {
    time_t now, expires;
    const char* rfc1123fmt = "%a, %d %b %Y %H:%M:%S GMT";
    char nowbuf[100];
    char modbuf[100];
    char expbuf[100];
    char fixed_type[500];
    char buf[1000];
    int partial_content;
    int s100;

    hc->status = status;
    hc->bytes_to_send = length;
    if ( hc->mime_flag )
	{
	if ( status == 200 && hc->got_range &&
	     ( hc->last_byte_index >= hc->first_byte_index ) &&
	     ( ( hc->last_byte_index != length - 1 ) ||
	       ( hc->first_byte_index != 0 ) ) &&
	     ( hc->range_if == (time_t) -1 ) ) /*changed by shen, there was hc->range_if == hc->sb.st_mtime(original)*/
	    {
	    partial_content = 1;
	    hc->status = status = 206;
	    title = ok206title;
	    }
	else
	    {
	    partial_content = 0;
	    hc->got_range = 0;
	    }

	now = time( (time_t*) 0 );
	if ( mod == (time_t) 0 )
	    mod = now;
	(void) strftime( nowbuf, sizeof(nowbuf), rfc1123fmt, gmtime( &now ) );
	(void) strftime( modbuf, sizeof(modbuf), rfc1123fmt, gmtime( &mod ) );
	(void) my_snprintf(
	    fixed_type, sizeof(fixed_type), type, hc->charset ); /*changed by shen, hc->hs->charset*/
	(void) my_snprintf( buf, sizeof(buf),
	    "%.20s %d %s\015\012Server: %s\015\012Content-Type: %s\015\012Date: %s\015\012Last-Modified: %s\015\012Accept-Ranges: bytes\015\012Connection: close\015\012",
	    hc->protocol, status, title, EXPOSED_SERVER_SOFTWARE, fixed_type,
	    nowbuf, modbuf );
	add_response( hc, buf );
	s100 = status / 100;
	if ( s100 != 2 && s100 != 3 )
	    {
	    (void) my_snprintf( buf, sizeof(buf),
		"Cache-Control: no-cache,no-store\015\012" );
	    add_response( hc, buf );
	    }
	if ( encodings[0] != '\0' )
	    {
	    (void) my_snprintf( buf, sizeof(buf),
		"Content-Encoding: %s\015\012", encodings );
	    add_response( hc, buf );
	    }
	if ( partial_content )
	    {
	    (void) my_snprintf( buf, sizeof(buf),
		"Content-Range: bytes %lld-%lld/%lld\015\012Content-Length: %lld\015\012",
		(long long) hc->first_byte_index,
		(long long) hc->last_byte_index,
		(long long) length,
		(long long) ( hc->last_byte_index - hc->first_byte_index + 1 ) );
	    add_response( hc, buf );
	    }
	else if ( length >= 0 )
	    {
	    (void) my_snprintf( buf, sizeof(buf),
		"Content-Length: %lld\015\012", (long long) length );
	    add_response( hc, buf );
	    }
	if ( hc->p3p[0] != '\0' ) /*shen, hc->hs->p3p[0]*/
	    {
	    (void) my_snprintf( buf, sizeof(buf), "P3P: %s\015\012", hc->p3p );/*shen, hc->hs->p3p*/
	    add_response( hc, buf );
	    }
	if ( hc->max_age >= 0 ) /*shen: hc->hs->max_age*/
	    {
	    expires = now + hc->max_age; /*hc->hs->max_age*/
	    (void) strftime(
		expbuf, sizeof(expbuf), rfc1123fmt, gmtime( &expires ) );
	    (void) my_snprintf( buf, sizeof(buf),
		"Cache-Control: max-age=%d\015\012Expires: %s\015\012",
		hc->max_age, expbuf ); /*hc->hs->max_age*/
	    add_response( hc, buf );
	    }
	if ( extraheads[0] != '\0' )
	    add_response( hc, extraheads );
	add_response( hc, "\015\012" );
	}
    }

// 71

/* Append a string to the buffer waiting to be sent as response. */
static void
add_response( shttpd_conn* hc, char* str )
    {
    size_t len;

    len = strlen( str );
    httpd_realloc_str( &hc->response, &hc->maxresponse, hc->responselen + len );
    (void) memmove( &(hc->response[hc->responselen]), str, len );
    hc->responselen += len;
    }

// 95
static void
send_response_tail( shttpd_conn* hc )
    {
    char buf[1000];

    (void) my_snprintf( buf, sizeof(buf), "\
    <hr>\n\
\n\
    <address><a href=\"%s\">%s</a></address>\n\
\n\
  </body>\n\
\n\
</html>\n",
	SERVER_ADDRESS, EXPOSED_SERVER_SOFTWARE );
    add_response( hc, buf );
    }

// 96
static void
defang( char* str, char* dfstr, int dfsize )
    {
    char* cp1;
    char* cp2;

    for ( cp1 = str, cp2 = dfstr;
	  *cp1 != '\0' && cp2 - dfstr < dfsize - 5;
	  ++cp1, ++cp2 )
	{
	switch ( *cp1 )
	    {
	    case '<':
	    *cp2++ = '&';
	    *cp2++ = 'l';
	    *cp2++ = 't';
	    *cp2 = ';';
	    break;
	    case '>':
	    *cp2++ = '&';
	    *cp2++ = 'g';
	    *cp2++ = 't';
	    *cp2 = ';';
	    break;
	    default:
	    *cp2 = *cp1;
	    break;
	    }
	}
    *cp2 = '\0';
    }

// 135
int
match( const char* pattern, const char* string )
    {
    const char* or;

    for (;;)
	{
	or = strchr( pattern, '|' );
	if ( or == (char*) 0 )
	    return match_one( pattern, strlen( pattern ), string );
	if ( match_one( pattern, or - pattern, string ) )
	    return 1;
	pattern = or + 1;
	}
    }

// 136
static int
match_one( const char* pattern, int patternlen, const char* string )
    {
    const char* p;

    for ( p = pattern; p - pattern < patternlen; ++p, ++string )
	{
	if ( *p == '?' && *string != '\0' )
	    continue;
	if ( *p == '*' )
	    {
	    int i, pl;
	    ++p;
	    if ( *p == '*' )
		{
		/* Double-wildcard matches anything. */
		++p;
		i = strlen( string );
		}
	    else
		/* Single-wildcard matches anything but slash. */
		i = strcspn( string, "/" );
	    pl = patternlen - ( p - pattern );
	    for ( ; i >= 0; --i )
		if ( match_one( p, pl, &(string[i]) ) )
		    return 1;
	    return 0;
	    }
	if ( *p != *string )
	    return 0;
	}
    if ( *string == '\0' )
	return 1;
    return 0;
    }


/*
test_out *
testproc_1_svc(test_in *inp, struct svc_req *rqstp)
{
	static test_out	out;

	printf("server : %s\n", inp->arg);

	service(strlen(inp->arg), inp->arg);

	out.res1 = strlen(inp->arg);
	return(&out);
}
*/
// extern  int * auth_check2_1_svc(shttpd_conn *, struct svc_req *);
//auth_check2( shttpd_conn* hc, char* dirname  )

int*
auth_check2_1_svc(shttpd_conn* shc, struct svc_req *rqstp)
{
	static int ret;
	printf("auth_check2 server:%s\n", shc->dirname);

	ret = auth_check2(shc, shc->dirname);

	return(&ret);
}






