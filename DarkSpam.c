
/*
 * DarkSpam - DarkSpam.c
 * Interface milter towards SpamAssassin
 *
 * Copyright (c) 2026 Vittorio Moccia
 * Licensed under the PolyForm Noncommercial License 1.0.0.
 * https://polyformproject.org/licenses/noncommercial/1.0.0/
 */

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <locale.h>
#include <fcntl.h>
#include <grp.h>
#include <libmilter/mfapi.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <pthread.h>
#include <pwd.h>
#include <regex.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>
#include "DarkSpam.h"
#include <db.h>


/* Syslog facility */
#define SYSLOG_FACILITY	LOG_DAEMON

	const char *pc_oconn = OCONN;
	const char *pc_user = USER;
        const char *pc_spamd_user = SDUSER;
        static long l_size = MAX_SIZE;

        int i_loglevel = LOG_NOTICE;                     /* -l, runtime, also used by DB.c via header */
        static const char *pc_spamd_addr = SPAMD_ADDRESS; /* -m */
        static int i_spamd_port = SPAMD_PORT;             /* -m */
        static int i_foreground = 0;                      /* -f */
        static int i_mime_filter = 1;                     /* -M disables it: default ENABLED */
        static int i_tag_mode = 0;                        /* -t: tag the spam instead of rejecting it */
        static char ca_spamd_addr[MAXHOST];               /* buffer for -m */

/* multi-rcpt: one line per envelope recipient.
   ca_addr is the RCPT in the RAW form received from sendmail (with <>),
   because smfi_delrcpt wants exactly that form back.
   c_state is the result of c_find_state; '\0' = line never written. */
#define RCPT_BASE   200
#define RCPT_GROW   100
#define RCPT_ADDR   256

struct rcpt_entry {
    char ca_addr[RCPT_ADDR];
    char c_state;
};

struct context {
    char addr[MAXADDR];
    char host[MAXHOST];
    char dghost[MAXHOST];
    char helo[MAXHOST];
    char hdr_from[MAXHEAD];
    char hdr_to[MAXHEAD];
    char hdr_subject[MAXLINE];
    char from[MAXLINE];
    char rcpt[MAXLINE];
    char authid[MAXLINE];
    int sock;
    double score, threshold;
    time_t arrival;
    struct timeval tstart;
    struct timeval tend;
    unsigned long body_size;
    int msg_id;
    char c_discard;   /* patch 2.7: connection-level DISCARD entry, applied in envfrom */
    char c_skip_conn;               /* connection-level skip (whitelist/access) */
    char ca_skip_conn[MAXHOST];     /* reason */
    char c_skip_msg;                /* message-level skip (from/rcpt) */
    char ca_skip_msg[MAXHOST];      /* reason */
    struct rcpt_entry *ps_rcpts;    /* multi-rcpt: lines {raw addr, access state} */
    int i_rcpt_alloc;               /* allocated lines (RCPT_BASE + RCPT_GROW batches) */
    int i_rcpt_count;               /* rcpts of the current message */
    int i_rcpt_white;               /* of which OK/RELAY/FRIEND */
    int i_rcpt_ovfl;                /* alloc failed: incomplete list, fail-safe */
    char queue[MAXLINE];
    char ca_main_bound[MIME_BOUND_LEN];  /* boundary of the main Content-Type (dg_header) */
    struct mime_stream mime;             /* MIME filter automaton, per-message */
};

static regex_t		re_ignore_connect;
static const char	*ignore_connect = WHITE_LIST;
extern time_t last_db_check;

static sfsistat dg_connect(SMFICTX *, char *, _SOCK_ADDR *); 
static sfsistat dg_helo(SMFICTX *, char *); 
static sfsistat dg_envfrom(SMFICTX *, char **); 
static sfsistat dg_envrcpt(SMFICTX *, char **); 
static sfsistat dg_header(SMFICTX *, char *, char *); 
static sfsistat dg_eoh(SMFICTX *); 
static sfsistat dg_body(SMFICTX *, u_char *, size_t); 
static sfsistat dg_eom(SMFICTX *); 
static sfsistat dg_abort(SMFICTX *); 
static sfsistat dg_close(SMFICTX *); 
static void dg_usage(const char *); 
static int i_spamd_start (struct context *); 
static int i_spamd_connect(int, struct sockaddr *, int); 
static int i_spamd_send(struct context *, const char *, size_t); 
static int i_spamd_recv(struct context *, char *pc_buffer, size_t size); 
void handle_reload(int sig);
static void resetcontext (struct context *);
static void resetcontext_env (struct context *);
static void rcpt_add (struct context *, const char *, char);
static const char *pc_rcpt_disp (struct context *, char *, long);
static void init_regex(void);
extern void cleanup_and_exit(int sig);
extern volatile sig_atomic_t reload_needed;
void cleanup_session(SMFICTX *);

struct smfiDesc smfilter = {
	"DarkSpam",	/* filter name */
        SMFI_VERSION,   /* version code */
	SMFIF_ADDHDRS|SMFIF_CHGHDRS|SMFIF_DELRCPT,	/* flags */
	dg_connect,	/* connection info filter */
	dg_helo,	/* SMTP HELO command filter */
	dg_envfrom,	/* envelope sender filter */
	dg_envrcpt,	/* envelope recipient filter */
	dg_header,	/* header filter */
	dg_eoh,		/* end of header */
	dg_body,	/* body block */
	dg_eom,		/* end of message */
	dg_abort,	/* message aborted */
	dg_close	/* connection cleanup */
};

extern DB *global_dbp;
extern pthread_mutex_t config_mutex;

static pthread_once_t re_once = PTHREAD_ONCE_INIT;


static int i_re_ok = 0;   /* 1 = whitelist regex compiled correctly */

static void init_regex(void)
{
    /* single point where the whitelist is compiled (via pthread_once).
       ICASE: case-insensitive match on the hostname; NOSUB: result only. */
    if (regcomp(&re_ignore_connect, ignore_connect, REG_EXTENDED | REG_ICASE | REG_NOSUB) == 0)
        i_re_ok = 1;
    else
        syslog(LOG_ERR, "init_regex: regcomp failed, whitelist disabled");
}



int main (int argc, char **argv)
{
	int i_get=0,
            i_ret=0;
	const char *pc_ofile = NULL;

	/* Pin the C locale.  Domains and addresses are lowercased before the
	 * access.db lookup, and states are matched with toupper(): under a
	 * single-byte LC_CTYPE those routines map octets >= 0x80, so two
	 * different domains could fold to the same key and match the wrong
	 * access.db entry.  Nothing else calls setlocale, so this makes the
	 * current behaviour explicit rather than incidental. */
	setlocale(LC_ALL, "C");

	tzset();
    


// ... inside main ...
sigset_t mask;
    sigemptyset(&mask);
    sigaddset(&mask, SIGHUP);
    
    // Try to unblock it BEFORE anything else
    pthread_sigmask(SIG_UNBLOCK, &mask, NULL);

struct sigaction sa;
memset(&sa, 0, sizeof(sa));
sa.sa_handler = handle_reload;
sa.sa_flags = SA_RESTART;
sigaction(SIGUSR1, &sa, NULL); // Changed here
sigaction(SIGHUP,  &sa, NULL); /* patch 2.5: HUP = reload (convention), no longer default termination */


	openlog("DarkSpam", LOG_PID | LOG_NDELAY, SYSLOG_FACILITY);

        /* white list regex: compiled only once in init_regex()
           via pthread_once at the first dg_connect (patch 2.3)      */

	while ((i_get = getopt(argc, argv, "z:p:u:U:m:l:w:fhMt")) != -1) {
		switch (i_get) {
		case 'z':
		{
			char *pc_end = NULL;
			l_size = strtol(optarg, &pc_end, 10);
			if (pc_end == optarg || *pc_end != '\0' || l_size <= 0) {
				fprintf(stderr, "-z: invalid value (bytes, > 0): %s\n", optarg);
				dg_usage(argv[0]);
			}
			break;
		}
		case 'p':
			pc_oconn = optarg;
			break;
		case 'u':
			pc_user = optarg;
			break;
		case 'U':
			pc_spamd_user = optarg;
			break;
		case 'm':
		{
			/* spamd host[:port]; host in dotted-quad IPv4 */
			int i;
			char *pc_end = NULL;
			long l_port;
			securecpy(ca_spamd_addr, optarg, MAXHOST);
			for (i = 0; ca_spamd_addr[i] != '\0'; i++) {
				if (ca_spamd_addr[i] == ':') {
					l_port = strtol(&ca_spamd_addr[i+1], &pc_end, 10);
					if (pc_end == &ca_spamd_addr[i+1] || *pc_end != '\0' ||
					    l_port < 1 || l_port > 65535) {
						fprintf(stderr, "-m: invalid port: %s\n", optarg);
						dg_usage(argv[0]);
					}
					i_spamd_port = (int) l_port;
					ca_spamd_addr[i] = '\0';
					break;
				}
			}
			if (inet_addr(ca_spamd_addr) == INADDR_NONE) {
				fprintf(stderr, "-m: invalid spamd address (dotted-quad): %s\n", ca_spamd_addr);
				dg_usage(argv[0]);
			}
			pc_spamd_addr = ca_spamd_addr;
			break;
		}
		case 'l':
		{
			char *pc_end = NULL;
			long l_lev = strtol(optarg, &pc_end, 10);
			if (pc_end == optarg || *pc_end != '\0' || l_lev < LOG_EMERG || l_lev > LOG_DEBUG) {
				fprintf(stderr, "-l: invalid level (0-7): %s\n", optarg);
				dg_usage(argv[0]);
			}
			i_loglevel = (int) l_lev;
			break;
		}
		case 'f':
			i_foreground = 1;
			break;
		case 'M':
			i_mime_filter = 0;
			break;
		case 'w':
			ignore_connect = optarg;   /* whitelist regex; empty string = disable */
			break;
		case 't':
			i_tag_mode = 1;
			break;
		case 'h':
		default:
			dg_usage(argv[0]);
		}
	}

	/* verbosity is governed centrally by the syslog mask:
	   each call declares its own true semantic level */
	setlogmask(LOG_UPTO(i_loglevel));
	syslog(LOG_INFO, "DarkSpam %s: socket %s, spamd %s:%d, max_size %ld, loglevel %d",
	       DG_VERSION, pc_oconn, pc_spamd_addr, i_spamd_port, l_size, i_loglevel);

        if (!strncmp(pc_oconn, "unix:", 5))
	  pc_ofile = pc_oconn + 5;
        else if (!strncmp(pc_oconn, "local:", 6)) 
           pc_ofile = pc_oconn + 6;
        if (pc_ofile) unlink(pc_ofile);


	if (!getuid()) 
        {
		struct passwd *pw;

		if ((pw = getpwnam(pc_user)) == NULL) {
			fprintf(stderr, "getpwnam: %s: %s\n", pc_user,
			    strerror(errno));
			return (1);
		}
		setgroups(1, &pw->pw_gid);
		if (setegid(pw->pw_gid) || setgid(pw->pw_gid)) {
			fprintf(stderr, "setgid: %s\n", strerror(errno));
			return (1);
		}
		if (
		    seteuid(pw->pw_uid) ||
		    setuid(pw->pw_uid)) {
			fprintf(stderr, "setuid: %s\n", strerror(errno));
			return (1);
		}
	}
        if (init_access_db() != 1) {
        // If the DB is not found, log the error and exit
          syslog(LOG_ERR, "Fatal error: unable to load %s", ACCESS_FILE);
          exit(1); 
        }
	if (smfi_setconn((char *)pc_oconn) != MI_SUCCESS) {
		fprintf(stderr, "smfi_setconn: %s: failed\n", pc_oconn);
		i_ret = 1;
		goto done;
	}

	if (smfi_register(smfilter) != MI_SUCCESS) {
		fprintf(stderr, "smfi_register: failed\n");
		i_ret = 1;
		goto done;
	}

	/* daemonize (detach from controlling terminal), salvo -f */
	if ((!i_foreground) && daemon(0, 0)) {
		fprintf(stderr, "daemon: %s\n", strerror(errno));
		i_ret = 1;
		goto done;
	}
	umask(0177);
	signal(SIGPIPE, SIG_IGN);
  //      signal(SIGHUP, handle_reload);
        signal(SIGTERM, cleanup_and_exit);
        signal(SIGINT,  cleanup_and_exit);
	i_ret = smfi_main();

	if (i_ret != MI_SUCCESS)
		 syslog(LOG_ERR, "[ERROR] DarkSpam terminated due to a fatal error");
done:
	return (i_ret);
}


long securecpy (register char *pc_dst, register const char *pc_src, long l_sizeof)
{
/* copy two string preventing buffer overflow */
    register long i;
    if (pc_dst == NULL || l_sizeof < 1) return (0);
    if (pc_src == NULL) { pc_dst[0] = '\0'; return (0); }

    if (l_sizeof > 1)
    {
      pc_dst[0]='\0';
      l_sizeof--;
      for (i = 0; i < l_sizeof && (pc_dst[i] = pc_src[i]) != 0; i++) continue;
      pc_dst[i] = '\0';
      return (i);
    }
    else
    {
      return (0);
    }
}


long securecat (register char *pc_dst, register const char *pc_src, long l_sizeof)
{
/* cat two string preventing buffer overflow */
   register long i, j;
   if (pc_dst == NULL || l_sizeof < 1) return (0);

   for (j = 0; j < l_sizeof; j++)
      if (pc_dst[j] == 0) break;

   /* NULL source: nothing to append, leave the existing string intact */
   if (pc_src == NULL) return (j);

   if ((j + 1) == (l_sizeof))
      return (0);
   if (l_sizeof > 1)
   {
      l_sizeof--;
      for (i = 0; j < l_sizeof && (pc_dst[j] = pc_src[i]) != 0; i++, j++) continue;
      pc_dst[j] = '\0';
      return (j);
   }
   else
   {
      return (0);
   }

}


static void resetcontext (struct context *ps_context)
{
 	ps_context->hdr_from[0]='\0';
        ps_context->hdr_to[0]='\0';
	ps_context->hdr_subject[0]='\0';
        ps_context->from[0]='\0';
        ps_context->rcpt[0]='\0';
        ps_context->queue[0]='\0';
        ps_context->helo[0]='\0';
        ps_context->addr[0]='\0';
        ps_context->dghost[0]='\0';
	ps_context->score = ps_context->threshold = 0.0;
        ps_context->body_size = 0;
        ps_context->sock = -1;
        ps_context->msg_id = 0;
        ps_context->ca_main_bound[0]='\0';
        ps_context->c_skip_msg = 0;
        ps_context->ca_skip_msg[0]='\0';
        ps_context->i_rcpt_count = 0;   /* the list stays allocated: reuse */
        ps_context->i_rcpt_white = 0;
        ps_context->i_rcpt_ovfl = 0;
}

static void resetcontext_env (struct context *ps_context)
{
        ps_context->hdr_from[0]='\0';
        ps_context->hdr_to[0]='\0';
        ps_context->hdr_subject[0]='\0';
        ps_context->from[0]='\0';
        ps_context->rcpt[0]='\0';
        ps_context->queue[0]='\0';
        ps_context->score = ps_context->threshold = 0.0;
        ps_context->body_size = 0;
        ps_context->sock = -1;
        ps_context->msg_id = 0;
        ps_context->ca_main_bound[0]='\0';
        ps_context->c_skip_msg = 0;
        ps_context->ca_skip_msg[0]='\0';
        ps_context->i_rcpt_count = 0;   /* the list stays allocated: reuse */
        ps_context->i_rcpt_white = 0;
        ps_context->i_rcpt_ovfl = 0;
}


static void dg_usage(const char *argv0)
{
 fprintf(stderr,
   "usage: %s [options]\n"
   "  Options taking a value accept both forms: -l 7 or -l7\n"
   "\n"
   "  -z <bytes>      maximum size forwarded to spamd per message\n"
   "                  (default %d; counts the bytes AFTER the MIME filter)\n"
   "  -u <user>       user for the privilege drop (default %s)\n"
   "  -U <user>       value of the User: header towards spamd (default %s)\n"
   "  -p <socket>     milter socket: unix:/path or inet:port@host\n"
   "                  (default %s)\n"
   "  -m <ip[:port]>  spamd address in dotted-quad (default %s:%d)\n"
   "  -w <regex>      connection whitelist (extended regex on IP and hostname,\n"
   "                  default \"%s\"; empty string to disable it)\n"
   "  -l <0-7>        syslog level: 4=warning 5=notice (default) 6=info\n"
   "                  7=debug. NB: to see level 7 the syslog daemon\n"
   "                  must log daemon.debug (check with:\n"
   "                  logger -p daemon.debug TEST)\n"
   "  -t              tag the spam (X-Spam-Flag: YES) and deliver it,\n"
   "                  instead of the 554 reject (default: reject)\n"
   "  -M              disable the streaming MIME filter (default: enabled)\n"
   "  -f              foreground: does not go into background (debug/systemd)\n"
   "  -h              this help\n",
   argv0, MAX_SIZE, USER, SDUSER, OCONN, SPAMD_ADDRESS, SPAMD_PORT, WHITE_LIST);
 exit(1);
}

static void close_socket(int i_sock) {
    int i_ret;

    syslog(LOGLEVEL, "close_socket");

    if (i_sock < 0) return;
    shutdown(i_sock, SHUT_RDWR);
    do {
	i_ret = close(i_sock);
    } while (i_ret < 0 && errno == EINTR);
}

static int i_block_socket(int i_sock, int i_block) {
    int i_flags;

    if (i_sock < 0) 
       return -1;
    if ((i_flags = fcntl(i_sock, F_GETFL)) < 0) 
       return -2;
    if (i_block)
	i_flags &= ~O_NONBLOCK;
    else
	i_flags |= O_NONBLOCK;
    if (fcntl(i_sock, F_SETFL, i_flags) < 0) 
       return -3;
    return 0;
}


static int i_spamd_connect(int i_sock, struct sockaddr *address, int addrlen) {
    int optval, i_ret=0, i_ret1=0;
    fd_set wfds;
    struct timeval tv;
    socklen_t optlen = sizeof(optval);

    syslog(LOGLEVEL, "i_spamd_connect start");

    if (i_sock < 0)
    {
       syslog(LOG_DEBUG, "i_spamd_connect: no socket");
       return -1;
    }

    if (i_block_socket(i_sock, 0) < 0)
    {  
       syslog(LOG_ERR, "i_spamd_connect: unable to set socket");
       return -2;
    }

    if ((i_ret = connect(i_sock, address, addrlen)) < 0)
	if (errno != EINPROGRESS)
        { 
           syslog (LOG_WARNING, "i_spamd_connect: error on connect(): %s", strerror(errno));
           return -3;
        }

    if (i_ret == 0)
    {
      syslog (LOGLEVEL, "i_spamd_connect: connection already active");
      return 0;
    }

    do {
	FD_ZERO(&wfds);
	FD_SET(i_sock, &wfds);
	tv.tv_sec = SPAMD_TIMEOUT;
	tv.tv_usec = 0;
	i_ret = select(i_sock + 1, NULL, &wfds, NULL, &tv);
    } while (i_ret < 0 && errno == EINTR);

    if (i_ret <= 0)
    {
       syslog (LOG_WARNING, "i_spamd_connect: error on select(): %s", strerror(errno));
       return -4;
    }

    if (!FD_ISSET(i_sock, &wfds))
    {
      syslog (LOG_WARNING, "i_spamd_connect: error on FD_ISSET");
      return -5;
    }

    if (getsockopt(i_sock, SOL_SOCKET, SO_ERROR, &optval, &optlen) < 0)
    {
      syslog (LOG_WARNING, "i_spamd_connect: error on getsockopt");
      return -6;
    }

    if (optval)
    {
      syslog (LOG_WARNING, "i_spamd_connect: optval error %d", optval);
      return -7;
    }

    i_ret1=i_block_socket(i_sock, 1);
    if (i_ret1 < 0)
    {
      syslog (LOG_WARNING, "i_spamd_connect: error on setting type of socket: %d", i_ret1);
      return -8;
    }

    syslog(LOGLEVEL, "i_spamd_connect: Connection executed with socket %d", i_sock);

    return 0;
}


static int i_spamd_send(struct context *ps_context, const char *pc_buffer, size_t t_size) 
{
    int i_ret=0;
    fd_set myset;
    struct timeval tv;
    int i_sock=ps_context->sock;

    syslog(LOGLEVEL, "%s - i_spamd_send: sock %d %s",  ps_context->queue, i_sock, pc_buffer);

    if (i_sock < 0) 
    {
       syslog(LOG_DEBUG, "i_spamd_send: no socket");
       return -1;
    }

    do 
    {
	FD_ZERO(&myset);
	FD_SET(i_sock, &myset);
	tv.tv_sec = SPAMD_TIMEOUT;
	tv.tv_usec = 0;
	i_ret = select(i_sock+1, NULL, &myset, NULL, &tv);

    } while (i_ret < 0 && errno == EINTR);

    if (i_ret <= 0) /* timeout or !EINTR */
    {
       syslog (LOG_WARNING, "%s - i_spamd_send: error on select(): %s",  ps_context->queue, strerror(errno));
       return -2;
    }

    if (!FD_ISSET(i_sock, &myset))
    {
       syslog (LOG_WARNING, "%s - i_spamd_send: error on FD_ISSET: %s",  ps_context->queue, strerror(errno));
       return -3;
    }

    do 
    {
	i_ret = send(i_sock, pc_buffer, t_size, MSG_NOSIGNAL);
    } while (i_ret < 0 && errno == EINTR);

    if (i_ret < 0 || (size_t) i_ret < t_size) 
    {
       syslog (LOG_WARNING, "%s - i_spamd_send: unable to send the whole buffer",  ps_context->queue);
       return -4;
    }

    syslog(LOGLEVEL, "%s - i_spamd_send: sent %d bytes with socket %d", ps_context->queue, (int) t_size, i_sock);
    return 0;
}

static int i_spamd_recv(struct context *ps_context, char *pc_buffer, size_t size) 
{
    int i_ret;
    fd_set rfds;
    struct timeval tv;
    int i_sock=ps_context->sock;

    syslog(LOGLEVEL, "%s - i_spamd_recv start with socket %d",  ps_context->queue, i_sock);

    if (i_sock >= 0) 
    {
       do 
       {
          FD_ZERO(&rfds);
	  FD_SET(i_sock, &rfds);
	  tv.tv_sec = SPAMD_TIMEOUT_REPLY / SPAMD_RETRIES;
	  tv.tv_usec = 0;
	  i_ret = select(i_sock + 1, &rfds, NULL, NULL, &tv);
       } while (i_ret < 0 && errno == EINTR);

       if (i_ret < 0) 
       {
          syslog(LOG_WARNING, "%s - i_spamd_recv: select fails: %s", ps_context->queue, strerror(errno));
          return -2;
       }

       if (i_ret == 0) 
       /* end-of-file and empty buffer */
       {
            syslog (LOG_WARNING, "%s - i_spamd_recv: end-of-file and empty buffer", ps_context->queue);
            return 0;
       }

       if (!FD_ISSET(i_sock, &rfds)) 
       {
          syslog(LOG_WARNING, "%s - i_spamd_recv: select fails: %s", ps_context->queue, strerror(errno));
          return -3;
       }

        size_t total_read = 0;
        ssize_t bytes = 0;   
    
    // Clear the buffer before starting
       memset(pc_buffer, 0, size);

        while (total_read < size - 1) 
        {
           /* the first recv is protected by the select outside the loop,
              the following ones by the select at the tail of each iteration (patch 2.1) */
           bytes = recv(i_sock, pc_buffer + total_read, size - total_read - 1, 0);

           if (bytes < 0)
           {
               if (errno == EINTR) continue; // Interrupted by signal: readiness persists, retry the recv
               syslog(LOG_WARNING, "Recv error: %s", strerror(errno));  /* spamd: fail-open */
               return -1;
           }

           if (bytes == 0)
           {
               // The server closed the connection (EOF). 
               // Since we did shutdown(SHUT_WR), this is the signal that it is done.
               break;
           }

           total_read += bytes;

          // Optional: if the end-of-header sequence "\r\n\r\n" is found, we could stop earlier
          // if the rewritten body is not of interest.
          if (strstr(pc_buffer, "\r\n\r\n") != NULL) {
               break; 
          }

           /* more data needed: wait with timeout before the next recv.
              A spamd that stalls mid-reply must not hang the
              thread until sendmail's milter timeout */
           do 
           {
              FD_ZERO(&rfds);
              FD_SET(i_sock, &rfds);
              tv.tv_sec = SPAMD_TIMEOUT_REPLY / SPAMD_RETRIES;
              tv.tv_usec = 0;
              i_ret = select(i_sock + 1, &rfds, NULL, NULL, &tv);
           } while (i_ret < 0 && errno == EINTR);

           if (i_ret <= 0)
           {
              syslog(LOG_WARNING, "%s - i_spamd_recv: timeout or error on select in the accumulation loop: %s",
                     ps_context->queue, i_ret < 0 ? strerror(errno) : "timeout");
              return -1;
           }
        }

        pc_buffer[total_read] = '\0'; // Make sure it is a valid string
        i_ret=total_read;
        return (i_ret);

/*

       do 
       {
	    i_ret = recv(i_sock, pc_buffer, size - 1, MSG_NOSIGNAL);
            if (i_ret >= 0) {
                pc_buffer[i_ret] = '\0';
            }
       } while (i_ret < 0 && errno == EINTR);
*/
    }
    else
    {
       syslog(LOG_DEBUG, "i_spamd_recv: no socket");
       return -1;
    }


    if (i_ret <= 0)
    {
       syslog (LOG_WARNING, "%s - i_spamd_recv: error on recv(): %s", ps_context->queue, strerror(errno));
       return -1;
    }

    syslog(LOGLEVEL, "%s - i_spamd_recv end: received %s with socket %d", ps_context->queue, pc_buffer, i_sock);
    return 0;
}


static int i_spamd_start (struct context *ps_context)
{
    struct sockaddr_in address;
    // struct tm s_localtime;
    char ca_cmd[MAXCOMMAND];

    int i_sock, i_ret=0;
    int i_optval = 1;

    syslog(LOGLEVEL, "i_spamd_start");

    socklen_t optlen = sizeof(i_optval);
    memset(&address, 0, sizeof(address));
    address.sin_addr.s_addr = inet_addr(pc_spamd_addr);   /* -m, default SPAMD_ADDRESS */
    address.sin_family = AF_INET;
    address.sin_port = htons(i_spamd_port);               /* -m, default SPAMD_PORT */

    /* create a socket and returns the socket descriptor */
    i_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (i_sock < 0) 
    {
       syslog(LOG_ERR, "i_spamd_start: unable to get sock");
       return -1;
    }
    /* TCP_NODELAY: no Nagle towards spamd. The dialogue is request/reply
       with partial final segments (command, body tail before the
       shutdown): coalescing would only add latency. Failure
       non-fatal: we go on with Nagle enabled. */
    if (setsockopt(i_sock, IPPROTO_TCP, TCP_NODELAY, &i_optval, optlen) < 0)
    {
      syslog(LOG_WARNING, "i_spamd_start: unable to set TCP_NODELAY on %d", i_sock);
    }

    /*  set the specified options: socket level, handle the network failures */
    if (setsockopt(i_sock, SOL_SOCKET, SO_KEEPALIVE, &i_optval, optlen) < 0) 
    {
      syslog(LOG_ERR, "i_spamd_start: unable to set sockey options on %d", i_sock);
      close_socket(i_sock);
      return -2;
    }
    i_ret=i_spamd_connect(i_sock, (struct sockaddr *) &address, sizeof(address));
    if (i_ret < 0) 
    {      
      syslog(LOG_WARNING, "spamd_start: Spamd connection failed: %d", i_ret);
      close_socket(i_sock);
      return -3;
    }
    ps_context->queue[0]=0;    
    ps_context->sock=i_sock;
    /* SYMBOLS: besides the Spam: verdict, spamd returns the list of
       triggered symbols. Today it is neither parsed nor printed (headers
       intentionally terse), but it stays requested to keep open
       the option of using it in the future without touching the protocol. */
    securecpy(ca_cmd, "SYMBOLS SPAMC/1.2\r\n", sizeof(ca_cmd));
    i_ret = i_spamd_send(ps_context, ca_cmd, strlen(ca_cmd));
    if (i_ret < 0) 
    {
      syslog(LOG_WARNING, "Fatal call to i_spamd_send: %d with sock %d", i_ret, i_sock);
      close_socket(i_sock);   
      return -4;
    }

    syslog(LOGLEVEL, "i_spamd_start: executed with sock %d", i_sock);
    return 0;
}

static int i_get_spamd_reply(struct context *ps_context) 
{
    char ca_buffer[BIGLINE];
    char ca_spam[20];
    int i = 0;
    int i_notexit=1;
    double s, t;
    char *p = NULL;
    int i_ret=-2, i_ret1=0;  /* default fail-open: unparsable reply => error => accept */

    syslog(LOGLEVEL, "%s - i_get_spamd_reply: start", ps_context->queue);
 
    if (shutdown(ps_context->sock, SHUT_WR) >= 0) 
    /* shuts down the connection of socket ps_context->sock: 
      stop both reception and transmission                   */
    {
       gettimeofday(&ps_context->tstart, NULL);
       while ((i++ < SPAMD_RETRIES) && (i_notexit)) 
       {
	  memset(ca_buffer, 0, sizeof(ca_buffer));
	  memset(ca_spam, 0, sizeof(ca_spam));
          i_ret1=i_spamd_recv(ps_context, ca_buffer, sizeof(ca_buffer));
	  if (i_ret1 <= 0)
          { 
            i_notexit=0;
            close_socket(ps_context->sock);
            ps_context->sock = -1;
            syslog(LOG_WARNING, "%s - i_spamd_recv call failed: %d", ps_context->queue, i_ret1);
            i_ret= -2;
          }
          else
          {
             if ((p = strstr(ca_buffer, "Spam:")) && sscanf(p + 6, "%5s ; %lf / %lf", ca_spam, &s, &t) == 3) 
             {
	        gettimeofday(&ps_context->tend, NULL);
	        close_socket(ps_context->sock);
	        ps_context->sock = -1;
	        ps_context->score = s;
	        ps_context->threshold = t;
                i_notexit=0;
	        if (strstr(ca_spam, "True")) 
                { 
                   i_ret= 1; 
                }
                else if (strstr(ca_spam, "False"))
                {
	          i_ret=0;
                }
                else i_ret=-1;

                i_notexit=0;
             }
          } /* end else */
       } /* end while */

       if (i_notexit)   /* retries exhausted without a valid "Spam:" line */
       {
          syslog(LOG_WARNING, "%s - i_get_spamd_reply: unparsable spamd reply, failing open", ps_context->queue);
          close_socket(ps_context->sock);
          ps_context->sock = -1;
          i_ret = -2;
       }
    }
    else
    {
       syslog(LOG_WARNING, "%s - i_get_spamd_reply: shutdown failed", ps_context->queue);
       close_socket(ps_context->sock);
       ps_context->sock = -1;
       i_ret= -1;
    }

    syslog(LOGLEVEL, "%s - i_get_spamd_reply: [%s]", ps_context->queue, ca_buffer);
    return (i_ret);
}

static sfsistat dg_abort(SMFICTX *ctx) 
{
    struct context *ps_context;

    syslog(LOGLEVEL, "dg_abort: start");

    if ((ps_context = (struct context *)smfi_getpriv(ctx)) == NULL) 
    {
       return (SMFIS_CONTINUE);
    }

    /* abort = end of the MESSAGE, not of the connection: xxfi_close
       is called anyway, always, at connection close.
       Here we close the spamd socket and reset the message state,
       but the context stays alive for any subsequent MAIL FROM.
       The free is the exclusive job of dg_close. */
    if (ps_context->sock >= 0) 
    {
        close_socket(ps_context->sock);
    }
    resetcontext_env (ps_context);   /* also resets sock = -1 */

    syslog(LOGLEVEL, "dg_abort: end");

    return SMFIS_CONTINUE;
}


static sfsistat dg_connect(SMFICTX *ctx, char *pc_name, _SOCK_ADDR *sa) 
{
    struct context *ps_context=0;
    char c, c2;
    int i;
    int i_discard = 0;   /* patch 2.7: connection-level DISCARD entry found */
    int i_skip = 0;                 /* skip: whitelist/access accept but we want a trace */
    char ca_skiploc[MAXHOST]; ca_skiploc[0]='\0';
    char c_type='i';
    char ca_ip[MAXADDR], ca_found [MAXADDR], ca_domain[MAXHOST];
    struct stat st;
    static time_t last_check_time = 0; // Persistent memory across calls
    time_t now = time(NULL);
    // 1. Check for SIGNAL (kill -USR1)
    if (reload_needed) {
        reload_needed = 0;
        syslog(LOG_INFO, "DarkSpam: Forced reload from USR1 signal");
        init_access_db(); 
    } 
    else if (now - last_check_time >= 60) {
        last_check_time = now;
        if (stat(ACCESS_FILE, &st) == 0) {
            if (st.st_mtime > last_db_check) {
                syslog(LOG_INFO, "DarkSpam: Automatic change detected on %s, updating...", ACCESS_FILE);
                init_access_db();
            }
        }
    }


    memset(ca_ip, 0, sizeof(ca_ip)); // Initialize to zero
    strncpy(ca_ip, "0.0.0.0", MAXADDR - 1);

    syslog(LOGLEVEL, "dg_connect: start");

    switch (sa->sa_family) 
    {
	case AF_INET: 
	{
	    struct sockaddr_in *sin = (struct sockaddr_in *)sa;
            /* convert a numeric IPv4 address into a text string suitable for presentation */
	    inet_ntop(AF_INET, &sin->sin_addr.s_addr, ca_ip, MAXADDR);
	    break;
	}
	case AF_INET6: 
	{
	    struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)sa;

            /* IPv4-mapped (::ffff:a.b.c.d): IPv4 connection arrived on a
               dual-stack socket. We extract the IPv4 part and continue
               with c_type='i', so whitelist and IPv4 access.db entries
               keep applying to these connections. */
            if (IN6_IS_ADDR_V4MAPPED(&sin6->sin6_addr))
            {
                struct in_addr s_v4;
                memcpy(&s_v4, &sin6->sin6_addr.s6_addr[12], 4);
                inet_ntop(AF_INET, &s_v4, ca_ip, MAXADDR);
                /* c_type stays 'i' (default) */
                break;
            }

            c_type='6';
            /* convert a numeric IPv6 address into a text string suitable for presentation */
	    inet_ntop(AF_INET6, &sin6->sin6_addr, ca_ip, MAXADDR);
	    break;
	}
    }
    
    pthread_once(&re_once, init_regex);  // once
    if (i_re_ok && ignore_connect[0] && (
	    !regexec(&re_ignore_connect, ca_ip, 0, NULL, 0) ||
	    !regexec(&re_ignore_connect, pc_name, 0, NULL, 0))) 
    {
    /* whitelist regex: no more silent accept, the skip is marked and
       we let it run to dg_eom, which will add header and log (point 5) */
        i_skip = 1;
        snprintf (ca_skiploc, MAXHOST, "whitelist regex [%s]", ca_ip);
    }
    /******************* 1 - CHECK for address and host sender ********************/
    c = i_skip ? STATE_SKIP : c_search_IP (ca_ip, ca_found, c_type);
    switch (c)
    {
         case STATE_RELAY:
         case STATE_OK:
         case STATE_FRIEND:
               i_skip = 1;
               snprintf (ca_skiploc, MAXHOST, "access.db %c ip %s", c, ca_found);
               break;
         case STATE_REJECT:
         case STATE_ERROR:
         case STATE_HATER:
               return SMFIS_REJECT;
                    break;
         case STATE_SKIP:
                    break;
         case STATE_DISCARD:
             /* SMFIS_DISCARD is not a valid return from xxfi_connect:
                we store it and apply it in dg_envfrom (patch 2.7) */
             i_discard = 1;
             break;
         case STATE_NOT_FOUND:
             securecpy (ca_domain, pc_name, MAXHOST);
             /* The (unsigned char) cast is required: char is signed on the
              * usual targets, so an octet >= 0x80 reaches tolower() as a
              * negative int, which the C standard leaves undefined.  A
              * hostname carrying UTF-8 or Latin-1 is enough to get there. */
             for (i = 0; ca_domain[i]; i++)
             {
                    ca_domain[i] = tolower((unsigned char)ca_domain[i]);
             }
             // for ( ; *p; ++p) *p = tolower(*p);
             c2=c_search_domain (ca_domain, ca_found);
             switch (c2)
             {
                case STATE_RELAY:
                case STATE_OK:
                case STATE_FRIEND:
                    i_skip = 1;
                    snprintf (ca_skiploc, MAXHOST, "access.db %c domain %s", c2, ca_found);
                    break;
                case STATE_REJECT:
                case STATE_ERROR:
                case STATE_HATER:
                    return SMFIS_REJECT;
                    break;
                case STATE_DISCARD:
                    i_discard = 1;
                    break;
                case STATE_SKIP:
                case STATE_NOT_FOUND:
                    break;
                default:
                    break;
             }
             break;
         default:
                   break;
    }
    
// context allocation
    if (!(ps_context = calloc(1, sizeof(*ps_context)))) 
    {
	syslog(LOG_ERR, "dg_connect calloc error");
	return SMFIS_ACCEPT;
    }

    /* sets the private data pointer for this connection*/
    smfi_setpriv(ctx, ps_context);
    
    resetcontext (ps_context);

    ps_context->c_discard = i_discard;  /* patch 2.7: applicato in dg_envfrom */
    ps_context->c_skip_conn = i_skip;
    securecpy (ps_context->ca_skip_conn, ca_skiploc, MAXHOST);
    securecpy (ps_context->addr, ca_ip, MAXADDR);
    securecpy (ps_context->host, pc_name, MAXHOST);
    securecpy (ps_context->helo, "undefined", MAXHOST);

    syslog(LOGLEVEL, "dg_connect: end %s %s %s", ps_context->addr, ps_context->host, ps_context->helo);
    return SMFIS_CONTINUE;
}

static sfsistat dg_helo(SMFICTX *ctx, char *pc_helohost)
{
    struct context *ps_context;

    syslog(LOGLEVEL, "dg_helo: start");

    if ((ps_context = (struct context *)smfi_getpriv(ctx)) == NULL) 
    {
       syslog(LOG_ERR, "dg_helo error: smfi_getpriv");
       return (SMFIS_ACCEPT);
    }
    securecpy(ps_context->helo, pc_helohost, MAXHOST);

    syslog(LOGLEVEL, "dg_helo: end %s", ps_context->helo);
    return (SMFIS_CONTINUE);
}

static sfsistat dg_envfrom(SMFICTX *ctx, char **args)
{
    int i;
    struct context *ps_context;
    char c, c_part,ca_user[MAXUSER], ca_domain[MAXHOST], ca_subdomain[MAXHOST];
    const char *ca_msg_size = smfi_getsymval(ctx, "{msg_size}");
    const char *ca_mail_addr = smfi_getsymval(ctx, "{mail_addr}");
    char ca_email[MAXEMAIL];

    syslog(LOGLEVEL, "dg_envfrom: start");
    syslog(LOG_DEBUG, "dg_envfrom mail_addr: %s", ca_mail_addr);


   /******************* 3 - CHECK for From ca_mail_addr **************************/

    if ((ps_context = (struct context *)smfi_getpriv(ctx)) == NULL) 
    {
       syslog (LOG_ERR, "dg_envfrom error: smfi_getpriv");
       return (SMFIS_ACCEPT);
    }
    resetcontext_env (ps_context);

    if (ps_context->c_discard)  /* patch 2.7: DISCARD entry found in dg_connect */
    {
       syslog(LOG_NOTICE, "dg_envfrom: DISCARD from access.db for %s [%s]", ps_context->host, ps_context->addr);
       return SMFIS_DISCARD;
    }

if (ca_mail_addr != NULL) {
    securecpy(ca_email, ca_mail_addr, MAXEMAIL);
} else {
    securecpy(ca_email, "unknown", MAXEMAIL);
}

             /* (unsigned char) cast required — see ca_domain above. */
             for (i = 0; ca_email[i]; i++)
             {
                    ca_email[i] = tolower((unsigned char)ca_email[i]);
             }

             c=c_search_from_email (ca_email, ca_user, ca_domain, ca_subdomain, &c_part);
             switch (c)
             {
                case STATE_RELAY:
                case STATE_OK:
                case STATE_FRIEND:
                    ps_context->c_skip_msg = 1;
                    snprintf (ps_context->ca_skip_msg, MAXHOST, "access.db %c from %s", c, ca_email);
                    break;
                case STATE_REJECT:
                case STATE_ERROR:
                case STATE_HATER:
                    // cleanup_session(ctx);
                    return SMFIS_REJECT;
                    break;
                case STATE_DISCARD:
                    return SMFIS_DISCARD;  /* patch 2.7 */
                    break;
                case STATE_SKIP:
                case STATE_NOT_FOUND:
                    break;
                default:
                    break;
             }


    if (*args) 
    {
       securecpy(ps_context->from, *args, MAXLINE);

    }
    if (ca_msg_size && atol(ca_msg_size) > l_size)
    {
       syslog (LOGLEVEL, "dg_envfrom: message size %ld > %ld", atol(ca_msg_size), l_size);
       return SMFIS_ACCEPT;
    }

    ps_context->msg_id = 0;
    ps_context->arrival = time(NULL);;

    syslog(LOGLEVEL, "dg_envfrom: end");

    return (SMFIS_CONTINUE);
}


static sfsistat dg_envrcpt(SMFICTX *ctx, char **args)
{
    struct context *ps_context;
    char *rcpt_addr, *rcpt_host, *rcpt_mailer;
    int i;
    char c, c_part,ca_user[MAXUSER], ca_domain[MAXHOST], ca_subdomain[MAXHOST], ca_emai_tmp[MAXEMAIL];
    rcpt_addr = smfi_getsymval(ctx, "{rcpt_addr}");
    rcpt_host = smfi_getsymval(ctx, "{rcpt_host}");
    rcpt_mailer = smfi_getsymval(ctx, "{rcpt_mailer}");

    syslog(LOGLEVEL, "dg_envrcpt: start - rcpt_addr: %s, rcpt_host: %s, rcpt_mailer: %s", rcpt_addr, rcpt_host, rcpt_mailer);
    if ((ps_context = (struct context *)smfi_getpriv(ctx)) == NULL) 
    {
       syslog(LOG_ERR, "dg_envrcpt: smfi_getpriv");
       return (SMFIS_ACCEPT);
    }
    if (*args != NULL) 
    {
       securecpy(ps_context->rcpt, *args, MAXLINE);	
       syslog(LOGLEVEL, "dg_envrcpt: ps_context->rcpt %s", ps_context->rcpt);
    }
    /************************ 2 - CHECK for rcpt *************************************/

    securecpy (ca_emai_tmp, ps_context->rcpt, MAXEMAIL);
    remove_all_chars(ca_emai_tmp, '<');
    remove_all_chars(ca_emai_tmp, '>');
             /* (unsigned char) cast required — see ca_domain above. */
             for (i = 0; ca_emai_tmp[i]; i++)
             {
                    ca_emai_tmp[i] = tolower((unsigned char)ca_emai_tmp[i]);
             }

    c=c_search_to_email (ca_emai_tmp, ca_user, ca_domain, ca_subdomain, &c_part);
             switch (c)
             {
                case STATE_RELAY:
                case STATE_OK:
                case STATE_FRIEND:
                    /* multi-rcpt: no skip at the first whitelisted (it was an
                       open invitation to bypass); it is recorded and decided at full
                       envelope with the unanimity rule (dg_header) */
                    break;
                case STATE_REJECT:
                case STATE_ERROR:
                case STATE_HATER:
                    // cleanup_session(ctx);
                    return SMFIS_REJECT;
                    break;
                case STATE_DISCARD:
                    return SMFIS_DISCARD;  /* patch 2.7 */
                    break;
                case STATE_SKIP:
                case STATE_NOT_FOUND:
                    break;
                default:
                    break;
             }

    /* multi-rcpt: record {raw addr, state}. REJECT/DISCARD do not
       reach here (return above): the list contains only who will be
       delivered, and it is the basis for unanimity and selective delrcpt */
    rcpt_add (ps_context, ps_context->rcpt, c);

    syslog(LOGLEVEL, "dg_envrcpt: end");

    return (SMFIS_CONTINUE);
}


/* accumulate a recipient into the context list. Lazy preallocation
   of RCPT_BASE lines, growth in RCPT_GROW batches, reuse across
   messages of the same connection (free only in dg_close).
   On allocation failure the list is incomplete: i_rcpt_ovfl
   disables unanimity and selective delrcpt (fail-safe: it scans
   and on spam rejects for all, historical behavior). */
static void rcpt_add (struct context *ps_context, const char *pc_addr, char c_state)
{
    if (ps_context->ps_rcpts == NULL)
    {
        ps_context->ps_rcpts = calloc (RCPT_BASE, sizeof(struct rcpt_entry));
        if (ps_context->ps_rcpts == NULL)
        {
            syslog (LOG_ERR, "rcpt_add: calloc failed, fail-safe scan for all");
            ps_context->i_rcpt_ovfl = 1;
            return;
        }
        ps_context->i_rcpt_alloc = RCPT_BASE;
    }
    if (ps_context->i_rcpt_count >= ps_context->i_rcpt_alloc)
    {
        struct rcpt_entry *ps_new;
        ps_new = realloc (ps_context->ps_rcpts,
                 (ps_context->i_rcpt_alloc + RCPT_GROW) * sizeof(struct rcpt_entry));
        if (ps_new == NULL)
        {
            syslog (LOG_ERR, "rcpt_add: realloc failed at %d rcpts, fail-safe",
                    ps_context->i_rcpt_count);
            ps_context->i_rcpt_ovfl = 1;
            return;
        }
        memset (ps_new + ps_context->i_rcpt_alloc, 0,
                RCPT_GROW * sizeof(struct rcpt_entry));
        ps_context->ps_rcpts = ps_new;
        ps_context->i_rcpt_alloc += RCPT_GROW;
    }
    securecpy (ps_context->ps_rcpts[ps_context->i_rcpt_count].ca_addr, pc_addr, RCPT_ADDR);
    ps_context->ps_rcpts[ps_context->i_rcpt_count].c_state = c_state;
    ps_context->i_rcpt_count++;
    if ((c_state == STATE_RELAY) || (c_state == STATE_OK) || (c_state == STATE_FRIEND))
        ps_context->i_rcpt_white++;
}

/* recipient for the logs: single as-is, multiple as
   "first (+N others)" so as not to write novels at NOTICE */
static const char *pc_rcpt_disp (struct context *ps_context, char *pc_buf, long l_size)
{
    if (ps_context->i_rcpt_count > 1)
        snprintf (pc_buf, l_size, "%s (+%d others)",
                  ps_context->ps_rcpts[0].ca_addr, ps_context->i_rcpt_count - 1);
    else
        securecpy (pc_buf, ps_context->rcpt, l_size);
    return pc_buf;
}

/* emit of the MIME automaton towards spamd: counts the bytes ACTUALLY
   FORWARDED (DROP parts do not pass through here) and applies l_size
   to the forwarded stream, not to the input: a mail with a huge attachment
   and little text is now scanned instead of passing untouched */
static int i_emit_spamd (void *pv_ctx, const char *pc_buf, long l_len)
{
    struct context *ps_context = (struct context *) pv_ctx;

    ps_context->body_size += l_len;
    if (ps_context->body_size > (unsigned long) l_size)
       return -1;                     /* threshold exceeded: stop upstream */

    return i_spamd_send (ps_context, (char *) pc_buf, l_len);
}

static sfsistat dg_header(SMFICTX *ctx, char *pc_name, char *pc_value) 
{
    struct context *ps_context;
   
    char ca_cmd[MAXCOMMAND];
    char ca_tmp[MAXTMP];
    char ca_bigbuf[BIGLINE]; 
    int i_start=0, i_ret=0;


    memset (ca_cmd, 0, MAXCOMMAND);
    memset (ca_tmp, 0, MAXTMP);
    memset (ca_bigbuf, 0, BIGLINE); /* vi */

    if ((ps_context = (struct context *)smfi_getpriv(ctx)) == NULL) 
    {
       syslog(LOG_ERR, "dg_header: srmfi_getpriv");
       return (SMFIS_ACCEPT);
    }

    /* multi-rcpt unanimity: ALL recipients whitelisted => message
       skip. Evaluated here because the envelope is complete. The connection
       skip (IP/domain/whitelist regex) and the sender one
       PREVAIL and are already marked upstream. With an incomplete list
       (i_rcpt_ovfl) no unanimity: fail-safe, it scans. */
    if ((!ps_context->c_skip_conn) && (!ps_context->c_skip_msg) &&
        (!ps_context->i_rcpt_ovfl) &&
        (ps_context->i_rcpt_count > 0) &&
        (ps_context->i_rcpt_white == ps_context->i_rcpt_count))
    {
        ps_context->c_skip_msg = 1;
        snprintf (ps_context->ca_skip_msg, MAXHOST, "all %d rcpts whitelisted",
                  ps_context->i_rcpt_count);
    }

    if (ps_context->c_skip_conn || ps_context->c_skip_msg)
       return SMFIS_CONTINUE;          /* skip: no spamd, header in dg_eom */

    /* MIME filter: capture of the boundary from the main Content-Type.
       libmilter delivers the full value, folding included, so
       mime_extract_boundary finds it even on a continuation line */
    if (i_mime_filter && (ps_context->ca_main_bound[0] == '\0') && (pc_name != NULL))
    {
       int i_k;
       const char *pc_ct = "content-type";
       for (i_k = 0; pc_ct[i_k] != '\0'; i_k++)
       {
          char c_a = pc_name[i_k];
          if ((c_a >= 'A') && (c_a <= 'Z')) c_a += 32;
          if (c_a != pc_ct[i_k]) break;
       }
       if ((pc_ct[i_k] == '\0') && (pc_name[i_k] == '\0'))
          mime_extract_boundary (pc_value, ps_context->ca_main_bound, MIME_BOUND_LEN);
    }

    if (ps_context->queue[0]!='\0')
    {
      syslog(LOG_DEBUG, "%s - dg_header: start", ps_context->queue);
    }
    else
    {
      syslog(LOG_DEBUG, "dg_header: start");
    }

    if (ps_context->sock < 0) 
    {
       const char *pc_sendmail_queue = smfi_getsymval(ctx, "i");  // Queue ID
       const char *pc_sendmail_date = smfi_getsymval(ctx, "b");   // current date
       const char *pc_sendmail_name = smfi_getsymval(ctx, "j");   // hostname
       const char *pc_auth_type = smfi_getsymval(ctx, "{auth_type}"); //  if auth you should skip
       const char *pc_auth_ssf = smfi_getsymval(ctx, "{auth_ssf}"); 

       i_start = i_spamd_start(ps_context);
       if (i_start < 0)
       { 
  	  syslog(LOG_WARNING, "dg_header: SpamAssassin is out of service (connect failed): %d", i_start);
          resetcontext_env (ps_context);
          // cleanup_session(ctx);
	  return SMFIS_ACCEPT;
       }

       if (pc_spamd_user[0]!=0)  /* command line input value */
       {
         snprintf(ca_tmp, (size_t) sizeof(ca_tmp), "User: %s\r\n\r\n", pc_spamd_user);
         syslog (LOGLEVEL, "dg_header - User: %s\r\n\r\n", pc_spamd_user);
       }
       else 
          snprintf(ca_tmp, sizeof (ca_tmp), "\r\n");

       securecpy (ca_bigbuf, ca_tmp, sizeof(ca_bigbuf));
       memset (ca_tmp, 0, MAXTMP);

       /* send fake Received: header */
       snprintf(ca_tmp, sizeof (ca_tmp), "Received: from %s (%s [%s])",
               ps_context->helo, ps_context->host, ps_context->addr);
       securecat (ca_bigbuf, ca_tmp, sizeof(ca_bigbuf));
       memset (ca_tmp, 0, MAXTMP);
    

       if (pc_auth_type != NULL && pc_auth_type[0])
       {
          securecat (ca_bigbuf, "\r\n\t(authenticated", sizeof(ca_bigbuf));
          if (pc_auth_ssf != NULL && pc_auth_ssf[0])
          {
              snprintf(ca_tmp, sizeof (ca_tmp), " bits=%s", pc_auth_ssf);
              securecat (ca_bigbuf, ca_tmp, sizeof(ca_bigbuf));
          }
          securecat (ca_bigbuf, ")", sizeof(ca_bigbuf) );
          memset (ca_tmp, 0, MAXTMP);
       }
   
       if (pc_sendmail_name != NULL && pc_sendmail_name[0]) 
       {
          securecpy(ps_context->dghost, pc_sendmail_name, MAXHOST);
          syslog (LOGLEVEL, "dg_header - pc_sendmail_name: %s", pc_sendmail_name);
          snprintf(ca_tmp, sizeof (ca_tmp), "\r\n\tby %s (DarkSpam)", pc_sendmail_name);
          securecat (ca_bigbuf, ca_tmp, sizeof (ca_bigbuf));

          memset (ca_tmp, 0, MAXTMP);
 

          // memset (ca_tmp, 0, MAXLINE);
          if (pc_sendmail_queue != NULL && pc_sendmail_queue[0])
          {
              syslog (LOGLEVEL, "dg_header - pc_sendmail_queue: %s", pc_sendmail_queue);
              snprintf(ca_tmp, sizeof(ca_tmp), " id %s", pc_sendmail_queue);
              securecat (ca_bigbuf, ca_tmp, sizeof(ca_bigbuf));
              securecpy (ps_context->queue,  pc_sendmail_queue, MAXLINE);
          }
       }
       if (ps_context->rcpt[0]) 
       {   /***********************************************************************/
           syslog (LOGLEVEL, "dg_header - ps_context->rcpt: %s", ps_context->rcpt); 
           snprintf(ca_tmp, sizeof (ca_tmp), "\r\n\tfor %s", ps_context->rcpt);
           securecat (ca_bigbuf, ca_tmp, sizeof(ca_bigbuf));   
       }
       

       if (pc_sendmail_date != NULL && pc_sendmail_date[0])
       {
           syslog (LOGLEVEL, "dg_header - ps_sendmail_date:  %s", pc_sendmail_date);
           snprintf(ca_tmp, sizeof(ca_tmp),"; %s", pc_sendmail_date);
       }
       else 
       {
         char ca_date[128];
         struct tm tm_buf; // Buffer local to the thread stack
         time_t t_t = time(NULL);
    /* We use localtime_r (reentrant) instead of localtime.
       localtime_r writes the data into &tm_buf (in the current thread's stack)
       instead of using a shared static area.
    */
         if (strftime(ca_date, sizeof(ca_date), "%a, %e %b %Y %H:%M:%S %z", 
                 localtime_r(&t_t, &tm_buf)))
         {
                snprintf(ca_tmp, sizeof (ca_tmp), "; %s", ca_date);
                syslog (LOGLEVEL, "dg_header - date: %s", ca_tmp); 
         }
         securecat (ca_bigbuf, ca_tmp, sizeof(ca_bigbuf));
       
         securecat (ca_bigbuf, "\r\n", sizeof(ca_bigbuf));
       }
    }

       snprintf(ca_tmp, sizeof(ca_tmp), "%s: %s\r\n", pc_name, pc_value);
       securecat (ca_bigbuf, ca_tmp, sizeof(ca_bigbuf));
    
       i_ret=i_spamd_send(ps_context, ca_bigbuf, strlen(ca_bigbuf));

       if (i_ret < 0) 
       {
        syslog (LOG_WARNING, "dg_header: SpamAssassin is out of service, transfer failed: %d", i_ret);
        close_socket(ps_context->sock); // better to close
        resetcontext_env (ps_context);
	return SMFIS_ACCEPT;
       }

       if (!strcasecmp(pc_name, "Message-Id")) 
           ps_context->msg_id = 1;
       else if (!strcasecmp(pc_name, "Subject")) 
       {
          securecpy(ps_context->hdr_subject, pc_value, MAXLINE);
          syslog(LOGLEVEL, "%s - dg_header: hdr_subject %s",  ps_context->queue, ps_context->hdr_subject);
       }
       else if (!strcasecmp(pc_name, "From"))
       {
          securecpy(ps_context->hdr_from, pc_value, MAXHEAD);
       
         syslog(LOG_DEBUG, "%s - dg_header: hdr_from %s",  ps_context->queue, ps_context->hdr_from);

       }
       else if (!strcasecmp(pc_name, "To"))
       {
          securecpy (ps_context->hdr_to, pc_value, MAXHEAD);
       
          syslog(LOG_DEBUG, "%s - dg_header: hdr_to %s",  ps_context->queue, ps_context->hdr_to);
       }
      syslog(LOGLEVEL, "%s - dg_header: end",  ps_context->queue);

    return SMFIS_CONTINUE;
}

static sfsistat dg_eoh(SMFICTX *ctx)
{

/* End of heafer ==> to be refined */
    struct context *ps_context;
    char ca_buf[MAXHEAD];

    if ((ps_context = (struct context *)smfi_getpriv(ctx)) == NULL) 
    {
       syslog(LOG_ERR, "dg_eoh: srmfi_getpriv");
       return (SMFIS_ACCEPT);
    }
    if (ps_context->c_skip_conn || ps_context->c_skip_msg)
       return SMFIS_CONTINUE;
     syslog(LOGLEVEL, "%s - dg_eoh: start", ps_context->queue);


    if (ps_context->msg_id)
    {
	securecpy(ca_buf, "\r\n", MAXHEAD);
    }
    else {
	struct tm gmtm;
	char ca_date[16];

	gmtime_r((const time_t *) &ps_context->arrival, &gmtm);
	if (!strftime(ca_date, sizeof(ca_date), "%Y%m%d%H%M", &gmtm))
        {
	    securecpy(ca_buf, "\r\n", MAXHEAD);
        }
        else
	   snprintf(ca_buf, sizeof(ca_buf), "Message-Id: <%s.%s@%s>\r\n\r\n", ca_date, ps_context->queue, ps_context->host);
    }


    if (i_spamd_send(ps_context, ca_buf, strlen(ca_buf)) < 0) 
    {
	syslog(LOG_WARNING, "dg_eoh: SpamAssassin is out of service (eoh transfer failed)");
        close_socket(ps_context->sock);
        resetcontext_env (ps_context); /* sock = -1: avoids double close in dg_close */
	return SMFIS_ACCEPT;
    }
    /* MIME filter: with -M or without a boundary, init with empty/NULL puts
       the automaton in pure passthrough (i_active=0), cost of one if per chunk */
    mime_stream_init (&ps_context->mime,
                      i_mime_filter ? ps_context->ca_main_bound : NULL);
    ps_context->body_size = 0;
    syslog(LOGLEVEL, "%s - dg_eoh: end", ps_context->queue);
    return (SMFIS_CONTINUE);
}

static sfsistat dg_body(SMFICTX *ctx, u_char *chunk, size_t size)
{
    struct context *ps_context;

    if ((ps_context = (struct context *)smfi_getpriv(ctx)) == NULL) 
    {
       syslog(LOG_ERR, "dg_body: srmfi_getpriv");
       return (SMFIS_ACCEPT);
    }
    if (ps_context->c_skip_conn || ps_context->c_skip_msg)
       return SMFIS_CONTINUE;
    syslog(LOGLEVEL, "%s - dg_body: start with size %ld", ps_context->queue, (long) size);

    /* the chunk goes through the MIME automaton; the l_size threshold is applied
       inside i_emit_spamd on the forwarded bytes. Negative return =
       spamd down or threshold exceeded: same fail-open as always */
    if (mime_stream_feed (&ps_context->mime, (const char *) chunk, (long) size,
                          i_emit_spamd, ps_context) < 0)
    {
	syslog(LOG_WARNING, "%s - dg_body: SpamAssassin is out of service (body transfer failed)", ps_context->queue);
        close_socket(ps_context->sock);  // better to reopen later
        resetcontext_env (ps_context);
	return SMFIS_ACCEPT;
    }

    syslog(LOGLEVEL, "%s - dg_body: end", ps_context->queue);
    return SMFIS_CONTINUE;
}


static sfsistat dg_eom(SMFICTX *ctx) 
{ 
    float elapsed;
    int i_ret;
    struct context *ps_context;
    syslog(LOGLEVEL, "dg_eom: start");
    if ((ps_context = (struct context *)smfi_getpriv(ctx)) == NULL) 
    {
       syslog(LOG_ERR, "dg_eom: smfi_getpriv");
       return (SMFIS_ACCEPT);
    }
    syslog(LOGLEVEL, "%s - dg_eom: start", ps_context->queue);

    if (ps_context->c_skip_conn || ps_context->c_skip_msg)
    {
        /* point 5: the skip ALWAYS leaves a trace, in header and logs.
           The queue must be requested directly because dg_header was
           skipped and ps_context->queue may be empty */
        char ca_header[MAXLINE];
        char *pc_q = smfi_getsymval(ctx, "i");
        const char *pc_why = ps_context->c_skip_conn ? ps_context->ca_skip_conn
                                                     : ps_context->ca_skip_msg;
        snprintf (ca_header, sizeof(ca_header), "skipped (%s) by DarkSpam v" DG_VERSION, pc_why);
        smfi_addheader (ctx, "X-DarkSpam", ca_header);
        {
        char ca_rd[300];
        syslog (LOG_NOTICE, "%s - skipped (%s), %s -> %s",
                pc_q ? pc_q : "-", pc_why, ps_context->from,
                pc_rcpt_disp(ps_context, ca_rd, sizeof(ca_rd)));
        }
        resetcontext_env (ps_context);
        return SMFIS_ACCEPT;
    }

    mime_stream_flush (&ps_context->mime, i_emit_spamd, ps_context);  /* final carry before the shutdown */
    if (ps_context->mime.i_active)
       syslog (ps_context->mime.l_parts_drop > 0 ? LOG_NOTICE : LOG_INFO,
               "%s - mime: %ld parts kept, %ld dropped (%ld bytes filtered out)",
               ps_context->queue, ps_context->mime.l_parts_keep,
               ps_context->mime.l_parts_drop, ps_context->mime.l_bytes_drop);
    i_ret = i_get_spamd_reply(ps_context);  // socket closed inside
    if (i_ret < 0) 
    {
	syslog(LOG_WARNING, "%s - dg_eom: SpamAssassin answer not received %d", ps_context->queue, i_ret);
        resetcontext_env (ps_context);
	return SMFIS_ACCEPT;
    }
    elapsed = ps_context->tend.tv_sec - ps_context->tstart.tv_sec + (ps_context->tend.tv_usec - ps_context->tstart.tv_usec) / 1.0e6;
    if (i_ret == 1) /* spam */
    {
	if (i_tag_mode)   /* -t: tag and deliver, no reject (point 10) */
	{
	    char ca_header[MAXLINE];
	    smfi_addheader(ctx, "X-Spam-Flag", "YES");
	    snprintf(ca_header, sizeof(ca_header), "SPAM %.1f/%.1f, scanned in %.3fsec at (%s) by DarkSpam v" DG_VERSION,
	        ps_context->score, ps_context->threshold, elapsed, ps_context->dghost);
	    smfi_addheader(ctx, "X-DarkSpam", ca_header);
	    {
	    char ca_rd[300];
	    syslog(LOG_NOTICE, "%s - spam TAGGED (%.1f/%.1f), %.3fsec, %s -> %s", ps_context->queue,
	           ps_context->score, ps_context->threshold, elapsed, ps_context->from,
	           pc_rcpt_disp(ps_context, ca_rd, sizeof(ca_rd)));
	    }
	    return SMFIS_CONTINUE;
	}
	if ((ps_context->i_rcpt_white > 0) && (!ps_context->i_rcpt_ovfl))
	{
	    /* MIXED case: some rcpts whitelisted, others not. The non-white
	       ones are removed from the envelope (for them the alternative was the
	       reject: silent removal, per-rcpt DISCARD semantics);
	       to the whitelisted, who want all their mail, it is delivered
	       tagged. If none were white we fall into the total reject
	       below (unanimity of the compliant). */
	    char ca_header[MAXLINE];
	    char ca_list[MAXLINE];
	    char ca_rd[300];
	    int i_k, i_removed = 0;
	    ca_list[0] = '\0';
	    for (i_k = 0; i_k < ps_context->i_rcpt_count; i_k++)
	    {
	        char c_s = ps_context->ps_rcpts[i_k].c_state;
	        if ((c_s == STATE_RELAY) || (c_s == STATE_OK) || (c_s == STATE_FRIEND))
	            continue;                     /* whitelisted: delivered */
	        if (smfi_delrcpt(ctx, ps_context->ps_rcpts[i_k].ca_addr) != MI_SUCCESS)
	        {
	            syslog(LOG_ERR, "%s - smfi_delrcpt failed for %s", ps_context->queue,
	                   ps_context->ps_rcpts[i_k].ca_addr);
	            continue;
	        }
	        i_removed++;
	        if (ca_list[0] != '\0')
	            securecat(ca_list, ", ", MAXLINE);
	        securecat(ca_list, ps_context->ps_rcpts[i_k].ca_addr, MAXLINE);
	        syslog(LOG_DEBUG, "%s - delrcpt %s", ps_context->queue,
	                   ps_context->ps_rcpts[i_k].ca_addr);
	    }
	    smfi_addheader(ctx, "X-Spam-Flag", "YES");
	    snprintf(ca_header, sizeof(ca_header), "SPAM %.1f/%.1f, scanned in %.3fsec at (%s) by DarkSpam v" DG_VERSION,
	        ps_context->score, ps_context->threshold, elapsed, ps_context->dghost);
	    smfi_addheader(ctx, "X-DarkSpam", ca_header);
	    syslog(LOG_NOTICE, "%s - spam (%.1f/%.1f), %.3fsec, %s -> %s: removed %d rcpts (%s), delivered tagged to %d whitelisted",
	           ps_context->queue, ps_context->score, ps_context->threshold, elapsed,
	           ps_context->from, pc_rcpt_disp(ps_context, ca_rd, sizeof(ca_rd)),
	           i_removed, ca_list, ps_context->i_rcpt_white);
	    return SMFIS_CONTINUE;
	}
	if (ps_context->score >= ps_context->threshold) /* could be removed */
        {
	    char ca_reject[MAXLINE];
            snprintf(ca_reject, sizeof(ca_reject), "Sorry, looks like spam: (%.1f/%.1f) ", ps_context->score, ps_context->threshold);
	    smfi_setreply(ctx, "554", "5.7.1", ca_reject);
	    {
	    char ca_rd[300];
	    syslog(LOG_NOTICE, "%s - spam (%.1f/%.1f), %.3fsec, %s -> %s", ps_context->queue, ps_context->score, ps_context->threshold, elapsed, ps_context->from,
                  pc_rcpt_disp(ps_context, ca_rd, sizeof(ca_rd)));
	    }
	}

     	return SMFIS_REJECT;
    }
    else
    {
      if (ADD_HEADER) 
      {
	char ca_header[MAXLINE];
        memset (ca_header, 0, MAXLINE); 

	snprintf(ca_header, sizeof(ca_header), "%.1f/%.1f, scanned in %.3fsec at (%s) by DarkSpam v" DG_VERSION,
	    ps_context->score, ps_context->threshold, elapsed, ps_context->dghost);
	smfi_addheader(ctx, "X-DarkSpam", ca_header);
        {
        char ca_rd[300];
        syslog(LOG_NOTICE, "%s - clean (%.1f/%.1f), %.3fsec, %s -> %s",  ps_context->queue, 
                       ps_context->score, 
                       ps_context->threshold, 
                       elapsed, ps_context->from,
                       pc_rcpt_disp(ps_context, ca_rd, sizeof(ca_rd)));
        }
      }

    }

    syslog(LOGLEVEL, "%s - dg_eom: end",  ps_context->queue);
    return SMFIS_CONTINUE;

}

static sfsistat dg_close(SMFICTX *ctx) 
{
    struct context *ps_context;
    syslog(LOGLEVEL, "dg_close start"); 

    if ((ps_context = (struct context *)smfi_getpriv(ctx)) == NULL) 
    {
       syslog(LOGLEVEL, "dg_close: srmfi_getpriv");
       return (SMFIS_ACCEPT);
    }
    if (ps_context != NULL)
          syslog(LOGLEVEL, "%s - dg_close: start",  ps_context->helo);
    

    
    if (ps_context != NULL) 
    {
        if (ps_context->sock >= 0) {
            close(ps_context->sock); // IF NOT CLOSED
        }

	smfi_setpriv(ctx, NULL);
        syslog (LOGLEVEL, "dg_close: free ps_context");
        if (ps_context->ps_rcpts != NULL)
      {
         free(ps_context->ps_rcpts);
         ps_context->ps_rcpts = NULL;
      }
      free(ps_context);
    }

    syslog(LOGLEVEL, "dg_close: end");
    return SMFIS_CONTINUE;

}

void cleanup_session(SMFICTX *ctx)
{  
    struct context *ps_context = (struct context *)smfi_getpriv(ctx);
    if (ps_context != NULL)
    {
        if (ps_context->sock >= 0) 
        {
            close(ps_context->sock); // IF NOT CLOSED
        }

        smfi_setpriv(ctx, NULL);
        syslog (LOGLEVEL, "dg_close: free ps_context");
        if (ps_context->ps_rcpts != NULL)
      {
         free(ps_context->ps_rcpts);
         ps_context->ps_rcpts = NULL;
      }
      free(ps_context);
    }
}



void handle_reload(int sig) {
    reload_needed = 1;
}
