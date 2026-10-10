/*
 * DarkSpam - DarkSpam.h
 * Definitions and prototypes
 *
 * Copyright (c) 2026 Vittorio Moccia
 * Licensed under the PolyForm Noncommercial License 1.0.0.
 * https://polyformproject.org/licenses/noncommercial/1.0.0/
 */

/* Hosts/Networks whitelist (extended regex format) */
#define WHITE_LIST      "(^127\\.|^192\\.168\\.|^10\\.)"
//  #define WHITE_LIST  "(^192\\.168\\.|^1\\.)"
#define ACCESS_FILE                     "/etc/mail/access.db"
#define DG_VERSION  "1.1"

/* Maximal message size */
#define MAX_SIZE        131072 /* bytes */
#define MAX_BODY        (65535+1)

/* Probable SPAM e-Mail messages Subject tagging */
#define TAG_SUBJECT     1 /* set 0 to disable */

/* Extra SPAM e-Mail messages */
#define EXTRA_SPAM      10 /* SpamAssassin SPAM score value */

/* Contact e-Mail address for rejected extra SPAM e-Mail messages */
#define CONTACT_ADDRESS "notspam@itb.it" /* "all_spam_to" from your SpamAssassin local.cf */

/* Probable SPAM e-Mail messages quarantine */
#define REDIRECT_SPAM   0 /* set 1 to enable */

/* Probable SPAM e-Mail messages collector (if quarantine is not active) */
#define COPY_SPAM       0 /* set 1 to enable */

/*  */
#define ADD_HEADER      1 /* set 1 to enable */

/*  */
/* Log: i_loglevel is settable at runtime with -l (default LOG_NOTICE).
   DEBUG is now a runtime expression: the historical if (DEBUG) blocks are
   enabled with -l 7 without recompiling. LOGLEVEL survives only inside
   those blocks and is therefore LOG_DEBUG. */
extern int i_loglevel;
#define DEBUG           (i_loglevel >= LOG_DEBUG)
#define LOGLEVEL        LOG_DEBUG
/* SpamAssassin daemon listen here */
#define SPAMD_PORT      783
#define SPAMD_ADDRESS   "127.0.0.1"

/* Syslog facility */
#define SYSLOG_FACILITY LOG_DAEMON

#define OCONN           "unix:/var/spool/DarkSpam/sock"
#define USER            "smmsp"
#define SDUSER          "smmsp"
#define MAXLINE         2048
#define BIGLINE         8192
#define MAXHEAD         (1024*3)
#define MAXTMP          4096
#define MAXHOST         256
#define MAXUSER         256                 
// 65
// #define MAXEMAIL        (MAXHOST+MAXUSER+1)
#define MAXEMAIL        2048
#define MAXADDR         128
#define MAXCOMMAND      4096
#define RCODE_REJECT    "554"
#define XCODE_REJECT    "5.7.1"
#define SPAMD_ADDR      "127.0.0.1"
#define SPAMD_PORT      783
#define SPAMD_TIMEOUT   60
#define SPAMD_TIMEOUT_REPLY  120
#define SPAMD_RETRIES   4
#define MAXIP           MAXADDR


extern long securecpy (register char *, register const char *, long);
extern long securecat (register char *, register const char *, long);

#define STATE_NOT_FOUND 'N'
#define STATE_SKIP      'S'
#define STATE_REJECT    'R'
#define STATE_RELAY     'Y'
#define STATE_FRIEND    'F'
#define STATE_OK        'O'
#define STATE_DISCARD   'D'
#define STATE_ERROR     'E'
#define STATE_HATER     'H'


// extern int db_open(DB **dbp, char *name, int dups);
// extern int db_get(DB *db, char *pc_key, char **pc_string);
// extern int db_close(DB *db);

extern void find_previous_ipclass (char *, char *, long);
extern void find_next_subdomain (char *, char *, long);
extern int split_email (const char *, char *, char *, long, long, long);
extern char c_search_IP (const char *, char *, char);
extern char c_search_domain (const char *, char *);
extern char c_search_from_email (const char *, char *, char *, char *, char *);
extern char c_search_to_email (const char *, char *, char *, char *, char *);
extern int init_access_db(void);
extern int refresh_db_handle(void);

void remove_all_chars(char* str, char c);
char c_search_test (const char *pc_domain);

extern pthread_mutex_t db_mutex; // "extern" means: it is defined in another file
extern void normalizza (char stringa[]);
extern void find_previous_ip6class (char *, char *, long);

/* ---- streaming MIME filter (Parse.c) ---- */
#define MIME_MAX_DEPTH  8     /* maximum depth of nested multipart */
#define MIME_BOUND_LEN  72    /* boundary max 70 per RFC 2046 + margin */
#define MIME_LINE_LEN   1024  /* logical line assembly across chunks */

#define MS_SEEK        0   /* preamble/epilogue: seek boundary, the rest passes */
#define MS_SCAN_BOUND  1   /* part headers: they ALWAYS pass, the state is decided */
#define MS_KEEP        2   /* text part body: forward while seeking boundary */
#define MS_DROP        3   /* binary part body: consume while seeking boundary */

struct mime_stream {
    int  i_state;
    int  i_active;                                   /* 0 = never was multipart: pure passthrough */
    int  i_depth;                                    /* boundary stack; may return to 0 in the epilogue */
    char ca_bound[MIME_MAX_DEPTH][MIME_BOUND_LEN];
    char ca_line[MIME_LINE_LEN];                     /* line being built (carry across chunks) */
    long l_line;
    int  i_longline;   /* line beyond MIME_LINE_LEN: flush raw, cannot be a boundary */
    int  i_in_ct;      /* in SCAN_BOUND: continuation (folding) lines of the Content-Type */
    int  i_ct_seen;    /* in SCAN_BOUND: Content-Type encountered in this part */
    int  i_next_state; /* state decided by the headers, applied at the blank line */
    long l_parts_keep; /* statistics for the summary log in dg_eom */
    long l_parts_drop;
    long l_bytes_drop;
};

typedef int (*mime_emit_cb)(void *pv_ctx, const char *pc_buf, long l_len);

extern int  mime_extract_boundary (const char *pc_value, char *pc_bound, long l_size);
extern void mime_stream_init (struct mime_stream *ps, const char *pc_boundary);
extern int  mime_stream_feed (struct mime_stream *ps, const char *pc_chunk, long l_len,
                              mime_emit_cb pf_emit, void *pv_ctx);
extern int  mime_stream_flush (struct mime_stream *ps, mime_emit_cb pf_emit, void *pv_ctx);
