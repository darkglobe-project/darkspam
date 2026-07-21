/*
 * DarkSpam - DB.c
 * Access to access.db and progressive lookup
 *
 * Copyright (c) 2026 Vittorio Moccia
 * Licensed under the PolyForm Noncommercial License 1.0.0.
 * https://polyformproject.org/licenses/noncommercial/1.0.0/
 */

/*
1 - IP connection
Look up as
DS-Connect:IP
Connect:IP
IP

OK - RELAY                accept
REJECT - ERROR - DISCARD  reject
SKIP                      examine (default) 


2 - IPv6 connection
Look up as

DS-Connect:IPv6:
Connect:IPv6
IPv6:

3 - host connection:
Look up as
DS-Connect:[IP]
DS-Connect:[IPV6:2001:0DB8::1234:5678]
DS-Connect:host
Connect:[IP]
Connect:[host]
[IP]
host

OK - RELAY                accept
REJECT - ERROR - DISCARD  reject
SKIP                      examine (default) 

3 - from connection
Look up as
DS-From:email
DS-From:domain
DS-From:username
Spam:email
Spam:domain
Spam:username
From:email
From:domain
From:username
email
domain
username

3 - to connection
Look up as
DS-To:email
DS-To:domain
DS-To:username
Spam:email
Spam:domain
Spam:username
To:email
To:domain
To:username
email
domain
username


cyberspammer.com	ERROR:550 "We don't accept mail from spammers"
okay.cyberspammer.com	OK
sendmail.org		RELAY
128.32			RELAY
IPv6:1:2:3:4:5:6:7	RELAY
[127.0.0.3]		OK
[IPv6:1:2:3:4:5:6:7:8]	OK
badlocaluser@		ERROR:550 Mailbox disabled for this username
host.mydomain.com	ERROR:550 That host does not accept mail
user@otherhost.mydomain.com	ERROR:550 Mailbox disabled for this recipient
spammer@aol.com		REJECT
cyberspammer.com	REJECT
Connect:10.1		OK
Connect:127.0.0.1	RELAY
To:my.domain		RELAY
Connect:my.domain	RELAY
From:spammer@some.dom   REJECT
To:friend.domain        RELAY
Connect:friend.domain   OK
Connect:from.domain     RELAY
From:good@another.dom   OK
From:another.dom        REJECT
        Connect:        connection information (${client_addr}, ${client_name})
        From:           envelope sender
        To:             envelope recipient

Email sequence for domain sender:
DS-From:email@sender.com RELAY/SKIP
DS-To:email@sender.com RELAY/SKIP

Domain sequence for domain sender:
DS-From:domain.com RELAY/SKIP
From:domain.com RELAY/OK
domain.com RELAY/OK

Domain sequence for domain recipient:
DS-To:domain.com SKIP
To:domain.com RELAY/OK
domain.com RELAY/OK

relay/ok make spam controls
skip accept
Reject

*/

#include <ctype.h>
#include <errno.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <db.h>
#include <sys/types.h>
#include <fcntl.h>
#include <syslog.h>
#include "DarkSpam.h"

#define IPV6_TAG_LENGTH                 5
#define IPV6_LENGTH                     ((128/16)*4+(128/16)-1)
#define MAIL_LENGTH                     255
#define DOMAIN_LENGTH                   255

static DB *global_dbp = NULL;
pthread_mutex_t db_mutex = PTHREAD_MUTEX_INITIALIZER;

static char c_find_state (char * pc_state);
volatile sig_atomic_t reload_needed = 0;

#define MAX_TYPE_IP     3
#define MAX_TYPE_DOMAIN  3
#define MAX_TYPE_FROM_EMAIL  4
#define MAX_TYPE_TO_EMAIL  3

static char ca_type_above_ipd[MAX_TYPE_IP][100]={"ds-connect:","connect:",""};
static char ca_type_from_email[MAX_TYPE_FROM_EMAIL][20]={"ds-from:","spam:","from:",""};
static char ca_type_to_email[MAX_TYPE_TO_EMAIL][20]={"ds-to:","to:",""};

static void mutex_lock(pthread_mutex_t *mutex) {
    pthread_mutex_lock(mutex);
}

static void mutex_unlock(pthread_mutex_t *mutex) {
    pthread_mutex_unlock(mutex);
}

time_t last_db_check = 0; // Stores the time of the last load

/* This function does ONLY the physical reload */
int init_access_db() {
    int ret;
    struct stat st;
    DB *tmp_new_dbp = NULL;
    DB *old_to_close = NULL;

    // Open the new DB
    if ((ret = db_create(&tmp_new_dbp, NULL, 0)) != 0) return -1;
    ret = tmp_new_dbp->open(tmp_new_dbp, NULL, ACCESS_FILE, NULL, DB_HASH, DB_RDONLY, 0644);
    if (ret != 0) {
        tmp_new_dbp->close(tmp_new_dbp, 0);
        return -1;
    }

    // Atomic swap
    pthread_mutex_lock(&db_mutex);
    old_to_close = global_dbp;
    global_dbp = tmp_new_dbp;
    
    // Update last_db_check so the automatic check knows we are aligned
    if (stat(ACCESS_FILE, &st) == 0) {
        last_db_check = st.st_mtime;
    }
    pthread_mutex_unlock(&db_mutex);

    // Close the old one
    if (old_to_close) old_to_close->close(old_to_close, 0);

    syslog(LOG_INFO, "DB: Database %s (re)loaded successfully", ACCESS_FILE);
    return 1; 
}


int i_exists(const char *fname)
{
  struct stat buffer;   
  return (stat (fname, &buffer) == 0);
}


extern int db_open(DB **dbp, char *name, int dups)
{
    DB *db;
    int i_ret;

     /* Create the database handle. */
     if ((i_ret = db_create(&db, NULL, 0)) != 0) 
     {
        syslog(LOG_ERR, "db_create: %s", db_strerror(i_ret));
//         db->err(db, i_ret, "%s", name);
        return (-1);
     }

     if( i_exists(ACCESS_FILE))
     {      
       /* Open the database in the environment */
       if ((i_ret = db->open(db, NULL, name, NULL, DB_HASH, DB_RDONLY, 0644)) != 0) 
       {
           syslog (LOGLEVEL, "db_open: after open");
           (void)db->close(db, 0);
             syslog(LOGLEVEL, " db->open: %s", db_strerror(i_ret));
 //        db->err(db, i_ret, "%s", name);
           return (-2);
       }
     }
     else
     {
        return (-3);
     }
     *dbp = db;
     syslog(LOGLEVEL, "db_open OK - end");
     return 1;
}

extern int db_get_persistent(char *pc_key, char **pc_string) 
{
  DBT s_value, s_key;
  memset(&s_value, 0, sizeof (s_value));
  memset(&s_key, 0, sizeof (s_key));

  s_key.data = pc_key;
  s_key.size = strlen(pc_key);

  syslog(LOGLEVEL, "db_get - start %s", pc_key);


  mutex_lock(&db_mutex);
  int i_rc = -1;
  if (global_dbp != NULL) {
        i_rc = global_dbp->get(global_dbp, NULL, &s_key, &s_value, 0);
        if (i_rc == 0) 
        {
           *pc_string = malloc(s_value.size + 1);
           if (*pc_string == NULL)
           {
              syslog(LOG_ERR, "db_get: malloc failed (%lu bytes)", (unsigned long)(s_value.size + 1));
              mutex_unlock(&db_mutex);
              return -1;
           }
           memcpy(*pc_string, s_value.data, s_value.size);
           (*pc_string)[s_value.size] = '\0';
            mutex_unlock(&db_mutex);
           syslog(LOGLEVEL, "db_get - end");
           return 1;
        }
  }

  mutex_unlock(&db_mutex);
  

  return (i_rc == DB_NOTFOUND) ? 0 : -1;

}

extern int db_close(DB *db) 
{
  int i_ret;
  i_ret = db->close(db, 0);
  if (i_ret)
     return (0);
  else
    return 1;
}


extern void find_next_subdomain (char *pc_slave, char *pc_master, long l_size)
{

   register long i, j;
   long l_len=0;

   for (i=0; i<l_size && (pc_slave[i]!=0); i++);
   if (i==l_size)
   {
       pc_master[0]='\0';      
   }
   else
   {
     l_len=i;
     for (i=0; i<l_len && (pc_slave[i]!='.'); i++);
     if (i>=(l_len-1)) 
     {
         pc_master[0]='\0';      
     }
     else
     {  
        i++;
        for (j=0; pc_slave[i]!='\0'; i++, j++)
           pc_master[j]=pc_slave[i];
        pc_master[j]='\0';
     }
   }  
}


extern void find_previous_ipclass (char *pc_ipmain, char *pc_ipsub, long l_size)
{

   register long i, j;

   for (i=0; i<l_size && (pc_ipmain[i]!=0); i++);
   if (i==l_size)
   {
       pc_ipsub[0]='\0';        
   }
   else
   {

     for (j=i-1; j>=0 && (pc_ipmain[j]!='.'); j--);
     if (j<=0)
     {
        pc_ipsub[0]='\0';
     }
     else
     {
        securecpy (pc_ipsub, pc_ipmain, j+1);        
     }

   }
  
}

extern void remove_all_chars(char* str, char c) 
{
    char *pr = str, *pw = str;
    while (*pr) {
        *pw = *pr++;
        pw += (*pw != c);
    }
    *pw = '\0';
}


extern int split_email (const char *pc_email, char *pc_user, char *pc_domain, long l_size,
                        long l_user, long l_domain)
{
   long i, i_max=0, l_len=0;

   int i_ret=0;
  
   for (i=0; i<l_size && (pc_email[i]!=0); i++);
   if (i==l_size)
   {
       i_ret=0;
       pc_user[0]=pc_domain[0]='\0';      
   }
   else
   {
     l_len=i;
     for (i=0; i<l_len && (pc_email[i]!='@'); i++);
     if (i==(l_len-1) && (i>0))
     {
        i_ret=0;
        if (l_user >=(i+1))
           i_max=i+1;
        else i_max=l_user;
        securecpy (pc_user, pc_email, i_max);
        pc_domain[0]='\0';
     }
     else if (i<(l_len-1))
     {
        i_ret=1;
        if (l_user >=(i+1))
           i_max=i+1;
        else i_max=l_user;
        securecpy (pc_user, pc_email, i_max);
        if (l_domain >=(l_len-i))
           i_max=l_len-i;
        else i_max=l_domain;
        securecpy (pc_domain, pc_email+i+1, i_max);
     } 
     else
     {
        i_ret=0;
        pc_user[0]=pc_domain[0]='\0';
     }
   }  
   return i_ret;
}



extern char c_search_IP (const char *pc_ip, char *pc_ip_found, char c_type)
{
    char *pc_data=NULL;
    int i;
   
    char ca_localip[MAXADDR], ca_tempip[MAXADDR];
    char pc_key[MAXHEAD]="";
    char c_state=STATE_NOT_FOUND;
    pc_ip_found[0]='\0';

   syslog (LOGLEVEL, "c_search_IP -> %s", pc_ip);
   if (c_type=='i')
   {
        
        securecpy (ca_tempip, pc_ip, MAXADDR);
        {  
           syslog (LOGLEVEL, "c_search_IP ->Start search");
           while (ca_tempip[0]!='\0')
           {
             securecpy (ca_localip, ca_tempip, MAXADDR);
             for (i=0; i<MAX_TYPE_IP; i++)
             {
               securecpy(pc_key, ca_type_above_ipd[i], MAXHEAD);
               securecat(pc_key, ca_localip, MAXHEAD);
               syslog (LOGLEVEL, "search IP: %s", pc_key);
               int i_ret = db_get_persistent(pc_key, &pc_data);
              

               if (i_ret==1)
               {
                   securecpy (pc_ip_found, ca_localip, MAXADDR);
                   c_state = c_find_state(pc_data);
                   free(pc_data);
                   syslog (LOG_NOTICE, "c_search_IP found %s, %c", pc_key, c_state);
                   goto done;
               }
             }
             find_previous_ipclass (ca_localip, ca_tempip, MAXADDR);
           }
 
done:
          
           
        }
        return c_state;
   }
   else if (c_type=='6')
   {
        /* normalizza() works in place: local copy of the address.
           From the socket it already arrives in canonical form (inet_ntop), so
           here it acts as zero-cost validation. */
        securecpy (ca_tempip, pc_ip, MAXADDR);
        normalizza (ca_tempip);
        if (ca_tempip[0]=='\0')
        {
           /* must never happen on input from the socket: if it does
              it is an anomaly that deserves to make noise in the logs */
           syslog (LOG_WARNING, "c_search_IP: non-normalizable IPv6 address: %s", pc_ip);
           return c_state;   /* STATE_NOT_FOUND */
        }

        syslog (LOGLEVEL, "c_search_IP v6 -> %s", ca_tempip);

        while (ca_tempip[0]!='\0')
        {
          securecpy (ca_localip, ca_tempip, MAXADDR);
          for (i=0; i<MAX_TYPE_IP; i++)
          {
            securecpy(pc_key, ca_type_above_ipd[i], MAXHEAD);
            securecat(pc_key, "ipv6:", MAXHEAD);
            securecat(pc_key, ca_localip, MAXHEAD);
            int i_ret = db_get_persistent(pc_key, &pc_data);
            if (i_ret==1)
            {
                securecpy (pc_ip_found, ca_localip, MAXADDR);
                c_state = c_find_state(pc_data);
                free(pc_data);
                syslog (LOG_NOTICE, "c_search_IP found %s, %c", pc_key, c_state);
                return c_state;
            }
          }
          find_previous_ip6class (ca_localip, ca_tempip, MAXADDR);
        }
        return c_state;   /* ladder exhausted: STATE_NOT_FOUND */
   }
   else
   {
     /* unknown type: no lookup */
     return c_state;
   }
}


char c_search_domain (const char *pc_domain, char *pc_domain_found)
{
    char *pc_data=NULL;

    int i;
    
    char ca_localdomain[MAXHOST], ca_tempdomain[MAXHOST];
    char pc_key[MAXHEAD];
    char c_state=STATE_NOT_FOUND;
    pc_domain_found[0]='\0';

      syslog (LOGLEVEL, "c_search_domain -> %s", pc_domain);

      securecpy (ca_tempdomain, pc_domain, MAXHOST);
 
      if (ca_tempdomain[0]!='[')
      {

        {
           syslog (LOGLEVEL, "c_search_domain ->Start search");
           while (ca_tempdomain[0]!='\0')
           {
             securecpy (ca_localdomain, ca_tempdomain, MAXHOST);
             
             for (i=0; i<MAX_TYPE_DOMAIN; i++)
             {
               securecpy(pc_key, ca_type_above_ipd[i], MAXHEAD);
               securecat(pc_key, ca_localdomain, MAXHEAD);
               syslog (LOGLEVEL, "search domain: %s", pc_key);
               if (db_get_persistent(pc_key, &pc_data)==1)
               {
                   securecpy (pc_domain_found, ca_localdomain, MAXHOST);
                   c_state = c_find_state(pc_data);
                   syslog (LOG_NOTICE, "c_search_domain found %s, %c", pc_key, c_state);
                   free(pc_data);
                   goto done1;
               }
             }
             // void find_next_subdomain (char *pc_slave, char *pc_master, long l_size)
             find_next_subdomain (ca_localdomain, ca_tempdomain, MAXHOST);
           }
done1:

        }
      }
      else
      {

        {
             syslog (LOGLEVEL, "c_search_domain ->Start search");
             securecpy (ca_localdomain, ca_tempdomain, MAXHOST);
             
             for (i=0; i<MAX_TYPE_DOMAIN; i++)
             {
               pc_key[0]=0;
               securecpy(pc_key, ca_type_above_ipd[i], MAXHEAD);
               securecat(pc_key, ca_localdomain, MAXHEAD);
               if (db_get_persistent(pc_key, &pc_data)==1)
               {
                   securecpy (pc_domain_found, ca_localdomain, MAXHOST);
                   c_state = c_find_state(pc_data);
                   syslog (LOG_NOTICE, "c_search_domain found %s, %c", pc_key, c_state);
                   free(pc_data);
                   goto done;
               }
             }
done:
             // db_close (db_domain);
         }
      } 

        return c_state;
}

static char c_find_state(char *pc_state)
{
    // 1. Safety check: if the pointer is null or the string is empty
    if (pc_state == NULL || pc_state[0] == '\0') {
        return STATE_NOT_FOUND;
    }

    /* We use the first character as a fast selector (switch).
       toupper() lets us accept both "REJECT" and "reject".
    */
    switch (toupper((unsigned char)pc_state[0])) 
    {
        case 'S': // SKIP
            return STATE_SKIP;
        
        case 'F': // FRIEND
            return STATE_FRIEND;
        
        case 'O': // OK
            return STATE_OK;
        
        case 'D': // DISCARD
            return STATE_DISCARD;
        
        case 'E': // ERROR
            return STATE_ERROR;
        
        case 'H': // HATER
            return STATE_HATER;
        
        case 'R': // REJECT or RELAY
            /* Instead of pc_state[2], which crashes if the string is
               shorter than 3 characters, we use strncasecmp.
            */
            if (strncasecmp(pc_state, "REJECT", 6) == 0) {
                return STATE_REJECT;
            }
            if (strncasecmp(pc_state, "RELAY", 5) == 0) {
                return STATE_RELAY;
            }
            return STATE_NOT_FOUND;

        default:
            return STATE_NOT_FOUND;
    }
}


char c_search_from_email (const char *pc_email, char *pc_user, char *pc_domain, char *pc_subdomain, char *c_part)
{
    char *pc_data=NULL;

    int i, i_ret=0;
    
    char pc_key[MAXHEAD]="";
    char c_state=STATE_NOT_FOUND;
    *c_part='n';

    char ca_tempdomain[MAXHOST], ca_localdomain[MAXHOST];

    syslog (LOGLEVEL, "c_search_from_email -> %s", pc_email);

    i_ret=split_email (pc_email, pc_user, pc_domain, MAXEMAIL, MAXUSER, MAXHOST);

    if (i_ret==1)
    {  
        securecpy (pc_subdomain, pc_domain, MAXHOST);
 

        // if (db_open(&db_domain, ACCESS_FILE, 0)==1)
        {
          syslog (LOGLEVEL, "c_search_from_email ->Start search");

          for (i=0; i<MAX_TYPE_FROM_EMAIL; i++)
          {
              securecpy(ca_tempdomain, pc_domain, MAXHOST);
 
              securecpy(pc_key, ca_type_from_email[i], MAXHEAD);
              securecat(pc_key, pc_email, MAXHEAD);

              if (db_get_persistent(pc_key, &pc_data)==1)
              {
                  c_state = c_find_state(pc_data);
                  free(pc_data);
                  syslog (LOG_NOTICE, "c_search_from_email %s, %c", pc_key, c_state);
                  *c_part='a';
                  goto done;
              }

              while (ca_tempdomain[0]!='\0')
              {
                  securecpy (ca_localdomain, ca_tempdomain, MAXHOST);
                  securecpy(pc_key, ca_type_from_email[i], MAXHEAD);
                  securecat(pc_key, ca_localdomain, MAXHEAD);

                  if (db_get_persistent(pc_key, &pc_data)==1)
                  {
                     securecpy (pc_subdomain, ca_localdomain, MAXHOST);
                     c_state = c_find_state(pc_data);
                     free(pc_data);
                     syslog (LOG_NOTICE, "c_search_from_email %s, %c", pc_key, c_state);
                     *c_part='d';
                     goto done;
                  }
                  find_next_subdomain (ca_localdomain, ca_tempdomain, MAXHOST);
              }

              securecpy(pc_key, ca_type_from_email[i], MAXHEAD);
              securecat(pc_key, pc_user, MAXHEAD);

              if (db_get_persistent(pc_key, &pc_data)==1)
              {
                  c_state = c_find_state(pc_data);
                  free(pc_data);
                  *c_part='u';
                 syslog (LOG_NOTICE, "c_search_from_email %s, %c", pc_key, c_state);
                 goto done;
              }
           }
done:

        }

  
     }
     return c_state;
}



char c_search_to_email (const char *pc_email, char *pc_user, char *pc_domain, char *pc_subdomain, char *c_part)
{
    char *pc_data=NULL;
    int i, i_ret=0;
    
    char pc_key[MAXHEAD]="";
    char c_state=STATE_NOT_FOUND;
    *c_part='n';

    char ca_tempdomain[MAXHOST], ca_localdomain[MAXHOST];
    syslog (LOGLEVEL, "c_search_to_email -> %s", pc_email);
    i_ret=split_email (pc_email, pc_user, pc_domain, MAXEMAIL, MAXUSER, MAXHOST);

    if (i_ret==1)
    {  
        securecpy (pc_subdomain, pc_domain, MAXHOST);
 

 
        {
          syslog (LOGLEVEL, "c_search_to_email ->Start search");
          for (i=0; i<MAX_TYPE_TO_EMAIL; i++)
          {
              securecpy(ca_tempdomain, pc_domain, MAXHOST);
 
              securecpy(pc_key, ca_type_to_email[i], MAXHEAD);
              securecat(pc_key, pc_email, MAXHEAD);
              
              if (db_get_persistent(pc_key, &pc_data)==1)
              {
                  c_state = c_find_state(pc_data);
                  free(pc_data);
                  syslog (LOG_NOTICE, "c_search_to_email %s, %c", pc_key, c_state);
                  *c_part='a';
                  goto done2;
              }

              while (ca_tempdomain[0]!='\0')
              {
                  securecpy (ca_localdomain, ca_tempdomain, MAXHOST);
                  securecpy(pc_key, ca_type_to_email[i], MAXHEAD);
                  securecat(pc_key, ca_localdomain, MAXHEAD);

                  if (db_get_persistent(pc_key, &pc_data)==1)
                  {
                     securecpy (pc_subdomain, ca_localdomain, MAXHOST);
                     c_state = c_find_state(pc_data);
                     free(pc_data);
                     syslog (LOG_NOTICE, "c_search_to_email %s, %c", pc_key, c_state);
                     *c_part='d';
                     goto done2;
                  }
                  find_next_subdomain (ca_localdomain, ca_tempdomain, MAXHOST);
              }

              securecpy(pc_key, ca_type_to_email[i], MAXHEAD);
              securecat(pc_key, pc_user, MAXHEAD);

              if (db_get_persistent(pc_key, &pc_data)==1)
              {
                  c_state = c_find_state(pc_data);
                  free(pc_data);
                  syslog (LOG_NOTICE, "c_search_to_email %s, %c", pc_key, c_state);
                  *c_part='u';
                  goto done2;
              }
           }
done2:
 
        }

  
     }
     return c_state;
}


void cleanup_and_exit(int sig) {
    /* patch 2.6: in a signal handler only async-signal-safe functions.
       dbp->close() and exit() are not: close does internal malloc/free and
       could run while another thread has a get in progress on the DB.
       The DB is opened read-only: there is nothing to flush, the
       kernel closes the fds when the process dies. write() and _exit()
       are both async-signal-safe. */
    ssize_t sink = write(2, "Signal received, exiting...\n", 28);
    (void)sink;
    _exit(0);
}

