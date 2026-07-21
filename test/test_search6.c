/* Harness funzionale: chiama c_search_IP con c_type='6' contro il DB di prova */
#include <stdio.h>
#include <pthread.h>
#include <string.h>
#include <db.h>
#include "DarkSpam.h"

int i_loglevel = 7;  /* LOG_DEBUG: nell'harness vogliamo vedere tutto (definita in DarkSpam.c nel milter) */

/* securecpy/securecat vivono in DarkSpam.c che qui non linkiamo: copie locali */
long securecpy (register char *pc_dst, register const char *pc_src, long l_sizeof)
{
    register long i;
    if (l_sizeof > 1)
    {
      pc_dst[0]='\0';
      l_sizeof--;
      for (i = 0; i < l_sizeof && (pc_dst[i] = pc_src[i]) != 0; i++) continue;
      pc_dst[i] = '\0';
      return (i);
    }
    return (0);
}
long securecat (register char *pc_dst, register const char *pc_src, long l_sizeof)
{
    register long i,j;
    for (j=0; j<l_sizeof; j++)
       if (pc_dst[j]==0) break;
    if ((j+1)==(l_sizeof)) return (0);
    if (l_sizeof > 1)
    {
      l_sizeof--;
      for (i = 0; j < l_sizeof && (pc_dst[j] = pc_src[i]) != 0; i++, j++) continue;
      pc_dst[j] = '\0';
      return (j);
    }
    return (0);
}

static const char *nome(char c)
{
    switch (c) {
      case STATE_RELAY: return "RELAY";  case STATE_OK: return "OK";
      case STATE_FRIEND: return "FRIEND"; case STATE_REJECT: return "REJECT";
      case STATE_SKIP: return "SKIP";    case STATE_NOT_FOUND: return "NOT_FOUND";
      default: return "?";
    }
}

static void prova(const char *ip, char tipo, const char *atteso)
{
    char trovato[MAXADDR];
    char c = c_search_IP(ip, trovato, tipo);
    printf("%-28s -> %-9s (match su '%s')%s\n", ip, nome(c),
           trovato[0] ? trovato : "-",
           strcmp(nome(c), atteso) ? "   <<< ATTESO " : "");
    if (strcmp(nome(c), atteso)) printf("                                ATTESO: %s\n", atteso);
}

int main(void)
{
    if (init_access_db() < 0) { puts("init_access_db fallita"); return 1; }
    puts("--- IPv6 ---");
    prova("2001:db8::1",              '6', "RELAY");     /* esatto, primo tag */
    prova("2001:db8::9:9",            '6', "OK");        /* scala fino a 2001:db8:: */
    prova("fd00:aa:1:2:3:4:5:6",      '6', "REJECT");    /* scala fino a fd00:aa, tag nudo */
    prova("::1",                       '6', "FRIEND");    /* chiave ipv6:::1 */
    prova("2a00:1450:4002:800::200e", '6', "NOT_FOUND"); /* assente */
    prova("2001:0db8::0001",          '6', "RELAY");     /* sporco: normalizza in gioco */
    puts("--- non regressione IPv4 ---");
    prova("192.168.77.1",             'i', "RELAY");
    prova("8.8.8.8",                  'i', "NOT_FOUND");
    return 0;
}
