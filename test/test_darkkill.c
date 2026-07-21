/* Casi derivati da darkkill.txt (bestiario reale 2001 di Vittorio) */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <pthread.h>
#include "DarkSpam.h"
int i_loglevel = 5;
static char ca_out[131072]; static long l_out;
static int emit(void *pv, const char *pc, long l)
{ (void)pv; if (l_out+l>=131072) exit(2); memcpy(ca_out+l_out,pc,l); l_out+=l; return 0; }
static long run(const char *m, const char *b, long lc, char *dst)
{ struct mime_stream s; long L=(long)strlen(m), i, n;
  mime_stream_init(&s,b); l_out=0;
  for(i=0;i<L;i+=lc){ n=(L-i<lc)?(L-i):lc; if(mime_stream_feed(&s,m+i,n,emit,NULL)<0) exit(2);}
  mime_stream_flush(&s,emit,NULL); memcpy(dst,ca_out,l_out); dst[l_out]=0; return l_out; }
static int tests=0, fails=0;
static void caso(const char *nome, const char *msg, const char *bound,
                 const char *si[], const char *no[])
{ static char rf[131072], tr[131072];
  long lr=run(msg,bound,131072,rf), lt, cs[]={1,7,80,1500}; int i, ok=1;
  for(i=0;i<4;i++){ lt=run(msg,bound,cs[i],tr);
    if(lt!=lr||memcmp(tr,rf,lr)){ printf("[%s] DIVERGE chunk=%ld\n",nome,cs[i]); ok=0; } }
  for(i=0;si[i];i++) if(!strstr(rf,si[i])){ printf("[%s] MANCA: '%.40s'\n",nome,si[i]); ok=0; }
  for(i=0;no[i];i++) if(strstr(rf,no[i])){ printf("[%s] NON RIMOSSO: '%.40s'\n",nome,no[i]); ok=0; }
  tests++; if(!ok) fails++;
  printf("%-36s %s (out %ld)\n", nome, ok?"ok":"FALLITO", lr); }

int main(void)
{
  const char *nulla[]={NULL};

  /* K1: DSN sendmail completo: boundary con slash/punti e trailing spaces
     sulla riga; prima parte SENZA header; delivery-status; message/rfc822
     col multipart interno e l'EXE camuffato da image/gif in base64 */
  {
    const char *msg =
    "This is a MIME-encapsulated message\r\n"
    "   \r\n"
    "--f7D7Bx613287.997686719/dns.itb.it   \r\n"
    "\r\n"
    "The original message was received at Mon, 13 Aug 2001\r\n"
    "   ----- The following addresses had permanent fatal errors -----\r\n"
    "<anigra@fastcom.it>\r\n"
    "\r\n"
    "--f7D7Bx613287.997686719/dns.itb.it\r\n"
    "Content-Type: message/delivery-status\r\n"
    "\r\n"
    "Reporting-MTA: dns; dns.itb.it\r\n"
    "Action: failed\r\n"
    "Status: 5.1.1\r\n"
    "\r\n"
    "--f7D7Bx613287.997686719/dns.itb.it\r\n"
    "Content-Type: message/rfc822\r\n"
    "\r\n"
    "Return-Path: <tpnino@itb.it>\r\n"
    "FROM: tonino <tonino@itb.it>\r\n"
    "SUBJECT: merce: A VISTA\r\n"
    "MIME-Version: 1.0\r\n"
    "Content-Type: multipart/mixed;\r\n"
    "        boundary=\"----=_NextPart_000_00C3_01BFDCE5.11ECE5D0\"\r\n"
    "Content-Transfer-Encoding: 7bit\r\n"
    "\r\n"
    "This is a multi-part message in MIME format.\r\n"
    "\r\n"
    "------=_NextPart_000_00C3_01BFDCE5.11ECE5D0\r\n"
    "Content-Type: text/plain; charset=ISO-8859-1\r\n"
    "\r\n"
    "CONSEGNE URGENTI Autista: Targa:\r\n"
    "------=_NextPart_000_00C3_01BFDCE5.11ECE5D0\r\n"
    "Content-Type: image/gif; name=\"LTHOMOL.EXE\"\r\n"
    "Content-Transfer-Encoding: base64\r\n"
    "Content-Disposition: attachment; filename=\"LTHOMOL.EXE\"\r\n"
    "\r\n"
    "TVqQAAMAAAAEAAAA-BLOB-EXE-DA-ELIMINARE\r\n"
    "AAAAgAAAAA4fug4AtAnNIbgBTM0h-ALTRO-BLOB\r\n"
    "------=_NextPart_000_00C3_01BFDCE5.11ECE5D0--\r\n"
    "\r\n"
    "--f7D7Bx613287.997686719/dns.itb.it--\r\n";
    const char *si[]={"permanent fatal errors","Status: 5.1.1","CONSEGNE URGENTI",
                      "filename=\"LTHOMOL.EXE\"","SUBJECT: merce",NULL};
    const char *no[]={"BLOB-EXE-DA-ELIMINARE","ALTRO-BLOB",NULL};
    caso("K1 dsn+rfc822+exe camuffato", msg, "f7D7Bx613287.997686719/dns.itb.it", si, no);
  }

  /* K2: riga di SOLI SPAZI come separatore header/body (applefile 2001)
     e trailing spaces sugli header */
  {
    const char *msg =
    "--BB\r\n"
    "Content-Type: application/applefile   \r\n"
    "Content-Transfer-Encoding: base64   \r\n"
    " \r\n"
    "AAUWBwACAAAAAA-APPLE-BLOB-VIA\r\n"
    "--BB\r\n"
    "Content-Type: text/plain; charset=us-ascii; x-mac-type=\"54455854\"\r\n"
    "\r\n"
    "saSADX>WXDaS>XS testo che resta\r\n"
    "--BB--\r\n";
    const char *si[]={"testo che resta","x-mac-type",NULL};
    const char *no[]={"APPLE-BLOB-VIA",NULL};
    caso("K2 separatore di soli spazi", msg, "BB", si, no);
  }

  /* K3: parte con zero header e testo appiccicato (DSN prima parte,
     variante senza nemmeno la riga vuota dopo il boundary) */
  {
    const char *msg =
    "--CC\r\n"
    "The original message was received at...\r\n"
    "transcript diretto senza header\r\n"
    "--CC\r\n"
    "Content-Type: application/pdf\r\n"
    "\r\n"
    "PDF-VIA\r\n"
    "--CC--\r\n";
    const char *si[]={"transcript diretto senza header",NULL};
    const char *no[]={"PDF-VIA",NULL};
    caso("K3 parte senza header", msg, "CC", si, no);
  }

  printf("\nTotale: %d casi, %d falliti\n", tests, fails);
  return fails!=0;
}
