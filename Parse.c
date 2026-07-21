/*
 * DarkSpam - Parse.c
 * Pure parsing and teardown functions (no DB access)
 *
 * Copyright (c) 2026 Vittorio Moccia
 * Licensed under the PolyForm Noncommercial License 1.0.0.
 * https://polyformproject.org/licenses/noncommercial/1.0.0/
 */

/* Contains:
     normalizza()             - brings a textual IPv6 to the compressed
                                canonical form RFC 5952; empty string on invalid input
     find_previous_ip6class() - reduction ladder for the progressive lookup
                                in access.db (the '::' cannot be crossed)
   The future MIME text-extraction function will also live here. */

#include <string.h>
#include <pthread.h>
#include <syslog.h>
#include "DarkSpam.h"

#define MAXIP6TXT 64   /* a textual IPv6 is at most 45 characters */

void normalizza (char stringa[])
{
    char normalizzata[MAXIP6TXT*2], finale [MAXIP6TXT*2];
    int cnt=0, primo=1, pos=0, max=0, continua=1, first=0;
    int i=0, j=0, k=0, noseq=1;
    int oktry=0;
    memset (normalizzata, 0, sizeof(normalizzata));

    /* upfront check: only hex digits and ':' are allowed,
       any other character invalidates the input (empty string output).
       The same scan doubles as a length guard. */
    for (i = 0; stringa[i] != '\0'; i++)
    {
       if (i >= MAXIP6TXT) { stringa[0]='\0'; return; }
       if (stringa[i] == ':') continue;
       if ((stringa[i] >= '0') && (stringa[i] <= '9')) continue;
       if ((stringa[i] >= 'a') && (stringa[i] <= 'f')) continue;
       if ((stringa[i] >= 'A') && (stringa[i] <= 'F')) continue;
       stringa[0]='\0';
       return;
    }

    /* upfront check on the ':' sequences:
       - three or more consecutive ':' are invalid (:::)
       - the '::' pair may appear at most once (RFC 4291)
       - a single ':' at head or tail delimits nothing and is invalid */
    {
       int run=0, doppi=0, len=0;
       for (i = 0; stringa[i] != '\0'; i++)
       {
          if (stringa[i] == ':')
          {
             run++;
             if (run > 2)  { stringa[0]='\0'; return; }   /* ::: and beyond */
             if (run == 2) doppi++;
          }
          else run=0;
          len++;
       }
       if (doppi > 1) { stringa[0]='\0'; return; }        /* 1::2::3 */
       if ((stringa[0]==':') && (stringa[1]!=':'))         /* :1:2:... */
          { stringa[0]='\0'; return; }
       if ((len>=1) && (stringa[len-1]==':') &&
           ((len<2) || (stringa[len-2]!=':')))             /* ...:2:3: */
          { stringa[0]='\0'; return; }
    }

    /* upfront check on the counts:
       - each group at most 4 hex digits
       - without '::' the groups must be exactly 8
       - with '::' the explicit groups can be at most 7,
         because the ellipsis is worth at least one group of zeros */
    {
       int gruppi=0, cifre=0, ha_doppio=0;
       for (i = 0; stringa[i] != '\0'; i++)
       {
          if (stringa[i] == ':')
          {
             if ((i>0) && (stringa[i-1]==':')) ha_doppio=1;
             cifre=0;
          }
          else
          {
             cifre++;
             if (cifre > 4)  { stringa[0]='\0'; return; }  /* 12345::1 */
             if (cifre == 1) gruppi++;
          }
       }
       if ((!ha_doppio) && (gruppi != 8)) { stringa[0]='\0'; return; }
       if (( ha_doppio) && (gruppi > 7))  { stringa[0]='\0'; return; }
    }

    for(i = 0; stringa[i]; i++)  
    {
    	if(stringa[i] == ':')
    	{
          cnt++;     /* numer of : */
          if (i>=1)
          {
            if ((stringa[i]==':') && (stringa[i-1]==':'))
              noseq=0;
          }
        }
    }
    if (cnt<=1) { stringa[0]='\0'; return;}
    if ((cnt <7) && (noseq)) { stringa[0]='\0'; return;}

    for(i = 0; stringa[i]!='\0'; i++)   /* scan the string */
    {

       if ((stringa[i] == ':') && (i==0))   /* if leading :, prepend 0 */
          normalizzata[j++]='0';

       if (stringa[i] != '0')  /* if not 0, copy into normalizzata */ 
       {
         normalizzata[j++]=stringa[i];
         primo=0;
         if(stringa[i] == ':') primo=1;  /* found a : */
       }

       if (j>=1)
       {
           if ((stringa[i] == '0') && (!primo))   /* zero inside the group: always copy (N1) */
/* N1: the condition (normalizzata[j-1]!='0') discarded the second consecutive zero
   even in the middle of the group: 2001 => 201, fe00 => fe0. Leading zeros are already
   excluded by the fact that no rule copies while primo is high.
           if ((stringa[i] == '0') &&
           (
              ((!primo) && (j>=1) && (normalizzata[j-1]!='0'))      // 0010:788 => 10:788

              )
          ) 
*/
          {
              normalizzata[j++]=stringa[i];
//            primo=0;
          }
       }

       if ( (stringa[i] == '0') &&
              ( (primo) && ((stringa[i+1]=='\0') || (stringa[i+1]==':')) ) 
          )
       {
         normalizzata[j++]=stringa[i];
         primo=0;
       }
 

      if (stringa[i+1] != '\0')
       if((stringa[i] == ':') && (stringa[i+1] == ':'))
       {
         i++;
         for(k = 0; k< (8-cnt); k++)
         {
           normalizzata[j++]='0'; 
           normalizzata[j++]=':';
          
         }
//         printf ("\n %c %c %c", stringa[i-1], stringa[i], stringa[i+1]);
         if (stringa[i+1] == '\0')
         {
           normalizzata[j++]='0';
         }
         primo=1;
       }
  
    }
    normalizzata[j]=0;

    primo=1; i=0; j=0; k=0; max=0;
    continua=1;


/* a341:0:0:1:0:0:0:4 */
    for (i=0; normalizzata[i] != '\0'; i++)
    {
        if(stringa[i] == ':') primo=1;


        if ((i==0) && (normalizzata[0]=='0')) oktry=1;
        if ((i>0) &&
              ( (normalizzata[i-1]==':') &&
                    (normalizzata[i]=='0')  && ((normalizzata[i+1]==':') || (normalizzata[i+1]=='\0')) )
           )
            oktry=1;

           if (oktry)
           {    /* 230:7320:0:0:0:6760 */
              oktry=0;
              pos=i; cnt=1; continua=1;
              for(k = pos+1; (normalizzata[k]!='\0') && continua; k++)
              {
                 if(normalizzata[k] == ':') 
                 {
                   if(normalizzata[k+1] == '0')
                   {
                      cnt++; k++;
                   } else continua=0;
                 } else 
                 {
                    continua=0;
                 }
                 if ((cnt>max)) {max=cnt; first=pos;};
              }
              i=k;   
           }
    }
    k=0; i=0;

    if ((max>1))
    {
      if (!first) 
        finale[k++]=':';

      for (i=0; i<first; i++)
         finale[k++]=normalizzata[i];
      finale[k++]=':';
      finale[k]='\0';
      if (!first) 
       strcat (finale, &normalizzata[k+max*2-2]);  
      else
       strcat (finale, &normalizzata[k+max*2-1]);     
    }
    else
      strcpy (finale, normalizzata);
    strcpy (stringa, finale);

}


/* IPv6 reduction ladder for the progressive lookup in access.db.
   The '::' cannot be crossed: never truncate to its right, to avoid
   false positives (2001:db8::1 is NOT a prefix of 2001:db8::1:2).
   Examples:
      abc:cda::1:3  =>  abc:cda::
      abc:cda::     =>  abc:cda
      abc:cda:1     =>  abc:cda        (last group gone)
      abc           =>  (empty)        */
void find_previous_ip6class(char *pc_ipmain, char *pc_ipsub, long l_size) {
    if (pc_ipmain == NULL || pc_ipsub == NULL || l_size <= 0) return;

    // 1. Validate the terminator within l_size
    long len = 0;
    while (len < l_size && pc_ipmain[len] != '\0') {
        len++;
    }
    if (len == l_size) return; // No terminator found

    if (len == 0) return;
    // 2. Copy the input into the output
    for (long i = 0; i <= len; i++) {
        pc_ipsub[i] = pc_ipmain[i];
    }

    // 3. REDUCTION LOGIC
    
    // CASE A: If the string ends exactly with "::"
    // Example: "a341:0:1::" -> must become "a341:0:1"
    //
    // CASE B: If the string contains "::"
    // Example: "a341:0:1::ad:1" -> must become "a341:0:1::"
    long i=1;
    while (i < len)
    {
       if ((pc_ipsub[i - 1] == ':') && (pc_ipsub[i]==':'))
       {
         if (i==(len-1))
         {
            pc_ipsub[i - 1] = '\0';   // abc:cda:: => abc:cda 
         }
         else if (i<(len-1))
         {
            pc_ipsub[i+1] = '\0';      // abc:cda::1:3 => abc:cda::
         }
         return;
       }
       i++;
    }
       

    // CASE C: Find the last occurrence of the ':' character
    long last_colon_idx = -1;
    for (long i = len - 1; i >= 0; i--) {
        if (pc_ipsub[i] == ':') {
            last_colon_idx = i;
            break;
        }
    }

    if (last_colon_idx != -1) 
    {
         pc_ipsub[last_colon_idx] = '\0';
    } else 
    {
        // No colon found: empty the string
        pc_ipsub[0] = '\0';
    }
}


/* ================== STREAMING MIME FILTER ==================
   4-state automaton (design Vittorio, session 2026-07):
     SEEK       outside the parts (preamble/epilogue): everything passes,
                the active boundaries are sought
     SCAN_BOUND part header: they ALWAYS pass (no filter on the
                headers); here the state of the body that follows is decided
     KEEP       text body: forwarded while seeking the boundary
     DROP       binary body: consumed while seeking the boundary
   No QP/base64 decoding: the KEEP parts pass verbatim and SpamAssassin
   decodes them. O(1) memory: 1024-byte line + 8x72 stack.
   Dirty MIME: when in doubt KEEP and let SpamAssassin decide. */

static int i_ci_eq (char a, char b)
{
    if ((a >= 'A') && (a <= 'Z')) a += 32;
    if ((b >= 'A') && (b <= 'Z')) b += 32;
    return (a == b);
}

/* search pc_needle (ASCII) in pc_hay, case insensitive; returns the index
   of the first character after the match, or -1 */
static long l_ci_find (const char *pc_hay, long l_len, const char *pc_needle)
{
    long i, j;
    for (i = 0; i < l_len; i++)
    {
       for (j = 0; pc_needle[j] != '\0'; j++)
       {
          if ((i + j >= l_len) || (!i_ci_eq(pc_hay[i+j], pc_needle[j])))
             break;
       }
       if (pc_needle[j] == '\0')
          return (i + j);
    }
    return -1;
}

/* extract the boundary= parameter from a Content-Type value (quoted or not,
   case insensitive). Returns 1 if found, 0 otherwise. */
int mime_extract_boundary (const char *pc_value, char *pc_bound, long l_size)
{
    long l_len, l_pos, i, j;

    for (l_len = 0; pc_value[l_len] != '\0'; l_len++) continue;

    l_pos = l_ci_find (pc_value, l_len, "boundary=");
    if (l_pos < 0)
       return 0;

    i = l_pos;
    j = 0;
    if ((i < l_len) && (pc_value[i] == '"'))
    {
       i++;
       while ((i < l_len) && (pc_value[i] != '"') && (j < l_size - 1))
          pc_bound[j++] = pc_value[i++];
    }
    else
    {
       while ((i < l_len) && (pc_value[i] != ';') && (pc_value[i] != ' ') &&
              (pc_value[i] != '\t') && (pc_value[i] != '\r') && (pc_value[i] != '\n') &&
              (j < l_size - 1))
          pc_bound[j++] = pc_value[i++];
    }
    pc_bound[j] = '\0';
    return (j > 0);
}

void mime_stream_init (struct mime_stream *ps, const char *pc_boundary)
{
    long i;
    memset (ps, 0, sizeof(*ps));
    ps->i_state = MS_SEEK;
    ps->i_next_state = MS_KEEP;
    if ((pc_boundary != NULL) && (pc_boundary[0] != '\0'))
    {
       for (i = 0; (pc_boundary[i] != '\0') && (i < MIME_BOUND_LEN - 1); i++)
          ps->ca_bound[0][i] = pc_boundary[i];
       ps->ca_bound[0][i] = '\0';
       ps->i_depth = 1;
       ps->i_active = 1;
    }
}

/* Is the line (complete, with an optional CRLF) a delimiter of one of the
   stacked boundaries? Returns: -1 no; otherwise the level (0-based)
   and in *pi_final 1 if it is the closing form --bound-- */
static int i_match_boundary (struct mime_stream *ps, const char *pc_line, long l_len, int *pi_final)
{
    int  i_lev;
    long i, l_blen;
    const char *pc_b;

    if ((l_len < 3) || (pc_line[0] != '-') || (pc_line[1] != '-'))
       return -1;

    for (i_lev = ps->i_depth - 1; i_lev >= 0; i_lev--)
    {
       pc_b = ps->ca_bound[i_lev];
       for (l_blen = 0; pc_b[l_blen] != '\0'; l_blen++) continue;
       if (l_len < 2 + l_blen)
          continue;
       for (i = 0; i < l_blen; i++)
          if (pc_line[2+i] != pc_b[i])
             break;
       if (i < l_blen)
          continue;
       /* after the boundary: optional --, then only spaces/CRLF */
       i = 2 + l_blen;
       *pi_final = 0;
       if ((i + 1 < l_len) && (pc_line[i] == '-') && (pc_line[i+1] == '-'))
       {
          *pi_final = 1;
          i += 2;
       }
       while ((i < l_len) &&
              ((pc_line[i]==' ') || (pc_line[i]=='\t') || (pc_line[i]=='\r') || (pc_line[i]=='\n')))
          i++;
       if (i == l_len)
          return i_lev;
    }
    return -1;
}

/* process a complete logical line; returns <0 on emit error */
static int i_mime_line (struct mime_stream *ps, const char *pc_line, long l_len,
                        mime_emit_cb pf_emit, void *pv_ctx)
{
    int i_lev, i_final = 0;
    int i_blank;
    long l_pos;
    char ca_nested[MIME_BOUND_LEN];

    /* line longer than the buffer: it cannot be a boundary nor is it
       of interest as a header, it follows the current state in raw */
    if (ps->i_longline)
    {
       if (ps->i_state != MS_DROP)
          return pf_emit (pv_ctx, pc_line, l_len);
       return 0;
    }

    i_lev = i_match_boundary (ps, pc_line, l_len, &i_final);
    if (i_lev >= 0)
    {
       /* boundaries are structure: they always pass. Intermediate levels
          left unclosed (ragged MIME) are popped automatically */
       ps->i_depth = i_lev + 1;
       if (i_final)
       {
          ps->i_depth = i_lev;              /* pop */
          ps->i_state = MS_SEEK;            /* epilogue of the level */
          if (DEBUG)
             syslog (LOG_DEBUG, "mime: closing boundary, depth %d", ps->i_depth);
       }
       else
       {
          ps->i_state = MS_SCAN_BOUND;      /* header of the new part */
          ps->i_next_state = MS_KEEP;       /* pragmatic: without CT it is kept */
          ps->i_ct_seen = 0;
          ps->i_in_ct = 0;
       }
       return pf_emit (pv_ctx, pc_line, l_len);
    }

    switch (ps->i_state)
    {
       case MS_SCAN_BOUND:
       {
          /* part header: NO FILTER, the line passes anyway */
          int i_ret = pf_emit (pv_ctx, pc_line, l_len);
          if (i_ret < 0)
             return i_ret;

          /* fix K2: a line of only spaces/tabs (+CRLF) closes the headers
             like a blank line; vintage dirty MIME. The check MUST come
             before the folding branch, which would otherwise catch it. */
          i_blank = 1;
          {
             long l_i;
             for (l_i = 0; l_i < l_len; l_i++)
                if ((pc_line[l_i] != ' ') && (pc_line[l_i] != '\t') &&
                    (pc_line[l_i] != '\r') && (pc_line[l_i] != '\n'))
                   { i_blank = 0; break; }
          }
          if (i_blank)
          {
             /* end of header: the decision is applied. If the decision is
                SCAN_BOUND again (message: the headers of the encapsulated
                message are re-scanned) it restarts with clean flags and
                the pragmatic default KEEP. */
             ps->i_state = ps->i_next_state;
             ps->i_in_ct = 0;
             if (ps->i_state == MS_KEEP)
                ps->l_parts_keep++;
             else if (ps->i_state == MS_DROP)
                ps->l_parts_drop++;
             if (DEBUG)
                syslog (LOG_DEBUG, "mime: part body -> %s",
                        (ps->i_state == MS_KEEP) ? "KEEP" :
                        (ps->i_state == MS_DROP) ? "DROP" :
                        (ps->i_state == MS_SCAN_BOUND) ? "RESCAN (message)" : "DESCEND (multipart)");
             if (ps->i_state == MS_SCAN_BOUND)
             {
                ps->i_next_state = MS_KEEP;
                ps->i_ct_seen = 0;
             }
             return 0;
          }

          /* folding: a line starting with space/tab continues the previous header */
          if ((pc_line[0]==' ') || (pc_line[0]=='\t'))
          {
             if (ps->i_in_ct)
             {
                /* Content-Type continuation: the nested boundary may be here */
                if ((ps->i_next_state == MS_SEEK) && (ps->i_depth < MIME_MAX_DEPTH))
                {
                   if (mime_extract_boundary (pc_line, ca_nested, MIME_BOUND_LEN))
                   {
                      long k;
                      for (k = 0; ca_nested[k] != '\0'; k++)
                         ps->ca_bound[ps->i_depth][k] = ca_nested[k];
                      ps->ca_bound[ps->i_depth][k] = '\0';
                      ps->i_depth++;
                      ps->i_in_ct = 0;   /* found: nothing else needed */
                   }
                }
             }
             return 0;
          }

          ps->i_in_ct = 0;
          l_pos = l_ci_find (pc_line, l_len, "content-type:");
          /* the find returns the index AFTER the match: "content-type:" at the
             start of the line gives 13, with a tolerated leading space 14 */
          if ((l_pos >= 13) && (l_pos <= 14))
          {
             ps->i_ct_seen = 1;
             ps->i_in_ct = 1;
             if (DEBUG)
                syslog (LOG_DEBUG, "mime: part header '%.*s'", (int)(l_len > 2 ? l_len - 2 : l_len), pc_line);
             if (l_ci_find (pc_line, l_len, "multipart/") >= 0)
             {
                ps->i_next_state = MS_SEEK;   /* container: we descend */
                if (ps->i_depth < MIME_MAX_DEPTH)
                {
                   if (mime_extract_boundary (pc_line, ca_nested, MIME_BOUND_LEN))
                   {
                      long k;
                      for (k = 0; ca_nested[k] != '\0'; k++)
                         ps->ca_bound[ps->i_depth][k] = ca_nested[k];
                      ps->ca_bound[ps->i_depth][k] = '\0';
                      ps->i_depth++;
                      ps->i_in_ct = 0;
                      if (DEBUG)
                         syslog (LOG_DEBUG, "mime: nested boundary '%s', depth %d", ca_nested, ps->i_depth);
                   }
                }
             }
             else if (l_ci_find (pc_line, l_len, "text/") >= 0)
                ps->i_next_state = MS_KEEP;        /* text: passes */
             else if (l_ci_find (pc_line, l_len, "message/") >= 0)
                ps->i_next_state = MS_SCAN_BOUND;  /* fix K1: rfc822 and kin:
                   the headers of the encapsulated message are re-scanned,
                   so an inner multipart is captured and descended */
             else
                ps->i_next_state = MS_DROP;   /* logic BY EXCLUSION: any
                   DECLARED type other than text/multipart/message is
                   cut off (image, application, audio, video, font, model and
                   whatever IANA will invent). The benefit of the doubt
                   goes only to the ABSENT or unreadable Content-Type, which
                   keeps the pragmatic default MS_KEEP set
                   at the entry of the part. The headers pass anyway. */
          }
          return 0;
       }

       case MS_DROP:
          ps->l_bytes_drop += l_len;
          return 0;                            /* consume */

       case MS_SEEK:
       case MS_KEEP:
       default:
          return pf_emit (pv_ctx, pc_line, l_len);
    }
}

int mime_stream_feed (struct mime_stream *ps, const char *pc_chunk, long l_len,
                      mime_emit_cb pf_emit, void *pv_ctx)
{
    long i;
    int  i_ret;

    /* no multipart declared AT THE ORIGIN: pure passthrough, zero
       work. NB: i_depth is not used, since it legitimately returns to 0
       in the epilogue after the pop of the final boundary: from there on it
       stays on the normal path (SEEK emits anyway) so as not to skip
       the partial line in ca_line */
    if (!ps->i_active)
       return pf_emit (pv_ctx, pc_chunk, l_len);

    for (i = 0; i < l_len; i++)
    {
       if (ps->l_line >= MIME_LINE_LEN - 1)
       {
          /* line beyond the buffer (including repeated saturations of the
             same line): flush raw according to the state and restart,
             such a line cannot be a boundary */
          ps->i_longline = 1;
          if (ps->i_state != MS_DROP)
          {
             i_ret = pf_emit (pv_ctx, ps->ca_line, ps->l_line);
             if (i_ret < 0) return i_ret;
          }
          else
             ps->l_bytes_drop += ps->l_line;
          ps->l_line = 0;
       }

       ps->ca_line[ps->l_line++] = pc_chunk[i];

       if (pc_chunk[i] == '\n')
       {
          if (ps->i_longline)
          {
             /* tail of the long line: raw according to state */
             if (ps->i_state != MS_DROP)
             {
                i_ret = pf_emit (pv_ctx, ps->ca_line, ps->l_line);
                if (i_ret < 0) return i_ret;
             }
             else
                ps->l_bytes_drop += ps->l_line;
             ps->i_longline = 0;
          }
          else
          {
             i_ret = i_mime_line (ps, ps->ca_line, ps->l_line, pf_emit, pv_ctx);
             if (i_ret < 0) return i_ret;
          }
          ps->l_line = 0;
       }
    }
    return 0;
}

/* end of message: the possible last line without newline follows the state */
int mime_stream_flush (struct mime_stream *ps, mime_emit_cb pf_emit, void *pv_ctx)
{
    int i_ret = 0;
    if (ps->l_line > 0)
    {
       if (ps->i_longline || (ps->i_state != MS_DROP))
          i_ret = i_mime_line (ps, ps->ca_line, ps->l_line, pf_emit, pv_ctx);
       ps->l_line = 0;
    }
    ps->i_longline = 0;
    return i_ret;
}
