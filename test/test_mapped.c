/* Verifica dell'estrazione IPv4 da sockaddr_in6 mapped, stessa logica di dg_connect */
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/in.h>

static void prova(const char *ip6txt, const char *atteso_ip, char atteso_tipo)
{
    struct sockaddr_in6 sin6;
    char ca_ip[128];
    char c_type='i';
    memset(&sin6, 0, sizeof(sin6));
    sin6.sin6_family = AF_INET6;
    inet_pton(AF_INET6, ip6txt, &sin6.sin6_addr);

    if (IN6_IS_ADDR_V4MAPPED(&sin6.sin6_addr))
    {
        struct in_addr s_v4;
        memcpy(&s_v4, &sin6.sin6_addr.s6_addr[12], 4);
        inet_ntop(AF_INET, &s_v4, ca_ip, sizeof(ca_ip));
    }
    else
    {
        c_type='6';
        inet_ntop(AF_INET6, &sin6.sin6_addr, ca_ip, sizeof(ca_ip));
    }
    printf("%-24s -> ca_ip=%-16s c_type=%c  %s\n", ip6txt, ca_ip, c_type,
           (strcmp(ca_ip, atteso_ip)==0 && c_type==atteso_tipo) ? "ok" : "<<< ERRORE");
}

int main(void)
{
    prova("::ffff:192.168.77.10", "192.168.77.10", 'i');  /* mapped privato */
    prova("::ffff:127.0.0.1",     "127.0.0.1",     'i');  /* mapped loopback: whitelist */
    prova("::ffff:8.8.8.8",       "8.8.8.8",       'i');  /* mapped pubblico */
    prova("2001:db8::1",          "2001:db8::1",   '6');  /* v6 vero: intoccato */
    prova("::1",                  "::1",           '6');  /* loopback v6: resta v6 */
    prova("64:ff9b::808:808",     "64:ff9b::808:808", '6'); /* NAT64: NON mapped, resta v6 */
    return 0;
}
