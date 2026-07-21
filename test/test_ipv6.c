/* Harness di test per normalizza() e find_previous_ipclass() (versione IPv6)
   Oracolo: inet_pton + inet_ntop = forma canonica RFC 5952 */
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <arpa/inet.h>

void normalizza (char *);
void find_previous_ipclass (char *pc_ipmain, char *pc_ipsub, long l_size);

static int tests = 0, fails = 0;

static void t_norm(const char *input)
{
    char mine[2000], oracle[INET6_ADDRSTRLEN];
    unsigned char buf[16];
    strcpy(mine, input);
    normalizza(mine);

    int valid = inet_pton(AF_INET6, input, buf) == 1;
    tests++;
    if (valid) {
        inet_ntop(AF_INET6, buf, oracle, sizeof(oracle));
        /* confronto case-insensitive: il case lo trattiamo come rilievo separato */
        if (strcasecmp(mine, oracle) != 0) {
            fails++;
            printf("DIVERGE  in='%s'\n         mia='%s'  attesa='%s'\n", input, mine, oracle);
        } else {
            printf("ok       in='%-28s' out='%s'\n", input, mine);
        }
    } else {
        /* input invalido: la funzione segnala con stringa vuota */
        if (mine[0] != '\0') {
            fails++;
            printf("NOVALID  in='%s' e' invalido ma la funzione ritorna '%s'\n", input, mine);
        } else {
            printf("ok-inv   in='%-28s' correttamente scartato\n", input);
        }
    }
}

static void t_ladder(const char *canonical)
{
    char ca_localip[2000], ca_tempip[2000];
    strcpy(ca_tempip, canonical);
    printf("scala per %s:\n", canonical);
    while (ca_tempip[0] != '\0') {
        strncpy(ca_localip, ca_tempip, 2000);
        printf("   ipv6:%s\n", ca_tempip);
        find_previous_ipclass(ca_localip, ca_tempip, 2000);
    }
}

int main(void)
{
    puts("=== NORMALIZZA: input validi sporchi ===");
    t_norm("111b:a341:1::1:2:3");          /* il tuo caso di test attivo */
    t_norm("2001:0DB8:0:0:0:0:1234:5678"); /* zeri iniziali + maiuscole */
    t_norm("2001:DB8::1");                  /* gia' compresso, maiuscolo */
    t_norm("2001:db8::1");                  /* gia' canonico: idempotenza */
    t_norm("0:0:0:0:0:0:0:1");              /* loopback esteso */
    t_norm("::1");                           /* loopback compresso */
    t_norm("0:0:0:0:0:0:0:0");              /* tutto zero */
    t_norm("::");                            /* tutto zero compresso */
    t_norm("1::");                           /* run di zeri in coda */
    t_norm("1:0:0:0:0:0:0:0");              /* run in coda estesa */
    t_norm("0:0:0:0:0:0:0:8");              /* run in testa estesa */
    t_norm("1:2:3:4:5:6:0:0");              /* run corta in coda */
    t_norm("0:0:1:2:3:4:5:6");              /* run corta in testa */
    t_norm("1:0:0:1:0:0:1:1");              /* pareggio di run: vince la sinistra */
    t_norm("1:0:0:0:1:0:0:1");              /* run lunga al centro... */
    t_norm("1:2:3:0:5:6:7:8");              /* UN solo gruppo zero: RFC vieta :: */
    t_norm("1:0:1:0:1:0:1:0");              /* zeri alternati singoli */
    t_norm("2450:0897::0:67:00");           /* dai tuoi commenti */
    t_norm("0::897:0:67:00");
    t_norm("000:10::67:00");
    t_norm("0:1:0:1:0:1:0:1");
    t_norm("::00");
    t_norm("000:00b8:0:00:67:0:0:0");
    t_norm("0:1:0:0:0:1:0:0");
    t_norm("::a341:1:0:1:6767:0:12");
    t_norm("fe80::215:5dff:fe00:101");      /* link-local reale */

    puts("\n=== NORMALIZZA: input invalidi ===");
    t_norm(":1:00");
    t_norm("1:2:3");                         /* troppo corto senza :: */
    t_norm("1::2::3");                       /* doppio :: */
    t_norm(":::");
    t_norm("1:2:3:4:5:6:7:8:9");             /* 9 gruppi */
    t_norm("12345::1");                      /* gruppo da 5 cifre */
    t_norm("gggg::1");                       /* esadecimale invalido */
    t_norm("2001:db8::1::");
    t_norm("1::2:3:4:5:6:7:8");            /* :: con 8 gruppi espliciti */
    t_norm("1:2:3:4:5:6:7");                /* 7 gruppi senza :: */
    t_norm("abcd:ef01:2345:6789:abcd:ef01:2345:6789"); /* pieno, tutte cifre */

    puts("\n=== SCALA DI RICERCA ===");
    t_ladder("2001:db8::1");
    t_ladder("2001:db8::1:2");
    t_ladder("111b:a341:1::1:2:3");
    t_ladder("1:2:3:4:5:6:7:8");
    t_ladder("::1");

    printf("\nTotale: %d test, %d divergenze\n", tests, fails);
    return fails != 0;
}
