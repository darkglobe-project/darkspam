/* Harness del filtro MIME streaming: ogni messaggio viene dato in pasto
   all'automa a chunk di dimensioni diverse (incluso 1 byte per volta) e
   l'output DEVE essere byte-identico a prescindere dal chunking, oltre a
   rispettare le attese di contenuto (testo tenuto, body binari via,
   header sempre presenti). */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <pthread.h>
#include "DarkSpam.h"

int i_loglevel = 5;

static char ca_out[65536];
static long l_out;

static int emit(void *pv, const char *pc, long l)
{
    (void)pv;
    if (l_out + l >= (long)sizeof(ca_out)) { puts("OVERFLOW HARNESS"); exit(2); }
    memcpy(ca_out + l_out, pc, l);
    l_out += l;
    return 0;
}

static long run(const char *pc_msg, const char *pc_bound, long l_chunk, char *pc_dst)
{
    struct mime_stream s;
    long l_len = (long)strlen(pc_msg), i, n;
    mime_stream_init(&s, pc_bound);
    l_out = 0;
    for (i = 0; i < l_len; i += l_chunk) {
        n = (l_len - i < l_chunk) ? (l_len - i) : l_chunk;
        if (mime_stream_feed(&s, pc_msg + i, n, emit, NULL) < 0) { puts("EMIT FAIL"); exit(2); }
    }
    mime_stream_flush(&s, emit, NULL);
    memcpy(pc_dst, ca_out, l_out);
    pc_dst[l_out] = '\0';
    return l_out;
}

static int tests = 0, fails = 0;

static void caso(const char *nome, const char *pc_msg, const char *pc_bound,
                 const char *deve_contenere[], const char *non_deve[])
{
    static char ca_ref[65536], ca_try[65536];
    long l_ref, l_try, chunks[] = {1, 7, 80, 1500, 65536};
    int i, ok = 1;

    l_ref = run(pc_msg, pc_bound, 65536, ca_ref);
    for (i = 0; i < 5; i++) {
        l_try = run(pc_msg, pc_bound, chunks[i], ca_try);
        if (l_try != l_ref || memcmp(ca_try, ca_ref, l_ref)) {
            printf("[%s] DIVERGE con chunk=%ld (len %ld vs %ld)\n", nome, chunks[i], l_try, l_ref);
            ok = 0;
        }
    }
    for (i = 0; deve_contenere[i]; i++)
        if (!strstr(ca_ref, deve_contenere[i])) {
            printf("[%s] MANCA nell'output: '%s'\n", nome, deve_contenere[i]); ok = 0;
        }
    for (i = 0; non_deve[i]; i++)
        if (strstr(ca_ref, non_deve[i])) {
            printf("[%s] PRESENTE ma doveva sparire: '%s'\n", nome, non_deve[i]); ok = 0;
        }
    tests++;
    if (!ok) fails++;
    printf("%-34s %s (out %ld byte)\n", nome, ok ? "ok" : "FALLITO", l_ref);
}

int main(void)
{
    const char *nulla[] = {NULL};

    /* 1: messaggio semplice non multipart: passthrough totale */
    {
        const char *msg = "Ciao,\r\nquesto e' un semplice testo.\r\nSaluti\r\n";
        const char *si[] = {"semplice testo", NULL};
        caso("semplice passthrough", msg, NULL, si, nulla);
    }

    /* 2: multipart/mixed con testo + PDF: il body del PDF sparisce, header restano */
    {
        const char *msg =
        "Preambolo da ignorare o passare.\r\n"
        "--AAA\r\n"
        "Content-Type: text/plain; charset=utf-8\r\n"
        "\r\n"
        "Parte di testo visibile.\r\n"
        "--AAA\r\n"
        "Content-Type: application/pdf; name=\"doc.pdf\"\r\n"
        "Content-Transfer-Encoding: base64\r\n"
        "\r\n"
        "JVBERi0xLjQKJcTE5PDF-BLOB-DA-ELIMINARE\r\n"
        "JVBERi0xLjQKJcTE5ALTRO-BLOB\r\n"
        "--AAA--\r\n"
        "Epilogo.\r\n";
        const char *si[] = {"Parte di testo visibile", "name=\"doc.pdf\"",
                            "Content-Transfer-Encoding: base64", "--AAA--", "Epilogo", NULL};
        const char *no[] = {"BLOB-DA-ELIMINARE", "ALTRO-BLOB", NULL};
        caso("mixed testo+pdf", msg, "AAA", si, no);
    }

    /* 3: annidato: mixed che contiene alternative (plain+html) + immagine */
    {
        const char *msg =
        "--EXT\r\n"
        "Content-Type: multipart/alternative; boundary=\"INT\"\r\n"
        "\r\n"
        "--INT\r\n"
        "Content-Type: text/plain\r\n"
        "\r\n"
        "versione plain\r\n"
        "--INT\r\n"
        "Content-Type: text/html\r\n"
        "\r\n"
        "<b>versione html</b>\r\n"
        "--INT--\r\n"
        "--EXT\r\n"
        "Content-Type: image/jpeg; name=\"foto.jpg\"\r\n"
        "\r\n"
        "FFD8-JPEG-DA-ELIMINARE\r\n"
        "--EXT--\r\n";
        const char *si[] = {"versione plain", "versione html", "name=\"foto.jpg\"", "--INT--", "--EXT--", NULL};
        const char *no[] = {"JPEG-DA-ELIMINARE", NULL};
        caso("annidato alt+jpeg", msg, "EXT", si, no);
    }

    /* 4: boundary annidato su riga di continuazione (folding) */
    {
        const char *msg =
        "--EXT\r\n"
        "Content-Type: multipart/related;\r\n"
        "\tboundary=\"FOLDED\"\r\n"
        "\r\n"
        "--FOLDED\r\n"
        "Content-Type: text/html\r\n"
        "\r\n"
        "html dentro folded\r\n"
        "--FOLDED\r\n"
        "Content-Type: image/png\r\n"
        "\r\n"
        "PNG-VIA\r\n"
        "--FOLDED--\r\n"
        "--EXT--\r\n";
        const char *si[] = {"html dentro folded", "Content-Type: image/png", NULL};
        const char *no[] = {"PNG-VIA", NULL};
        caso("boundary in folding", msg, "EXT", si, no);
    }

    /* 5: MIME sporco: parte senza Content-Type -> KEEP pragmatico */
    {
        const char *msg =
        "--B\r\n"
        "X-Strano: header fuso senza content type\r\n"
        "\r\n"
        "testo senza dichiarazione che deve passare\r\n"
        "--B\r\n"
        "Content-Type: audio/mpeg\r\n"
        "\r\n"
        "MP3-VIA\r\n"
        "--B--\r\n";
        const char *si[] = {"testo senza dichiarazione che deve passare", "X-Strano", NULL};
        const char *no[] = {"MP3-VIA", NULL};
        caso("senza CT -> keep", msg, "B", si, no);
    }

    /* 6: chiusura esterna senza chiusura interna (sbrindellato): pop d'ufficio */
    {
        const char *msg =
        "--EXT\r\n"
        "Content-Type: multipart/mixed; boundary=INT\r\n"
        "\r\n"
        "--INT\r\n"
        "Content-Type: application/zip\r\n"
        "\r\n"
        "ZIP-VIA\r\n"
        "--EXT--\r\n"
        "coda dopo chiusura esterna\r\n";
        const char *si[] = {"coda dopo chiusura esterna", "--EXT--", NULL};
        const char *no[] = {"ZIP-VIA", NULL};
        caso("chiusura esterna diretta", msg, "EXT", si, no);
    }

    /* 7: finale --bound-- mancante (spam tipico): il flush non perde il testo */
    {
        const char *msg =
        "--B\r\n"
        "Content-Type: text/plain\r\n"
        "\r\n"
        "ultima riga senza newline finale";
        const char *si[] = {"ultima riga senza newline finale", NULL};
        caso("senza terminatore", msg, "B", si, nulla);
    }

    /* 8: riga mostruosa oltre il buffer in una parte testo: passa raw */
    {
        static char msg[8192];
        char lunga[4001];
        memset(lunga, 'x', 4000); lunga[4000] = '\0';
        snprintf(msg, sizeof(msg),
        "--B\r\nContent-Type: text/plain\r\n\r\nprima\r\n%s\r\ndopo\r\n--B--\r\n", lunga);
        const char *si[] = {"prima", "xxxxxxxxxx", "dopo", NULL};
        caso("riga oltre buffer", msg, "B", si, nulla);
    }

    /* 9: riga mostruosa in una parte DROP: NON deve passare */
    {
        static char msg[8192];
        char lunga[4001];
        memset(lunga, 'y', 4000); lunga[4000] = '\0';
        snprintf(msg, sizeof(msg),
        "--B\r\nContent-Type: application/octet-stream\r\n\r\n%s\r\nZZZ-VIA\r\n--B--\r\nfine\r\n", lunga);
        const char *si[] = {"fine", NULL};
        const char *no[] = {"yyyyyyyyyy", "ZZZ-VIA", NULL};
        caso("riga oltre buffer in drop", msg, "B", si, no);
    }

    /* 10: logica per esclusione: tipo esotico DICHIARATO -> DROP */
    {
        const char *msg =
        "--B\r\n"
        "Content-Type: font/woff2\r\n"
        "\r\n"
        "WOFF-VIA\r\n"
        "--B\r\n"
        "Content-Type: model/gltf-binary; name=\"x.glb\"\r\n"
        "\r\n"
        "GLTF-VIA\r\n"
        "--B\r\n"
        "Content-Type: text/plain\r\n"
        "\r\n"
        "testo superstite\r\n"
        "--B--\r\n";
        const char *si[] = {"testo superstite", "Content-Type: font/woff2", "name=\"x.glb\"", NULL};
        const char *no[] = {"WOFF-VIA", "GLTF-VIA", NULL};
        caso("esotico dichiarato -> drop", msg, "B", si, no);
    }

    /* 11: controprova: CT ASSENTE resta KEEP pragmatico anche con l'esclusione */
    {
        const char *msg =
        "--B\r\n"
        "X-Boh: niente content type qui\r\n"
        "\r\n"
        "testo senza dichiarazione, deve passare ancora\r\n"
        "--B--\r\n";
        const char *si[] = {"testo senza dichiarazione, deve passare ancora", NULL};
        caso("CT assente resta keep", msg, "B", si, nulla);
    }

    printf("\nTotale: %d casi, %d falliti\n", tests, fails);
    return fails != 0;
}
