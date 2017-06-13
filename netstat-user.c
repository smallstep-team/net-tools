/*
 * netstat-user
 *
 * This file contains the command to search a network file for an entry
 * matching a local and remote address.
 */

#include <arpa/inet.h>
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <net/if.h>
#include <netdb.h>
#include <netinet/in.h>
#include <paths.h>
#include <pwd.h>
#include <sys/ioctl.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>

#include "config.h"
#include "intl.h"
#include "lib/net-support.h"
#include "lib/pathnames.h"
#include "lib/util.h"

int flag_all = 0;
int flag_lst = 0;
int flag_not = FLAG_NUM; // Like using `-n` option of netstat
int flag_wide= 0;


//*
static void addr_do_one(char *buf, size_t buf_len, size_t short_len, const struct aftype *ap,
            const struct sockaddr_storage *addr,
            int port, const char *proto
)
{
    const char *sport, *saddr;
    size_t port_len, addr_len;

    saddr = ap->sprint(addr, flag_not & FLAG_NUM_HOST);
    sport = get_sname(htons(port), proto, flag_not & FLAG_NUM_PORT);
    addr_len = strlen(saddr);
    port_len = strlen(sport);
    if (!flag_wide && (addr_len + port_len > short_len)) {
    // Assume port name is short
    port_len = netmin(port_len, short_len - 4);
    addr_len = short_len - port_len;
    strncpy(buf, saddr, addr_len);
    buf[addr_len] = '\0';
    strcat(buf, ":");
    strncat(buf, sport, port_len);
    } else
    snprintf(buf, buf_len, "%s:%s", saddr, sport);
}
//*/

/*
 * Parse the /net/proc/tcp file line and search for the given socket addresses.
 *
 * @param char *output_buffer       - address of string to store result
 * @param const char *sock_addrs    - local and remote socket addresses
 *      to search for. (e.g. "172.31.23.18:9200<->172.31.23.18:49212")
 * @param const char *line          - line to parse and search
 *
 * @return int  - 0 on success, 1 on failure, 2 on error
 */
int tcp_search_line(char *output_buffer, const char *sock_addrs, const char *line)
{
    unsigned long rxq, txq, time_len, retr, inode;
    int num, local_port, rem_port, d, state, uid, timer_run, timeout;
    char rem_addr[128], local_addr[128], timers[64], current_sock_addrs[1000];
    const struct aftype *ap;
    struct passwd *user_info;
    struct sockaddr_storage localsas, remsas;
    struct sockaddr_in *localaddr = (struct sockaddr_in *)&localsas;
    struct sockaddr_in *remaddr = (struct sockaddr_in *)&remsas;
#if HAVE_AFINET6
    char addr6[INET6_ADDRSTRLEN];
    struct in6_addr in6;
    extern struct aftype inet6_aftype;
#endif
    long clk_tck = ticks_per_second();

    num = sscanf(line,
    "%d: %64[0-9A-Fa-f]:%X %64[0-9A-Fa-f]:%X %X %lX:%lX %X:%lX %lX %d %d %lu %*s\n",
		 &d, local_addr, &local_port, rem_addr, &rem_port, &state,
		 &txq, &rxq, &timer_run, &time_len, &retr, &uid, &timeout, &inode);

    if (num < 11) {
	    fprintf(stderr, _("warning, got bogus tcp line.\n"));
	    return 1;
    }

    if (!flag_all && ((flag_lst && rem_port) || (!flag_lst && !rem_port)))
        return 1;

    if (strlen(local_addr) > 8) {
#if HAVE_AFINET6
	/* Demangle what the kernel gives us */
    	sscanf(local_addr, "%08X%08X%08X%08X",
    	       &in6.s6_addr32[0], &in6.s6_addr32[1],
               &in6.s6_addr32[2], &in6.s6_addr32[3]);
    	inet_ntop(AF_INET6, &in6, addr6, sizeof(addr6));
    	inet6_aftype.input(1, addr6, &localsas);
    	sscanf(rem_addr, "%08X%08X%08X%08X",
    	       &in6.s6_addr32[0], &in6.s6_addr32[1],
    	       &in6.s6_addr32[2], &in6.s6_addr32[3]);
    	inet_ntop(AF_INET6, &in6, addr6, sizeof(addr6));
    	inet6_aftype.input(1, addr6, &remsas);
    	localsas.ss_family = AF_INET6;
    	remsas.ss_family = AF_INET6;
#endif
    } else {
    	sscanf(local_addr, "%X", &localaddr->sin_addr.s_addr);
    	sscanf(rem_addr, "%X", &remaddr->sin_addr.s_addr);
    	localsas.ss_family = AF_INET;
    	remsas.ss_family = AF_INET;
    }

    if ((ap = get_afntype(localsas.ss_family)) == NULL) {
	    sprintf(output_buffer, ("netstat: unsupported address family %d !\n"),
	    	localsas.ss_family);
	    return 2;
    }

	addr_do_one(local_addr, sizeof(local_addr), 22, ap, &localsas, local_port, "tcp");
	addr_do_one(rem_addr, sizeof(rem_addr), 22, ap, &remsas, rem_port, "tcp");

    sprintf(current_sock_addrs, "%s<->%s", local_addr, rem_addr);

    //printf("%s\n", current_sock_addrs);
    //printf("%s\n", sock_addrs);
    if (strcmp(current_sock_addrs, sock_addrs) == 0) {
        user_info = getpwuid(uid);
        sprintf(output_buffer, "%s", user_info->pw_name);
        return 0;
    } else
        return 1;
}

/*
 * Parse the /net/proc/tcp file line and search for the given socket addresses.
 *
 * @param FILE *fp                  - file handle to be searched
 * @param char *output_buffer       - address of string to store result
 * @param int buffer_size           - address of string to store result
 * @param const char *sock_addrs    - local and remote socket addresses
 *      to search for. (e.g. "172.31.23.18:9200<->172.31.23.18:49212")
 *
 * @return int  - 0 on success, 1 on failure, 2 on error
 */
int tcp_search_proc(FILE *fp, char *output_buffer, int buffer_size, const char *sock_addrs) {
    int found = 0;
    char * line = NULL;
    size_t len = 0;
    ssize_t read;

    // Nullify the output buffer.
    memset(output_buffer, 0, buffer_size);

    // Reposition file pointer to first byte of the file.
    rewind(fp);

    read = getline(&line, &len, fp); // skip first line of file
    while ((read = getline(&line, &len, fp)) != -1) {
        found = tcp_search_line(output_buffer, sock_addrs, line);
        if (found == 0 || found == 2)
            break;
    }

    free(line);
    return found;
}

/*
int main(int argc, char* argv[]) {
    if ( argc != 2 ) {
        printf( "usage: %s local_host:local_port<->remote_host:remote_port", argv[0] );
        exit(EXIT_FAILURE);
    } else {
        FILE * fp;
        int exit_code = 0, buffer_size = 256;
        char output_buffer[buffer_size];

        fp = fopen("/proc/net/tcp", "r");
        if (fp == NULL) {
            sprintf(output_buffer, "Could not open file: /proc/net/tcp");
            return 2;
        };

        printf("%s\n\n", argv[1]);

        exit_code = tcp_search_proc(fp, output_buffer, buffer_size, argv[1]);
        fclose(fp);

        switch(exit_code) {
            case 0:
                printf("%s\n", output_buffer);
                exit(EXIT_SUCCESS);
                break;
            case 1:
                exit(EXIT_SUCCESS);
                break;
            case 2:
                printf("Error: %s\n", output_buffer);
                exit(EXIT_FAILURE);
                break;
            default:
                printf("Error: Should not be here\n");
                exit(EXIT_FAILURE);
                break;
        }
    }
}
//*/
