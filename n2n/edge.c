/*
 * (C) 2007-09 - Luca Deri <deri@ntop.org>
 *               Richard Andrews <andrews@ntop.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not see see <http://www.gnu.org/licenses/>
 *
 * Code contributions courtesy of:
 * Don Bindner <don.bindner@gmail.com>
 * Sylwester Sosnowski <syso-n2n@no-route.org>
 * Wilfried "Wonka" Klaebe
 *
 */

#include "minilzo.h"
#include "n2n.h"
#include <assert.h>
#include <sys/stat.h>
//#ifndef Windows
////#include <semaphore.h>
//#else
//#include <Windows.h>
//#endif // Windows
#include "sendqueue.h"
#include "list.h"
/** Time between logging system STATUS messages */
#define STATUS_UPDATE_INTERVAL (30 * 60) /*secs*/

/* maximum length of command line arguments */
#define MAX_CMDLINE_BUFFER_LENGTH    4096
/* maximum length of a line in the configuration file */
#define MAX_CONFFILE_LINE_LENGTH     1024

struct n2n_edge
{
  u_char              re_resolve_supernode_ip;
  struct peer_addr    supernode;
  char                supernode_ip[48];
  char *              community_name /*= NULL*/;
  
  /*     int                 sock; */
  /*     char                is_udp_socket /\*= 1*\/; */
  n2n_sock_info_t     sinfo;

  u_int               pkt_sent /*= 0*/;
  tuntap_dev          device;
  int                 allow_routing /*= 0*/;
  int                 drop_ipv6_ndp /*= 0*/;
  char *              encrypt_key /* = NULL*/;
  TWOFISH *           enc_tf[16];
  TWOFISH *           dec_tf[16];

  list_t  known_peers /* = NULL*/;
  list_t  pending_peers /* = NULL*/;
  time_t              last_register /* = 0*/;
  multiThreadQueue_t mt_queue; /*线程安全的queue*/
};

static void supernode2addr(n2n_edge_t * eee, char* addr);

static void send_packet2net(n2n_edge_t * eee,
			    char *decrypted_msg, size_t len);


/* ************************************** */

/* parse the configuration file */
static int readConfFile(const char* filename, char* const linebuffer) {
    struct stat stats;
    FILE* fd;
    char* buffer = NULL;

    buffer = (char*)malloc(MAX_CONFFILE_LINE_LENGTH);
    if (!buffer) {
        traceEvent(TRACE_ERROR, "Unable to allocate memory");
        return -1;
    }

    if (stat(filename, &stats)) {
        if (errno == ENOENT)
            traceEvent(TRACE_ERROR, "parameter file %s not found/unable to access\n", filename);
        else
            traceEvent(TRACE_ERROR, "cannot stat file %s, errno=%d\n", filename, errno);
        free(buffer);
        return -1;
    }

    fd = fopen(filename, "rb");
    if (!fd) {
        traceEvent(TRACE_ERROR, "Unable to open parameter file '%s' (%d)...\n", filename, errno);
        free(buffer);
        return -1;
    }
    while (fgets(buffer, MAX_CONFFILE_LINE_LENGTH, fd)) {
        char* p = NULL;

        /* strip out comments */
        p = strchr(buffer, '#');
        if (p) *p = '\0';

        /* remove \n */
        p = strchr(buffer, '\n');
        if (p) *p = '\0';

        /* strip out heading spaces */
        p = buffer;
        while (*p == ' ' && *p != '\0') ++p;
        if (p != buffer) strncpy(buffer, p, strlen(p) + 1);

        /* strip out trailing spaces */
        while (strlen(buffer) && buffer[strlen(buffer) - 1] == ' ')
            buffer[strlen(buffer) - 1] = '\0';

        /* check for nested @file option */
        if (strchr(buffer, '@')) {
            traceEvent(TRACE_ERROR, "@file in file nesting is not supported\n");
            free(buffer);
            return -1;
        }
        if ((strlen(linebuffer) + strlen(buffer) + 2) < MAX_CMDLINE_BUFFER_LENGTH) {
            strncat(linebuffer, " ", 1);
            strncat(linebuffer, buffer, strlen(buffer));
        }
        else {
            traceEvent(TRACE_ERROR, "too many argument");
            free(buffer);
            return -1;
        }
    }

    free(buffer);
    fclose(fd);

    return 0;
}

/* Create the argv vector */
static char** buildargv(char* const linebuffer) {
    const int  INITIAL_MAXARGC = 16;	/* Number of args + NULL in initial argv */
    int     maxargc;
    int     argc = 0;
    char** argv;
    char* buffer, * buff;

    buffer = (char*)calloc(1, strlen(linebuffer) + 2);
    if (!buffer) {
        traceEvent(TRACE_ERROR, "Unable to allocate memory");
        return NULL;
    }
    strncpy(buffer, linebuffer, strlen(linebuffer));

    maxargc = INITIAL_MAXARGC;
    argv = (char**)malloc(maxargc * sizeof(char*));
    if (argv == NULL) {
        traceEvent(TRACE_ERROR, "Unable to allocate memory");
        return NULL;
    }
    buff = buffer;
    while (buff) {
        char* p = strchr(buff, ' ');
        if (p) {
            *p = '\0';
            argv[argc++] = strdup(buff);
            while (*++p == ' ' && *p != '\0');
            buff = p;
            if (argc >= maxargc) {
                maxargc *= 2;
                argv = (char**)realloc(argv, maxargc * sizeof(char*));
                if (argv == NULL) {
                    traceEvent(TRACE_ERROR, "Unable to re-allocate memory");
                    free(buffer);
                    return NULL;
                }
            }
        }
        else {
            argv[argc++] = strdup(buff);
            break;
        }
    }
    argv[argc] = NULL;
    free(buffer);
    return argv;
}

static int peer_compare(char* peer1, char* peer2) {
     return memcmp(peer1 + COMMUNITY_LEN, peer2 + COMMUNITY_LEN, 6);
}


/* ************************************** */

static int edge_init(n2n_edge_t* eee) {
#ifdef WIN32
    initWin32();
#endif
    memset(eee, 0, sizeof(n2n_edge_t));

    eee->re_resolve_supernode_ip = 0;
    eee->community_name = NULL;
    eee->sinfo.sock = -1;
    eee->sinfo.is_udp_socket = 1;
    eee->pkt_sent = 0;
    eee->allow_routing = 0;
    eee->drop_ipv6_ndp = 0;
    eee->encrypt_key = NULL;
    for (int i = 0; i < 16; i++) {
        eee->enc_tf[i] = NULL;
        eee->dec_tf[i] = NULL;
    }
    eee->known_peers = list_create(peer_compare);
    eee->pending_peers = list_create(peer_compare);
    eee->last_register = 0;
    if (lzo_init() != LZO_E_OK) {
        traceEvent(TRACE_ERROR, "LZO compression error");
        return(-1);
    }

    return(0);
}

static int edge_init_twofish(n2n_edge_t* eee, u_int8_t* encrypt_pwd, u_int32_t encrypt_pwd_len)
{
    for (int i = 0; i < 16; i++) {
        eee->enc_tf[i] = TwoFishInit(encrypt_pwd, encrypt_pwd_len);
        eee->dec_tf[i] = TwoFishInit(encrypt_pwd, encrypt_pwd_len);
    }
    if ((eee->enc_tf) && (eee->dec_tf))
    {
        return 0;
    }
    else
    {
        return 1;
    }
}

/* ************************************** */

static void edge_deinit(n2n_edge_t* eee) {
    for (int i = 0; i < 16; i++) {
        TwoFishDestroy(eee->enc_tf[i]);
        TwoFishDestroy(eee->dec_tf[i]);
    }
    if (eee->sinfo.sock >= 0)
    {
        close(eee->sinfo.sock);
    }
}

static void readFromIPSocket( n2n_edge_t * eee );

static void help() {
    print_n2n_version();

    printf("edge "
#ifdef __linux__
        "-d <tun device> "
#endif
        "-a <tun IP address> "
        "-c <community> "
        "-k <encrypt key> "
        "-s <netmask> "
#ifndef WIN32
        "[-u <uid> -g <gid>]"
        "[-f]"
#endif
        "[-m <MAC address>]"
        "\n"
        "-l <supernode host:port> "
        "[-p <local port>] [-M <mtu>] "
        "[-t] [-r] [-v] [-b] [-h]\n\n");

#ifdef __linux__
    printf("-d <tun device>          | tun device name\n");
#endif

    printf("-a <tun IP address>      | n2n IP address\n");
    printf("-c <community>           | n2n community name\n");
    printf("-k <encrypt key>         | Encryption key (ASCII) - also N2N_KEY=<encrypt key>\n");
    printf("-s <netmask>             | Edge interface netmask in dotted decimal notation (255.255.255.0)\n");
    printf("-l <supernode host:port> | Supernode IP:port\n");
    printf("-b                       | Periodically resolve supernode IP\n");
    printf("                         | (when supernodes are running on dynamic IPs)\n");
    printf("-p <local port>          | Local port used for connecting to supernode\n");
#ifndef WIN32
    printf("-u <UID>                 | User ID (numeric) to use when privileges are dropped\n");
    printf("-g <GID>                 | Group ID (numeric) to use when privileges are dropped\n");
    printf("-f                       | Fork and run as a daemon. Use syslog.\n");
#endif
    printf("-m <MAC address>         | Choose a MAC address for the TAP interface\n"
        "                         | eg. -m 01:02:03:04:05:06\n");
    printf("-M <mtu>                 | Specify n2n MTU (default %d)\n", DEFAULT_MTU);
    printf("-t                       | Use http tunneling (experimental)\n");
    printf("-r                       | Enable packet forwarding through n2n community\n");
    printf("-x                       | Threads default at 2\n");
    printf("-v                       | Verbose\n");

    printf("\nEnvironment variables:\n");
    printf("  N2N_KEY                | Encryption key (ASCII)\n");
    t();
    list_test();
    exit(0);
}

/* *********************************************** */

static void send_register(n2n_edge_t* eee,
    const struct peer_addr* remote_peer,
    u_char is_ack) {
    struct n2n_packet_header hdr;
    char pkt[N2N_PKT_HDR_SIZE];
    size_t len = sizeof(hdr);
    ipstr_t ip_buf;

    fill_standard_header_fields(&(eee->sinfo), &hdr, (char*)(eee->device.mac_addr));
    hdr.sent_by_supernode = 0;
    hdr.msg_type = (is_ack == 0) ? MSG_TYPE_REGISTER : MSG_TYPE_REGISTER_ACK;
    memcpy(hdr.community_name, eee->community_name, COMMUNITY_LEN);

    marshall_n2n_packet_header((u_int8_t*)pkt, &hdr);
    send_packet(&(eee->sinfo), pkt, &len, remote_peer, N2N_COMPRESSION_ENABLED);

    traceEvent(TRACE_INFO, "Sent %s message to %s:%hu",
        ((hdr.msg_type == MSG_TYPE_REGISTER) ? "MSG_TYPE_REGISTER" : "MSG_TYPE_REGISTER_ACK"),
        intoa(ntohl(remote_peer->addr_type.v4_addr), ip_buf, sizeof(ip_buf)),
        ntohs(remote_peer->port));
}

/* *********************************************** */

static void send_deregister(n2n_edge_t* eee,
    struct peer_addr* remote_peer) {
    struct n2n_packet_header hdr;
    char pkt[N2N_PKT_HDR_SIZE];
    size_t len = sizeof(hdr);

    fill_standard_header_fields(&(eee->sinfo), &hdr, (char*)(eee->device.mac_addr));
    hdr.sent_by_supernode = 0;
    hdr.msg_type = MSG_TYPE_DEREGISTER;
    memcpy(hdr.community_name, eee->community_name, COMMUNITY_LEN);

    marshall_n2n_packet_header((u_int8_t*)pkt, &hdr);
    send_packet(&(eee->sinfo), pkt, &len, remote_peer, N2N_COMPRESSION_ENABLED);
}

/* *********************************************** */

static void update_peer_address(n2n_edge_t * eee,
                                const struct n2n_packet_header * hdr,
                                time_t when);
void trace_registrations(list_t list );
int is_ip6_discovery( const void * buf, size_t bufsize );
void check_peer( n2n_edge_t * eee,
                 const struct n2n_packet_header * hdr );
void try_send_register( n2n_edge_t * eee,
                        const struct n2n_packet_header * hdr );
void sending_additional_regist(n2n_edge_t* eee,struct peer_info* scan);
void set_peer_operational( n2n_edge_t * eee, const struct n2n_packet_header * hdr );

static void send_package2netQ(sending_pkg pkg);
static void send_package2tapQ(recving_pkg pkg);

/** Start the registration process.
 *
 *  If the peer is already in pending_peers, ignore the request.
 *  If not in pending_peers, add it and send a REGISTER.
 *
 *  If hdr is for a direct peer-to-peer packet, try to register back to sender
 *  even if the MAC is in pending_peers. This is because an incident direct
 *  packet indicates that peer-to-peer exchange should work so more aggressive
 *  registration can be permitted (once per incoming packet) as this should only
 *  last for a small number of packets..
 *
 *  Called from the main loop when Rx a packet for our device mac.
 */
void try_send_register(n2n_edge_t* eee,
    const struct n2n_packet_header* hdr)
{
    ipstr_t ip_buf;
    
    /* REVISIT: purge of pending_peers not yet done. */
    struct peer_info* scan = find_peer_by_mac(eee->pending_peers, hdr->src_mac);
    multiThreadQueue_t queue = eee->mt_queue;
    if (NULL == scan)
    {
        traceEvent(TRACE_NORMAL, "try_send_register.lock.1.0：");
        if (lockOne(&queue->lock4UpdatePeer) == 0) {
            traceEvent(TRACE_NORMAL, "try_send_register.lock.1.1：");
            scan = find_peer_by_mac(eee->pending_peers, hdr->src_mac);
            if (NULL == scan) {
                scan = calloc(1, sizeof(struct peer_info));

                memcpy(scan->mac_addr, hdr->src_mac, 6);
                scan->public_ip = hdr->public_ip;
                scan->last_seen = time(NULL); /* Don't change this it marks the pending peer for removal. */
                scan->regcount = 1;
                peer_list_add(eee->pending_peers, scan);
                macstr_t mac_buf;
                ipstr_t ip_buf2;
                traceEvent(TRACE_NORMAL, "=== new peer pending [mac=%s][private=%s][socket=%s:%hu]",
                    macaddr_str(scan->mac_addr, mac_buf, sizeof(mac_buf)),
                    intoa(ntohl(scan->private_ip.addr_type.v4_addr), ip_buf2, sizeof(ip_buf2)),
                    intoa(ntohl(scan->public_ip.addr_type.v4_addr), ip_buf, sizeof(ip_buf)),
                    ntohs(scan->public_ip.port));

                traceEvent(TRACE_NORMAL, "Pending peers list size=%ld",
                    peer_list_size(eee->pending_peers));

                traceEvent(TRACE_NORMAL, "Sending REGISTER request to %s:%hu",
                    intoa(ntohl(scan->public_ip.addr_type.v4_addr), ip_buf, sizeof(ip_buf)),
                    ntohs(scan->public_ip.port));

                send_register(eee,
                    &(scan->public_ip),
                    0 /* is not ACK */);

                /* pending_peers now owns scan. */
            }
            int  dd = releaseOne(&queue->lock4UpdatePeer);
            traceEvent(TRACE_NORMAL, "try_send_register.lock.1.4,rt=%d", dd);
        }
        else {
            traceEvent(TRACE_NORMAL, "try_send_register.lock.2.1");
        }
    }
    else
    {
        /* scan already in pending_peers. */

        if (0 == hdr->sent_by_supernode)
        {
            traceEvent(TRACE_NORMAL, "try_send_register.lock.2.0：");
           if (lockOne(&queue->lock4UpdatePeer) == 0) {
                traceEvent(TRACE_NORMAL, "try_send_register.lock.2.1：");
                if (0 == hdr->sent_by_supernode)
                {
                    /* over-write supernode-based socket with direct socket. */
                    //TO CONFIRM
                    //scan->public_ip = hdr->public_ip;

                    traceEvent(TRACE_NORMAL, "Sending additional REGISTER request to %s:%hu",
                        intoa(ntohl(scan->public_ip.addr_type.v4_addr), ip_buf, sizeof(ip_buf)),
                        ntohs(scan->public_ip.port));


                    send_register(eee,
                        &(scan->public_ip),
                        0 /* is not ACK */);
                }
                releaseOne(&queue->lock4UpdatePeer);
            }
            else {
                traceEvent(TRACE_NORMAL, "try_send_register.lock.2.2：");
            }
        }
        else if (scan->regcount > 0 && scan->regcount < 3 && (time(NULL) - scan->last_seen) > scan->regcount) {
            sending_additional_regist(eee,scan);
        }
    }
}


void sending_additional_regist(n2n_edge_t* eee, struct peer_info* scan)
{
    ipstr_t ip_buf;
    if (scan != NULL)
    {
        multiThreadQueue_t queue = eee->mt_queue;
        if (lockOne(&queue->lock4UpdatePeer) == 0) {
            if (scan->regcount > 0 && scan->regcount < 3 && (time(NULL) - scan->last_seen) > scan->regcount) {
                scan->regcount = scan->regcount + 1;

                traceEvent(TRACE_NORMAL, "Sending 2 REGISTER request to %s:%hu",
                    intoa(ntohl(scan->public_ip.addr_type.v4_addr), ip_buf, sizeof(ip_buf)),
                    ntohs(scan->public_ip.port));

                send_register(eee,
                    &(scan->public_ip),
                    0 /* is not ACK */);
            }
            releaseOne(&queue->lock4UpdatePeer);
        }
    }
}

/** Update the last_seen time for this peer, or get registered. */
/** 检查节点是否存在，如果存在，则更新通信时间，否则发送相互注册信号包 */
void check_peer(n2n_edge_t* eee,
    const struct n2n_packet_header* hdr)
{
    struct peer_info* scan = find_peer_by_mac(eee->known_peers, hdr->src_mac);

    if (NULL == scan)
    {
        /* Not in known_peers - start the REGISTER process. */
        try_send_register(eee, hdr);
    }
    else
    {
        /* Already in known_peers. */
        update_peer_address(eee, hdr, time(NULL));
    }
}


/* Move the peer from the pending_peers list to the known_peers lists.
 *
 * peer must be a pointer to an element of the pending_peers list.
 *
 * Called by main loop when Rx a REGISTER_ACK.
 */
void set_peer_operational(n2n_edge_t* eee, const struct n2n_packet_header* hdr)
{
    struct peer_info* scan;
    macstr_t mac_buf;
    ipstr_t ip_buf;
    traceEvent(TRACE_INFO, "=== set peer optional [mac=%s][socket=%s:%hu]",
        macaddr_str(hdr->src_mac, mac_buf, sizeof(mac_buf)),
        intoa(ntohl(hdr->public_ip.addr_type.v4_addr), ip_buf, sizeof(ip_buf)),
        ntohs(hdr->public_ip.port));

    int idx = list_indexOf(eee->pending_peers, (hdr->src_mac) - COMMUNITY_LEN);

   // printf("set_peer_operational %X%X%X%X%X%X to %X%X%X%X%X%X \r\n", hdr->dst_mac[0], hdr->dst_mac[1], hdr->dst_mac[2], hdr->dst_mac[3], hdr->dst_mac[4], hdr->dst_mac[5], peer2[0], peer2[1], peer2[2], peer2[3], peer2[4], peer2[5]);



    if (idx >= 0)
    {
        scan = list_get(eee->pending_peers, idx); //eee->pending_peers;

        /* Remove scan from pending_peers. */
     //   if ( prev )
     //     {
        //prev->next = scan->next;
     //     }
     //   else
     //     {
        //eee->pending_peers = scan->next;
     //     }

     //   /* Add scan to known_peers. */
     //   scan->next = eee->known_peers;
     //   eee->known_peers = scan;


        scan->public_ip = hdr->public_ip;
        list_add(eee->known_peers, scan);
        list_removeAt(eee->pending_peers, idx);
        ipstr_t ip_buf2;
        traceEvent(TRACE_NORMAL, "=== new peer opt [mac=%s][private=%s][socket=%s:%hu]",
            macaddr_str(scan->mac_addr, mac_buf, sizeof(mac_buf)),
            intoa(ntohl(scan->private_ip.addr_type.v4_addr), ip_buf2, sizeof(ip_buf2)),
            intoa(ntohl(scan->public_ip.addr_type.v4_addr), ip_buf, sizeof(ip_buf)),
            ntohs(scan->public_ip.port));

        traceEvent(TRACE_NORMAL, "Pending peers list size=%ld",
            peer_list_size(eee->pending_peers));

        traceEvent(TRACE_NORMAL, "Operational peers list size=%ld",
            peer_list_size(eee->known_peers));


        scan->last_seen = time(NULL);
    }
    else
    {
        traceEvent(TRACE_WARNING, "Failed to find sender in pending_peers.");
    }
}


void trace_registrations(list_t list)
{
    macstr_t mac_buf;
    ipstr_t ip_buf;
    struct peer_info* scan;
    for (int i = 0; i < list->count; i++)
    {
        scan = list_get(list, i);
        traceEvent(TRACE_INFO, "=== peer [mac=%s][socket=%s:%hu]",
            macaddr_str(scan->mac_addr, mac_buf, sizeof(mac_buf)),
            intoa(ntohl(scan->public_ip.addr_type.v4_addr), ip_buf, sizeof(ip_buf)),
            ntohs(scan->public_ip.port));

        //scan = scan->next;
    }
}

u_int8_t broadcast_mac[6] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };


/** Keep the known_peers list straight.
 *
 *  Ignore broadcast L2 packets, and packets with invalid public_ip.
 *  If the dst_mac is in known_peers make sure the entry is correct:
 *  - if the public_ip socket has changed, erase the entry
 *  - if the same, update its last_seen = when
 */
static void update_peer_address(n2n_edge_t* eee,
    const struct n2n_packet_header* hdr,
    time_t when)
{
    ipstr_t ip_buf;


    if (0 == hdr->public_ip.addr_type.v4_addr)
    {
        /* Not to be registered. */
        return;
    }

    if (0 == memcmp(hdr->dst_mac, broadcast_mac, 6))
    {
        /* Not to be registered. */
        return;
    }
    int idx = list_indexOf(eee->known_peers, hdr->src_mac - COMMUNITY_LEN);
    struct peer_info* scan = list_get(eee->known_peers, idx);// eee->known_peers;;

    if (NULL == scan)
    {
        /* Not in known_peers. */
        traceEvent(TRACE_INFO, "Peer changed public socket not found, Was %s:%hu  for MAC %02X:%02X:%02X:%02X:%02X:%02X",
            intoa(ntohl(hdr->public_ip.addr_type.v4_addr), ip_buf, sizeof(ip_buf)),
            ntohs(hdr->public_ip.port), hdr->dst_mac[0] & 0xFF, hdr->dst_mac[1] & 0xFF, hdr->dst_mac[2] & 0xFF,
            hdr->dst_mac[3] & 0xFF, hdr->dst_mac[4] & 0xFF, hdr->dst_mac[5] & 0xFF);
        return;
    }

    if (0 != memcmp(&(scan->public_ip), &(hdr->public_ip), sizeof(struct peer_addr)))
    {
        if (0 == hdr->sent_by_supernode)
        {
            traceEvent(TRACE_NORMAL, "update_peer_address.lock.1.1：");
            if (lockOne(&eee->mt_queue->lock4UpdatePeer) == 0) {
                ipstr_t ip_buf2;
                traceEvent(TRACE_NORMAL, "Peer changed public socket, Was %s -> %s:%hu for MAC %02X:%02X:%02X:%02X:%02X:%02X",
                    intoa(ntohl(hdr->private_ip.addr_type.v4_addr), ip_buf2, sizeof(ip_buf)),
                    intoa(ntohl(hdr->public_ip.addr_type.v4_addr), ip_buf, sizeof(ip_buf)),
                    ntohs(hdr->public_ip.port), hdr->dst_mac[0] & 0xFF, hdr->dst_mac[1] & 0xFF, hdr->dst_mac[2] & 0xFF,
                    hdr->dst_mac[3] & 0xFF, hdr->dst_mac[4] & 0xFF, hdr->dst_mac[5] & 0xFF);

                idx = list_indexOf(eee->known_peers, hdr->src_mac - COMMUNITY_LEN);
                if (idx >= 0) {
                    list_removeAt(eee->known_peers, idx);
                }
                releaseOne(&eee->mt_queue->lock4UpdatePeer);
                traceEvent(TRACE_NORMAL, "update_peer_address.unlock.1.2：");
            }
            free(scan);
            try_send_register(eee, hdr);
        }
        else
        {
            /* Don't worry about what the supernode reports, it could be seeing a different socket. */
        }
    }
    else
    {
        /* Found and unchanged. */
        scan->last_seen = when;
    }
}



#if defined(DUMMY_ID_00001) /* Disabled waiting for config option to enable it */

/* *********************************************** */

static char gratuitous_arp[] = {
  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, /* Dest mac */
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* Src mac */
  0x08, 0x06, /* ARP */
  0x00, 0x01, /* Ethernet */
  0x08, 0x00, /* IP */
  0x06, /* Hw Size */
  0x04, /* Protocol Size */
  0x00, 0x01, /* ARP Request */
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* Src mac */
  0x00, 0x00, 0x00, 0x00, /* Src IP */
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* Target mac */
  0x00, 0x00, 0x00, 0x00 /* Target IP */
};

static int build_gratuitous_arp(char *buffer, u_short buffer_len) {
  if(buffer_len < sizeof(gratuitous_arp)) return(-1);

  memcpy(buffer, gratuitous_arp, sizeof(gratuitous_arp));
  memcpy(&buffer[6], device.mac_addr, 6);
  memcpy(&buffer[22], device.mac_addr, 6);
  memcpy(&buffer[28], &device.ip_addr, 4);

  /* REVISIT: BbMaj7 - use a real netmask here. This is valid only by accident
   * for /24 IPv4 networks. */
  buffer[31] = 0xFF; /* Use a faked broadcast address */
  memcpy(&buffer[38], &device.ip_addr, 4);
  return(sizeof(gratuitous_arp));
}

/** Called from update_registrations to periodically send gratuitous ARP
 * broadcasts. */
static void send_grat_arps(n2n_edge_t * eee,) {
  char buffer[48];
  size_t len;

  traceEvent(TRACE_NORMAL, "Sending gratuitous ARP...");
  len = build_gratuitous_arp(buffer, sizeof(buffer));
  send_packet2net(eee, buffer, len);
  send_packet2net(eee, buffer, len); /* Two is better than one :-) */
}
#endif /* #if defined(DUMMY_ID_00001) */



/* *********************************************** */

/** @brief Check to see if we should re-register with our peers and the
 *         supernode.
 *
 *  This is periodically called by the main loop. The list of registrations is
 *  not modified. Registration packets may be sent.
 */
static void update_registrations( n2n_edge_t * eee ) {
  /* REVISIT: BbMaj7: have shorter timeout to REGISTER to supernode if this has
   * not yet succeeded. */

  if(time(NULL) < (eee->last_register+REGISTER_FREQUENCY)) return; /* Too early */

  traceEvent(TRACE_NORMAL, "Registering with supernode");
  if(eee->re_resolve_supernode_ip)
    supernode2addr(eee, eee->supernode_ip);

  send_register(eee, &(eee->supernode), 0); /* Register with supernode */

  /* REVISIT: turn-on gratuitous ARP with config option. */
  /* send_grat_arps(sock_fd, is_udp_sock); */

  eee->last_register = time(NULL);
}

/* ***************************************************** */

static int find_peer_destination(n2n_edge_t* eee,
    const u_char* mac_address,
    struct peer_addr* destination) {
    int idx = list_indexOf(eee->known_peers, mac_address - COMMUNITY_LEN);
    macstr_t mac_buf;
    ipstr_t ip_buf;
    int retval = 0;

    traceEvent(TRACE_INFO, "Searching destination peer for MAC %02X:%02X:%02X:%02X:%02X:%02X",
        mac_address[0] & 0xFF, mac_address[1] & 0xFF, mac_address[2] & 0xFF,
        mac_address[3] & 0xFF, mac_address[4] & 0xFF, mac_address[5] & 0xFF);

    if (idx >= 0) {
        struct peer_info* scan = list_get(eee->known_peers, idx);
        if ((scan->last_seen > 0))
        {
            memcpy(destination, &scan->public_ip, sizeof(struct sockaddr_in));
            retval = 1;
        }
    }

    if (0 == retval)
    {
        memcpy(destination, &(eee->supernode), sizeof(struct sockaddr_in));
    }

    traceEvent(TRACE_INFO, "find_peer_address(%s) -> [socket=%s:%hu]",
        macaddr_str((char*)mac_address, mac_buf, sizeof(mac_buf)),
        intoa(ntohl(destination->addr_type.v4_addr), ip_buf, sizeof(ip_buf)),
        ntohs(destination->port));

    return retval;
}

/* *********************************************** */

static const struct option long_options[] = {
  { "community",       required_argument, NULL, 'c' },
  { "supernode-list",  required_argument, NULL, 'l' },
  { "tun-device",      required_argument, NULL, 'd' },
  { "euid",            required_argument, NULL, 'u' },
  { "egid",            required_argument, NULL, 'g' },
  { "help"   ,         no_argument,       NULL, 'h' },
  { "verbose",         no_argument,       NULL, 'v' },
  { NULL,              0,                 NULL,  0  }
};

/* ***************************************************** */
static long seedtwofishEn = 0;
/** A layer-2 packet was received at the tunnel and needs to be sent via UDP. */
static void send_packet2net(n2n_edge_t* eee,
    char* decrypted_msg, size_t len) {
    ipstr_t ip_buf;
    char packet[2048];
    int data_sent_len;
    struct n2n_packet_header hdr;
    struct peer_addr destination;
    macstr_t mac_buf;
    macstr_t mac2_buf;
    struct ether_header* eh = (struct ether_header*)decrypted_msg;

    /* Discard IP packets that are not originated by this hosts */
    if (!(eee->allow_routing)) {
        if (ntohs(eh->ether_type) == 0x0800) {
            /* This is an IP packet from the local source address - not forwarded. */
#define ETH_FRAMESIZE 14
#define IP4_SRCOFFSET 12
            u_int32_t dst;
            memcpy(&dst, &decrypted_msg[ETH_FRAMESIZE + IP4_SRCOFFSET], sizeof(dst));

            /* The following comparison works because device.ip_addr is stored in network order */
            if (dst != eee->device.ip_addr) {
                /* This is a packet that needs to be routed */
                traceEvent(TRACE_INFO, "Discarding routed packet [%s]",
                    intoa(ntohl(dst), ip_buf, sizeof(ip_buf)));
                return;
            }
            else {
                /* This packet is originated by us */
                /* traceEvent(TRACE_INFO, "Sending non-routed packet"); */
            }
        }
    }

    /* Encrypt "decrypted_msg" into the second half of the n2n packet. */

    long s = safeIncrement(&seedtwofishEn) % 16;
    len = TwoFishEncryptRaw((u_int8_t*)decrypted_msg,
        (u_int8_t*)&packet[N2N_PKT_HDR_SIZE], len, eee->enc_tf[s]);
    //   releaseOne(&(eee->mt_queue->lock4UpdatePeer));
  // }
   /* Add the n2n header to the start of the n2n packet. */
    fill_standard_header_fields(&(eee->sinfo), &hdr, (char*)(eee->device.mac_addr));
    hdr.msg_type = MSG_TYPE_PACKET;
    hdr.sent_by_supernode = 0;
    memcpy(hdr.community_name, eee->community_name, COMMUNITY_LEN);
    memcpy(hdr.dst_mac, decrypted_msg, 6);

    marshall_n2n_packet_header((u_int8_t*)packet, &hdr);

    len += N2N_PKT_HDR_SIZE;

    if (find_peer_destination(eee, eh->ether_dhost, &destination)){
        traceEvent(TRACE_INFO, "** Going direct [dst_mac=%s][dest=%s:%hu]",
            macaddr_str((char*)eh->ether_dhost, mac_buf, sizeof(mac_buf)),
            intoa(ntohl(destination.addr_type.v4_addr), ip_buf, sizeof(ip_buf)),
            ntohs(destination.port));
    }
    else {
        traceEvent(TRACE_INFO, "   Going via supernode [src_mac=%s][dst_mac=%s]",
            macaddr_str((char*)eh->ether_shost, mac_buf, sizeof(mac_buf)),
            macaddr_str((char*)eh->ether_dhost, mac2_buf, sizeof(mac2_buf)));
        struct peer_info* scan2 = list_find(eee->pending_peers, eh->ether_dhost - COMMUNITY_LEN);
        if (scan2 != NULL && scan2->regcount > 0 && scan2->regcount < 3 && (time(NULL) - scan2->last_seen) > scan2->regcount) {
            sending_additional_regist(eee, scan2);
        }
    }

    if (lockOne(&(eee->mt_queue->lock4send)) == 0) {
        data_sent_len = reliable_sendto(&(eee->sinfo), packet, &len, &destination,
            N2N_COMPRESSION_ENABLED);

        releaseOne(&(eee->mt_queue->lock4send));
    }
    else {
        data_sent_len = 0;
    }

    if (data_sent_len != len)
        traceEvent(TRACE_WARNING, "sendto() [sent=%d][attempted_to_send=%d] [%s]\n",
            data_sent_len, len, strerror(errno));
    else {
        ++(eee->pkt_sent);
        traceEvent(TRACE_INFO, "Sent %d byte MSG_TYPE_PACKET ok", data_sent_len);
    }
}

/* ***************************************************** */

/** Destination MAC 33:33:0:00:00:00 - 33:33:FF:FF:FF:FF is reserved for IPv6
 * neighbour discovery.
 */
int is_ip6_discovery( const void * buf, size_t bufsize )
{
  int retval = 0;

  if ( bufsize >= sizeof(struct ether_header) )
    {
      struct ether_header *eh = (struct ether_header*)buf;
      if ( (0x33 == eh->ether_dhost[0]) &&
	   (0x33 == eh->ether_dhost[1]) )
        {
	  retval = 1; /* This is an IPv6 neighbour discovery packet. */
        }
    }
  return retval;
}


/* ***************************************************** */

/*
 * Return: 0 = ok, -1 = invalid packet
 *
 */
static int check_received_packet(n2n_edge_t * eee, char *pkt,
				 u_int pkt_len) {

  if(pkt_len == 42) {
    /* ARP */
    if((pkt[12] != 0x08) || (pkt[13] != 0x06)) return(0); /* No ARP */
    if((pkt[20] != 0x00) || (pkt[21] != 0x02)) return(0); /* No ARP Reply */
    if(memcmp(&pkt[28], &(eee->device.ip_addr), 4))   return(0); /* This is not me */

    if(memcmp(eee->device.mac_addr, &pkt[22], 6) == 0) {
      traceEvent(TRACE_WARNING, "Bounced packet received: supernode bug?");
      return(0);
    }

    traceEvent(TRACE_ERROR, "Duplicate address found. Your IP is used by MAC %02X:%02X:%02X:%02X:%02X:%02X",
	       pkt[22+0] & 0xFF, pkt[22+1] & 0xFF, pkt[22+2] & 0xFF,
	       pkt[22+3] & 0xFF, pkt[22+4] & 0xFF, pkt[22+5] & 0xFF);
    exit(0);
  } else if(pkt_len > 32 /* IP + Ethernet */) {
    /* Check if this packet is for us or if it's routed */
    struct ether_header *eh = (struct ether_header*)pkt;
      
    const struct in_addr bcast = { 0xffffffff };

    if(ntohs(eh->ether_type) == 0x0800) {

      /* Note: all elements of the_ip are in network order */
      struct ip the_ip;
      memcpy( &the_ip, pkt+sizeof(struct ether_header), sizeof(the_ip) );

      if((the_ip.ip_dst.s_addr != eee->device.ip_addr)
	 && ((the_ip.ip_dst.s_addr & eee->device.device_mask) != (eee->device.ip_addr & eee->device.device_mask)) /* Not a broadcast */
	 && ((the_ip.ip_dst.s_addr & 0xE0000000) != (0xE0000000 /* 224.0.0.0-239.255.255.255 */)) /* Not a multicast */
	 && ((the_ip.ip_dst.s_addr) != (bcast.s_addr)) /* always broadcast (RFC919) */
	 && (!(eee->allow_routing)) /* routing is enabled so let it in */
	 )
      {
          /* Dropping the packet */

          ipstr_t ip_buf;
          ipstr_t ip_buf2;

	  /* This is a packet that needs to be routed */
	  traceEvent(TRACE_INFO, "Discarding routed packet [rcvd=%s][expected=%s]",
		     intoa(ntohl(the_ip.ip_dst.s_addr), ip_buf, sizeof(ip_buf)),
		     intoa(ntohl(eee->device.ip_addr), ip_buf2, sizeof(ip_buf2)));
      } else {
	/* This packet is for us */

	/* traceEvent(TRACE_INFO, "Received non-routed packet"); */
	return(0);
      }
    } else
      return(0);
  } else {
    traceEvent(TRACE_INFO, "Packet too short (%d bytes): discarded", pkt_len);
  }

  return(-1);
}

/* ***************************************************** */

/** Read a single packet from the TAP interface, process it and write out the
 *  corresponding packet to the cooked socket.
 *
 *  REVISIT: fails if more than one packet is waiting to be read.
 */
static void readFromTAPSocket(n2n_edge_t * eee )
{
  /* tun -> remote */
    sending_pkg pkg = malloc(sizeof(struct sending_package_st));
  //u_char decrypted_msg[2048];
  //size_t len;
  //len = tuntap_read(&(eee->device), decrypted_msg, sizeof(decrypted_msg));
   
  size_t len;
  len = tuntap_read(&(eee->device), pkg->decrypted_msg, sizeof(pkg->decrypted_msg));
  pkg->len = len;
  pkg->eee = eee;
  pkg->p = send_package2netQ;
  if((len <= 0) || (len > sizeof(pkg->decrypted_msg)))
    traceEvent(TRACE_WARNING, "read()=%d [%d/%s]\n",
	       len, errno, strerror(errno));
  else {
    traceEvent(TRACE_INFO, "### Rx L2 Msg (%d) tun -> network", len);

    if ( eee->drop_ipv6_ndp && is_ip6_discovery( pkg->decrypted_msg, len ) ) {
      traceEvent(TRACE_WARNING, "Dropping unsupported IPv6 neighbour discovery packet");
    } else {
      //send_packet2net(eee, (char*)decrypted_msg, len);
        enqueue(eee->mt_queue, pkg, 1);
        return;
    }
  }
  free(pkg);
}

static void send_package2netQ(sending_pkg pkg) {
    if (pkg == NULL) {
        return;
    }
    send_packet2net(pkg->eee, (char*)pkg->decrypted_msg, pkg->len);
    free(pkg);
}

/* ***************************************************** */


void readFromIPSocket(n2n_edge_t* eee)
{
    recving_pkg pkg = malloc(sizeof(struct recving_package_st));
    memset(pkg, 0, sizeof(struct recving_package_st));
    ipstr_t ip_buf;
    macstr_t mac_buf;
    //  char packet[2048], decrypted_msg[2048];
    size_t len;
    int data_sent_len;
    // struct peer_addr sender;

     /* remote -> tun */
    u_int8_t discarded_pkt;
    //struct n2n_packet_header hdr_storage;

    /*接收数据udp*/
    len = receive_data(&(eee->sinfo), pkg->packet, sizeof(pkg->packet), &pkg->sender,
        &discarded_pkt, (char*)(eee->device.mac_addr),
        N2N_COMPRESSION_ENABLED, &pkg->hdr);
    pkg->len = len;
    pkg->p = send_package2tapQ;
    pkg->eee = eee;
    if (len <= 0) {
        free(pkg);
        return;
    }

    traceEvent(TRACE_INFO, "### Rx N2N Msg network -> tun");

    if (discarded_pkt) {
        traceEvent(TRACE_INFO, "Discarded incoming pkt");
    }
    else {
        if (len <= 0)
            traceEvent(TRACE_WARNING, "receive_data()=%d [%s]\n", len, strerror(errno));
        else {
            if (len < N2N_PKT_HDR_SIZE)
                traceEvent(TRACE_WARNING, "received packet too short [len=%d]\n", len);
            else {
                struct n2n_packet_header* hdr = &pkg->hdr;// &hdr_storage;

                traceEvent(TRACE_INFO, "Received packet from %s:%hu",
                    intoa(ntohl(pkg->sender.addr_type.v4_addr), ip_buf, sizeof(ip_buf)),
                    ntohs(pkg->sender.port));

                traceEvent(TRACE_INFO, "Received message [msg_type=%s] from %s [dst mac=%s]",
                    msg_type2str(hdr->msg_type),
                    hdr->sent_by_supernode ? "supernode" : "peer",
                    macaddr_str(hdr->dst_mac, mac_buf, sizeof(mac_buf)));

                if (hdr->version != N2N_PKT_VERSION) {
                    traceEvent(TRACE_WARNING,
                        "Received packet with unknown protocol version (%d): discarded\n",
                        hdr->version);
                    free(pkg);
                    return;
                }

                /* FIX - Add IPv6 support */
                if (hdr->public_ip.addr_type.v4_addr == 0) {
                    hdr->public_ip.addr_type.v4_addr = pkg->sender.addr_type.v4_addr;
                    hdr->public_ip.port = pkg->sender.port;
                    hdr->public_ip.family = AF_INET;
                }

                if (strncmp(hdr->community_name, eee->community_name, COMMUNITY_LEN) != 0) {
                    traceEvent(TRACE_WARNING, "Received packet with invalid community [expected=%s][received=%s]\n",
                        eee->community_name, hdr->community_name);
                }
                else {
                    enqueue(eee->mt_queue, pkg, 2);
                    return;
                }
            }
        }
    }
    free(pkg);
}

static long seedtwofishDe = 0;

static void send_package2tapQ(recving_pkg pkg) {
    if (pkg == NULL) {
        return;
    }
    struct n2n_packet_header* hdr = &pkg->hdr;
    char decrypted_msg[2048];
    int len = pkg->len;
    n2n_edge_t* eee = pkg->eee;
    ipstr_t ip_buf;
    macstr_t mac_buf;
    int data_sent_len;
    if (hdr->msg_type == MSG_TYPE_PACKET) {
        /* assert: the packet received is destined for device.mac_addr or broadcast MAC. */
        /* 数据包，先解密，再检查包是否合格，再检查对端节点是否存在，不存在则相互注册，再写入tab/tun结束*/
        len -= N2N_PKT_HDR_SIZE;
        long seed = safeIncrement(&seedtwofishDe) % 16;
        /* Decrypt message first */
        /* 解密*/
        len = TwoFishDecryptRaw((u_int8_t*)&pkg->packet[N2N_PKT_HDR_SIZE],
            (u_int8_t*)decrypted_msg, len, eee->dec_tf[seed]);

        if (len > 0) {
            if (check_received_packet(eee, decrypted_msg, len) == 0) {

                if (0 == memcmp(hdr->dst_mac, eee->device.mac_addr, 6))
                {
                    check_peer(eee, hdr);
                }

                /*数据包写入tab/tun*/
                data_sent_len = 0;
                if (lockOne(&(eee->mt_queue->lock4send)) == 0) {
                    data_sent_len = tuntap_write(&(eee->device), (u_char*)decrypted_msg, len);
                    releaseOne(&(eee->mt_queue->lock4send));
                }

                if (data_sent_len != len)
                    traceEvent(TRACE_WARNING, "tuntap_write() [sent=%d][attempted_to_send=%d] [%s]\n",
                        data_sent_len, len, strerror(errno));
                else {
                    /* Normal situation. */
                    traceEvent(TRACE_INFO, "### Tx L2 Msg -> tun");
                }
            }
            else {
                traceEvent(TRACE_WARNING, "Bad destination: message discarded");
            }
        }

        /* else silently ignore empty packet. */
    }
    else if (hdr->msg_type == MSG_TYPE_REGISTER) { /*注册请求数据包，发送响应 */
        traceEvent(TRACE_INFO, "Received registration request from remote peer [ip=%s:%hu]",
            intoa(ntohl(hdr->public_ip.addr_type.v4_addr), ip_buf, sizeof(ip_buf)),
            ntohs(hdr->public_ip.port));
        if (0 == memcmp(hdr->dst_mac, (eee->device.mac_addr), 6))
        {
            check_peer(eee, hdr);
        }
        send_register(eee, &hdr->public_ip, 1); /* Send ACK back */ /*发送响应*/
    }
    else if (hdr->msg_type == MSG_TYPE_REGISTER_ACK) {
        traceEvent(TRACE_NORMAL, "Received REGISTER_ACK from remote peer [ip=%s:%hu]",
            intoa(ntohl(hdr->public_ip.addr_type.v4_addr), ip_buf, sizeof(ip_buf)),
            ntohs(hdr->public_ip.port));

        /* if ( 0 == memcmp(hdr->dst_mac, eee->device.mac_addr, 6) ) */
        {
            if (hdr->sent_by_supernode)
            {
                /* Response to supernode registration. Supernode is not in the pending_peers list. */
            }
            else
            {
                /* Move from pending_peers to known_peers; ignore if not in pending. */
                /* 相互注册（点对点）响应包，说明可直连，移到optional队列 */
                traceEvent(TRACE_NORMAL, "set_peer_operational_lock.1.1：");
                if (lockOne(&pkg->eee->mt_queue->lock4UpdatePeer) == 0) {
                    set_peer_operational(eee, hdr);
                    traceEvent(TRACE_NORMAL, "set_peer_operational_lock.1.2：");
                    releaseOne(&pkg->eee->mt_queue->lock4UpdatePeer);
                    traceEvent(TRACE_NORMAL, "set_peer_operational_lock.1.3：");
                }
                else {
                    traceEvent(TRACE_NORMAL, "set_peer_operational_lock.1.4：");
                }
            }
        }
    }
    else {
        traceEvent(TRACE_WARNING, "Unable to handle packet type %d: ignored\n", hdr->msg_type);
        //return;
    }
    free(pkg);

}


/* ***************************************************** */


#ifdef WIN32
static DWORD tunReadThread(LPVOID lpArg )
{
  n2n_edge_t *eee = (n2n_edge_t*)lpArg;

  while(1) {
    readFromTAPSocket(eee);
  }

  return((DWORD)NULL);
}

/* ***************************************************** */

static void startTunReadThread(n2n_edge_t *eee) {
  HANDLE hThread;
  DWORD dwThreadId;

  hThread = CreateThread(NULL, /* no security attributes */
			 0,            /* use default stack size */
			 (LPTHREAD_START_ROUTINE)tunReadThread, /* thread function */
			 (void*)eee,     /* argument to thread function */
			 0,            /* use default creation flags */
			 &dwThreadId); /* returns the thread identifier */
}
#endif

/* ***************************************************** */

static void supernode2addr(n2n_edge_t * eee, char* addr) {
  char *supernode_host = strtok(addr, ":");

  if(supernode_host) {
    char *supernode_port = strtok(NULL, ":");
    const struct addrinfo aihints = {0, PF_INET, 0, 0, 0, NULL, NULL, NULL};
    struct addrinfo * ainfo = NULL;
    int nameerr;
    ipstr_t ip_buf;

    if ( supernode_port )
      eee->supernode.port = htons(atoi(supernode_port));
    else
      traceEvent(TRACE_WARNING, "Bad supernode parameter (-l <host:port>)");

    nameerr = getaddrinfo( supernode_host, NULL, &aihints, &ainfo );

    if( 0 == nameerr )
      {
	struct sockaddr_in * saddr;

	/* ainfo s the head of a linked list if non-NULL. */
	if ( ainfo && (PF_INET == ainfo->ai_family) )
	  {
	    /* It is definitely and IPv4 address -> sockaddr_in */
	    saddr = (struct sockaddr_in *)ainfo->ai_addr;

	    eee->supernode.addr_type.v4_addr = saddr->sin_addr.s_addr;
	  }
	else
	  {
	    /* Should only return IPv4 addresses due to aihints. */
	    traceEvent(TRACE_WARNING, "Failed to resolve supernode IPv4 address for %s", supernode_host);
	  }

	freeaddrinfo(ainfo); /* free everything allocated by getaddrinfo(). */
	ainfo = NULL;
      } else {
      traceEvent(TRACE_WARNING, "Failed to resolve supernode host %s, assuming numeric", supernode_host);
      eee->supernode.addr_type.v4_addr = inet_addr(supernode_host);
    }

    traceEvent(TRACE_NORMAL, "Using supernode %s:%hu",
	       intoa(ntohl(eee->supernode.addr_type.v4_addr), ip_buf, sizeof(ip_buf)),
	       ntohs(eee->supernode.port));
  } else
    traceEvent(TRACE_WARNING, "Wrong supernode parameter (-l <host:port>)");
}

/* ***************************************************** */

extern int useSyslog;

#define N2N_NETMASK_STR_SIZE 16 /* dotted decimal 12 numbers + 3 dots */


int main(int argc, char* argv[]) {
  int opt=0;
  u_int16_t local_port = 0 /* any port */;
  char *tuntap_dev_name = "edge0";
  char *ip_addr = NULL;
  char  netmask[N2N_NETMASK_STR_SIZE]="255.255.255.0";
  int   mtu = DEFAULT_MTU;
  int   got_s = 0;

#ifndef WIN32
  uid_t userid=0; /* root is the only guaranteed ID */
  gid_t groupid=0; /* root is the only guaranteed ID */
  int   fork_as_daemon=0;
#endif

  size_t numPurged;
  time_t lastStatus=0;

  char * device_mac=NULL;
  char * encrypt_key=NULL;

  int     i, effectiveargc=0;
  char ** effectiveargv=NULL;
  char  * linebuffer = NULL;
  int threadcount = 1; //默认线程数
  n2n_edge_t eee; /* single instance for this program */

  if (-1 == edge_init(&eee) ){
    traceEvent( TRACE_ERROR, "Failed in edge_init" );
    exit(1);
  }

  if( getenv( "N2N_KEY" )) {
    encrypt_key = strdup( getenv( "N2N_KEY" ));
  }

#ifdef WIN32
  tuntap_dev_name = "";
#endif
  memset(&(eee.supernode), 0, sizeof(eee.supernode));
  eee.supernode.family = AF_INET;

  linebuffer = (char *)malloc(MAX_CMDLINE_BUFFER_LENGTH);
  if (!linebuffer) {
    traceEvent( TRACE_ERROR, "Unable to allocate memory");
    exit(1);
  }
  snprintf(linebuffer, MAX_CMDLINE_BUFFER_LENGTH, "%s",argv[0]);

#ifdef WIN32
	for(i=0; i<strlen(linebuffer); i++)
		if(linebuffer[i] == '\\') linebuffer[i] = '/';
#endif

  for(i=1;i<argc;++i) {
    if(argv[i][0] == '@') {
      if (readConfFile(&argv[i][1], linebuffer)<0) exit(1); /* <<<<----- check */
    } else
      if ((strlen(linebuffer)+strlen(argv[i])+2) < MAX_CMDLINE_BUFFER_LENGTH) {
	strncat(linebuffer, " ", 1);
	strncat(linebuffer, argv[i], strlen(argv[i]));
      } else {
	traceEvent( TRACE_ERROR, "too many argument");
	exit(1);
      }
  }
  /*  strip trailing spaces */
  while(strlen(linebuffer) && linebuffer[strlen(linebuffer)-1]==' ')
    linebuffer[strlen(linebuffer)-1]= '\0';

  /* build the new argv from the linebuffer */
  effectiveargv = buildargv(linebuffer);

  effectiveargc =0;
  while (effectiveargv[effectiveargc]) ++effectiveargc;
effectiveargv[effectiveargc] = 0;
  if (linebuffer) {
    free(linebuffer);
    linebuffer = NULL;
  }

  /* {int k;for(k=0;k<effectiveargc;++k)  printf("%s\n",effectiveargv[k]);} */

  optarg = NULL;
  while((opt = getopt_long(effectiveargc, effectiveargv, "k:a:bc:u:g:m:M:s:d:l:p:x:fvhrt", long_options, NULL)) != EOF) {
    switch (opt) {
    case 'a':
		  printf("%s\n", optarg);
      ip_addr = strdup(optarg);
      break;
    case 'c': /* community */
      eee.community_name = strdup(optarg);
      if(strlen(eee.community_name) > COMMUNITY_LEN)
	eee.community_name[COMMUNITY_LEN] = '\0';
      break;
#ifndef WIN32

    case 'u': /* uid */
      {
        userid = atoi(optarg);
        break;
      }
    case 'g': /* uid */
      {
        groupid = atoi(optarg);
        break;
      }
    case 'f' : /* fork as daemon */
      {
        fork_as_daemon = 1;
        break;
      }
#endif
    case 'm' : /* device_mac */
      {
        device_mac = strdup(optarg);
        break;
      }
    case 'M' : /* device_mac */
      {
        mtu = atoi(optarg);
        break;
      }
    case 'k': /* encrypt key */
      encrypt_key = strdup(optarg);
      break;
    case 'r': /* enable packet routing across n2n endpoints */
      eee.allow_routing = 1;
      break;
    case 'x':
        printf("x=%s", optarg);
        threadcount = atoi(optarg);
        printf("x=%d", threadcount);
      break;
    case 'l': /* supernode-list */
      snprintf(eee.supernode_ip, sizeof(eee.supernode_ip), "%s", optarg);
      supernode2addr(&eee, eee.supernode_ip);
      break;
#ifdef __linux__
    case 'd': /* tun-device */
      tuntap_dev_name = strdup(optarg);
      break;
#endif
    case 't': /* Use HTTP tunneling */
      eee.sinfo.is_udp_socket = 0;
      break;
    case 'b':
      eee.re_resolve_supernode_ip = 1;
      break;
    case 'p':
      local_port = atoi(optarg) & 0xffff;
      break;
    case 's': /* Subnet Mask */
      if (0 != got_s) {
          traceEvent(TRACE_WARNING, "Multiple subnet masks supplied.");
      }
      strncpy(netmask, optarg, N2N_NETMASK_STR_SIZE);
      got_s = 1;
      break;
    case 'h': /* help */
      help();
      break;
    case 'v': /* verbose */
      traceLevel = 3;
      break;
    }
  }

  if(!(
#ifdef __linux__
       tuntap_dev_name &&
#endif
       eee.community_name &&
       ip_addr &&
       eee.supernode.addr_type.v4_addr &&
       encrypt_key))
    help();

#ifndef WIN32
  /* If running suid root then we need to setuid before using the force. */
  setuid( 0 );
  /* setgid( 0 ); */
#endif

  if(tuntap_open(&(eee.device), tuntap_dev_name, ip_addr, netmask, device_mac, mtu) < 0)
    return(-1);

#ifndef WIN32
  if ( (userid != 0) || (groupid != 0 ) ) {
    traceEvent(TRACE_NORMAL, "Interface up. Dropping privileges to uid=%d, gid=%d", userid, groupid);

    /* Finished with the need for root privileges. Drop to unprivileged user. */
    setreuid( userid, userid );
    setregid( groupid, groupid );
  }
#endif

  if(local_port > 0)
    traceEvent(TRACE_NORMAL, "Binding to local port %hu", local_port);

  if(edge_init_twofish( &eee, (u_int8_t *)(encrypt_key), strlen(encrypt_key) ) < 0) return(-1);
  eee.sinfo.sock = open_socket(local_port, eee.sinfo.is_udp_socket, 0);
  if(eee.sinfo.sock < 0) return(-1);

  if( !(eee.sinfo.is_udp_socket) ) {
    int rc = connect_socket(eee.sinfo.sock, &(eee.supernode));

    if(rc == -1) {
      traceEvent(TRACE_WARNING, "Error while connecting to supernode\n");
      return(-1);
    }
  }

#ifndef WIN32
  if ( fork_as_daemon )
    {
      useSyslog=1; /* traceEvent output now goes to syslog. */
      daemon( 0, 0 );
    }
#endif

  //初始化队列
  eee.mt_queue = createQueue();
  startConsumers(eee.mt_queue, threadcount);

  update_registrations(&eee);

  traceEvent(TRACE_NORMAL, "");
  traceEvent(TRACE_NORMAL, "Ready");

#ifdef WIN32
  //TODO 读取tab数据并处理，改多线程
  startTunReadThread(&eee);
#endif

  /* Main loop
   *
   * select() is used to wait for input on either the TAP fd or the UDP/TCP
   * socket. When input is present the data is read and processed by either
   * readFromIPSocket() or readFromTAPSocket()
   */

  while(1) {
    int rc, max_sock = 0;
    fd_set socket_mask;
    struct timeval wait_time;
    time_t nowTime;

    FD_ZERO(&socket_mask);
    FD_SET(eee.sinfo.sock, &socket_mask);
#ifndef WIN32
    FD_SET(eee.device.fd, &socket_mask);
    max_sock = max( eee.sinfo.sock, eee.device.fd );
#endif

    wait_time.tv_sec = SOCKET_TIMEOUT_INTERVAL_SECS; wait_time.tv_usec = 0;

    //查询socket
    rc = select(max_sock+1, &socket_mask, NULL, NULL, &wait_time);
    nowTime=time(NULL);

    if(rc > 0)
      {
        /* Any or all of the FDs could have input; check them all. */

        if(FD_ISSET(eee.sinfo.sock, &socket_mask))
	  {
            /* Read a cooked socket from the internet socket. Writes on the TAP
             * socket. */
            //TODO 读取socket数据并处理，改多线程
            readFromIPSocket(&eee);
	  }

#ifndef WIN32
        if(FD_ISSET(eee.device.fd, &socket_mask))
	  {
            /* Read an ethernet frame from the TAP socket. Write on the IP
             * socket. */
            //TODO LINUX下读取Tun
            readFromTAPSocket(&eee);
	  }
#endif
      }
    //TODO 注册相关，注意以下逻辑保持单线程（原子性）

    //维护与supernode连接
    update_registrations(&eee);

    //清理过期连接
    numPurged =  purge_expired_registrations2(eee.mt_queue, (eee.known_peers),(eee.pending_peers) );
    /*numPurged += purge_expired_registrations( &(eee.pending_peers) );*/
    if ( numPurged > 0 )
      {
        traceEvent( TRACE_NORMAL, "Peer removed: pending=%ld, operational=%ld",
                    peer_list_size( eee.pending_peers ), peer_list_size( eee.known_peers ) );
      }

    if ( ( nowTime - lastStatus ) > STATUS_UPDATE_INTERVAL )
      {
        lastStatus = nowTime;

        traceEvent( TRACE_NORMAL, "STATUS: pending=%ld, operational=%ld",
                    peer_list_size( eee.pending_peers ), peer_list_size( eee.known_peers ) );
      }
  } /* while */
  eee.mt_queue->state = 2;
  for (int i = 0; i < 5 * threadcount; i++) //往队列里加几个空数据，以便线程正常退出
      enqueue(eee.mt_queue, NULL, 1);

  //退出，反注册
  send_deregister( &eee, &(eee.supernode));
  //关闭socket
  closesocket(eee.sinfo.sock);
  //关闭tun/tab
  tuntap_close(&(eee.device));
  //卸载
  edge_deinit( &eee );

  return(0);
}


