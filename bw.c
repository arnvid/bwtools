/* [isd] Bandwidth monitor  --  rewritten to not be a poor /proc/  reader!
 * -----------------------------------------------------------------------
 * written by : Arnvid Karstad
 * ideas by   : Erik Sperling
 *  
 * compile    : gcc -o bw bw.c
 * prereq's   : libpcap
 *
 *
 * $Id$
 */
 
#include <stdlib.h>
#include <stdio.h>
#include <pcap.h>
#include <unistd.h>
#include <sys/signal.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <string.h>
#include <ctype.h>
#include <time.h> 

#define VER "1.2b"
#ifdef __FreeBSD__
# define DIF "fxp0"
#else
# define DIF "eth0"
#endif


char errbuf[PCAP_ERRBUF_SIZE];char arg_interface[128];
int  interval;
int  cnt;
int  pkt;
int  pktsiz;

void pccb(unsigned char * dummy, const struct pcap_pkthdr * hdr, const unsigned char * data) {
  ++pkt;
  pktsiz = pktsiz + hdr->len;  
}


void usage(char * binary) {
  printf("Usage: %s [-i interface] [-l interval] [-h] [-s] [-k]\n", binary);
  printf("  Default interface    : %s [-i if]\n", DIF);
  printf("  Default loadinterval : 30 sec [-l sec]\n\n");
  printf("  -h : help\n");
  printf("  -s : dont print info\n");
  printf("  -k : print in kbytes\n");
  printf("\n");
  exit(1);
}

int main(int argc, char ** argv, char ** envp) {
  int dorun, flag;
  pcap_t * pc;
  struct bpf_program fp;
  struct timeval tv1, tv2;
  unsigned long tm;
  time_t tm3;
  char s[128];
  int LIFESUX=0;
  u_int kbyte=0;

  dorun = 1;
  strcpy(arg_interface, DIF);
  interval = 30;
  
  while((flag = (int) getopt(argc, argv, "l:i:hsk")) != EOF) {
	switch(flag) {
		case 'l':
			interval = atoi(optarg);
			break;
		case 'i':
			strncpy(arg_interface, optarg, sizeof(arg_interface));
			break;
		case 'h':
			dorun = 0;
			break;
                case 's':
                        LIFESUX = 1;
                        break;
                case 'k':
                        kbyte = 1;
                        break;
		default:
			printf("Unknown flag %c\n", flag);
			break;
	}
  }

  if (!LIFESUX) printf("[isd/2004] bandwidth monitor v%s\n",VER);
  if (dorun == 0) {
    usage(argv[0]);
    exit(1);
  }
  if (!LIFESUX) printf("running on device [%s] and load interval [%i]\n\n", arg_interface, interval);
  interval = interval * 1000;  // convert to ms;)
  pc = pcap_open_live(arg_interface, 256, 0, 1, errbuf);
  if (!pc) {
    printf("Failed to open \"%s\": %s\n", arg_interface, errbuf);
    exit(1);
  }
  do {
    cnt=0;
    pkt=0;
    pktsiz=0;

    gettimeofday(&tv1, 0);
    do {
      pcap_dispatch(pc, 0, pccb, 0);
      gettimeofday(&tv2, 0);
      tm = (tv2.tv_sec * 1000 + tv2.tv_usec / 1000) - (tv1.tv_sec * 1000 + tv1.tv_usec / 1000);
    } while (tm < interval);
    tm3 = time(0);
    strftime(s, sizeof(s), "%b %d %T", localtime(&tm3));
    if (kbyte) {
      printf("(%s) [%s] %i second interval rate %i kbytes/sec, %i packets/sec \n", s, arg_interface, interval/1000,
             (pktsiz/(interval/1000))/1024, pkt/(interval/1000));
    } else {
      printf("(%s) [%s] %i second interval rate %i bits/sec, %i packets/sec \n", s, arg_interface, interval/1000 , ((pktsiz/(interval/1000))*8), pkt/(interval/1000));
    }
  } while (1);
  pcap_freecode(&fp);
  pcap_close(pc);

  printf("cleaning up\n");
  return 0;
}
