/* [isd] bwtools -  bandwidth monitor 
 * -----------------------------------
 * written by : Arnvid Karstad
 * ideas by   : Erik Sperling
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
#include "include/serno.h"
#include "include/patchlevel.h"
#include "include/bwtools.h"

const char *_version = "$Revision$";

char errbuf[PCAP_ERRBUF_SIZE];
char arg_interface[128];
int  interval;
int  cnt;
int  pkt;
int  pktsiz;

void pccb(unsigned char * dummy, const struct pcap_pkthdr * hdr, const unsigned char * data) {
  ++pkt;
  pktsiz = pktsiz + hdr->len;  
}


void usage(char * binary) {
  printf("Usage: %s [-i interface] [-l interval] [-h] [-k] [-p]\n", binary);
  printf("  Default interface    : %s [-i if]\n", DIF);
  printf("  Default loadinterval : 30 sec [-l sec]\n\n");
  printf("  -h : help\n");
  printf("  -k : print in kbytes\n");
  printf("  -p : put if in promisc mode\n");
  printf("\n");
  exit(1);
}

int main(int argc, char ** argv, char ** envp) {
  int dorun, flag, do_promisc;
  pcap_t * pc;
  struct bpf_program fp;
  struct timeval tv1, tv2;
  unsigned long tm;
  time_t tm3;
  char s[128];
  u_int kbyte=0;

  dorun = 1;
  do_promisc = 0;
  strcpy(arg_interface, DIF);
  interval = 30;
  
  while((flag = (int) getopt(argc, argv, "l:i:hpk")) != EOF) {
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
                case 'k':
                        kbyte = 1;
                        break;
                case 'p':
                        do_promisc = 1;
                        break;
		default:
			printf("Unknown flag %c\n", flag);
			break;
	}
  }

  printf("[isd/bwtools] bandwidth monitor v%s (%s)\n",PATCHLEVEL,SERIALNUM);
  if (dorun == 0) {
    usage(argv[0]);
    exit(1);
  }
  printf("- running on device [%s] and load interval [%i]\n\n", arg_interface, interval);
  interval = interval * 1000;  // convert to ms;)
  pc = pcap_open_live(arg_interface, 256, do_promisc, 1, errbuf);
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
