/*
 * lanauth client
 * (c) visir
 * "THE BEER-WARE LICENSE" (Revision 42):
 * <visir@telenet.ru> wrote this file.  As long as you retain this notice you
 * can do whatever you want with this stuff. If we meet some day, and you think
 * this stuff is worth it, you can buy me a beer in return.                    
 * compile: gcc -O2 -Wall -s -lcrypto -o lanauth lanauth.c
 * run: ./lanauth -p yourpassword
 */

#include<sys/types.h>
#include<sys/stat.h>
#include<fcntl.h>
#include<signal.h>
#include<errno.h>
#include<netinet/in.h>
#include<arpa/inet.h>
#include<sys/time.h>
#include<sys/socket.h>
#include<unistd.h>
#include<stdio.h>
#include<stdlib.h>
#include<stdarg.h>
#include<string.h>
#include<syslog.h>
#include<openssl/md5.h>
#include<openssl/ripemd.h>

int nodaemon = 0;		/* don't become daemon */
int nobind = 1;			/* don't really bind, just assume we binded */
int nolip = 0;			/* don't touch localip */
int ver = 1;			/* protocol version */
char level = 2;			/* access level */
int sock = -1;			/* socket */
int first;			/* first try */
unsigned char localip[16], gateip[16], pass[21], challenge[256], digest[256];

void opensock();		/* connect to server */
void auth1();			/* generate response for v1 protocol */
void auth2();			/* generate response for v2 protocol */
void sigusr(int sig);		/* change access level */
int tmread(char *buf, int size, int timeout);	/* read with timeout */
#define tryread(buf,size,tm)	if(!tmread(buf,size,tm))\
				{ close(sock); if(first)sleep(5); continue; }
void usage()
{
	printf("Usage: lanauth [-i] [-v 1|2] [-b localip] [-n] [-g gid] [-u uid] [-s gateip] [-l accesslevel] -p password\n");
	exit(0);
}

void fatal(char *s, ...)
{
va_list ap;
	va_start(ap, s);
	vsyslog(LOG_ERR, s, ap);
	va_end(ap);
	exit(1);
}

int main(int argc, char **argv)
{
char		*s;
int		op;
unsigned char	ch;
	strcpy(gateip, "10.0.0.1");
	/* process command line arguments */
	while((op = getopt(argc, argv, "iv:b:ns:p:l:u:g:")) != -1) {
	switch(op) {
	case 'i':
		nodaemon = 1;
		break;
	case 'v':
		ver = atoi(optarg);
		if(ver != 1 && ver != 2)usage();
		break;
	case 'b':
		strncpy(localip, optarg, sizeof(localip)-1);
		localip[sizeof(localip)-1] = 0;
		nobind = 0;
		nolip = 1;
		break;
	case 'n':
		nobind = 1;
		if(!nolip)usage();
		break;
	case 's':
		strncpy(gateip, optarg, sizeof(gateip)-1);
		gateip[sizeof(gateip)-1] = 0;
		break;
	case 'p':
		strncpy(pass, optarg, sizeof(pass)-1);
		pass[sizeof(pass)-1] = 0;
		/* hide password */
		for(s = optarg; *s; s++) *s = '*';
		break;
	case 'l':
		level = atoi(optarg);
		break;
	case 'u':
		setuid(atoi(optarg));
		break;
	case 'g':
		setgid(atoi(optarg));
		break;
	default:
		usage();
	}}

	if(!*pass)usage();

	openlog(NULL, nodaemon ? LOG_PERROR|LOG_PID : LOG_PID, LOG_DAEMON);

	signal(SIGUSR1, sigusr);
	signal(SIGUSR2, sigusr);
	if(!nodaemon) {
		signal(SIGPIPE, SIG_IGN);
		signal(SIGHUP, SIG_IGN);
		daemon(0, 0);
	}

	/* main loop */
	while(1) {
		/* connect to server */
		opensock();
		ch = 0;
		first = 1;
		/* start conversation */
		tryread((char*)&ch, 1, 10);
		switch(ch) {
		case 0:	/* access closed */
			syslog(LOG_NOTICE, "access closed for us");
			close(sock);
			sleep(60);
		case 1: /* continue authorization */
			break;
		case 2: /* redirect to real server */
			read(sock, (char*)&ch, 1);
			if(ch < 7 || ch > 15)
			fatal("redirect: invalid gateway lenght %d", ch);
			read(sock, gateip, ch);
			gateip[ch] = 0;
			syslog(LOG_NOTICE, "gate changed to %s", gateip);
			close(sock);
			break;
		default:
			close(sock);
			syslog(LOG_NOTICE, "unknown protocol %d", ch);
			sleep(60);
			break;
		}
		if(ch != 1)continue;
		/* main loop of challenge-response authorization */
next:
		tryread(challenge, sizeof(challenge), 240);
		switch(ver) {
			case 1: auth1(); break;
			case 2: auth2(); break;
		}
		write(sock, digest, (ver == 1) ? 16 : 256);
		tryread((char*)&ch, 1, 10);
		if(first) {
			first = 0;
			syslog(LOG_NOTICE, "auth succeful, access level = %d", ch);
		}
		goto next;
	}
}

void sigusr(int sig)
{
	switch(sig) {
	case SIGUSR1:
		level = 1;
		signal(SIGUSR1, sigusr);
		break;
	case SIGUSR2:
		level = 2;
		signal(SIGUSR2, sigusr);
		break;
	}
}

void opensock()
{
struct sockaddr_in sin;
int	len;
again:
	/* create socket */
	if((sock = socket(PF_INET, SOCK_STREAM, 0)) == -1)fatal("socket: %m");

	/* bind it to specified ip, if needed */
	if(*localip && !nobind) {
		bzero(&sin, sizeof(sin));
		sin.sin_family = AF_INET;
		sin.sin_addr.s_addr = inet_addr(localip);
		sin.sin_port = 0;
		if(sin.sin_addr.s_addr == INADDR_NONE)
			fatal("%s: invalid ip address", localip);
		if(bind(sock, (struct sockaddr*)&sin, sizeof(sin)) == -1)
			fatal("bind: %m");
	}
	
	/* connect to server */
	bzero(&sin, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = inet_addr(gateip);
	sin.sin_port = htons((ver == 1) ? 8899 : 8314);
	if(sin.sin_addr.s_addr == INADDR_NONE)
		fatal("%s: invalid ip address", gateip);

	if(connect(sock, (struct sockaddr*)&sin, sizeof(sin)) == -1) {
		syslog(LOG_NOTICE, "connect: %m");
		sleep(30);
		close(sock);
		goto again;
	}

	/* save localip, if needed */
	len = sizeof(sin);
	getsockname(sock, (struct sockaddr*)&sin, &len);
	if(!nolip)strcpy(localip, inet_ntoa(sin.sin_addr));
//	syslog(LOG_DEBUG, "connected, local ip is %s", localip);
}

int tmread(char *buf, int size, int timeout)
{
fd_set	fds;
int	n;
struct timeval tv;
	/* wait */
	FD_ZERO(&fds);
	FD_SET(sock, &fds);
	tv.tv_sec = timeout;
	tv.tv_usec = 0;
	n = select(sock+1, &fds, NULL ,NULL, &tv);
	if(n < 0 && errno == EINTR) {
		syslog(LOG_DEBUG, "reconnecting by request");
		return 0;
	}
	if(n < 0)fatal("select: %m");
	if(!n) {
		syslog(LOG_DEBUG, "no response from server, reconnecting");
		return 0;
	}
	/* wait a moment */
	if(size > 1) {
		tv.tv_sec = 3;
		tv.tv_usec = 0;
		select(0, NULL, NULL, NULL, &tv);
	}
	/* read */
	n = read(sock, buf, size);
	if(n < 0) {
		syslog(LOG_DEBUG, "read: %m");
		return 0;
	}
	if(!n) {
		syslog(LOG_DEBUG, "server closed connection");
		return 0;
	}
	return n;
}

void auth1()
{
MD5_CTX	ctx;
	MD5_Init(&ctx);
	MD5_Update(&ctx, challenge+1, challenge[0]);
	MD5_Update(&ctx, localip, strlen(localip));
	level += '0';
	MD5_Update(&ctx, &level, 1);
	level -= '0';
	MD5_Update(&ctx, pass, strlen(pass));
	MD5_Final(digest, &ctx);
}

void auth2()
{
RIPEMD160_CTX ctx;
int	i;
	for(i = 0; i < 255; i++)digest[i] = rand() % 256;
	digest[0] = level - 1;
	digest[1] = 2 + rand() % 230;
	RIPEMD160_Init(&ctx);
	RIPEMD160_Update(&ctx, challenge+1, challenge[0]);
	RIPEMD160_Update(&ctx, pass, strlen(pass));
	RIPEMD160_Final(digest+digest[1], &ctx);
}

