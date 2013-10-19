/*
* Copyright (C) 2009, HustMoon Studio
*
* src/mentohust.c
* HustMoon@BYHH <www.ehust@gmail.com>
*
* Fixed by Weiwei Jia <harryxiyou@gmail.com> (C) 2013
*          Yuli Tian
*  
*
*/
#include <signal.h>
#include <string.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <unistd.h>
#include "myconfig.h"
#include "i18n.h"
#include "mystate.h"
#include "myfunc.h"
#include "pcap.h"

extern pcap_t *hPcap;
extern volatile int state;
extern u_char *fillBuf;
extern const u_char *capBuf;
extern unsigned startMode, dhcpMode, maxFail;
extern u_char destMAC[];
extern int lockfd;
#if 0
#define NO_NOTIFY      /*Remove notify, we do not need*/
#ifndef NO_NOTIFY
extern int showNotify;
#endif
#endif
#ifndef NO_ARP
extern u_int32_t rip, gateway;
extern u_char gateMAC[];
#endif

static void exit_handle(void);	/* 退出回调 */
static void sig_handle(int sig);	/* 信号回调 */
static void pcap_handle(u_char *user, const struct pcap_pkthdr *h, const u_char *buf);	/* pcap_loop回调 */
static void showRuijieMsg(const u_char *buf, unsigned bufLen);	/* 显示锐捷服务器提示信息 */
static void showCernetMsg(const u_char *buf);	/* 显示赛尔服务器提示信息 */

int main(int argc, char **argv)
{/*9991*/
	fprintf(stdout, "999--->enter %s func!\n", __func__);
#ifdef ENABLE_NLS
	textdomain(GETTEXT_PACKAGE);
	setlocale(LC_ALL, "");
#endif
	atexit(exit_handle);
	initConfig(argc, argv);
	signal(SIGALRM, sig_handle);	/* 定时器 */
	signal(SIGHUP, sig_handle);	 /* 注销时 */
	signal(SIGINT, sig_handle);	 /* Ctrl+C */
	signal(SIGQUIT, sig_handle);	/* Ctrl+\ */
	signal(SIGTSTP, sig_handle);	/* Ctrl+Z */
	signal(SIGTERM, sig_handle);	/* 被结束时 */
	fprintf(stdout, "999 dhcpMode2 is %d\n", dhcpMode);
	if (dhcpMode == 3)	  /* 认证前DHCP */
		switchState(ID_DHCP);
	else
		switchState(ID_START);	/* 开始认证 */
	if (-1 == pcap_loop(hPcap, -1, pcap_handle, NULL)) { /* 开始捕获数据包 */
		printf(_("!! 捕获数据包失败，请检查网络连接！\n"));
#if 0
#ifndef NO_NOTIFY
		if (showNotify && show_notify(_("MentoHUST - 错误提示"),
			_("捕获数据包失败，请检查网络连接！"), 1000*showNotify) < 0)
			showNotify = 0;
#endif
#endif
	}
	fprintf(stdout, "999--->leave %s func!\n", __func__);
	exit(EXIT_FAILURE);
}

static void exit_handle(void)
{
	fprintf(stdout, "999--->enter %s func!\n", __func__);
	if (state != ID_DISCONNECT)
		switchState(ID_DISCONNECT);
	if (hPcap != NULL)
		pcap_close(hPcap);
	if (fillBuf != NULL)
		free(fillBuf);
	if (lockfd > -1)
		close(lockfd);
#if 0
#ifndef NO_NOTIFY
	free_libnotify();
#endif
#ifndef NO_DYLOAD
	free_libpcap();
#endif
#endif
	printf(_(">> 认证已退出。\n"));
}

static void sig_handle(int sig)
{
	fprintf(stdout, "999--->enter %s func!\n", __func__);
	if (sig == SIGALRM)	 /* 定时器 */
	{
		if (-1 == switchState(state))
		{
			pcap_breakloop(hPcap);
			printf(_("!! 发送数据包失败, 请检查网络连接！\n"));
#if 0
#ifndef NO_NOTIFY
			if (showNotify && show_notify(_("MentoHUST - 错误提示"),
				_("发送数据包失败, 请检查网络连接！"), 1000*showNotify) < 0)
				showNotify = 0;
#endif
#endif
			exit(EXIT_FAILURE);
		}
	}
	else	/* 退出 */
	{
		pcap_breakloop(hPcap);
		exit(EXIT_SUCCESS);
	}
}

static void pcap_handle(u_char *user, const struct pcap_pkthdr *h, const u_char *buf)
{
	fprintf(stdout, "999--->enter %s func!\n", __func__);
	static unsigned failCount = 0;
#ifndef NO_ARP
	fprintf(stdout, "999 buf1 is\n-----------------\n%s\n--------------\n", buf);
	fprintf(stdout, "999 1----->buf[0x0c] is %x, buf[0x0d] is %x\n", buf[0x0c], buf[0x0d]);
	if (buf[0x0c]==0x88 && buf[0x0d]==0x8e) {
#endif
		fprintf(stdout, "999 buf2 is\n-----------------\n%s\n--------------\n", buf);
	fprintf(stdout, "999 2----->buf[0x0c] is %x, buf[0x0d] is %x\n", buf[0x0c], buf[0x0d]);
		if (memcmp(destMAC, buf+6, 6)!=0 && startMode>2)	/* 服务器MAC地址不符 */
			return;
		capBuf = buf;
	    fprintf(stdout, "999 2----->buf[0x12]is %x, buf[0x16] is %x\n", buf[0x12], buf[0x16]);
		if (buf[0x0F]==0x00 && buf[0x12]==0x01 && buf[0x16]==0x01) {	/* 验证用户名 */
			fprintf(stdout, "999 startMode is %d\n", startMode);
			fprintf(stdout, "999 destMac is %s\n", destMAC);
			if (startMode < 3) {
				memcpy(destMAC, buf+6, 6);
				fprintf(stdout, "999 destMac is %s\n", destMAC);
				printf(_("** 认证MAC:\t%s\n"), formatHex(destMAC, 6));
				startMode += 3;	/* 标记为已获取 */
			}
			if (startMode==3 && memcmp(buf+0x17, "User name", 9)==0)	/* 塞尔 */
				startMode = 5;
			switchState(ID_IDENTITY);
		}
		else if (buf[0x0F]==0x00 && buf[0x12]==0x01 && buf[0x16]==0x04)	{/* 验证密码 */
			switchState(ID_CHALLENGE);
		}
		else if (buf[0x0F]==0x00 && buf[0x12]==0x03) {	/* 认证成功 */
			printf(_(">> 认证成功!\n"));
			failCount = 0;
			if (!(startMode%3 == 2)) {
				getEchoKey(buf);
				showRuijieMsg(buf, h->caplen);
			}
			if (dhcpMode==1 || dhcpMode==2)	/* 二次认证第一次或者认证后 */
				switchState(ID_DHCP);
			else if (startMode%3 == 2)
				switchState(ID_WAITECHO);
			else
				switchState(ID_ECHO);
		}
		else if (buf[0x0F]==0x00 && buf[0x12]==0x01 && buf[0x16]==0x02)	/* 显示赛尔提示信息 */
			showCernetMsg(buf);
		else if (buf[0x0F] == 0x05)	/* (赛尔)响应在线 */
			switchState(ID_ECHO);
		else if (buf[0x0F]==0x00 && buf[0x12]==0x04) {  /* 认证失败或被踢下线 */
			if (state==ID_WAITECHO || state==ID_ECHO) {
				printf(_(">> 认证掉线，开始重连!\n"));
				switchState(ID_START);
			}
			else if (buf[0x1b]!=0 || startMode%3==2) {
				printf(_(">> 认证失败!\n"));
				if (startMode%3 != 2)
					showRuijieMsg(buf, h->caplen);
				if (maxFail && ++failCount>=maxFail) {
					printf(_(">> 连续认证失败%u次，退出认证。\n"), maxFail);
					exit(EXIT_SUCCESS);
				}
				restart();
			}
			else
				switchState(ID_START);
		}
#ifndef NO_ARP
	} else if (gateMAC[0]!=0xFE && buf[0x0c]==0x08 && buf[0x0d]==0x06) {
		if (*(u_int32_t *)(buf+0x1c) == gateway) {
			char str[50];
			if (gateMAC[0] == 0xFF) {
				memcpy(gateMAC, buf+0x16, 6);
				printf(_("** 网关MAC:\t%s\n"), formatHex(gateMAC, 6));
				sprintf(str, "arp -s %s %s", formatIP(gateway), formatHex(gateMAC, 6));
				system(str);
			} else if (buf[0x15]==0x02 && memcmp(&rip, buf+0x26, 4)==0
				&& memcmp(gateMAC, buf+0x16, 6)!=0) {
				printf(_("** ARP欺骗:\t%s\n"), formatHex(buf+0x16, 6));
#if 0
#ifndef NO_NOTIFY
				if (showNotify) {
					sprintf(str, _("欺骗源: %s"), formatHex(buf+0x16, 6));
					if (show_notify(_("MentoHUST - ARP提示"), str, 1000*showNotify) < 0)
						showNotify = 0;
				}
#endif
#endif
			}
		}
	}
#endif
}

static void showRuijieMsg(const u_char *buf, unsigned bufLen)
{
	fprintf(stdout, "999--->enter %s func!\n", __func__);
	char *serverMsg;
	int length = buf[0x1b];
	if (length > 0) {
		for (serverMsg=(char *)(buf+0x1c); *serverMsg=='\r'||*serverMsg=='\n'; serverMsg++,length--);	/* 跳过开头的换行符 */
		if (strlen(serverMsg) < length)
			length = strlen(serverMsg);
		if (length>0 && (serverMsg=gbk2utf(serverMsg, length))!=NULL) {
			if (strlen(serverMsg)) {
				printf(_("$$ 系统提示:\t%s\n"), serverMsg);
#if 0
#ifndef NO_NOTIFY
				if (showNotify && show_notify(_("MentoHUST - 系统提示"),
					serverMsg, 1000*showNotify) < 0)
					showNotify = 0;
#endif
#endif
			}
			free(serverMsg);
		}
	}
	if ((length=0x1c+buf[0x1b]+0x69+39) < bufLen) {
		serverMsg=(char *)(buf+length);
		if (buf[length-1]-2 > bufLen-length)
			length = bufLen - length;
		else
			length = buf[length-1]-2;
		for (; *serverMsg=='\r'||*serverMsg=='\n'; serverMsg++,length--);
		if (length>0 && (serverMsg=gbk2utf(serverMsg, length))!=NULL) {
			if (strlen(serverMsg)) {
				printf(_("$$ 计费提示:\t%s\n"), serverMsg);
#if 0
#ifndef NO_NOTIFY
				if (showNotify && show_notify(_("MentoHUST - 计费提示"),
					serverMsg, 1000*showNotify) < 0)
					showNotify = 0;
#endif
#endif
			}
			free(serverMsg);
		}
	}
}

static void showCernetMsg(const u_char *buf)
{
	fprintf(stdout, "999--->enter %s func!\n", __func__);
	char *serverMsg = (char *)(buf+0x17);
	int length = ntohs(*(u_int16_t *)(buf+0x14)) - 5;
	if (strlen(serverMsg) < length)
		length = strlen(serverMsg);
	if (length>0 && (serverMsg=gbk2utf(serverMsg, length))!=NULL)
	{
		printf(_("$$ 系统提示:\t%s\n"), serverMsg);
#if 0
#ifndef NO_NOTIFY
			if (showNotify && show_notify(_("MentoHUST - 系统提示"),
				serverMsg, 1000*showNotify) < 0)
				showNotify = 0;
#endif
#endif
		free(serverMsg);
	}
}
