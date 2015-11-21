add_executable (pingtun ping.c tun.c pingtun.c)
add_dependencies (pingtun bpf_icmp_echoreply.prog bpf_icmp_echo.prog)
target_link_libraries (pingtun event)

install (TARGETS pingtun
	RUNTIME DESTINATION sbin)
