add_executable (pingtun ping.c tun.c pingtun.c)
target_link_libraries (pingtun event)
