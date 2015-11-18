add_executable (pingtun ping.c tun.c pingtun.c)
target_link_libraries (pingtun event)
add_executable (pingserver ping.c ping_server.c)
add_executable (pinger ping.c pinger.c)
