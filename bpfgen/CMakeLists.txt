set (EMPTY_PCAP ${CMAKE_CURRENT_SOURCE_DIR}/empty.pcap)

function (generate_bpf filter target)
	add_custom_command (OUTPUT ${CMAKE_CURRENT_SOURCE_DIR}/${target}
		COMMAND tcpdump -r ${EMPTY_PCAP} -dd ${filter} > ${CMAKE_CURRENT_SOURCE_DIR}/${target}
		VERBATIM)
	add_custom_target (${target}
		DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/${target})
endfunction(generate_bpf)

generate_bpf("icmp[icmptype] == icmp-echo" bpf_icmp_echo.prog)
generate_bpf("icmp[icmptype] == icmp-echoreply" bpf_icmp_echoreply.prog)
