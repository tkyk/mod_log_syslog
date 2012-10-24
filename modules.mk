mod_log_syslog.la: mod_log_syslog.slo
	$(SH_LINK) -rpath $(libexecdir) -module -avoid-version  mod_log_syslog.lo
DISTCLEAN_TARGETS = modules.mk
shared =  mod_log_syslog.la
