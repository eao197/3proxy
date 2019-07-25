#
# 3 proxy common Makefile
#

#all:	$(BUILDDIR)3proxy$(EXESUFFICS) $(BUILDDIR)mycrypt$(EXESUFFICS) $(BUILDDIR)pop3p$(EXESUFFICS) $(BUILDDIR)smtpp$(EXESUFFICS) $(BUILDDIR)ftppr$(EXESUFFICS) $(BUILDDIR)tcppm$(EXESUFFICS) $(BUILDDIR)udppm$(EXESUFFICS) $(BUILDDIR)socks$(EXESUFFICS) $(BUILDDIR)proxy$(EXESUFFICS) allplugins

all:	$(BUILDDIR)3proxy$(EXESUFFICS)

sockmap$(OBJSUFFICS): sockmap.c proxy.h structures.h
	$(CC) $(CFLAGS) sockmap.c

common$(OBJSUFFICS): common.c proxy.h structures.h
	$(CC) $(CFLAGS) common.c

myalloc$(OBJSUFFICS): myalloc.c proxy.h structures.h
	$(CC) $(CFLAGS) myalloc.c

plugins$(OBJSUFFICS): plugins.c proxy.h structures.h
	$(CC) $(CFLAGS) plugins.c

base64$(OBJSUFFICS): base64.c
	$(CC) $(CFLAGS) base64.c

ftp$(OBJSUFFICS): ftp.c proxy.h structures.h
	$(CC) $(CFLAGS) ftp.c

sockgetchar$(OBJSUFFICS): sockgetchar.c proxy.h structures.h
	$(CC) $(CFLAGS) sockgetchar.c

client_limits$(OBJSUFFICS): client_limits.cpp proxy.h structures.h client_limits.h
	$(CXX) $(CXXFLAGS) client_limits.cpp

proxy$(OBJSUFFICS): proxy.c proxy.h structures.h proxymain.c
	$(CC) $(CFLAGS) $(DEFINEOPTION)WITHMAIN $(DEFINEOPTION)NOPORTMAP $(DEFINEOPTION)ANONYMOUS proxy.c

3proxy$(OBJSUFFICS): 3proxy.c proxy.h structures.h
	$(CC) $(CFLAGS) 3proxy.c

$(BUILDDIR)proxy$(EXESUFFICS): sockmap$(OBJSUFFICS) proxy$(OBJSUFFICS) sockgetchar$(OBJSUFFICS) myalloc$(OBJSUFFICS) common$(OBJSUFFICS) base64$(OBJSUFFICS) ftp$(OBJSUFFICS) $(COMPATLIBS)
	$(LN) $(LNOUT)$(BUILDDIR)proxy$(EXESUFFICS) $(LDFLAGS) sockmap$(OBJSUFFICS) proxy$(OBJSUFFICS) sockgetchar$(OBJSUFFICS) myalloc$(OBJSUFFICS) common$(OBJSUFFICS) base64$(OBJSUFFICS) ftp$(OBJSUFFICS) $(COMPATLIBS) $(LIBS)

mainfunc$(OBJSUFFICS): proxy.h structures.h proxymain.c
	$(CC) $(COUT)mainfunc$(OBJSUFFICS) $(CFLAGS) $(DEFINEOPTION)MODULEMAINFUNC=mainfunc proxymain.c

srvproxy$(OBJSUFFICS): proxy.c proxy.h structures.h
	$(CC) $(COUT)srvproxy$(OBJSUFFICS) $(CFLAGS) proxy.c

srvpop3p$(OBJSUFFICS): pop3p.c proxy.h structures.h
	$(CC) $(COUT)srvpop3p$(OBJSUFFICS) $(CFLAGS) pop3p.c

srvsmtpp$(OBJSUFFICS): smtpp.c proxy.h structures.h
	$(CC) $(COUT)srvsmtpp$(OBJSUFFICS) $(CFLAGS) smtpp.c

srvftppr$(OBJSUFFICS): ftppr.c proxy.h structures.h
	$(CC) $(COUT)srvftppr$(OBJSUFFICS) $(CFLAGS) ftppr.c

srvtcppm$(OBJSUFFICS): tcppm.c proxy.h structures.h
	$(CC) $(COUT)srvtcppm$(OBJSUFFICS) $(CFLAGS) tcppm.c

srvsocks$(OBJSUFFICS): socks.c proxy.h structures.h
	$(CC) $(COUT)srvsocks$(OBJSUFFICS) $(CFLAGS) socks.c

srvwebadmin$(OBJSUFFICS): webadmin.c proxy.h structures.h
	$(CC) $(COUT)srvwebadmin$(OBJSUFFICS) $(CFLAGS) webadmin.c

srvudppm$(OBJSUFFICS): udppm.c proxy.h structures.h
	$(CC) $(COUT)srvudppm$(OBJSUFFICS) $(CFLAGS) udppm.c

srvdnspr$(OBJSUFFICS): dnspr.c proxy.h structures.h
	$(CC) $(COUT)srvdnspr$(OBJSUFFICS) $(CFLAGS) dnspr.c

auth$(OBJSUFFICS): auth.c proxy.h structures.h
	$(CC) $(COUT)auth$(OBJSUFFICS) $(CFLAGS) auth.c

authradius$(OBJSUFFICS): authradius.c proxy.h structures.h
	$(CC) $(COUT)authradius$(OBJSUFFICS) $(CFLAGS) authradius.c

conf$(OBJSUFFICS): conf.c proxy.h structures.h
	$(CC) $(COUT)conf$(OBJSUFFICS) $(CFLAGS) conf.c

datatypes$(OBJSUFFICS): datatypes.c proxy.h structures.h
	$(CC) $(COUT)datatypes$(OBJSUFFICS) $(CFLAGS) datatypes.c

mycrypt$(OBJSUFFICS): mycrypt.c
	$(CC) $(COUT)mycrypt$(OBJSUFFICS) $(CFLAGS) mycrypt.c

mycryptmain$(OBJSUFFICS): mycrypt.c
	$(CC) $(COUT)mycryptmain$(OBJSUFFICS) $(CFLAGS) $(DEFINEOPTION)WITHMAIN mycrypt.c

$(BUILDDIR)mycrypt$(EXESUFFICS): md4$(OBJSUFFICS) md5$(OBJSUFFICS) mycryptmain$(OBJSUFFICS) base64$(OBJSUFFICS)
	$(LN) $(LNOUT)$(BUILDDIR)mycrypt$(EXESUFFICS) $(LDFLAGS) md4$(OBJSUFFICS) md5$(OBJSUFFICS) base64$(OBJSUFFICS) mycryptmain$(OBJSUFFICS)


md4$(OBJSUFFICS):  libs/md4.h libs/md4.c
	$(CC) $(COUT)md4$(OBJSUFFICS) $(CFLAGS) libs/md4.c

smbdes$(OBJSUFFICS):  libs/smbdes.c
	$(CC) $(COUT)smbdes$(OBJSUFFICS) $(CFLAGS) libs/smbdes.c

md5$(OBJSUFFICS):  libs/md5.h libs/md5.c
	$(CC) $(COUT)md5$(OBJSUFFICS) $(CFLAGS) libs/md5.c

ntlm$(OBJSUFFICS):  ntlm.c
	$(CC) $(COUT)ntlm$(OBJSUFFICS) $(CFLAGS) ntlm.c

stringtable$(OBJSUFFICS):  stringtable.c
	$(CC) $(COUT)stringtable$(OBJSUFFICS) $(CFLAGS) stringtable.c

$(BUILDDIR)3proxy$(EXESUFFICS): 3proxy$(OBJSUFFICS) mainfunc$(OBJSUFFICS) srvproxy$(OBJSUFFICS) srvpop3p$(OBJSUFFICS) srvsmtpp$(OBJSUFFICS) srvftppr$(OBJSUFFICS) srvsocks$(OBJSUFFICS) srvtcppm$(OBJSUFFICS) srvudppm$(OBJSUFFICS) sockmap$(OBJSUFFICS) sockgetchar$(OBJSUFFICS) myalloc$(OBJSUFFICS) common$(OBJSUFFICS) auth$(OBJSUFFICS) authradius$(OBJSUFFICS) conf$(OBJSUFFICS) datatypes$(OBJSUFFICS) md4$(OBJSUFFICS) md5$(OBJSUFFICS) mycrypt$(OBJSUFFICS) base64$(OBJSUFFICS) ftp$(OBJSUFFICS) smbdes$(OBJSUFFICS) ntlm$(OBJSUFFICS) stringtable$(OBJSUFFICS) srvwebadmin$(OBJSUFFICS) srvdnspr$(OBJSUFFICS) plugins$(OBJSUFFICS) client_limits$(OBJSUFFICS) $(COMPATLIBS)
	$(LN) $(LNOUT)$(BUILDDIR)3proxy$(EXESUFFICS) $(LDFLAGS) $(VERFILE)  3proxy$(OBJSUFFICS) mainfunc$(OBJSUFFICS) auth$(OBJSUFFICS) authradius$(OBJSUFFICS) conf$(OBJSUFFICS) datatypes$(OBJSUFFICS) srvproxy$(OBJSUFFICS) srvpop3p$(OBJSUFFICS) srvsmtpp$(OBJSUFFICS) srvftppr$(OBJSUFFICS) srvsocks$(OBJSUFFICS) srvtcppm$(OBJSUFFICS) srvudppm$(OBJSUFFICS) sockmap$(OBJSUFFICS) sockgetchar$(OBJSUFFICS) myalloc$(OBJSUFFICS) common$(OBJSUFFICS) mycrypt$(OBJSUFFICS) md5$(OBJSUFFICS) md4$(OBJSUFFICS) base64$(OBJSUFFICS) ftp$(OBJSUFFICS) smbdes$(OBJSUFFICS) ntlm$(OBJSUFFICS) stringtable$(OBJSUFFICS) srvwebadmin$(OBJSUFFICS) srvdnspr$(OBJSUFFICS) plugins$(OBJSUFFICS) client_limits$(OBJSUFFICS) $(COMPATLIBS) $(LIBS)

clean:
	@$(REMOVECOMMAND) *$(OBJSUFFICS) $(COMPFILES)
