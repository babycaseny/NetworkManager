EXTRA_DIST = NetworkManager.conf

INCLUDES = 					   \
	$(NM_CFLAGS) 			   \
	-DDBUS_API_SUBJECT_TO_CHANGE		   \
	-DBINDIR=\"$(bindir)\"			   \
	-DDATADIR=\"$(datadir)\"

bin_PROGRAMS = NetworkManager

NetworkManager_SOURCES =				\
		NetworkManagerAP.c			\
		NetworkManagerAP.h			\
		NetworkManagerDbus.c		\
		NetworkManagerDbus.h		\
		NetworkManagerDevice.c		\
		NetworkManagerDevice.h		\
		NetworkManager.c			\
		NetworkManager.h			\
		NetworkManagerPolicy.c		\
		NetworkManagerPolicy.h		\
		NetworkManagerUtils.c		\
		NetworkManagerUtils.h		\
		NetworkManagerWireless.c		\
		NetworkManagerWireless.h

NetworkManager_LDADD = $(NM_LIBS) $(IWLIB)

dbusservicedir = $(sysconfdir)/dbus-1/system.d
dbusservice_DATA = NetworkManager.conf

