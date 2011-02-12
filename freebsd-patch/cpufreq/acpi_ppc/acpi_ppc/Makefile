KMOD =		acpi_ppc
SRCS =		acpi_ppc.c
SRCS +=		device_if.h bus_if.h opt_acpi.h
CFLAGS +=	-I@/contrib/dev/acpica
KMODDIR ?=	/boot/modules

#CFLAGS +=	-DACPI_PPC_THRESHOLD_HIGH=98 
#CFLAGS +=	-DACPI_PPC_THRESHOLD_LOW=98 

.if !defined(OSVERSION)
OSVERSION !=	/sbin/sysctl -n kern.osreldate
.endif

.if ${OSVERSION} >= 502120
SRCS +=		acpi_if.h
.endif

.include <bsd.kmod.mk>
