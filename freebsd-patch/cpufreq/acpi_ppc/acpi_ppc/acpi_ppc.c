/*-
 * Copyright (c) 2004-2008 FUKUDA Nobuhiko <nfukuda@spa.is.uec.ac.jp>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * [acpi_ppc/20080615]
 */

/*
 * acpi_ppc.c: ACPI Processor Performance Control Module for FreeBSD
 *
 * Reference:
 *   - ACPI Specification Revision 2.0c, pp.232-236
 *
 * Sysctl:
 *   - hw.acpi.cpu.px_control: -1 = auto control, 0 <= fixed state (RW)
 *   - hw.acpi.cpu.px_highest: highest state (RW)
 *   - hw.acpi.cpu.px_lowest: lowest state (RD)
 *   - hw.acpi.cpu.px_current: current state (RD)
 *   - hw.acpi.cpu.px_supported: supported frequencies (RD)
 *   - hw.acpi.cpu.px_usage: percent usage for each Px state (RD)
 *
 * Auto control algorithm:
 *   - get CPU usage in every 0.5 seconds (busy%)
 *   - change performance:
 *     - up: busy% > 98%
 *     - down: busy% <= (98 * P[n+1]_freq / P[n]_freq)%
 *   - ex. ULV Mobile Intel Pentium III-M 933MHz (Enhanced SpeedStep)
 *     - has 2 states: P0_freq = 933MHz, P1_freq = 400MHz
 *
 *         98%                        42%            (busy%)
 *   100%|--+--------------------------+-------------------|0%
 *     P0|              *0            ->1                  |
 *     P1|0<-                      *1                      |
 *
 *   - ex. AMD Athlon 64 3000+ Rev.C0 (Cool'n'Quiet)
 *     - has 3 states: P0_freq = 2000MHz, P1_freq = 1800MHz, P2_freq = 800MHz
 *
 *         98% 88%                    43%            (busy%)
 *   100%|--+---+----------------------+-------------------|0%
 *     P0|  *0 ->1                                         |
 *     P1|0<-            *1           ->2                  |
 *     P2|1<-                      *2                      |
 *
 */

/**********************************************************************/
#include "opt_acpi.h"
#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/bus.h>
#include <sys/module.h>
#include <sys/sbuf.h>

#include "acpi.h"
#include <dev/acpica/acpivar.h>
/**********************************************************************/

#include <sys/resource.h>
#include <sys/systm.h>
#include <sys/time.h>

/*
 * glue for 4.x
 */
#if __FreeBSD_version < 500000

#include <machine/clock.h>

#include <sys/dkstat.h>

typedef u_int64_t uintmax_t;

#define ACPI_PKG_VALID(pkg, size)		\
    ((pkg) != NULL &&				\
    (pkg)->Type == ACPI_TYPE_PACKAGE &&		\
    (pkg)->Package.Count >= (size))

#endif	/* __FreeBSD_version < 500000 */

/*
 * glue for 5.2.1
 */
#if __FreeBSD_version < 502120

#define acpi_PkgInt32(res, idx, dst)			\
    do {						\
	ACPI_OBJECT *object;				\
	object = &(res)->Package.Elements[idx];		\
	if (object != NULL)				\
	    *(dst) = (u_int32_t)object->Integer.Value;	\
    } while (0)

#define ACPI_DRIVER_VERSION	100
#define ACPI_CPU_DRIVER_NAME	"acpi_cpu"

#else	/* __FreeBSD_version < 502120 */

#define ACPI_DRIVER_VERSION	1
#define ACPI_CPU_DRIVER_NAME	"cpu"

#endif	/* __FreeBSD_version < 502120 */

/*
 * glue for 7.0
 */
#if __FreeBSD_version < 700035

#define SpaceId			AddressSpaceId
#define BitWidth		RegisterBitWidth

#else	/* __FreeBSD_version < 700035 */

#define ACPI_VALID_ADDRESS(a)	(a)

#endif	/* __FreeBSD_version < 700035 */

/*
 * glue for 7.1
 */
#if __FreeBSD_version < 700103

#define read_cpu_time(ptr)	bcopy(cp_time, (ptr), sizeof(cp_time))

#endif	/* __FreeBSD_version < 700103 */

#if defined(__i386__) || defined(__amd64__)
#include <machine/cputypes.h>
#include <machine/md_var.h>
#endif	/* __i386__ || __amd64__ */

#ifndef ACPI_PPC_THRESHOLD_HIGH
#define ACPI_PPC_THRESHOLD_HIGH	98
#endif	/* ACPI_PPC_THRESHOLD_HIGH */

#ifndef ACPI_PPC_THRESHOLD_LOW
#define ACPI_PPC_THRESHOLD_LOW	98
#endif	/* ACPI_PPC_THRESHOLD_LOW */

struct acpi_px {
    u_int32_t		 frequency;
    u_int32_t		 control;
    u_int32_t		 status;
    u_int32_t		 threshold;
};
#define MAX_PX_STATES	 16

struct acpi_px_stats {
    u_int		 usage;
};

struct acpi_px_reg {
    u_long		 address;
    u_int		 bitwidth;
};

struct acpi_cpu_softc;
typedef int (*acpi_cpu_px_transit_t)(struct acpi_cpu_softc *sc);

/********************************************************************/
struct acpi_cpu_softc {
    device_t		 cpu_dev;
    ACPI_HANDLE		 cpu_handle;

    struct acpi_px	 cpu_px_states[MAX_PX_STATES];
    int			 cpu_px_count, cpu_px_state;
    struct acpi_px_reg	 cpu_px_control, cpu_px_status;
    acpi_cpu_px_transit_t cpu_px_transit;
};
static struct acpi_cpu_softc cpu0_softc;
static struct acpi_cpu_softc *cpu_softc[] = {
    &cpu0_softc
};

static struct sysctl_ctx_list acpi_cpu_sysctl_ctx;
static struct sysctl_oid *acpi_cpu_sysctl_tree;
/********************************************************************/

static int	acpi_cpu_px_probe(struct acpi_cpu_softc *sc);
static void	acpi_cpu_startup_px(void);

static int	cpu_px_control, cpu_px_highest, cpu_px_lowest, cpu_px_current;
static char	cpu_px_supported[128];
static struct acpi_px_stats	cpu_px_stats[MAX_PX_STATES];

static struct callout_handle
	cpu_px_timer_handle = CALLOUT_HANDLE_INITIALIZER(&cpu_px_timer_handle);

static int	acpi_cpu_px_evaluate(u_int high, u_int low);
static void	acpi_cpu_px_timer(void *arg);

static int	acpi_cpu_px_control_sysctl(SYSCTL_HANDLER_ARGS);
static int	acpi_cpu_px_highest_sysctl(SYSCTL_HANDLER_ARGS);
static int	acpi_cpu_px_usage_sysctl(SYSCTL_HANDLER_ARGS);

static int	acpi_cpu_px_transit_io(struct acpi_cpu_softc *sc);
#if defined(__i386__) || defined(__amd64__)
static int	acpi_cpu_px_transit_k8(struct acpi_cpu_softc *sc);
#endif	/* __i386__ || __amd64__ */
#if defined(__i386__)
static int	acpi_cpu_px_transit_k7(struct acpi_cpu_softc *sc);
#endif	/* __i386__ */

static int
acpi_cpu_px_probe(struct acpi_cpu_softc *sc)
{
    ACPI_STATUS status;
    ACPI_BUFFER buffer;
    ACPI_OBJECT *obj, *pctpkg, *psspkg;
    ACPI_GENERIC_ADDRESS gas;
    char *method = "Unknown, disabled";
    int i, error = ENXIO;

    KASSERT(sc != NULL, "Null sc");

    pctpkg = NULL;
    psspkg = NULL;

    sc->cpu_px_transit = NULL;

    /* 8.3.3.1 _PCT (Performance Control) */
    buffer.Pointer = NULL;
    buffer.Length = ACPI_ALLOCATE_BUFFER;
    status = AcpiEvaluateObject(sc->cpu_handle, "_PCT", NULL, &buffer);
    pctpkg = buffer.Pointer;
    if (ACPI_FAILURE(status) || !ACPI_PKG_VALID(pctpkg, 2))
	goto done;

    /* Performance Control Register */
    obj = &pctpkg->Package.Elements[0];
    if (obj != NULL && obj->Buffer.Length < sizeof(ACPI_GENERIC_ADDRESS) + 3)
	goto done;

    memcpy(&gas, obj->Buffer.Pointer + 3, sizeof(gas));
    switch (gas.SpaceId) {
    case ACPI_ADR_SPACE_SYSTEM_IO:
	if (!ACPI_VALID_ADDRESS(gas.Address))
	    goto done;
	sc->cpu_px_control.address = gas.Address;
	sc->cpu_px_control.bitwidth = gas.BitWidth;
	break;
    case ACPI_ADR_SPACE_FIXED_HARDWARE:
	sc->cpu_px_control.bitwidth = 0;
	break;
    default:
	goto done;
    }

    /* Performance Status Register */
    obj = &pctpkg->Package.Elements[1];
    if (obj != NULL && obj->Buffer.Length < sizeof(ACPI_GENERIC_ADDRESS) + 3)
	goto done;

    memcpy(&gas, obj->Buffer.Pointer + 3, sizeof(gas));
    switch (gas.SpaceId) {
    case ACPI_ADR_SPACE_SYSTEM_IO:
	if (!ACPI_VALID_ADDRESS(gas.Address))
	    goto done;
	sc->cpu_px_status.address = gas.Address;
	sc->cpu_px_status.bitwidth = gas.BitWidth;
	break;
    case ACPI_ADR_SPACE_FIXED_HARDWARE:
	sc->cpu_px_status.bitwidth = 0;
	break;
    default:
	goto done;
    }

    /* 8.3.3.2 _PSS (Performance Supported States) */
    buffer.Pointer = NULL;
    buffer.Length = ACPI_ALLOCATE_BUFFER;
    status = AcpiEvaluateObject(sc->cpu_handle, "_PSS", NULL, &buffer);
    psspkg = buffer.Pointer;
    if (ACPI_FAILURE(status) || psspkg->Type != ACPI_TYPE_PACKAGE)
	goto done;

    sc->cpu_px_count = psspkg->Package.Count;
    if (sc->cpu_px_count > MAX_PX_STATES)
	sc->cpu_px_count = MAX_PX_STATES;

    for (i = 0; i < sc->cpu_px_count; i++) {
	u_int32_t freq, power, tlat, bmlat, control, status;

	obj = &psspkg->Package.Elements[i];
	if (!ACPI_PKG_VALID(obj, 6))
	    break;

	acpi_PkgInt32(obj, 0, &freq);
	acpi_PkgInt32(obj, 1, &power);
	acpi_PkgInt32(obj, 2, &tlat);
	acpi_PkgInt32(obj, 3, &bmlat);
	acpi_PkgInt32(obj, 4, &control);
	acpi_PkgInt32(obj, 5, &status);

	if (freq == 0 || freq > 0x7fff)
	    break;

	device_printf(sc->cpu_dev, "Px state: P%u, %uMHz, %umW, %uus, %uus\n",
		i, freq, power, tlat, bmlat);

	sc->cpu_px_states[i].frequency = freq;
	sc->cpu_px_states[i].control = control;
	sc->cpu_px_states[i].status = status;
    }

    sc->cpu_px_count = i;
    if (sc->cpu_px_count < 1)
	goto done;

    for (i = 0; i < sc->cpu_px_count - 1; i++) {
	sc->cpu_px_states[i].threshold = ACPI_PPC_THRESHOLD_LOW *
		sc->cpu_px_states[i + 1].frequency /
		sc->cpu_px_states[i].frequency;
    }

    /* method decision */
    if (sc->cpu_px_control.bitwidth != 0 && sc->cpu_px_status.bitwidth != 0) {
	sc->cpu_px_transit = acpi_cpu_px_transit_io;
	method = "ACPI Generic I/O Port";
    }

#if defined(__i386__) || defined(__amd64__)
    if (strcmp(cpu_vendor, "AuthenticAMD") == 0) {
	u_int32_t regs[4];

	switch (cpu_id & 0x0f000f00) {
	case 0x00000600: /* K7 family */
	case 0x00000f00: /* K8 family */
	    do_cpuid(0x80000000, regs);
	    if (regs[0] < 0x80000007)	/* EAX[31:0] */
		break;
	    do_cpuid(0x80000007, regs);
	    if ((regs[3] & 0x6) != 0x6)	/* EDX[2:1] = 11b */
		break;

	    do_cpuid(0x80000001, regs);
	    if ((regs[0] & 0xf00) == 0xf00) {	/* EAX[11:0] */
		sc->cpu_px_transit = acpi_cpu_px_transit_k8;
		method = "AMD K8 Cool'n'Quiet";
#if defined(__i386__)
	    } else if ((regs[0] & 0xfff) != 0x760) {
		/* fudged workaround for K7 660 stepping A0 */
		sc->cpu_px_transit = acpi_cpu_px_transit_k7;
		method = "AMD K7 PowerNow!";
#endif	/* __i386__ */
	    }
	    break;
	}
    }
#endif	/* __i386__ || __amd64__ */

    device_printf(sc->cpu_dev, "Px method: %s\n", method);

    if (sc->cpu_px_transit != NULL)
	error = 0;

done:
    if (pctpkg != NULL)
	AcpiOsFree(pctpkg);
    if (psspkg != NULL)
	AcpiOsFree(psspkg);

    return error;
}

static void
acpi_cpu_startup_px(void)
{
    struct acpi_cpu_softc *sc = cpu_softc[0];
    struct sbuf sb;
    int i;

    cpu_px_control = -1;
    cpu_px_highest = 0;
    cpu_px_lowest = sc->cpu_px_count - 1;
    cpu_px_current = cpu_px_highest;

    sbuf_new(&sb, cpu_px_supported, sizeof(cpu_px_supported), SBUF_FIXEDLEN);
    for (i = 0; i <= cpu_px_lowest; i++)
	sbuf_printf(&sb, "%u ", sc->cpu_px_states[i].frequency);
    sbuf_trim(&sb);
    sbuf_finish(&sb);

    SYSCTL_ADD_PROC(&acpi_cpu_sysctl_ctx,
	SYSCTL_CHILDREN(acpi_cpu_sysctl_tree),
	OID_AUTO, "px_control", CTLTYPE_INT | CTLFLAG_RW,
	&cpu_px_control, 0, acpi_cpu_px_control_sysctl, "I", "");
    SYSCTL_ADD_PROC(&acpi_cpu_sysctl_ctx,
	SYSCTL_CHILDREN(acpi_cpu_sysctl_tree),
	OID_AUTO, "px_highest", CTLTYPE_INT | CTLFLAG_RW,
	&cpu_px_highest, 0, acpi_cpu_px_highest_sysctl, "I", "");
    SYSCTL_ADD_INT(&acpi_cpu_sysctl_ctx,
	SYSCTL_CHILDREN(acpi_cpu_sysctl_tree),
	OID_AUTO, "px_lowest", CTLFLAG_RD,
	&cpu_px_lowest, 0, "");
    SYSCTL_ADD_INT(&acpi_cpu_sysctl_ctx,
	SYSCTL_CHILDREN(acpi_cpu_sysctl_tree),
	OID_AUTO, "px_current", CTLFLAG_RD,
	&cpu_px_current, 0, "");
    SYSCTL_ADD_STRING(&acpi_cpu_sysctl_ctx,
	SYSCTL_CHILDREN(acpi_cpu_sysctl_tree),
	OID_AUTO, "px_supported", CTLFLAG_RD,
	&cpu_px_supported, 0, "");
    SYSCTL_ADD_PROC(&acpi_cpu_sysctl_ctx,
	SYSCTL_CHILDREN(acpi_cpu_sysctl_tree),
	OID_AUTO, "px_usage", CTLTYPE_STRING | CTLFLAG_RD,
	NULL, 0, acpi_cpu_px_usage_sysctl, "A", "");

    cpu_px_timer_handle = timeout(acpi_cpu_px_timer, NULL, 0);
}

static int
acpi_cpu_px_evaluate(u_int high, u_int low)
{
    static int initialized = 0;
    static long new_cpt[CPUSTATES], old_cpt[CPUSTATES];

    int i, state = cpu_px_current;

    read_cpu_time(new_cpt);

    if (!initialized) {
	initialized = 1;
    } else if (cpu_px_control < 0) {
	long sum = 0;
	int busy = 0;

	for (i = 0; i < CPUSTATES; i++)
	    sum += new_cpt[i] - old_cpt[i];
	if (sum > 0)
	    busy = 100 - (new_cpt[4] - old_cpt[4]) * 100 / sum;

	if (busy > high) {
	    if (state > cpu_px_highest)
		state--;
	} else if (state < cpu_px_lowest) {
	    if (busy <= low)
		state++;
	}
    } else {
	state = cpu_px_control;
    }

    bcopy(new_cpt, old_cpt, sizeof(old_cpt));

    if (state < cpu_px_highest)
	state = cpu_px_highest;

    if (state != cpu_px_current) {
	if (state < cpu_px_current)
	    state = cpu_px_current - 1;
	else /* state > cpu_px_current */
	    state = cpu_px_current + 1;
    }

    return state;
}

static void
acpi_cpu_px_timer(void *arg)
{
    struct acpi_cpu_softc *sc = cpu_softc[0];
    int high, low, state;

    high = ACPI_PPC_THRESHOLD_HIGH;
    low = sc->cpu_px_states[cpu_px_current].threshold;

    state = acpi_cpu_px_evaluate(high, low);
    if (state != cpu_px_current) {
	sc->cpu_px_state = state;
	if (sc->cpu_px_transit != NULL && sc->cpu_px_transit(sc) == 0)
	    cpu_px_current = state;
    }
    cpu_px_stats[state].usage++;

    cpu_px_timer_handle = timeout(acpi_cpu_px_timer, arg, hz / 2);
}

static int
acpi_cpu_px_control_sysctl(SYSCTL_HANDLER_ARGS)
{
    int error, val = cpu_px_control;

    error = sysctl_handle_int(oidp, &val, 0, req);
    if (error != 0 || req->newptr == NULL)
	return error;
    if (val < -1 || val > cpu_px_lowest)
	return EINVAL;
    if (val >= 0 && val < cpu_px_highest)
	val = cpu_px_highest;

    cpu_px_control = val;
    return 0;
}

static int
acpi_cpu_px_highest_sysctl(SYSCTL_HANDLER_ARGS)
{
    int error, val = cpu_px_highest;

    error = sysctl_handle_int(oidp, &val, 0, req);
    if (error != 0 || req->newptr == NULL)
	return error;
    if (val < 0 || val > cpu_px_lowest)
	return EINVAL;
    if (cpu_px_control >= 0 && cpu_px_control < val)
	cpu_px_control = val;

    cpu_px_highest = val;
    return 0;
}

static int
acpi_cpu_px_usage_sysctl(SYSCTL_HANDLER_ARGS)
{
    struct sbuf sb;
    char buf[128];
    int i;
    uintmax_t sum, whole, fract;

    sum = 0;
    for (i = 0; i <= cpu_px_lowest; i++)
	sum += (uintmax_t)cpu_px_stats[i].usage;
    sbuf_new(&sb, buf, sizeof(buf), SBUF_FIXEDLEN);
    for (i = 0; i <= cpu_px_lowest; i++) {
	if (sum > 0) {
	    whole = (uintmax_t)cpu_px_stats[i].usage * 100;
	    fract = (whole % sum) * 100;
	    sbuf_printf(&sb, "%u.%02u%% ",
	    	(u_int)(whole / sum), (u_int)(fract / sum));
	} else sbuf_printf(&sb, "0%% ");
    }
    sbuf_trim(&sb);
    sbuf_finish(&sb);
    sysctl_handle_string(oidp, sbuf_data(&sb), sbuf_len(&sb), req);
    sbuf_delete(&sb);

    return 0;
}

/*
 * ACPI Generic I/O Port
 *
 * Reference:
 *   - linux-2.6.3/arch/i386/kernel/cpu/cpufreq/acpi.c
 */
static int
acpi_cpu_px_transit_io(struct acpi_cpu_softc *sc)
{
    int i, state;

    KASSERT(sc != NULL, "Null sc");

    state = sc->cpu_px_state;

    AcpiOsWritePort(sc->cpu_px_control.address,
	sc->cpu_px_states[state].control, sc->cpu_px_control.bitwidth);

    for (i = 0; i < 100; i++) {
	u_int32_t status = 0;
	AcpiOsReadPort(sc->cpu_px_status.address,
	    &status, sc->cpu_px_status.bitwidth);
	if (status == sc->cpu_px_states[state].status)
	    return 0;
	DELAY(10);
    }

    return -1;
}

#if defined(__i386__) || defined(__amd64__)
/*
 * AMD K8 Cool'n'Quiet
 *
 * Reference:
 *   - BIOS and Kernel Developer's Guide
 *     for the AMD Athlon 64 and AMD Opteron Processors, 26094 Rev.3.12
 *   - linux-2.6.3/arch/i386/kernel/cpu/cpufreq/powernow-k8.[ch]
 */

#define MSR_FIDVID_CTL		0xc0010041
#define MSR_FIDVID_STATUS	0xc0010042

#define write_control(qw)	wrmsr(MSR_FIDVID_CTL, (qw))
#define read_status()		rdmsr(MSR_FIDVID_STATUS)

#define control_irt(dw)		(((dw) >> 30) & 0x3)
#define control_rvo(dw)		(((dw) >> 28) & 0x3)
#define control_pll(dw)		(((dw) >> 20) & 0x7f)
#define control_mvs(dw)		(((dw) >> 18) & 0x3)
#define control_vst(dw)		(((dw) >> 11) & 0x7f)
#define control_vid(dw)		(((dw) >> 6) & 0x1f)
#define control_fid(dw)		((dw) & 0x3f)

#define status_vid(qw)		(((qw) >> 32) & 0x1f)
#define status_fid(qw)		((qw) & 0x3f)

#define count_off_irt(irt)	DELAY(10 * (1 << (irt)))
#define count_off_vst(vst)	DELAY(20 * (vst))

#define FID_TO_VCO_FID(fid)	(((fid) < 8) ? 8 + ((fid) << 1) : (fid))

#define write_fidvid(fid, vid, cnt)	\
    write_control(((cnt) << 32) | (1ULL << 16) | ((vid) << 8) | (fid))
#define READ_PENDING_WAIT(qw)	\
    do { (qw) = read_status(); } while ((qw) & (1ULL << 31))

static int
acpi_cpu_px_transit_k8(struct acpi_cpu_softc *sc)
{
    int state;
    u_int irt, rvo, pll, mvs, vst, vid, fid;
    u_int val, rvo_steps, cur_vid, cur_fid, vco_fid, vco_cur_fid, vco_diff;
    u_int64_t v64;

    KASSERT(sc != NULL, "Null sc");

    state = sc->cpu_px_state;

    v64 = sc->cpu_px_states[state].control;
    irt = control_irt(v64);
    rvo = control_rvo(v64);
    pll = control_pll(v64);
    mvs = control_mvs(v64);
    vst = control_vst(v64);
    vid = control_vid(v64);
    fid = control_fid(v64);

    READ_PENDING_WAIT(v64);
    cur_vid = status_vid(v64);
    cur_fid = status_fid(v64);

    /* Phase 1 */
    while (cur_vid > vid) {
	val = cur_vid - (1 << mvs);
	write_fidvid(cur_fid, (val > 0) ? val : 0, 1ULL);
	READ_PENDING_WAIT(v64);
	cur_vid = status_vid(v64);
	count_off_vst(vst);
    }

    for (rvo_steps = rvo; rvo_steps > 0 && cur_vid > 0; rvo_steps--) {
	write_fidvid(cur_fid, cur_vid - 1, 1ULL);
	READ_PENDING_WAIT(v64);
	cur_vid = status_vid(v64);
	count_off_vst(vst);
    }

    /* Phase 2 */
    if (cur_fid != fid) {
	vco_fid = FID_TO_VCO_FID(fid);
	vco_cur_fid = FID_TO_VCO_FID(cur_fid);
	vco_diff = (vco_cur_fid < vco_fid) ?
	    vco_fid - vco_cur_fid : vco_cur_fid - vco_fid;
	while (vco_diff > 2) {
	    if (fid > cur_fid) {
		if (cur_fid > 6)
		    val = cur_fid + 2;
		else
		    val = FID_TO_VCO_FID(cur_fid) + 2;
	    } else {
		val = cur_fid - 2;
	    }
	    write_fidvid(val, cur_vid, pll * 200ULL);
	    READ_PENDING_WAIT(v64);
	    cur_fid = status_fid(v64);
	    count_off_irt(irt);

	    vco_cur_fid = FID_TO_VCO_FID(cur_fid);
	    vco_diff = (vco_cur_fid < vco_fid) ?
		vco_fid - vco_cur_fid : vco_cur_fid - vco_fid;
	}

	write_fidvid(fid, cur_vid, pll * 200ULL);
	READ_PENDING_WAIT(v64);
	cur_fid = status_fid(v64);
	count_off_irt(irt);
    }

    /* Phase 3 */
    if (cur_vid != vid) {
	write_fidvid(cur_fid, vid, 1ULL);
	READ_PENDING_WAIT(v64);
	cur_vid = status_vid(v64);
	count_off_vst(vst);
    }

    /* Done */
    if (cur_vid == vid && cur_fid == fid)
	return 0;

    return -1;
}
#endif	/* __i386__ || __amd64__ */

#if defined(__i386__)
/*
 * AMD K7 PowerNow!
 *
 * Reference:
 *   - Mobile AMD Athlon 4 Processor Model 6 CPGA Data Sheet, 24319 Rev.E
 *   - linux-2.6.11.9/arch/i386/kernel/cpu/cpufreq/powernow-k7.[ch]
 */

#define k7_control_sgtc(dw)	(((dw) >> 10) & 0xfffff)
#define k7_control_vid(dw)	(((dw) >> 5) & 0x1f)
#define k7_control_fid(dw)	((dw) & 0x1f)

#define k7_status_cvid(qw)	(((qw) >> 32) & 0x1f)
#define k7_status_cfid(qw)	((qw) & 0x1f)

#define k7_write_fid(fid, sgtc)	\
    write_control(((u_int64_t)(sgtc) << 32) | (1ULL << 16) | (fid))
#define k7_write_vid(vid, sgtc)	\
    write_control(((u_int64_t)(sgtc) << 32) | (2ULL << 16) | ((vid) << 8))

static int
acpi_cpu_px_transit_k7(struct acpi_cpu_softc *sc)
{
    int state;
    u_int32_t sgtc, vid, fid;
    u_int32_t cur_vid, cur_fid;
    u_int64_t v64;

    KASSERT(sc != NULL, "Null sc");

    state = sc->cpu_px_state;

    v64 = sc->cpu_px_states[state].control;
    sgtc = k7_control_sgtc(v64);
    vid = k7_control_vid(v64);
    fid = k7_control_fid(v64);

    v64 = read_status();
    cur_vid = k7_status_cvid(v64);
    cur_fid = k7_status_cfid(v64);

    /* Already done */
    if (cur_vid == vid && cur_fid == fid)
	return 0;

    /* Change state */
    if (cur_vid > vid) {
	k7_write_fid(fid, sgtc);
	k7_write_vid(vid, sgtc);
    } else {
	k7_write_vid(vid, sgtc);
	k7_write_fid(fid, sgtc);
    }

    v64 = read_status();
    cur_vid = k7_status_cvid(v64);
    cur_fid = k7_status_cfid(v64);

    /* Done */
    if (cur_vid == vid && cur_fid == fid)
	return 0;

    return -1;
}
#endif	/* __i386__ */

/**********************************************************************/
static int acpi_ppc_mod_event(module_t mod, modeventtype_t cmd, void *arg);

static moduledata_t acpi_ppc_mod = {
    "acpi_ppc",
    (modeventhand_t)acpi_ppc_mod_event,
    NULL
};
DECLARE_MODULE(acpi_ppc, acpi_ppc_mod, SI_SUB_PSEUDO, SI_ORDER_ANY);
MODULE_VERSION(acpi_ppc, 1);
MODULE_DEPEND(acpi_ppc, acpi,
	ACPI_DRIVER_VERSION, ACPI_DRIVER_VERSION, ACPI_DRIVER_VERSION);

static int
acpi_ppc_mod_event(module_t mod, modeventtype_t cmd, void *arg)
{
    struct acpi_cpu_softc *sc = cpu_softc[0];
    struct acpi_softc *acpi_sc;
    device_t dev;
    int error = 0;

    switch (cmd) {
    case MOD_LOAD:
	if (acpi_disabled("cpu"))
	    break;

	/* acpi0 */
	acpi_sc = devclass_get_softc(devclass_find("acpi"), 0);
	if (acpi_sc == NULL)
	    break;

	/* cpu0 */
	dev = devclass_get_device(devclass_find(ACPI_CPU_DRIVER_NAME), 0);
	if (dev == NULL)
	    break;

	sc->cpu_dev = dev;
	sc->cpu_handle = acpi_get_handle(dev);
	if (acpi_cpu_px_probe(sc) != 0)
	    break;

	sysctl_ctx_init(&acpi_cpu_sysctl_ctx);
	acpi_cpu_sysctl_tree = SYSCTL_ADD_NODE(&acpi_cpu_sysctl_ctx,
	    SYSCTL_CHILDREN(acpi_sc->acpi_sysctl_tree),
	    OID_AUTO, "cpu", CTLFLAG_RD, 0, "");

	acpi_cpu_startup_px();
	break;

    case MOD_UNLOAD:
    case MOD_SHUTDOWN:
	if (sc->cpu_px_transit == NULL)
	    break;

	sysctl_ctx_free(&acpi_cpu_sysctl_ctx);
	untimeout(acpi_cpu_px_timer, NULL, cpu_px_timer_handle);

	/* reset to highest state */
	while (cpu_px_current > 0) {
	    sc->cpu_px_state = --cpu_px_current;
	    if (sc->cpu_px_transit(sc) < 0)
		break;
	}
	break;

    default:
	error = EINVAL;
	break;
    }

    return error;
}
/**********************************************************************/
