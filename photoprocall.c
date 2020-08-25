/*
** ATOP - System & Process Monitor 
**
** This program is free software; you can redistribute it and/or modify it
** under the terms of the GNU General Public License as published by the
** Free Software Foundation; either version 2, or (at your option) any
** later version.
**
** This program is distributed in the hope that it will be useful, but
** WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
** See the GNU General Public License for more details.
**
** You should have received a copy of the GNU General Public License
** along with this program; if not, write to the Free Software
** Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
** --------------------------------------------------------------------------
**
** Experiment to benchmark the /proc/all idea
*/

#include <sys/types.h>
#include <sys/param.h>
#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include <time.h>

#include "atop.h"
#include "photoproc.h"

#define	SCANSTAT 	"%c   %d   %*d  %*d  %*d  %*d  "	\
			"%*d  %lld %*d  %lld %*d  %lld "	\
			"%lld %*d  %*d  %d   %d   %*d  "	\
			"%*d  %ld %lld %lld %*d  %*d  "	\
			"%*d  %*d  %*d  %*d  %*d  %*d  " 	\
			"%*d  %*d  %*d  %*d  %*d  %*d  "	\
			"%d   %d   %d "

/* ATOP-extension line of /proc/pid/stat */
#define ATOPSTAT	"%lld %llu %lld %llu %lld %llu %lld %llu "	\
			"%lld %llu %lld %llu %lld %lld"

static int	procallstat(struct tstat *, int, unsigned long long, char);
static int	procallstatus(struct tstat *, int);
static int	procallio(struct tstat *, int);
static int	procallcont(struct tstat *, int, char *);
static count_t	procallschedstat(struct tstat *, int);

unsigned long
photoprocall(struct tstat *tasklist, int maxtask)
{
	static int			firstcall = 1;
	static unsigned long long	bootepoch;

	FILE		*fp;
	char		dockstat=0;
	int		ret;

	/*
	** one-time initialization stuff
	*/
	if (firstcall)
	{
		/*
		** check if this kernel offers io-statistics per task
		*/
		regainrootprivs();

		if ( (fp = fopen("/proc/1/io", "r")) )
		{
			supportflags |= IOSTAT;
			fclose(fp);
		}

		if (! droprootprivs())
			mcleanstop(42, "failed to drop root privs\n");

		/*
 		** find epoch time of boot moment
		*/
		bootepoch = getboot();

		firstcall = 0;
	}

	/*
	** probe if the netatop module and (optionally) the
	** netatopd daemon are active
	*/
	regainrootprivs();

	netatop_probe();

	if (! droprootprivs())
		mcleanstop(42, "failed to drop root privs\n");

	ret = procallstat(tasklist, maxtask, bootepoch, 1);
	if (ret != 0)
	{
		fprintf(stderr, "procallstat failed with %d\n", ret);
		return ret;
	}

	ret = procallstatus(tasklist, maxtask);
	if (ret != 0)
	{
		fprintf(stderr, "procallstatus failed with %d\n", ret);
		return ret;
	}

	ret = procallio(tasklist, maxtask);
	if (ret != 0)
	{
		fprintf(stderr, "procallio failed with %d\n", ret);
		return ret;
	}

	ret = procallschedstat(tasklist, maxtask);
	if (ret != 0)
	{
		fprintf(stderr, "procallschedstat failed with %d\n", ret);
		return ret;
	}

	ret = procallcont(tasklist, maxtask, &dockstat);
	if (ret != 0)
	{
		fprintf(stderr, "procallcont failed with %d\n", ret);
		return ret;
	}

	if (dockstat)
		supportflags |= DOCKSTAT;
	else
		supportflags &= ~DOCKSTAT;

	return maxtask;
}

/*
** open file "stat" and obtain required info
*/
static int
procallstat(struct tstat *curtask, int maxtask, unsigned long long bootepoch, char isproc)
{
	FILE	*fp;
	int	ncurtask = 0;
	int	nr;
	char	line[4096], *p, *cmdhead, *cmdtail;

	if ( (fp = fopen("/proc/all/stat", "r")) == NULL)
		return 10;

	while (fgets(line, sizeof line, fp))
	{
		/*
		** fetch command name
		*/
		cmdhead = strchr (line, '(');
		cmdtail = strrchr(line, ')');

		if (!cmdhead || !cmdtail || cmdtail < cmdhead) // parsing failed?
		{
			fclose(fp);
			return 11;
		}

		if ( (nr = cmdtail-cmdhead-1) > PNAMLEN)
			nr = PNAMLEN;

		p = curtask->gen.name;

		memcpy(p, cmdhead+1, nr);
		*(p+nr) = 0;

		while ( (p = strchr(p, '\n')) != NULL)
		{
			*p = '?';
			p++;
		}

		/*
		** fetch other values
		*/
		curtask->gen.isproc  = isproc;
		curtask->cpu.rtprio  = 0;
		curtask->cpu.policy  = 0;
		curtask->gen.excode  = 0;

		sscanf(line, "%d", &(curtask->gen.pid));  /* fetch pid */

		nr = sscanf(cmdtail+2, SCANSTAT,
			&(curtask->gen.state), 	&(curtask->gen.ppid),
			&(curtask->mem.minflt),	&(curtask->mem.majflt),
			&(curtask->cpu.utime),	&(curtask->cpu.stime),
			&(curtask->cpu.prio),	&(curtask->cpu.nice),
			&(curtask->gen.btime),
			&(curtask->mem.vmem),	&(curtask->mem.rmem),
			&(curtask->cpu.curcpu),	&(curtask->cpu.rtprio),
			&(curtask->cpu.policy));

		if (nr < 12)		/* parsing failed? */
		{
			fclose(fp);
			return 12;
		}

		/*
		** normalization
		*/
		curtask->gen.btime   = (curtask->gen.btime+bootepoch)/hertz;
		curtask->cpu.prio   += 100; 	/* was subtracted by kernel */
		curtask->mem.vmem   /= 1024;
		curtask->mem.rmem   *= pagesize/1024;


		switch (curtask->gen.state)
		{
		case 'R':
			curtask->gen.nthrrun  = 1;
			break;
		case 'S':
			curtask->gen.nthrslpi = 1;
			break;
		case 'D':
			curtask->gen.nthrslpu = 1;
			break;
		}

		curtask++;
		ncurtask++;
		if (ncurtask == maxtask)
		{
			fprintf(stderr, "WARN: ncurtask == maxtask (in procallstat)\n");
			return 13;
		}
	}

	fclose(fp);

	return 0;
}

/*
** find the curtask, noting that /proc/all/ files return PIDs/TGIDs in numerically increasing order
*/
static int
findtask(int pid, struct tstat **pcurtask, int *ncurtask, int maxtask)
{

	while ((*pcurtask)->gen.pid != pid && *ncurtask < maxtask)
	{
		(*pcurtask)++;
		*ncurtask += 1;
	}
	if (*ncurtask > maxtask)
	{
		fprintf(stderr, "WARN: ncurtask > maxtask (in findtask)\n");
		return -1;
	}
	return 0;
}

/*
** open "/proc/allstatus" and obtain required info
*/
static int
procallstatus(struct tstat *tasklist, int maxtask)
{
	FILE	*fp;
	char	line[4096];
	struct	tstat *curtask = tasklist;
	int	ncurtask = 0;
	int	tgid = -1;

	if ( (fp = fopen("/proc/all/status", "r")) == NULL)
		return 1;


	while (fgets(line, sizeof line, fp))
	{
		if (memcmp(line, "Tgid:", 5) ==0)
		{
			sscanf(line, "Tgid: %d", &tgid);

			if (findtask(tgid, &curtask, &ncurtask, maxtask) != 0)
			{
				return 2;
			}

			curtask->gen.tgid = tgid;
			curtask->gen.nthr     = 1;	/* for compat with 2.4 */
			curtask->cpu.sleepavg = 0;	/* for compat with 2.4 */
			curtask->mem.vgrow    = 0;	/* calculated later */
			curtask->mem.rgrow    = 0;	/* calculated later */

			continue;
		}

		if (memcmp(line, "Pid:", 4) ==0)
		{
			sscanf(line, "Pid: %d", &(curtask->gen.pid));
			continue;
		}

		if (memcmp(line, "SleepAVG:", 9)==0)
		{
			sscanf(line, "SleepAVG: %d%%",
				&(curtask->cpu.sleepavg));
			continue;
		}

		if (memcmp(line, "Uid:", 4)==0)
		{
			sscanf(line, "Uid: %d %d %d %d",
				&(curtask->gen.ruid), &(curtask->gen.euid),
				&(curtask->gen.suid), &(curtask->gen.fsuid));
			continue;
		}

		if (memcmp(line, "Gid:", 4)==0)
		{
			sscanf(line, "Gid: %d %d %d %d",
				&(curtask->gen.rgid), &(curtask->gen.egid),
				&(curtask->gen.sgid), &(curtask->gen.fsgid));
			continue;
		}

		if (memcmp(line, "envID:", 6) ==0)
		{
			sscanf(line, "envID: %d", &(curtask->gen.ctid));
			continue;
		}

		if (memcmp(line, "VPid:", 5) ==0)
		{
			sscanf(line, "VPid: %d", &(curtask->gen.vpid));
			continue;
		}

		if (memcmp(line, "Threads:", 8)==0)
		{
			sscanf(line, "Threads: %d", &(curtask->gen.nthr));
			continue;
		}

		if (memcmp(line, "VmData:", 7)==0)
		{
			sscanf(line, "VmData: %lld", &(curtask->mem.vdata));
			continue;
		}

		if (memcmp(line, "VmStk:", 6)==0)
		{
			sscanf(line, "VmStk: %lld", &(curtask->mem.vstack));
			continue;
		}

		if (memcmp(line, "VmExe:", 6)==0)
		{
			sscanf(line, "VmExe: %lld", &(curtask->mem.vexec));
			continue;
		}

		if (memcmp(line, "VmLib:", 6)==0)
		{
			sscanf(line, "VmLib: %lld", &(curtask->mem.vlibs));
			continue;
		}

		if (memcmp(line, "VmSwap:", 7)==0)
		{
			sscanf(line, "VmSwap: %lld", &(curtask->mem.vswap));
			continue;
		}

		if (memcmp(line, "VmLck:", 6)==0)
		{
			sscanf(line, "VmLck: %lld", &(curtask->mem.vlock));
			continue;
		}
	}

	fclose(fp);
	return 0;
}

/*
** open file "io" (>= 2.6.20) and obtain required info
*/
#define	IO_READ		"read_bytes:"
#define	IO_WRITE	"write_bytes:"
#define	IO_CWRITE	"cancelled_write_bytes:"
static int
procallio(struct tstat *curtask, int maxtask)
{
	FILE	*fp;
	char	line[4096];
	int 	pid;
	int	ncurtask = 0;
	count_t skip1, skip2, skip3, skip4;
	count_t	dskrsz=0, dskwsz=0, dskcwsz=0;

	if (supportflags & IOSTAT)
	{
		regainrootprivs();

		if ( (fp = fopen("/proc/all/io", "r")) )
		{
			while (fgets(line, sizeof line, fp))
			{
				sscanf(line, "%d %llu %llu %llu %llu %llu %llu %llu",
					&pid, &skip1, &skip2, &skip3, &skip4,
					&dskrsz, &dskwsz, &dskcwsz);

				if (findtask(pid, &curtask, &ncurtask, maxtask) != 0)
				{
					return 2;
				}

				dskrsz /= 512;		// in sectors
				dskwsz /= 512;		// in sectors
				dskcwsz /= 512;		// in sectors

				curtask->dsk.rsz	= dskrsz;
				curtask->dsk.rio	= dskrsz;  // to enable sort
				curtask->dsk.wsz	= dskwsz;
				curtask->dsk.wio	= dskwsz;  // to enable sort
				curtask->dsk.cwsz	= dskcwsz;

			}

			fclose(fp);
		}

		if (! droprootprivs())
			mcleanstop(42, "failed to drop root privs\n");
	}

	return 0;
}

/*
** store the Docker container ID, retrieved from the 'cpuset'
** that might look like this:
**    /system.slice/docker-af78216c2a230f1aa5dce56cbf[SNAP].scope (e.g. CentOS)
**    /docker/af78216c2a230f1aa5dce56cbf[SNAP]   (e.g. openSUSE and Ubuntu))
**
** docker created by k8s might look like this:
**    /kubepods/burstable/pod07dbb922-[SNAP]/223dc5e15b[SNAP]
**
** In general:
** - search for last '/' (basename)
** - check if '/' followed by 'docker-': then skip 'docker-'
** - take 12 positions for the container ID
**
** Return value:
**	0 - no container
**	1 - container
*/
#define	CIDSIZE		12
#define	SHA256SIZE	64
#define	DOCKPREFIX	"docker-"

static int
procallcont(struct tstat *curtask, int maxtask, char *dockstat)
{
	FILE	*fp;
	char	line[256];
	int 	pid;
	int	ret = 0;
	int	ncurtask = 0;

	if ( (fp = fopen("/proc/all/cpuset", "r")) != NULL)
	{
		register char *p;

		while ( fgets(line, sizeof line, fp) )
		{
			pid = atoi(line);
			ret = findtask(pid, &curtask, &ncurtask, maxtask);
			if (ret != 0)
			{
				fprintf(stderr, "findtask failed in procallcont: %d\n", ret);
				return ret;
			}

			// fast check for processes not using cpuset
			// i.e. anyhow not container
			if (memcmp(line, "/\n", 3) == 0)
				return 0;

			// possibly container: find basename in path and
			// verify that its minimum length is the size of SHA256
			if ( (p = strrchr(line, '/')) != NULL &&
			                    strlen(p) >= SHA256SIZE)
			{
				p++;

				if (memcmp(p, DOCKPREFIX,
						sizeof(DOCKPREFIX)-1) == 0)
					p += sizeof(DOCKPREFIX)-1;

				memcpy(curtask->gen.container, p, CIDSIZE);
				*dockstat = 1;
				return 0;
			}
		}
		fclose(fp);
	}

	return 0;
}


/*
** get run_delay from /proc/<pid>/schedstat
** ref: https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/Documentation/scheduler/sched-stats.rst?h=v5.7-rc6
*/
static count_t
procallschedstat(struct tstat *curtask, int maxtask)
{
	FILE	*fp;
	char	line[4096];
	int	pid;
	int	ret = 0;
	int	ncurtask = 0;
	count_t	runtime, rundelay = 0;
	unsigned long pcount;
	static char *schedstatfile = "/proc/all/schedstat";

	/*
 	** open the schedstat file 
	*/
	if ( (fp = fopen(schedstatfile, "r")) )
	{
		while (fgets(line, sizeof line, fp))
		{
			sscanf(line, "%d %llu %llu %lu\n",
					&pid,
					&runtime, &rundelay, &pcount);

			ret = findtask(pid, &curtask, &ncurtask, maxtask);
			if (ret != 0)
			{
				fprintf(stderr, "findtask failed in procallschedstat: %d\n", ret);
				return ret;
			}

			curtask->cpu.rundelay = rundelay;
		}

		/*
		** verify if fgets returned NULL due to error i.s.o. EOF
		*/
		if (ferror(fp))
			curtask->cpu.rundelay = 0;

		fclose(fp);
	}
	else
	{
		curtask->cpu.rundelay = 0;
	}

	return 0;
}
