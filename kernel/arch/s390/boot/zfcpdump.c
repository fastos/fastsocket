/*
 * zfcpdump userspace tool
 *
 * This tool should be used in an intitramfs together with a kernel with
 * enabled CONFIG_ZFCPDUMP kernel build option. The tool is able to write
 * standalone system dumps on SCSI disks.
 *
 * See Documentation/s390/zfcpdump.txt for more information!
 *
 * Copyright IBM Corp. 2003, 2007.
 * Author(s): Michael Holzheu
 */

#define _GNU_SOURCE

#include <errno.h>
#include <string.h>
#include <dirent.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <fcntl.h>
#include <ctype.h>
#include <sys/reboot.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <sys/time.h>
#include <linux/reboot.h>
#include <asm/types.h>
#include "zfcpdump.h"
#ifdef GZIP_SUPPORT
#include <zlib.h>
#endif

static struct globals g;
static char *module_list[] = {"zfcp", "sd_mod", "ext2", "ext3", "zcore_mod",
			      NULL};

/*
 * parse one kernel parameter in the form keyword=value
 */
static int parse_parameter(char *parameter)
{
	char *token;
	char *end_ptr;

	token = strtok(parameter, "=");
	if (token == NULL)
		return 0;

	if (strcmp(token, PARM_DIR) == 0) {
		/* Dump Dir */
		g.parm_dir = strtok(NULL, "=");
		if (g.parm_dir == NULL) {
			PRINT_WARN("No value for '%s' parameter specified\n",
				    PARM_DIR);
			PRINT_WARN("Using default: %s\n", PARM_DIR_DFLT);
			g.parm_dir = PARM_DIR_DFLT;
		}
	} else if (strcmp(token, PARM_PART) == 0) {
		/* Dump Partition */
		g.parm_part = strtok(NULL, "=");
		if (g.parm_part == NULL) {
			PRINT_ERR("No value for '%s' parameter "
				  "specified\n", PARM_PART);
			return -1;
		}
	} else if (strcmp(token, PARM_MEM) == 0) {
		/* Dump mem */
		char *mem_str = strtok(NULL, "=");
		if (mem_str == NULL) {
			PRINT_ERR("No value for '%s' parameter "
				  "specified\n", PARM_MEM);
			return -1;
		}
		g.parm_mem = strtoll(mem_str, &end_ptr, 0);
		if (*end_ptr != 0) {
			PRINT_ERR("Invalid value for '%s' parameter "
				  "specified\n", PARM_MEM);
			return -1;
		}
	} else if (strcmp(token, PARM_COMP) == 0) {
		/* Dump Compression */
		g.parm_compress = strtok(NULL, "=");
		if (g.parm_compress == NULL) {
			PRINT_WARN("No value for '%s' parameter "
				   "specified\n", PARM_COMP);
			PRINT_WARN("Using default: %s\n", PARM_COMP_DFLT);
			g.parm_compress = PARM_COMP_DFLT;
		} else if ((strcmp(g.parm_compress, PARM_COMP_GZIP) != 0) &&
			   (strcmp(g.parm_compress, PARM_COMP_NONE) != 0)) {
			PRINT_WARN("Unknown dump compression '%s' "
				   "specified!\n", g.parm_compress);
			PRINT_WARN("Using default: %s\n", PARM_COMP_DFLT);
			g.parm_compress = PARM_COMP_DFLT;
		}
	} else if (strcmp(token, PARM_DEBUG) == 0) {
		/* Dump Debug */
		char *s = strtok(NULL, "=");
		if (s == NULL) {
			PRINT_WARN("No value for '%s' parameter "
				"specified\n", PARM_DEBUG);
			PRINT_WARN("Using default: %d\n", PARM_DEBUG_DFLT);
		} else {
			g.parm_debug = atoi(s);
			if ((g.parm_debug < PARM_DEBUG_MIN) ||
			    (g.parm_debug > PARM_DEBUG_MAX)) {
				PRINT_WARN("Invalid value (%i) for %s "
				"parameter specified (allowed range is "
				"%i - %i)\n", g.parm_debug, PARM_DEBUG,
				PARM_DEBUG_MIN, PARM_DEBUG_MAX);
				PRINT_WARN("Using default: %i\n",
				PARM_DEBUG_DFLT);
				g.parm_debug = PARM_DEBUG_DFLT;
			}
		}
	} else if (strcmp(token, PARM_MODE) == 0) {
		/* Dump Mode */
		char *s = strtok(NULL, "=");
		if (s == NULL) {
			PRINT_WARN("No value for '%s' parameter "
				"specified\n", PARM_MODE);
			PRINT_WARN("Using default: %s\n", PARM_MODE_DFLT);
		} else if (strcmp(s, PARM_MODE_INTERACT) == 0) {
			g.parm_mode = PARM_MODE_INTERACT_NUM;
		} else if (strcmp(s, PARM_MODE_AUTO) == 0) {
			g.parm_mode = PARM_MODE_AUTO_NUM;
		} else {
			PRINT_WARN("Unknown dump mode: %s\n", s);
			PRINT_WARN("Using default: %s\n", PARM_MODE_DFLT);
		}
	}
	return 0;
}

/*
 * Get dump parameters from /proc/cmdline
 * Return: 0       - ok
 *         (!= 0)  - error
 */
static int parse_parmline(void)
{
	int fh, i, count, token_cnt;
	char *token;
	char *parms[KERN_PARM_MAX];

	/* setting defaults */

	g.parm_compress = PARM_COMP_DFLT;
	g.parm_dir      = PARM_DIR_DFLT;
	g.parm_part     = PARM_PART_DFLT;
	g.parm_debug    = PARM_DEBUG_DFLT;
	g.parm_mode     = PARM_MODE_NUM_DFLT;
	g.parm_mem      = PARM_MEM_DFLT;

	fh = open(PROC_CMDLINE, O_RDONLY);
	if (fh == -1) {
		PRINT_PERR("open %s failed\n", PROC_CMDLINE);
		return -1;
	}
	count = read(fh, g.parmline, CMDLINE_MAX_LEN);
	if (count == -1) {
		PRINT_PERR("read %s failed\n", PROC_CMDLINE);
		close(fh);
		return -1;
	}
	g.parmline[count-1] = '\0'; /* remove \n */
	token_cnt = 0;
	token = strtok(g.parmline, " \t\n");
	while (token != NULL) {
		parms[token_cnt] = token;
		token = strtok(NULL, " \t\n");
		token_cnt++;
		if (token_cnt >= KERN_PARM_MAX) {
			PRINT_WARN("More than %i kernel parmameters "
				   "specified\n", KERN_PARM_MAX);
			break;
		}
	}
	for (i = 0; i < token_cnt; i++) {
		if (parse_parameter(parms[i])) {
			close(fh);
			return -1;
		}
	}
	PRINT_TRACE("dump dir  : %s\n", g.parm_dir);
	PRINT_TRACE("dump part : %s\n", g.parm_part);
	PRINT_TRACE("dump comp : %s\n", g.parm_compress);
	PRINT_TRACE("dump debug: %d\n", g.parm_debug);
	PRINT_TRACE("dump mem:   %llx\n", (unsigned long long) g.parm_mem);

	if (g.parm_mode == PARM_MODE_AUTO_NUM)
		PRINT_TRACE("dump mode : %s\n", PARM_MODE_AUTO);
	if (g.parm_mode == PARM_MODE_INTERACT_NUM)
		PRINT_TRACE("dump mode : %s\n", PARM_MODE_INTERACT);

	sprintf(g.dump_dir, "%s/%s", DUMP_DIR, g.parm_dir);
	close(fh);
	return 0;
}

static int write_to_file(const char *file, const char *command)
{
	int fh;

	PRINT_TRACE("Write: %s - %s\n", file, command);
	fh = open(file, O_WRONLY);
	if (fh == -1) {
		PRINT_PERR("Could not open %s\n", file);
		return -1;
	}
	if (write(fh, command, strlen(command)) == -1) {
		PRINT_PERR("Write to %s failed\n", file);
		close(fh);
		return -1;
	};
	close(fh);
	return 0;
}

static int read_file(const char *file, char *buf, int size)
{
	ssize_t count;
	int fh;

	PRINT_TRACE("Read: %s:\n", file);
	fh = open(file, O_RDONLY);
	if (fh == -1) {
		PRINT_PERR("open %s failed\n", file);
		return -1;
	}
	count = read(fh, buf, size - 1);
	if (count < 0) {
		PRINT_PERR("read %s failed\n", file);
		close(fh);
		return -1;
	}
	buf[count] = 0;
	if (buf[strlen(buf) - 1] == '\n')
		buf[strlen(buf) - 1] = 0; /* strip newline */
	close(fh);
	PRINT_TRACE("'%s'\n", buf);

	return 0;
}

/*
 * Get HSA size
 */
static __u64 get_hsa_size(void)
{
	char buf[128];

	if (read_file(DEV_ZCORE_HSA, buf, sizeof(buf)))
		return 0;
	return strtoul(buf, NULL, 16);
}

/*
 * Release HSA
 */
static void release_hsa(void)
{
	write_to_file(DEV_ZCORE_HSA, "0");
}

/*
 * Enable the scsi disk for dumping
 * Return:    0 - ok
 *         != 0 - error
 */
static int enable_zfcp_device(void)
{
	char command[1024], file[1024];
	struct stat s;

	/* device */
	if (read_file(IPL_DEVNO, g.dump_devno, sizeof(g.dump_devno)))
		return -1;
	sprintf(file, "/sys/bus/ccw/drivers/zfcp/%s/online", g.dump_devno);
	if (write_to_file(file, "1\n"))
		return -1;

	/* wwpn */
	if (read_file(IPL_WWPN, g.dump_wwpn, sizeof(g.dump_wwpn)))
		return -1;
	sprintf(file, "/sys/bus/ccw/drivers/zfcp/%s/port_add", g.dump_devno);
	/* The port_add attribute has been removed in recent kernels */
	if (stat(file, &s) == 0) {
		sprintf(command, "%s\n", g.dump_wwpn);
		if (write_to_file(file, command))
			return -1;
	}

	/* lun */
	if (read_file(IPL_LUN, g.dump_lun, sizeof(g.dump_lun)))
		return -1;
	sprintf(file, "/sys/bus/ccw/drivers/zfcp/%s/%s/unit_add", g.dump_devno,
		g.dump_wwpn);
	sprintf(command, "%s\n", g.dump_lun);
	if (write_to_file(file, command))
		return -1;

	/* bootprog */
	read_file("/sys/firmware/ipl/bootprog", g.dump_bootprog,
		sizeof(g.dump_bootprog));

	return 0;
}

/*
 * Mount the dump device
 * Return:    0 - ok
 *         != 0 - error
 */
static int mount_dump_device(void)
{
	int pid;
	char dump_part[16];

	PRINT_TRACE("e2fsck\n");
	sprintf(dump_part, "%s%i", DEV_SCSI, atoi(g.parm_part));

	pid = fork();
	if (pid < 0) {
		PRINT_PERR("fork failed\n");
		return -1;
	} else if (pid == 0) {
		execl("/bin/e2fsck", "e2fsck", dump_part, "-y", NULL);
		execl("/sbin/e2fsck", "e2fsck", dump_part, "-y", NULL);
		exit(1);
	} else {
		waitpid(pid, NULL, 0);
	}

	PRINT_TRACE("mount\n");
	if (mount(dump_part, DUMP_DIR, "ext4", 0, NULL) == 0)
		return 0;
	if (mount(dump_part, DUMP_DIR, "ext3", 0, NULL) == 0)
		return 0;
	if (mount(dump_part, DUMP_DIR, "ext2", 0, NULL) != 0) {
		PRINT_PERR("mount failed\n");
		return -1;
	}
	return 0;
}

/*
 * unmount the dump device
 * Return:    0 - ok
 *         != 0 - error
 */
static int umount_dump_device(void)
{
	if (umount(DUMP_DIR) != 0) {
		PRINT_PERR("umount failed\n");
		return -1;
	}
	return 0;
}

/*
 * Terminate the system dumper
 */
static void terminate(void)
{
	int fd;

	sleep(WAIT_TIME_END); /* give the messages time to be displayed */
	fd = open(DEV_ZCORE_REIPL, O_WRONLY, 0);
	if (fd == -1)
		goto no_reipl;
	write(fd, REIPL, 1);
	close(fd);
no_reipl:
	reboot(LINUX_REBOOT_CMD_POWER_OFF);
}

/*
 * Signal handler for zfcp_dumper
 */
static __sighandler_t dump_sig_handler(int sig, siginfo_t *sip, void*p)
{
	PRINT_ERR("Got signal: %i\n", sig);
	PRINT_ERR("Dump failed!\n");
	terminate();
	return 0;
}

/*
 * Setup the Signal handler for zfcp_dumper
 * Return:   0 - ok
 *         !=0 - error
 */
static int init_sig(void)
{
	g.sigact.sa_flags = (SA_NODEFER | SA_SIGINFO | SA_RESETHAND);
	g.sigact.sa_handler = (__sighandler_t)dump_sig_handler;
	if (sigemptyset(&g.sigact.sa_mask) < 0)
		return -1;
	if (sigaction(SIGINT, &g.sigact, NULL) < 0)
		return -1;
	if (sigaction(SIGTERM, &g.sigact, NULL) < 0)
		return -1;
	if (sigaction(SIGPIPE, &g.sigact, NULL) < 0)
		return -1;
	if (sigaction(SIGABRT, &g.sigact, NULL) < 0)
		return -1;
	if (sigaction(SIGSEGV, &g.sigact, NULL) < 0)
		return -1;
	if (sigaction(SIGBUS, &g.sigact, NULL) < 0)
		return -1;

	return 0;
}

/*
 * Set memory management parameters: Ensure that dirty pages are written
 * early enough! See "Documentation/filesystems/proc.txt"
 * Return:   0 - ok
 *         !=0 - error
 */
static int tune_vm(void)
{
	char *sysctl_names[] = {"/proc/sys/vm/dirty_ratio",
				"/proc/sys/vm/dirty_background_ratio",
				"/proc/sys/vm/dirty_writeback_centisecs",
				"/proc/sys/vm/dirty_expire_centisecs",
				"/proc/sys/vm/vfs_cache_pressure",
				"/proc/sys/vm/lowmem_reserve_ratio",
				NULL};
	char *sysctl_values[] = {"2", "5", "50", "50", "500", "32", NULL};
	int i;

	i = 0;
	while (sysctl_names[i]) {
		if (write_to_file(sysctl_names[i], sysctl_values[i]))
			return -1;
		i++;
	}
	return 0;
}

/*
 * Get dump number of either new dump or dump to erase
 * Parameter: dumpdir - dump directory (absolute path)
 *            mode    - DUMP_FIRST: Find smallest dump number in directory
 *                    - DUMP_LAST:  Find highest dump number in directory
 * Return: >= 0 - dump number
 *         -1   - no dump found in directory
 *         <-1  - error
 */
static int get_dump_num(const char *dumpdir, int mode)
{
	DIR *dir = NULL;
	struct dirent *dir_ent;
	int dump_found, rc;

	rc = 0;
	dump_found = 0;
	dir = opendir(dumpdir);
	if (!dir) {
		PRINT_PERR("Cannot evalute dump number\n");
		return -2;
	}

	while ((dir_ent = readdir(dir))) {
		int num;
		if (sscanf(dir_ent->d_name, "dump.%ui", &num) == 1) {
			char suffix[1024] = {};

			/*
			 * check if we have something like dump.001
			 * this is not treated as dump, since we do not allow
			 * leading zeros.
			 * Also files like dump.-1, dump.-10 are ignored.
			 */
			sscanf(dir_ent->d_name, "dump.%s", suffix);
			if (suffix[0] == '-')
				continue;
			if ((suffix[0] == '0') && isdigit(suffix[1]))
				continue;
			if (!dump_found) {
				dump_found = 1;
				rc = num;
			} else if (mode == DUMP_LAST) {
				rc = MAX(num, rc);
			} else if (mode == DUMP_FIRST) {
				rc = MIN(num, rc);
			}
		}
	}
	if (!dump_found)
		rc = NO_DUMP;
	closedir(dir);

	return rc;
}

/*
 * Erase oldest dump in dump directory
 * Return:    0 - ok
 *          !=0 - error
 */
static int erase_oldest_dump(void)
{
	int dump_nr;
	char dname[1024] = {};
	char answ[1024] = {};

	dump_nr = get_dump_num(g.dump_dir, DUMP_FIRST);
	if (dump_nr < 0) {
		PRINT_ERR("Internal error: dump number cannot be evaluated\n");
		return -1;
	}
	sprintf(dname, "dump.%i", dump_nr);
	if (dump_nr == g.dump_nr) {
		PRINT_ERR("Sorry, cannot delete any more dumps!\n");
		return -1;
	}
	if (g.parm_mode == PARM_MODE_AUTO_NUM) {
		PRINT("Removing oldest dump: '%s'\n", dname);
	} else {
		while ((strcmp(answ, "y") != 0) && (strcmp(answ, "n") != 0)) {
			PRINT("Remove oldest dump: '%s' (y/n)? ", dname);
			scanf("%s", answ);
		}
		if (strcmp(answ, "n") == 0)
			return -1;
	}
	sprintf(dname, "%s/dump.%i", g.dump_dir, dump_nr);
	if (unlink(dname) == -1) {
		PRINT_PERR("Could not remove dump\n");
		return -1;
	}
	sync();
	/*
	 * Wait some seconds in order to give ext3 time to discover that file
	 * has been removed.
	 */
	sleep(WAIT_TIME_ERASE);
	PRINT("Dump removed!\n");
	return 0;
}

/*
 * write buffer to dump. In case of ENOSPC try to remove oldest dump
 * Parameter: fd    - filedescriptor of dump file
 *            buf   - buffer to write
 *            count - nr of bytes to write
 *
 * Return:    size  - written bytes
 *            <0    - error
 */
static ssize_t dump_write(int fd, const void *buf, size_t count)
{
	ssize_t written, rc;

	written = 0;
	while (written != count) {
		rc = write(fd, buf + written, count - written);
		if ((rc == -1) && (errno == ENOSPC)) {
			PRINT_ERR("No space left on device!\n");
			/* Try to erase old dump */
			if (erase_oldest_dump())
				return -1;
			continue;
		} else if (rc == -1) {
			/* Write failed somehow */
			return -1;
		}
		written += rc;
	}
	return written;
}

#ifdef GZIP_SUPPORT
/*
 * Wrapper to gzip compress routine
 * Parameter: old      - buffer to compress (in)
 *            old_size - size of old buffer in bytes (in)
 *            new      - buffer for compressed data (out)
 *            new_size - size of 'new' buffer in bytes (in)
 * Return:    >=0 - Size of compressed buffer
 *            < 0 - error
 */
static int compress_gzip(const unsigned char *old, __u32 old_size,
			 unsigned char *new, __u32 new_size)
{
	int rc;
	unsigned long len;

	len = old_size;
	rc = compress(new, &len, old, new_size);
	switch (rc) {
	case Z_OK:
		return len;
	case Z_MEM_ERROR:
		PRINT_ERR("Z_MEM_ERROR (not enough memory)!\n");
		return -1;
	case Z_BUF_ERROR:
		/* In this case the compressed output is bigger than
		   the uncompressed */
		return -1;
	case Z_DATA_ERROR:
		PRINT_ERR("Z_DATA_ERROR (input data corrupted)!\n");
		return -1;
	default:
		PRINT_ERR("Z_UNKNOWN_ERROR (rc 0x%x unknown)!\n", rc);
		return -1;
	}
}
#endif

/*
 * Do nothing! - No compression
 */
static int compress_none(const unsigned char *old, __u32 old_size,
			 unsigned char *new, __u32 new_size)
{
	return -1; /* "-1" indicates, that compression was not done */
}

/*
 * Convert s390 standalone dump header to lkcd dump header
 * Parameter: s390_dh - s390 dump header (in)
 *            dh      - lkcd dump header (out)
 */
static void s390_to_lkcd_hdr(struct dump_hdr_s390 *s390_dh,
			     struct dump_hdr_lkcd *dh)
{
	struct timeval h_time;

	/* adjust todclock to 1970 */
	__u64 tod = s390_dh->tod;
	tod -= 0x8126d60e46000000LL - (0x3c26700LL * 1000000 * 4096);
	tod >>= 12;
	h_time.tv_sec  = tod / 1000000;
	h_time.tv_usec = tod % 1000000;

	dh->memory_size    = s390_dh->memory_size;
	dh->memory_start   = s390_dh->memory_start;
	dh->memory_end     = s390_dh->memory_end;
	dh->num_dump_pages = s390_dh->num_pages;
	dh->page_size      = s390_dh->page_size;
	dh->dump_level     = s390_dh->dump_level;

	sprintf(dh->panic_string, "zSeries-dump (CPUID = %16llx)",
		(unsigned long long) s390_dh->cpu_id);

	if (s390_dh->arch_id == DH_ARCH_ID_S390)
		strcpy(dh->utsname_machine, "s390");
	else if (s390_dh->arch_id == DH_ARCH_ID_S390X)
		strcpy(dh->utsname_machine, "s390x");
	else
		strcpy(dh->utsname_machine, "<unknown>");

	strcpy(dh->utsname_sysname, "<unknown>");
	strcpy(dh->utsname_nodename, "<unknown>");
	strcpy(dh->utsname_release, "<unknown>");
	strcpy(dh->utsname_version, "<unknown>");
	strcpy(dh->utsname_domainname, "<unknown>");

	dh->magic_number   = DUMP_MAGIC_NUMBER;
	dh->version        = DUMP_VERSION_NUMBER;
	dh->header_size    = sizeof(struct dump_hdr_lkcd);
	dh->time.tv_sec    = h_time.tv_sec;
	dh->time.tv_usec   = h_time.tv_usec;
}

/*
 * Convert s390 standalone dump header to lkcd asm dump header
 * Parameter: s390_dh - s390 dump header (in)
 *            dh_asm  - lkcd asm dump header (out)
 */
static void s390_to_lkcd_hdr_asm(struct dump_hdr_s390 *s390_dh,
			         struct dump_hdr_lkcd_asm *dh_asm)
{
	unsigned int i;

	dh_asm->magic_number = DUMP_MAGIC_NUMBER_ASM;
	dh_asm->version = 0;
	dh_asm->hdr_size = sizeof(*dh_asm);
	dh_asm->cpu_cnt = s390_dh->cpu_cnt;
	dh_asm->real_cpu_cnt = s390_dh->real_cpu_cnt;
	for (i = 0; i < dh_asm->cpu_cnt; i++)
		dh_asm->lc_vec[i] = s390_dh->lc_vec[i];
}

/*
 * Write progress information to screen
 * Parameter: written - So many bytes have been written to the dump
 *            max     - This is the whole memory to be written
 */
static void show_progress(unsigned long long written, unsigned long long max)
{
	int    time;
	struct timeval t;
	double percent;

	gettimeofday(&t, NULL);
	time = t.tv_sec;
	if ((time < g.last_progress) && (written != max) && (written != 0))
		return;
	g.last_progress = time + 10;
	percent = ((double) written / (double) max) * 100.0;
	PRINT(" %4lli MB of %4lli MB (%5.1f%% )\n", written >> 20, max >> 20,
		percent);
	fflush(stdout);
}

/*
 * create dump
 *
 * Return:   0  - ok
 *         !=0  - error
 */
static int create_dump(void)
{
	struct stat stat_buf;
	struct dump_hdr_lkcd dh;
	struct dump_hdr_lkcd_asm dh_asm;
	struct dump_hdr_s390 s390_dh;
	compress_fn_t compress_fn;
	struct dump_page dp;
	char buf[PAGE_SIZE], dpcpage[PAGE_SIZE];
	char dump_name[1024];
	__u64 mem_loc, mem_count, hsa_size;
	__u32 buf_loc = 0, dp_size, dp_flags;
	int size, fin, fout, fmap, rc = 0;
	char c_info[CHUNK_INFO_SIZE];
	struct mem_chunk *chunk, *chunk_first = NULL, *chunk_prev = NULL;
	char *end_ptr;
	void *page_buf;

	if (stat(g.dump_dir, &stat_buf) < 0) {
		PRINT_ERR("Specified dump dir '%s' not found!\n", g.dump_dir);
		return -1;
	} else if (!S_ISDIR(stat_buf.st_mode)) {
		PRINT_ERR("Specified dump dir '%s' is not a directory!\n",
			g.dump_dir);
		return -1;
	}

	/* Allocate buffer for writing */
	if (posix_memalign(&page_buf, PAGE_SIZE, DUMP_BUF_SIZE)) {
		PRINT_ERR("Out of memory: Could not allocate dump buffer\n");
		return -1;
	}

	/* initialize progress time */
	g.last_progress = 0;

	/* get dump number */
	g.dump_nr = get_dump_num(g.dump_dir, DUMP_LAST);
	if (g.dump_nr == NO_DUMP)
		g.dump_nr = 0;
	else if (g.dump_nr >= 0)
		g.dump_nr += 1;
	else
		return -1;

	/* Open the memory map file - only available with kernel 2.6.25 or
	* higher. If open fails, memory holes cannot be detected and only
	* one single memory chunk is assumed */
	fmap = open(DEV_ZCORE_MAP, O_RDONLY, 0);
	if (fmap == -1) {
		chunk_first = calloc(1, sizeof(struct mem_chunk));
		if (chunk_first == NULL) {
			PRINT_ERR("Could not allocate %d bytes of memory\n",
				  (int) sizeof(struct mem_chunk));
			return -1;
		}
		chunk_first->size = PARM_MEM_DFLT;
	} else {
	/* read information about memory chunks (start address and size) */
		do {
			if (read(fmap, c_info, sizeof(c_info)) != sizeof(c_info)) {
				PRINT_ERR("read() memory map file '%s' "
					  "failed!\n", DEV_ZCORE_MAP);
				rc = -1;
				goto failed_close_fmap;
			}
			chunk = calloc(1, sizeof(struct mem_chunk));
			if (chunk == NULL) {
				PRINT_ERR("Could not allocate %d bytes of "
					  "memory\n",
					  (int) sizeof(struct mem_chunk));
				rc = -1;
				goto failed_free_chunks;
			}
			chunk->size = strtoul(c_info + 17, &end_ptr, 16);
			if (end_ptr != c_info + 33 || *end_ptr != ' ') {
				PRINT_ERR("Invalid contents of memory map "
					  "file '%s'!\n", DEV_ZCORE_MAP);
				rc = -1;
				goto failed_free_chunks;
			}
			if (chunk->size == 0)
				break;
			chunk->addr = strtoul(c_info, &end_ptr, 16);
			if (end_ptr != c_info + 16 || *end_ptr != ' ') {
				PRINT_ERR("Invalid contents of memory map "
					  "file '%s'!\n", DEV_ZCORE_MAP);
				rc = -1;
				goto failed_free_chunks;
			}
			if (!chunk_first)
				chunk_first = chunk;
			else
				chunk_prev->next = chunk;
			chunk_prev = chunk;
		} while (1);
	}

	hsa_size = get_hsa_size();
	PRINT_TRACE("hsa size: %llx\n", (unsigned long long) hsa_size);

	/* try to open the source device */
	fin = open(DEV_ZCORE, O_RDONLY, 0);
	if (fin == -1) {
		PRINT_ERR("open() source device '%s' failed!\n", DEV_ZCORE);
		rc = -1;
		goto failed_free_chunks;
	}

	/* make the new filename */
	sprintf(dump_name, "%s/dump.%d", g.dump_dir, g.dump_nr);
	fout = open(dump_name, DUMP_FLAGS, DUMP_MODE);
	if (fout == -1) {
		PRINT_ERR("open() of dump file \"%s\" failed!\n", dump_name);
		rc = -1;
		goto failed_close_fin;
	}

	PRINT("dump file: dump.%d\n", g.dump_nr);
	memset(&dh, 0, sizeof(dh));

	/* get the dump header */
	if (lseek(fin, 0, SEEK_SET) < 0) {
		PRINT_ERR("Cannot lseek() to get the dump header from the "
			"dump file!\n");
		rc = -1;
		goto failed_close_fout;
	}
	if (read(fin, &s390_dh, sizeof(s390_dh)) != sizeof(s390_dh)) {
		PRINT_ERR("Cannot read() dump header from dump file!\n");
		rc = -1;
		goto failed_close_fout;
	}

	s390_to_lkcd_hdr(&s390_dh, &dh);
	if (s390_dh.version >= 5)
		s390_to_lkcd_hdr_asm(&s390_dh, &dh_asm);

	if (strcmp(g.parm_compress, PARM_COMP_GZIP) == 0) {
#ifdef GZIP_SUPPORT
		dh.dump_compress = DUMP_COMPRESS_GZIP;
		compress_fn = compress_gzip;
#else
		PRINT_WARN("No gzip support. Compression disabled!\n");
		dh.dump_compress = DUMP_COMPRESS_NONE;
		compress_fn = compress_none;
#endif
	} else {
		dh.dump_compress = DUMP_COMPRESS_NONE;
		compress_fn = compress_none;
	}

	if (g.parm_mem < dh.memory_size) {
		/* dump_mem parameter specified: Adjust memory size */
		dh.memory_size = g.parm_mem;
		dh.memory_end  = g.parm_mem;
		dh.num_dump_pages = g.parm_mem / dh.page_size;
	}

	memset(page_buf, 0, PAGE_SIZE);
	memcpy(page_buf, &dh, sizeof(dh));
	memcpy(page_buf + sizeof(dh), &dh_asm, sizeof(dh_asm));
	if (lseek(fout, 0L, SEEK_SET) < 0) {
		PRINT_ERR("lseek() failed\n");
		rc = -1;
		goto failed_close_fout;
	}
	if (dump_write(fout, page_buf, PAGE_SIZE) != PAGE_SIZE) {
		PRINT_ERR("Error: Write dump header failed\n");
		rc = -1;
		goto failed_close_fout;
	}
	if (lseek(fout, LKCD_HDR_SIZE, SEEK_SET) < 0) {
		PRINT_ERR("lseek() failed\n");
		rc = -1;
		goto failed_close_fout;
	}

	/* write dump */

	chunk = chunk_first;
	mem_loc = 0;
	mem_count = 0;
	if (lseek(fin, DUMP_HEADER_SZ_S390SA, SEEK_SET) < 0) {
		PRINT_ERR("lseek() failed\n");
		rc = -1;
		goto failed_close_fout;
	}
	while (mem_loc < dh.memory_end) {
		if (mem_loc >= chunk->addr + chunk->size) {
			chunk = chunk->next;
			mem_loc = chunk->addr;
			if (lseek(fin, DUMP_HEADER_SZ_S390SA + mem_loc,
				  SEEK_SET) < 0) {
				PRINT_ERR("lseek() failed\n");
				rc = -1;
				goto failed_close_fout;
			}
		}
		if (hsa_size && mem_loc >= hsa_size) {
			release_hsa();
			hsa_size = 0;
		}
		if (read(fin, buf, PAGE_SIZE) != PAGE_SIZE) {
			if (errno == EFAULT) {
				/* probably memory hole. Skip page */
				mem_loc += PAGE_SIZE;
				continue;
			}
			PRINT_PERR("read error\n");
			rc = -1;
			goto failed_close_fout;
		}
		memset(dpcpage, 0, PAGE_SIZE);
		/* get the new compressed page size */

		size = compress_fn((unsigned char *)buf, PAGE_SIZE,
			(unsigned char *)dpcpage, PAGE_SIZE);

		/* if compression failed or compressed was ineffective,
		 * we write an uncompressed page */
		if (size < 0) {
			dp_flags = DUMP_DH_RAW;
			dp_size = PAGE_SIZE;
		} else {
			dp_flags = DUMP_DH_COMPRESSED;
			dp_size = size;
		}
		dp.address = mem_loc;
		dp.size    = dp_size;
		dp.flags   = dp_flags;
		memcpy(page_buf + buf_loc, &dp, sizeof(dp));
		buf_loc += sizeof(struct dump_page);
		/* copy the page of memory */
		if (dp_flags & DUMP_DH_COMPRESSED)
			/* copy the compressed page */
			memcpy(page_buf + buf_loc, dpcpage, dp_size);
		else
			/* copy directly from memory */
			memcpy(page_buf + buf_loc, buf, dp_size);
		buf_loc += dp_size;
		mem_loc += PAGE_SIZE;
		mem_count += PAGE_SIZE;
		if (buf_loc + PAGE_SIZE + sizeof(dp) > DUMP_BUF_SIZE) {
			unsigned long rem = buf_loc % PAGE_SIZE;
			long size = buf_loc - rem;

			if (dump_write(fout, page_buf, size) != size) {
				PRINT_ERR("write error\n");
				rc = -1;
				goto failed_close_fout;
			}
			memmove(page_buf, page_buf + size, rem);
			buf_loc = rem;
		}
		show_progress(mem_count, dh.memory_size);
	}

	/* write end marker */

	dp.address = 0x0;
	dp.size    = 0x0;
	dp.flags   = DUMP_DH_END;
	memcpy(page_buf + buf_loc, &dp, sizeof(dp));
	buf_loc += sizeof(dp);
	dump_write(fout, page_buf, buf_loc + (PAGE_SIZE - buf_loc % PAGE_SIZE));
	if (ftruncate(fout, lseek(fout, 0, SEEK_CUR) -
		      (PAGE_SIZE - buf_loc % PAGE_SIZE)) == -1) {
		PRINT_ERR("truncate error\n");
		rc = -1;
		goto failed_close_fout;
	}
	dump_write(fout, &dp, sizeof(dp));

failed_close_fout:
	close(fout);
failed_close_fin:
	close(fin);
failed_free_chunks:
	chunk = chunk_first;
	while (chunk) {
		chunk_prev = chunk;
		chunk = chunk->next;
		free(chunk_prev);
	}
failed_close_fmap:
	close(fmap);
	return rc;
}

/*
 * Load a kernel module
 */
static void modprobe(const char *module)
{
	pid_t pid;

	pid = fork();
	if (pid < 0) {
		PRINT_PERR("fork failed\n");
		return;
	} else if (pid == 0) {
		execl("/bin/modprobe", "modprobe", module, "-q", NULL);
		execl("/sbin/modprobe", "modprobe", module, "-q", NULL);
		exit(1);
	} else {
		waitpid(pid, NULL, 0);
	}
}

/*
 * Load all required kernel modules
 */
static void load_modules(void)
{
	int i;

	for (i = 0; module_list[i]; i++)
		modprobe(module_list[i]);
}

/*
 * main routine of the zfcp_dumper
 */
int main(int argc, char *argv[])
{
	char linux_version[128];

#ifdef __s390x__
	PRINT("Linux System Dumper starting\n");
	PRINT("Version %s (64 bit)\n", ZFCPDUMP_VERSION);
#else
	PRINT("Linux System Dumper starting\n");
	PRINT("Version %s (32 bit)\n", ZFCPDUMP_VERSION);
#endif

	if (init_sig()) {
		PRINT_ERR("Init Signals failed!\n");
		goto fail;
	}
	if (mount("proc", "/proc", "proc", 0, NULL)) {
		if (errno != EBUSY) {
			PRINT_PERR("Unable to mount proc\n");
			goto fail;
		}
	}
	read_file("/proc/version", linux_version, sizeof(linux_version));
	PRINT("%s\n", linux_version);

	if (mount("sysfs", "/sys", "sysfs", 0, NULL)) {
		if (errno != EBUSY) {
			PRINT_PERR("Unable to mount sysfs\n");
			goto fail;
		}
	}
	if (mount("debugfs", "/sys/kernel/debug", "debugfs", 0, NULL)) {
		if (errno != EBUSY) {
			PRINT_PERR("Unable to mount debugfs\n");
			goto fail;
		}
	}
	if (tune_vm()) {
		PRINT_PERR("Unable to set VM settings\n");
		goto fail;
	}
	if (parse_parmline()) {
		PRINT_ERR("Could not parse parmline\n");
		goto fail;
	}
	load_modules();
	if (enable_zfcp_device()) {
		PRINT_ERR("Could not enable dump device\n");
		goto fail;
	}
	PRINT(" \n"); /* leading blank is needed that sclp console prints
			 the newline */
	PRINT("DUMP PARAMETERS:\n");
	PRINT("================\n");
	PRINT("devno    : %s\n", g.dump_devno);
	PRINT("wwpn     : %s\n", g.dump_wwpn);
	PRINT("lun      : %s\n", g.dump_lun);
	PRINT("conf     : %s\n", g.dump_bootprog);
	PRINT("partition: %s\n", g.parm_part);
	PRINT("directory: %s\n", g.parm_dir);
	PRINT("compress : %s\n", g.parm_compress);
	PRINT(" \n");
	PRINT("MOUNT DUMP PARTITION:\n");
	PRINT("=====================\n");
	sleep(WAIT_TIME_ONLINE);
	if (mount_dump_device()) {
		PRINT_ERR("Could not mount dump device\n");
		goto fail;
	}
	PRINT("DONE.\n");
	PRINT(" \n");
	PRINT("DUMP PROCESS STARTED:\n");
	PRINT("=====================\n");

	if (create_dump())
		goto fail_umount;

	if (umount_dump_device()) {
		PRINT_ERR("Could not umount dump device\n");
		goto fail;
	}
	PRINT(" \n");
	PRINT("DUMP 'dump.%i' COMPLETE\n", g.dump_nr);
	fflush(stdout);
	terminate();
	return 0;

fail_umount:
	if (umount_dump_device()) {
		PRINT_ERR("Could not umount dump device\n");
		goto fail;
	}
fail:
	PRINT("DUMP 'dump.%i' FAILED\n", g.dump_nr);
	fflush(stdout);
	terminate();
	return 1;
}
