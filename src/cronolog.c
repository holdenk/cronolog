/* ====================================================================
 * Copyright (c) 1995-1999 The Apache Group.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer. 
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the Apache Group
 *    for use in the Apache HTTP server project (http://www.apache.org/)."
 *
 * 4. The names "Apache Server" and "Apache Group" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    apache@apache.org.
 *
 * 5. Products derived from this software may not be called "Apache"
 *    nor may "Apache" appear in their names without prior written
 *    permission of the Apache Group.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the Apache Group
 *    for use in the Apache HTTP server project (http://www.apache.org/)."
 *
 * THIS SOFTWARE IS PROVIDED BY THE APACHE GROUP ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE APACHE GROUP OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 *
 * This software consists of voluntary contributions made by many
 * individuals on behalf of the Apache Group and was originally based
 * on public domain software written at the National Center for
 * Supercomputing Applications, University of Illinois, Urbana-Champaign.
 * For more information on the Apache Group and the Apache HTTP server
 * project, please see <http://www.apache.org/>.
 *
 */
/*
 * cronolog -- simple Apache log rotation program
 *
 * Copyright (c) 1996-1999 by Ford & Mason Ltd
 *
 * This software was submitted by Ford & Mason Ltd to the Apache
 * Software Foundation in December 1999.  Future revisions and
 * derivatives of this source code must acknowledge Ford & Mason Ltd
 * as the original contributor of this module.  All other licensing
 * and usage conditions are those of the Apache Software Foundation.
 *
 * Originally written by Andrew Ford <A.Ford@ford-mason.co.uk>
 *
 * cronolog is loosly based on the rotatelogs program, which is part of the
 * Apache package written by Ben Laurie <ben@algroup.co.uk>
 *
 * The argument to this program is the log file name template as an
 * strftime format string.  For example to generate new error and
 * access logs each day stored in subdirectories by year, month and day add
 * the following lines to the httpd.conf:
 *
 *    TransferLog "|/www/etc/cronolog /www/logs/%Y/%m/%d/access.log"
 *    ErrorLog    "|/www/etc/cronolog /www/logs/%Y/%m/%d/error.log"
 *
 * The option "-x file" specifies that debugging messages should be
 * written to "file" (e.g. /dev/console) or to stderr if "file" is "-".
 */

#ifndef _WIN32
#define _GNU_SOURCE 1
#define OPEN_EXCLUSIVE O_WRONLY|O_CREAT|O_EXCL|O_APPEND|O_LARGEFILE
#define OPEN_SHARED O_WRONLY|O_CREAT|O_APPEND|O_LARGEFILE
#else
#define OPEN_EXCLUSIVE O_WRONLY|O_CREAT|O_EXCL|O_APPEND
#define OPEN_SHARED O_WRONLY|O_CREAT|O_APPEND
#endif

#include "config.h"

#include <sys/types.h>
#include <sys/wait.h>
#include <signal.h>
#include "cronoutils.h"
#include "getopt.h"


/* Forward function declaration */

int    new_log_file(const char *, const char *, mode_t, const char *,
             PERIODICITY, int, int, char *, size_t, time_t, time_t *);

void    cleanup(int );
void    handle_file();
void    fork_to_handle_file();

int     openwrapper( const char *filename );

#ifndef _WIN32
void    setsig_handler( int signum,  void (*action)(int, siginfo_t *, void *));
void    set_signal_handlers();
#endif

/* Definition of version and usage messages */

#ifndef _WIN32
#define VERSION_MSG       PACKAGE " version " VERSION "\n"
#else
#define VERSION_MSG      "cronolog version 0.1\n"
#endif

#ifndef _WIN32
#define SETUGID_USAGE    "   -u USER,   --set-uid=USER  change to USER before doing anything (name or UID)\n" \
            "   -g GROUP,  --set-gid=GROUP change to GROUP before doing anything (name or GID)\n"
#else
#define SETUGID_USAGE    ""
#endif

#define USAGE_MSG     "usage: %s [OPTIONS] logfile-spec\n" \
            "\n" \
            "   -H NAME,   --hardlink=NAME maintain a hard link from NAME to current log\n" \
            "   -S NAME,   --symlink=NAME  maintain a symbolic link from NAME to current log\n" \
            "   -P NAME,   --prev-symlink=NAME  maintain a symbolic link from NAME to previous log\n" \
            "   -l NAME,   --link=NAME     same as -S/--symlink\n" \
            "   -h,        --help          print this help, then exit\n" \
            "   -p PERIOD, --period=PERIOD set the rotation period explicitly\n" \
            "   -d DELAY,  --delay=DELAY   set the rotation period delay\n" \
            "   -o,        --once-only     create single output log from template (not rotated)\n" \
            "   -x FILE,   --debug=FILE    write debug messages to FILE\n" \
            "                              ( or to standard error if FILE is \"-\")\n" \
            "   -r,        --helper=SCRIPT post rotation helper script to fork exec on old files\n" \
            "                              ( will be called like \"SCRIPT <oldlog>\" )\n" \
            "                              ( not tested on windows )\n" \
            "   -G,        --helper-arg=ARG argument passed to rotation helper script\n" \
            SETUGID_USAGE \
            "   -a,        --american         American date formats\n" \
            "   -e,        --european         European date formats (default)\n" \
            "   -n,        --no-alarm      wait to rotate logs and create new ones until there is traffic\n" \
            "   -s,    --start-time=TIME   starting time\n" \
            "   -z TZ, --time-zone=TZ      use TZ for timezone\n" \
            "   -V,      --version         print version number, then exit\n"


/* Definition of the short and long program options */

char          *short_options = "ad:enop:s:z:H:P:S:l:hVx:r:G:u:g:M:D:";

#ifndef _WIN32
struct option long_options[] =
{
    { "american",    no_argument,        NULL, 'a' },
    { "european",    no_argument,        NULL, 'e' },
    { "start-time",     required_argument,    NULL, 's' },
    { "time-zone",      required_argument,    NULL, 'z' },
    { "hardlink",      required_argument,     NULL, 'H' },
    { "symlink",       required_argument,     NULL, 'S' },
    { "prev-symlink",      required_argument,     NULL, 'P' },
    { "link",          required_argument,     NULL, 'l' },
    { "period",        required_argument,    NULL, 'p' },
    { "delay",        required_argument,    NULL, 'd' },
    { "helper",        required_argument,    NULL, 'r' },
    { "helper-arg",    required_argument,    NULL, 'G' },
    { "set-uid",    required_argument,  NULL, 'u' },
    { "set-gid",    required_argument,  NULL, 'g' },
    { "once-only",     no_argument,           NULL, 'o' },
    { "no-alarm",     no_argument,           NULL, 'n' },
    { "lock",         no_argument,           NULL, 'L' },
    { "file-mode",     required_argument,           NULL, 'M' },
    { "dir-mode",     required_argument,           NULL, 'D' },
    { "help",          no_argument,           NULL, 'h' },
    { "version",       no_argument,           NULL, 'V' }
};
#endif

static    char    handler[MAX_PATH+1];
static    char    handler_arg[MAX_PATH+1];
static    char    filename[MAX_PATH+1];
//  .happypandas is 13 chars and null
static    char    lockfilename[MAX_PATH+14];
static    int   use_handler =0;
static    int   use_handler_arg =0;
static    int   i_am_handler =0;
int     acquire_lock = 0;

//
// arguably we should use mode_t, but obscuring the type
// here can only hurt, since we have to specify a scanf format 
// string later on. 
//
static    unsigned int   file_mode = FILE_MODE ;
static    unsigned int   dir_mode = DIR_MODE ;

/* Main function.
 */
int
main(int argc, char **argv)
{
    PERIODICITY    periodicity = UNKNOWN;
    PERIODICITY    period_delay_units = UNKNOWN;
    int        period_multiple = 1;
    int        period_delay  = 0;
    int        use_american_date_formats = 0;
    char     read_buf[BUFSIZE];
    char     tzbuf[BUFSIZE];
    char    *start_time = NULL;
    char    *template;
    char    *linkname = NULL;
    char    *prevlinkname = NULL;
#ifndef _WIN32
    uid_t    new_uid = 0;
    gid_t    new_gid = 0;
    int        change_uid = 0;
    int        change_gid = 0;
#endif
    mode_t    linktype = 0;
    int     n_bytes_read;
    int        ch;
    time_t    time_now;
    time_t    time_offset = 0;
    time_t    next_period = 0;
    int     log_fd = -1;
    int     no_alarm = 0;

    memset( handler, '\0', MAX_PATH+1 );
    memset( handler_arg, '\0', MAX_PATH+1 );
    memset( filename, '\0', MAX_PATH+1 );
    // 13 is length of .happypandas , 14 with \0 :)
    memset( lockfilename, '\0', MAX_PATH+14 );

#ifndef _WIN32
    while ((ch = getopt_long(argc, argv, short_options, long_options, NULL)) != EOF)
#else
    while ((ch = getopt(argc, argv, short_options)) != EOF)
#endif        
    {
    switch (ch)
    {
    case 'a':
        use_american_date_formats = 1;
        break;
        
    case 'e':
        use_american_date_formats = 0;
        break;
        
    case 's':
        start_time = optarg;
        break;

    case 'z':
        sprintf(tzbuf, "TZ=%s", optarg);
        putenv(tzbuf);
        break;

    case 'H':
        linkname = optarg;
        linktype = S_IFREG;
        break;

    case 'l':
    case 'S':
        linkname = optarg;
#ifndef _WIN32
        linktype = S_IFLNK;
#endif        
        break;
    case 'L':
        acquire_lock = 1;
        break;
    case 'P':
        if (linkname == NULL)
        {
        fprintf(stderr, "A current log symlink is needed to mantain a symlink to the previous log\n");
        exit(1);
        }
        prevlinkname = optarg;
        break;
        

    case 'd':
        period_delay_units = parse_timespec(optarg, &period_delay);
        break;

    case 'p':
        periodicity = parse_timespec(optarg, &period_multiple);
        if (   (periodicity == INVALID_PERIOD)
        || (periodicity == PER_SECOND) && (60 % period_multiple)
        || (periodicity == PER_MINUTE) && (60 % period_multiple)
        || (periodicity == HOURLY)     && (24 % period_multiple)
        || (periodicity == DAILY)      && (period_multiple > 365)
        || (periodicity == WEEKLY)     && (period_multiple > 52)
        || (periodicity == MONTHLY)    && (12 % period_multiple)) {
        fprintf(stderr, "%s: invalid explicit period specification (%s)\n", argv[0], start_time);
        exit(1);
        }        
        break;
        
#ifndef _WIN32
    case 'u':
        new_uid = parse_uid(optarg, argv[0]);
        change_uid = 1;
        break;
    case 'g':
        new_gid = parse_gid(optarg, argv[0]);
        change_gid = 1;
        break;
#endif
    case 'M':
        sscanf( optarg, "%o", & file_mode );
        break;
    case 'D':
        sscanf( optarg, "%o", & dir_mode );
        break;
    case 'o':
        periodicity = ONCE_ONLY;
        break;
        
    case 'x':
        if (strcmp(optarg, "-") == 0)
        {
        debug_file = stderr;
        }
        else
        {
        debug_file = fopen(optarg, "a+");
        }
        break;
    case 'r':
            strncat(handler, optarg, MAX_PATH - strlen(handler) );
            use_handler=1;
            break;
    case 'G':
            strncat(handler_arg, optarg, MAX_PATH - strlen(handler) );
            use_handler_arg=1;
            break;
    case 'n':
            no_alarm=1;
            break;

    case 'V':
        fprintf(stderr, VERSION_MSG);
        exit(0);
        
    case 'h':
    case '?':
        fprintf(stderr, USAGE_MSG, argv[0]);
        exit(1);
    }
    }

    if ((argc - optind) != 1)
    {
    fprintf(stderr, USAGE_MSG, argv[0]);
    exit(1);
    }

#ifndef _WIN32
    if (change_gid && 
#ifndef CRONOLOG_HAS_SETREUID
            setgid(new_gid) 
#else 
            setregid(new_gid,new_gid) 
#endif  /* CRONOLOG_HAS_SETEUID */
            == -1) {
    fprintf(stderr, "setgid: unable to change to gid: %d\n", new_gid);
           exit(1);
    }
    if (change_uid && 
#ifndef CRONOLOG_HAS_SETREUID
            setuid(new_uid) 
#else 
            setreuid(new_uid,new_uid) 
#endif  /* CRONOLOG_HAS_SETEUID */
            == -1) {
    fprintf(stderr, "setuid: unable to change to uid: %d\n", new_uid);
           exit(1);
    }
#endif

    DEBUG((VERSION_MSG "\n"));

    if (start_time)
    {
    time_now = parse_time(start_time, use_american_date_formats);
    if (time_now == -1)
    {
        fprintf(stderr, "%s: invalid start time (%s)\n", argv[0], start_time);
        exit(1);
    }
    time_offset = time_now - time(NULL);
    DEBUG(("Using offset of %d seconds from real time\n", time_offset));
    }

    /* The template should be the only argument.
     * Unless the -o option was specified, determine the periodicity.
     */
    
    template = argv[optind];
    if (periodicity == UNKNOWN)
    {
    periodicity = determine_periodicity(template);
    }


    DEBUG(("periodicity = %d %s\n", period_multiple, periods[periodicity]));

    if (period_delay) {
    if (   (period_delay_units > periodicity)
        || (   period_delay_units == periodicity
        && abs(period_delay)  >= period_multiple)) {
        fprintf(stderr, "%s: period delay cannot be larger than the rollover period\n", argv[0]);
        exit(1);
    }        
    period_delay *= period_seconds[period_delay_units];
    }

    DEBUG(("Rotation period is per %d %s\n", period_multiple, periods[periodicity]));


#ifndef _WIN32
    set_signal_handlers();

    if( ! no_alarm )
    {
        //ensure that the first read() does not hang, and that the log file is promptly created
        //subsequent alarm() calls will set the alarm for the rotation period.
        alarm( 1 ); 
    }
#endif


    /* Loop, waiting for data on standard input */

    for (;;)
    {
    /* Read a buffer's worth of log file data, exiting on errors
     * or end of file.
     */
    n_bytes_read = read(0, read_buf, sizeof read_buf);
    if (n_bytes_read == 0)
    {
        cleanup(3);
    }
    if (errno == EINTR)
    {
        /* 
             * fall through, it may have been alarm, in which case it will be time to rotate.
             * */
    }
    else if (n_bytes_read < 0)
    {
        cleanup(4);
    }

    time_now = time(NULL) + time_offset;
    
    /* If the current period has finished and there is a log file
     * open, close the log file
     */
    if ((time_now >= next_period) && (log_fd >= 0))
    {
        close(log_fd);
        log_fd = -1;
            fork_to_handle_file();
    }
    
    /* If there is no log file open then open a new one.
     */
    if (log_fd < 0)
    {
        log_fd = new_log_file(template, linkname, linktype, prevlinkname,
                  periodicity, period_multiple, period_delay,
                  filename, sizeof (filename), time_now, &next_period);
#ifndef _WIN32
        if( ! no_alarm )
        {
            alarm( next_period - time_now );
        }
#endif
    }

    DEBUG(("%s (%d): wrote message; next period starts at %s (%d) in %d secs\n",
           timestamp(time_now), time_now, 
           timestamp(next_period), next_period,
           next_period - time_now));

    /* Write out the log data to the current log file.
     */
    if (n_bytes_read && write(log_fd, read_buf, n_bytes_read) != n_bytes_read)
    {
        perror(filename);
        cleanup(5);
    }
    }

    /* NOTREACHED */
    return 1;
}

/* Open a new log file: determine the start of the current
 * period, generate the log file name from the template,
 * determine the end of the period and open the new log file.
 *
 * Returns the file descriptor of the new log file and also sets the
 * name of the file and the start time of the next period via pointers
 * supplied.
 */
int
new_log_file(const char *template, const char *linkname, mode_t linktype, const char *prevlinkname,
         PERIODICITY periodicity, int period_multiple, int period_delay,
         char *pfilename, size_t pfilename_len,
         time_t time_now, time_t *pnext_period)
{
    time_t     start_of_period;
    struct tm     *tm;
    int     log_fd;


    start_of_period = start_of_this_period(time_now, periodicity, period_multiple);
    tm = localtime(&start_of_period);
    strftime(pfilename, BUFSIZE, template, tm);
    *pnext_period = start_of_next_period(start_of_period, periodicity, period_multiple) + period_delay;
    
    DEBUG(("%s (%d): using log file \"%s\" from %s (%d) until %s (%d) (for %d secs)\n",
    timestamp(time_now), time_now, pfilename, 
       timestamp(start_of_period), start_of_period,
    timestamp(*pnext_period), *pnext_period,
    *pnext_period - time_now));
    
    log_fd = openwrapper(pfilename);
    
#ifndef DONT_CREATE_SUBDIRS
    if ((log_fd < 0) && (errno == ENOENT))
    {
        create_subdirs(pfilename, dir_mode);
        log_fd = openwrapper(pfilename);
    }
#endif        

    if (log_fd < 0)
    {
        perror(pfilename);
        exit(2);
    }

    if (linkname)
    {
        create_link(pfilename, linkname, linktype, prevlinkname);
    }
    return log_fd;
}

/* 
 * fork, then exec an external handler to deal with rotated file.
 */
void
fork_to_handle_file()
{
    int fk ;
    static int childpid=0;

    if( ! use_handler || !i_am_handler || handler[0] =='\0' || filename[0] == '\0' )
    {
        return;
    }
    fk=fork();
    if( fk < 0 )
    {
        perror("couldnt fork");
        exit(2);
    }else if( fk > 0 )
    {
        if( childpid )
        {
            /* 
             * collect zombies. run twice, in case one or more children took longer than
             * the rotation period for a while, this will eventually clean them up.
             * Of course, if handler children take longer than rotation period to handle
             * things, you will eventually have a big problem.
             * 
             * */ 
            (void) waitpid( 0, NULL, WNOHANG | WUNTRACED );
            (void) waitpid( 0, NULL, WNOHANG | WUNTRACED );
        }
        childpid=fk;
        return; /* parent */
    }
    /* child */
    /* dont muck with stdin or out of parent, but allow stderr to be commingled */
    close(0);
    close(1);
    handle_file();
}

/* 
 * exec an external handler to deal with rotated file.
 */
void 
handle_file()
{
    char **exec_argv ;
    char **exec_envp ;
    if( ! use_handler || !i_am_handler || handler[0] =='\0' || filename[0] == '\0' )
    {
        return;
    }
    if ( acquire_lock ) {
      strncpy(lockfilename, filename, MAX_PATH);
      strcat(lockfilename, ".happypandas");
      int ret = open(lockfilename, OPEN_EXCLUSIVE, 'w');
      // file already exists
      if (ret == -1) {
	exit(0);
      }
    }
    exec_envp = malloc( sizeof( char *)*1);
    exec_envp[0] = NULL;

    exec_argv = malloc( sizeof( char *)*6);
    int i=0;
    //exec_argv[i++] = strdup( "/bin/bash" );
    //exec_argv[i++] = strdup( "--login" );
    exec_argv[i++] = strdup( handler );
    if ( use_handler_arg == 1 )
    {
        exec_argv[i++] = strdup( handler_arg );
    }
    exec_argv[i++] = strdup( filename );
    exec_argv[i++] = NULL;

    execve( exec_argv[0], exec_argv, exec_envp );
    perror("cant execvp");
    exit(2);
}



#ifndef _WIN32
/* 
 * wrapper to be called as signal handler.
 */
void 
handle_file_on_sig( int sig, siginfo_t *si, void *v )
{
    handle_file();
    /* not reached */
    exit( 3 );
};

/* 
 * wrapper to be called for alarm signal
 */
void 
alarm_signal_handler( int sig, siginfo_t *si, void *v )
{
        ;
        /* 
         * do nothing; the key thing is that the alarm will cause the read()
         * to fail with errno=EINTR. this empty handler is required, because the
         * default handler will exit(1)
         *
         */
};

void
set_signal_handlers()
{
    /* 
     * all signals which usually kill a process that can be caught are
     * set to handle_file when received. This will make apache shutdowns more 
     * graceful even if use_handler is false.
     */
    setsig_handler( SIGHUP, handle_file_on_sig );
    setsig_handler( SIGINT, handle_file_on_sig );
    setsig_handler( SIGQUIT, handle_file_on_sig );
    setsig_handler( SIGILL, handle_file_on_sig );
    setsig_handler( SIGABRT, handle_file_on_sig );
    setsig_handler( SIGBUS, handle_file_on_sig );
    setsig_handler( SIGFPE, handle_file_on_sig );
    setsig_handler( SIGPIPE, handle_file_on_sig );
    setsig_handler( SIGTERM, handle_file_on_sig );
    setsig_handler( SIGUSR1, handle_file_on_sig );

    /* sigalrm is used to break out of read() when it is time to rotate the log. */
    setsig_handler( SIGALRM, alarm_signal_handler );
}

void
setsig_handler( int signum,  void (*action)(int, siginfo_t *, void *))
{
    struct sigaction siga ;
    memset( &siga, '\0', sizeof( struct sigaction ));
    siga.sa_sigaction= action ;
    siga.sa_flags = SA_SIGINFO ;
    if( -1== sigaction( signum, &siga, NULL ))
    {
        perror( "cant set sigaction" );
    }
}
#endif


/* 
 * cleanup
 */
void
cleanup( int exit_status )
{
    handle_file();
    exit(exit_status);
}

/* 
 * only the first cronolog process to open a particular file is responsible
 * for starting the cleanup process later. This wrapper sets i_am_handler
 * according to that logic.
 * */
int 
openwrapper( const char *ofilename )
{
    int ret;
    if( use_handler !=1 )
    {
        return open(ofilename, OPEN_SHARED, file_mode );
    }
    ret = open(ofilename, OPEN_EXCLUSIVE, file_mode );
    if( ret < 0 )
    {
        ret = open(ofilename, OPEN_SHARED, file_mode );
        i_am_handler= 0;
    }
    else
    {
        i_am_handler=1;
    }
    return ret;
}

