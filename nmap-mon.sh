#!/bin/sh
# ****************************************************************************
#  $Id: nmap-mon.sh,v 1.26 2006/11/01 04:06:52 adam Exp $
#
#  This script handles running automated nmap scans for any series of 
#  configurations found in the ROOT_DIR. 
#
# ****************************************************************************
#
#  Copyright (c) 2001-2006, Adam Kaufman
#  All rights reserved.
#
#  Redistribution and use in source and binary forms, with or without
#  modification, are permitted provided that the following conditions are
#  met: 
#
#  1. Redistributions of source code must retain the above copyright
#     notice, this list of conditions and the following disclaimer. 
#
#  2. Redistributions in binary form must reproduce the above copyright
#     notice, this list of conditions and the following disclaimer in the
#     documentation and/or other materials provided with the distribution.
#
#  3. Neither the name of the author nor the names of its contributors may
#     be used to endorse or promote products derived from this software
#     without specific prior written permission. 
#
#  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
#  ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
#  LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
#  A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
#  HOLDERS OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
#  SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
#  TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
#  PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
#  LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
#  NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
#  SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#
# ****************************************************************************
# If you want to run scans more than once a day, change the SCANDATE 
# variable here to something more reasonable, for instance:
#
#SCANDATE=$(date +%Y%m%d%H%M%S)
#SCANDATE=$(date +%Y%m%d%H%M)
#SCANDATE=$(date +%Y%m%d%H)
SCANDATE=$(date +%Y%m%d)
PIDFILE=/var/run/nmap-mon.pid

# ****************************************************************************
#  Perform cleanup tasks before terminating
# ****************************************************************************
shutdown()
{
    rm -f ${PIDFILE};
    exit 1;
}

# ****************************************************************************
#  Make sure another process is not already running
# ****************************************************************************
if [ -e ${PIDFILE} ]; then
    ps -p `cat ${PIDFILE}`
    if [ $? -ne 0 ]; then
        echo "Nope, just a stale pid file."
        echo $$ > ${PIDFILE};
    else
        echo "Looks like another process is running. Quitting."
        exit 1;
    fi;
else
    echo $$ > ${PIDFILE};
fi;

# ****************************************************************************
#  Verify command line arguments
# ****************************************************************************
if [ -z $1 ]; then
    echo "Usage: $0 root_dir";
    shutdown;
else
    if [ -d $1 ]; then
         ROOT_DIR=$1
    else
         echo "$1 is not a valid root directory";
         shutdown;
    fi;
fi;

# ****************************************************************************
#  Set some sane defaults for global variables 
# ****************************************************************************
init_shell_env()
{
    NMAP=/usr/local/bin/nmap
    SCANDIFF=/usr/local/bin/scandiff
    PGP=/usr/local/bin/gpg

    NMAP_FLAGS="-P0 -sS -O -r -p 1-65535"
    SUBJECT="nmap/scandiff scan results"
    RECIPIENTS="bit-bucket"
    PGP_RECIPIENTS=""
    LOCAL_USER=""
    REMOTE_HOST=""
    SITE_DESCRIPTION=""
    SSH_PORT="22"
    SCAN_MODE="440"
    SCAN_OWNER="root"
    SCAN_GROUP="wheel"
    BASELINE_RESET="manual"
    LOGTYPE="xml"
}

# ****************************************************************************
# !SECURITY RISK! email results to the recipients without encrypting
# ****************************************************************************
notify()
{
    if [ -s ${curr_dir}/logs/diff-results.${SCANDATE} ]; then
        cat ${curr_dir}/logs/diff-results.${SCANDATE} | \
            mail -n -s "${SUBJECT}: ${site}" ${RECIPIENTS} 2>&1| \
            gzip -c >> ${logfile} 
    fi;
}

# ****************************************************************************
# Send email notification using gnupg to encrypt
# ****************************************************************************
pgp_notify()
{
    pgp_recipients=`echo ${PGP_RECIPIENTS} |sed -e 's/\([a-zA-Z0-9\.@]*\)/--recipient &/g'`
    if [ -s ${curr_dir}/logs/diff-results.${SCANDATE} ]; then
        ${PGP} --batch --armor --sign --encrypt ${pgp_recipients} \
            -o ${curr_dir}/diff-results.${SCANDATE}.pgp \
            ${curr_dir}/logs/diff-results.${SCANDATE} 2>&1| \
            gzip -c >> ${logfile} 
        rm ${curr_dir}/logs/diff-results.${SCANDATE}
    fi;

    # Mail the output to me and delete the diff file
    if [ -s ${curr_dir}/diff-results.${SCANDATE}.pgp ]; then
        cat ${curr_dir}/diff-results.${SCANDATE}.pgp | \
            mail -n -s "${SUBJECT}: ${site}" ${PGP_RECIPIENTS} 2>&1| \
            gzip -c >> ${logfile} 
        rm ${curr_dir}/diff-results.${SCANDATE}.pgp
    else
        zcat ${logfile} | \
            mail -n -s "${SUBJECT}: ${site}" ${PGP_RECIPIENTS} 2>&1| \
            gzip -c >> ${logfile} 
    fi;
}

# ****************************************************************************
#  Must define scanning function before we need it
# ****************************************************************************
perform_scan() 
{
    # Is this a remote scan?
    if [ -n "${LOCAL_USER}" ] && 
       [ -n "${REMOTE_HOST}" ]; then
        echo "We have a remote scan defined: ${LOCAL_USER}@${REMOTE_HOST}" \
            | gzip -c >> ${logfile};
        nmapcmd="${NMAP} ${NMAP_FLAGS} -iL targets -oA scanlog_${SCANDATE}";
        nmapcmd="${nmapcmd} 2>nmap_${SCANDATE}.log";

        sshcmd="ssh -p ${SSH_PORT} ${REMOTE_HOST}";
        scpcmd="scp -B -q -P ${SSH_PORT}";

        # Copy the targets file down and execute scan
        su ${LOCAL_USER} -c "${scpcmd} ${curr_dir}/targets ${REMOTE_HOST}:";
        su ${LOCAL_USER} -c "${sshcmd} -C 'sudo $nmapcmd'";
        echo "ssh remote scan returned $?" | gzip -c >> ${logfile}

        # Deal with each of the remote log files
        for ext in gnmap nmap xml
        do
            su ${LOCAL_USER} -c \
                "${scpcmd} ${REMOTE_HOST}:scanlog_${SCANDATE}.${ext} /tmp"
            echo "scp returned $?" | gzip -c >> ${logfile}
            chown ${SCAN_OWNER}:${SCAN_GROUP} /tmp/scanlog_${SCANDATE}.${ext} 
            chmod ${SCAN_MODE} /tmp/scanlog_${SCANDATE}.${ext}
            mv /tmp/scanlog_${SCANDATE}.${ext} ${curr_dir}/scans/;
            su ${LOCAL_USER} -c \
                "${sshcmd} -C 'rm scanlog_${SCANDATE}.${ext}'";
        done

        # Delete the remote targets file
        su ${LOCAL_USER} -c "${sshcmd} -C 'rm nmap_${SCANDATE}.log'";
        su ${LOCAL_USER} -c "${sshcmd} -C 'rm targets'";

        return 1;
    fi;

    # Run scan from localhost as current user
    ${NMAP} ${NMAP_FLAGS} \
        -iL ${curr_dir}/targets \
        -oA ${curr_dir}/scans/scanlog_${SCANDATE} 2>&1| \
         gzip -c >> ${logfile}
    if [ $? -ne 0 ]; then
        echo "${NMAP} returned $?" | gzip -c >> ${logfile}
    fi;

    return 1;
}

# ****************************************************************************
#  reset baseline so that scans will be compared against prior day
# ****************************************************************************
baseline_reset()
{
    for ext in gnmap nmap xml
    do
        baseline=${curr_dir}/scans/baseline.${ext};
        if [ -e ${baseline} ]; then
            rm -f ${baseline}
        fi;

        ln -s ${curr_dir}/scans/scanlog_${SCANDATE}.${ext} \
              ${curr_dir}/scans/baseline.${ext}
    done
}

# ****************************************************************************
#  Traverse only the directories found in root 
# ****************************************************************************
for site in `ls ${ROOT_DIR}`
do
    curr_dir=${ROOT_DIR}/${site};

    # Make sure we're dealing with a directory
    if [ ! -d ${curr_dir} ]; then 
        continue; # otherwise skip it
    fi;

    # Make sure all necessary directories exist
    for dir in logs scans
    do 
        if [ ! -e "${curr_dir}/${dir}" ]; then
             mkdir -m 0750 "${curr_dir}/${dir}";
             if [ $? -gt 0  ]; then
                 echo "$0: Fatal Error";
                 shutdown;
             fi;
        fi;
    done

    logfile=${curr_dir}/logs/log.gz;

    echo "*******************************************" | gzip -c > ${logfile}
    echo "$0 started:" `date` | gzip -c >> ${logfile}

    # Check to see if site is disabled
    if [ -e ${curr_dir}/disabled ]; then 
        echo "NOTICE: ${curr_dir} is disabled";
        echo "NOTICE: ${curr_dir} is disabled" | \
            gzip -c >> ${logfile} 
        continue;
    fi;

    # Check for targets file
    if [ ! -s ${curr_dir}/targets ]; then
        echo "***ERROR*** ${curr_dir}/targets not found";
        echo -n "Please see nmap man page section "
        echo "TARGET SPECIFICATION for syntax.";
        continue;
    fi;

    # Re-initialize environment to defaults, then override default 
    # settings with global config and then the site config.
    init_shell_env;

    if [ -s ${ROOT_DIR}/global-config ]; then
        . ${ROOT_DIR}/global-config
    else
        echo "Errr, where's the global-config file at?";
        shutdown;
    fi;

    if [ -s ${curr_dir}/site-config ]; then
        . ${curr_dir}/site-config 
    fi;

    # Run nmap scan if todays results aren't found
    if [ ! -s ${curr_dir}/scans/scanlog_${SCANDATE}.${LOGTYPE} ]; then
        perform_scan;
    fi;

    # Check for baseline file before continuing 
    baseline=${curr_dir}/scans/baseline.${LOGTYPE};
    if [ ! -s ${baseline} ]; then
        echo "${baseline} not found, moving on..." | gzip -c >> ${logfile}
        echo "$0 finished:" `date` | gzip -c >> ${logfile}
        continue;
    fi;
 
    # Run scandiff and decide whether to notify
    #  0 = no differences were found
    #  1 = some differences were found
    #  2 = trouble
    ${SCANDIFF} ${SCANDIFF_FLAGS} \
        ${curr_dir}/scans/baseline.${LOGTYPE} \
        ${curr_dir}/scans/scanlog_${SCANDATE}.${LOGTYPE} \
        > ${curr_dir}/logs/diff-results.${SCANDATE}
    retval=$?;
    echo "${SCANDIFF} returned: $retval" | gzip -c >> ${logfile};
    case $retval in
      0)  rm -f ${curr_dir}/logs/diff-results.${SCANDATE}
          ;;
      *)
          if [ ! -z "${RECIPIENTS}" ]; then notify; fi;
          if [ ! -z "${PGP_RECIPIENTS}" ]; then pgp_notify; fi;
          if [ "${BASELINE_RESET}" = "auto" ]; then baseline_reset; fi;
          ;;
    esac

    # Log the finish time
    echo "$0 finished:" `date` | gzip -c >> ${logfile}

done

shutdown;
