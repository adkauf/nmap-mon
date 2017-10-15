# nmap-mon
Automated monitoring and alerting for network changes 
# Synopsis
**nmap-mon.sh** root_dir
# Description
**namp-mon** is a script that will perform either a local or remote nmap scan for each site configured under the root directory. Stakeholders can be notified if differences against the baseline are identified. 
# Directory and File Structure
root_dir/
  * global-config
  * site_dir/
    * logs/
    * scans/
    * site-config
    * targets
    * disabled
# Configuration
 
**NMAP** location of nmap executable 

**SCANDIFF** location of diff executable 

**PGP** location of pgp executable

**NMAP_FLAGS** options to perform scan with

**SUBJECT** email notification subject line

**RECIPIENTS** email notification recipients

**PGP_RECIPIENTS** pgp email notification recipients
  
**LOCAL_USER** local user account to login to remote host

**REMOTE_HOST** remote host to perform scan from

**SITE_DESCRIPTION**

**SSH_PORT** port ssh is listening on remote host 
 
**SCAN_MODE**

**SCAN_OWNER**

**SCAN_GROUP**

**BASELINE_RESET**

**LOGTYPE**
  
