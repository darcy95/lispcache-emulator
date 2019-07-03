#!/usr/bin/perl 

use strict;
use lib '.';
no strict 'subs';
no strict 'refs';

local $| = 1;

# ==================================================
# Configuration 
# ==================================================
use constant INPUTSTREAM => "/dev/stdin"; # Standard Input device

# ==================================================
# Required modules
# ==================================================
use Net::Patricia;
use Getopt::Long;
use Cwd 'abs_path';
use File::Basename;

$::PROGRAM = basename($0);
$::DIRECTORY = dirname($0);

# ==================================================
# Use following modules to be fed from pcap file (won't scale though)
# ==================================================
#use Net::Pcap;
#use Net::PcapUtils;
#use NetPacket::Ethernet qw(:strip);
#use NetPacket::IP;
#use NetPacket::TCP;
#use NetPacket::UDP;

# --------------------------------------------------
# Constants
# --------------------------------------------------
use constant T => 1;
use constant F => 0;
use constant IN => 1;
use constant OUT => 2;
use constant BI => 3;
use constant NONE => 4;
use constant TRUE => 1;
use constant FALSE => 0;
use constant true => 1;
use constant false => 0;
use constant PKTS => 1;
use constant MISS => 2;

# --------------------------------------------------
# Options
# --------------------------------------------------
$::FAILXTR=-1;    # Also RECOVERXTR
$::NONFAILXTR=-1; # Also NON-RECOVERXTR

$::MODE = "none";
$::TIMEOUT = -1;
$::REFRESHTIME = 60;
$::GRANULARITY = 60;
$::SUFFIX = "";
$::SYMMETRIC = "no";
$::USERLIMIT = -1;
$::QUIET = "no";
$::SHARE = "no";
$::FAIL_OR_RECOVER = "none";
$::TIMEPOINT = 0;

GetOptions("mode|m=s" => \$::MODE,				# Reading from text (for large data) or pcap (only for small data set)
		"timeout|t=i" => \$::TIMEOUT,			# Timeout
	"granularity|g=i" => \$::GRANULARITY,		# 
		 "suffix|s=s" => \$::SUFFIX,			# Suffix of logout files.
      "symmetric|y=s" => \$::SYMMETRIC,			# When yes, the simulator will act as a symmetric LISP locator.
	  "userlimit|u=i" => \$::USERLIMIT,			# Simulation will be performed only for this number of end-hosts. (0: unlimited)
	      "quiet|q=s" => \$::QUIET,				# When yes, the script runs quietly
		  "share|h=s" => \$::SHARE,				# When yes, all xTRs will synchronize their cache entries.
    "failrecover|r=s" => \$::FAIL_OR_RECOVER, 	# Is this failure scenario? or recovery scenario?
	  "timepoint|f=i" => \$::TIMEPOINT,			# A time point of artificial xTR failure (in seconds, 0: no failure).
        "failxtr|a=i" => \$::FAILXTR,			# An array index of the xTR which fails in the scenario
	 "nonfailxtr|b=i" => \$::NONFAILXTR			# An array index of the xTR which runs without failure/recovery
);

printUsage() unless ($::MODE eq "text" || $::MODE eq "pcap");
printUsage() unless ($::TIMEOUT > 0);
printUsage() unless ($::GRANULARITY > 0);
printUsage() unless ($::SYMMETRIC eq "yes" || $::SYMMETRIC eq "no");
printUsage() unless ($::SHARE eq "yes" || $::SHARE eq "no");
printUsage() unless ($::USERLIMIT >= 0);
printUsage() unless ($::TIMEPOINT >= 0);
printUsage() unless ($::FAIL_OR_RECOVER eq "none" || $::FAIL_OR_RECOVER eq "fail" || $::FAIL_OR_RECOVER eq "recover");

$::TTL = $::TIMEOUT;
$::SUFFIX = "-t" . $::TTL . "-g" . $::GRANULARITY if ($::SUFFIX eq "");

my $config_prefixes_bgp = $::DIRECTORY . "/bgp-prefixes";
system "touch " . $config_prefixes_bgp unless (-e $config_prefixes_bgp); 

my $config_prefixes = $::DIRECTORY . "/lisp-database";
die "File Not Found: " . $config_prefixes . "\n" unless (-e $config_prefixes); 

prnt("Reading internal prefixes\n");
open(PREFIXESINTERN, "< $config_prefixes") or die "Cannot open prefix data.\n";

# --------------------------------------------------
# Count the number of xTRs to be simulated.
# --------------------------------------------------
my @xtr_indexes;

while (my $prefix_intern = <PREFIXESINTERN>)
{
	$prefix_intern =~ s/\n//;
	my ($index, $prefix) = split / /, $prefix_intern;
	die "Check " . $config_prefixes . ": the file contains only one column.\n" if ($index eq "" || $prefix eq "");

	my $last_index = scalar @xtr_indexes;

	@xtr_indexes[$last_index] = $index;
}

my $num_index = scalar @xtr_indexes;
die "FAIL_OR_RECOVER option only takes effect when multiple xTRs are simulated." if ($::FAIL_OR_RECOVER ne "none" && $num_index < 2);
die "TIMEPOINT option only takes effect when multiple xTRs are simulated." if ($::TIMEPOINT > 0 && $num_index < 2);
die "SHARE option only takes effect when multiple xTRs are simulated." if ($::SHARE eq "yes" && $num_index < 2);
die "FAIL_OR_RECOVER option must be fail or recover if TIMEPOINT option is specified." if ($::FAIL_OR_RECOVER eq "none" && $::TIMEPOINT > 0);
die "FAILXTR and NONFAILXTR cannot be the same." if ($::FAILXTR == $::NONFAILXTR && $::FAIL_OR_RECOVER ne "none");
die "FAILXTR and NONFAILXTR options only take effect when multiple xTRs are simulated." if ($::FAILXTR >= 0 && $::NONFAILXTR >= 0 && $num_index < 2);
die "An index of FAILXTR or NONFAILXTR cannot be greater than the number of xTRs." if ($::FAILXTR >= $num_index || $::NONFAILXTR >= $num_index);

# --------------------------------------------------
# Check presence of config files
# --------------------------------------------------
prnt("\n");
prnt("[Current settings]\n");
prnt("Mode: " . $::MODE  . "\n");
prnt("TTL: " . $::TTL . "\n");
prnt("Granularity: " . $::GRANULARITY . "\n");
prnt("Logfile Suffix: " . $::SUFFIX . "\n");
prnt("Symmetric LISP: " . $::SYMMETRIC . "\n");
prnt("Limit of endhosts: " . $::USERLIMIT . " (0 means no limit)\n");
prnt("Number of xTRs: " . $num_index . "\n");
prnt("LISP-Cache share: " . $::SHARE . "\n");
prnt("Scenario: " . $::FAIL_OR_RECOVER . " scenario\n");
prnt("Artificial failure/recovery point (after n seconds) of the first xTR: " . $::TIMEPOINT . " (0 means no failure/recovery)\n");
prnt("Failing/Recovering xTR: " . $::FAILXTR . " (-1 means no failure/recovery)\n");
prnt("Non-failing/recovering xTR: " . $::NONFAILXTR . " (-1 mean no failure/recovery)\n");
prnt("\n");
prnt("Starting the process\n");

unless (-s $config_prefixes_bgp)
{
	#prnt("Downloading bgp prefixes from iPlane\n\n");
	#my $wgetopt = ($::QUIET eq "yes") ? "-q" : "-v";
	#system "wget " . $wgetopt . " http://iplane.cs.washington.edu/data/origin_as_mapping.txt -O " . $config_prefixes_bgp;
	system "bash bootstrap-data.sh";
	prnt("\n");
}

# --------------------------------------------------
# Check arguments
# --------------------------------------------------
my $stream_input = T unless exists $ARGV[0];

# --------------------------------------------------
# Patricia Trie (BGP)
# --------------------------------------------------
my $patricia_bgp_prefixes = new Net::Patricia;

prnt("Reading known BGP prefixes\n");
open(PREFIXESBGP, "< " . $config_prefixes_bgp) or die "Cannot open bgp prefix data.\n";

while (my $line = <PREFIXESBGP>)
{
	$line =~ s/\n//;
	my ($prefix_bgp, $as) = split / /, $line;
	$patricia_bgp_prefixes->add_string($prefix_bgp);
}

close(PREFIXESBGP);

# --------------------------------------------------
# Patricia Trie (internal network prefixes)
# --------------------------------------------------
my %patricia_int_prefixes;
my %patricia_int_prefixes_backup;

for (my $i = 0 ; $i < $num_index ; $i++)
{
    # Using a hash as a reference is deprecated ...
    # Changing from % to $ is suggested ... from the dev community, but
	#%patricia_int_prefixes->{$xtr_indexes[$i]} = new Net::Patricia;
	$patricia_int_prefixes{$xtr_indexes[$i]} = new Net::Patricia;
	$patricia_int_prefixes_backup{$xtr_indexes[$i]} = new Net::Patricia;

}

sysseek(PREFIXESINTERN, 0, SEEK_SET); # Rewinding file descriptor. 

while (my $prefix_intern = <PREFIXESINTERN>)
{
	$prefix_intern =~ s/\n//;
	my ($index, $prefix) = split / /, $prefix_intern;
	$patricia_int_prefixes{$index}->add_string($prefix);
	$patricia_int_prefixes_backup{$index}->add_string($prefix);
}

close(PREFIXESINTERN);

my $FD_LOGFILE = "LOGFILE";
my $FD_CACHELOGFILE = "CACHELOGFILE";
my $FD_MISSPACKETFILE = "MISSPACKETFILE";

for (my $i = 0 ; $i < $num_index ; $i++)
{
	my $logfileref = $FD_LOGFILE . $xtr_indexes[$i];
	my $cachelogfileref = $FD_CACHELOGFILE . $xtr_indexes[$i];
	my $misspacketfileref = $FD_MISSPACKETFILE . $xtr_indexes[$i];

	open($logfileref, "> trace-summary" . $::SUFFIX . "-xtr-" . $xtr_indexes[$i] . ".log");
	open($cachelogfileref, "> cache-expires" . $::SUFFIX . "-xtr-" . $xtr_indexes[$i] . ".log");
	open($misspacketfileref, "> cachemiss-packets" . $::SUFFIX . "-xtr-" . $xtr_indexes[$i] . ".log");
}

# --------------------------------------------------
# %output
# ---------------+----------------------------------
#  Key name      | Field description
# ---------------+----------------------------------
#  slicestart    | Slice_Start -  the start 
#                | timestamp of the time slice
#                | (bin/slot/ or whatever).
#                |
#  sliceend      | Slice_End - ending timestamp of the 
#                | slice.
#                | 
#                |       These values are unix
#                |       timestamp format 
#                |       i.e, seconds.milseconds
#                |
#  entries       | Entries - number of entries present in 
#                | the cache at the end of the time slice.
#                |
#  hit           | Hit - number of flows started in the 
#                | current time slice that have generated a 
#                | HIT in the cache, i.e., # of mappings in
#                | the cache.
#                |
#  miss          | Miss - number of flows started in the 
#                | current time slice that have generated a 
#                | cachemiss in the cache.
#                |
# flows_total    | Total number of flows
#                |
# flows_tcp_in   |
#                |
# flows_tcp_out  |
#                |
# flows_udp_in   |
#                |
# flows_udp_out  |
#                |
# flows_other_in |
#                |
# flows_other_out|
#                |
#  inhit         | InHit - number of incoming flows started 
#                | in the current time slice that have generated 
#                | a HIT in the cache.
#                |
#  inmiss        | InMiss - number of incoming flows started in 
#                | the current time slice that have generated a 
#                | MISS in the cache.
#                |
#  outflows      | Out_Flows - number of outgoing flows started 
#                | in the current time slice. 
#                |
#  outhit        | OutHit - number of outgoing flows started in the 
#                | current time slice that have generated a HIT in 
#                | the cache
#                |
#  outmiss       | OutMiss - number of outgoing flows started in 
#                | the current time slice that have genrated a MISS 
#                | in the cache.
#                |
#  timeouts      | Timeouts - number of entries that expire in the
#                | current time slice.
#                |
#  pkts          | Pkts - total number of packets of the flows 
#                | started in the current time slice. 
#                |
#  inpkts        | In_Pkts - number of packets of the incoming 
#                | flows started in the current time slice. 
#                |
#  outpkts       | Out_Pkts - number of packets of the outgoing 
#                | flows started in the current time slice. 
#                |
#  bytes         | Bytes - IP header (20 bytes) is included
#                |
#  inbytes       | In_Bytes
#                |
#  outbytes      | Out_Bytes
#                |
#  inpfx         | Number of incoming flow prefixes 
#                |
#  outpfx        | Number of outgoing flow prefixes
#                |
#  unipfx        | Number of union prefixes of incoming & outgoing 
#                | flows
#                |
#  intpfx        | Number of intersection prefixes of incoming & 
#                | outgoing flows
#                |
# http_pkts      | The number of http packets 
#                |
# nntp_pkts      | The number of nntp packets
#                |
# edtcp_pkts     | The number of eDonkey (TCP) packets
#                |
# torrent_pkts   | The number of BitTorrent packets
#                |
# ftp_pkts       |
#                |
# smtp_pkts      |
#                |
# dns_pkts       |
#                |
# ntp_pkts       |
#                |
# edudp_pkts     | The number of eDonkey (UDP) packets
#                |
# known_tcp_pkts | The number of packets for well-known (port number <= 1024) protocol on TCP
#                |
# un_tcp_pkts    | (port number > 1024)
#                |
# known_udp_pkts |
#                |
# un_udp_pkts    |
#                |
# http_miss      | The number of http cache misses
#                |
# nntp_miss      | The number of nntp cache misses
#                |
# edtcp_miss     | The number of eDonkey (TCP) cache misses
#                |
# torrent_miss   | The number of BitTorrent cache misses
#                |
# ftp_miss       |
#                |
# smtp_miss      |
#                |
# dns_miss       |
#                |
# ntp_miss       |
#                |
# edudp_miss     | The number of eDonkey (UDP) cache misses
#                |
# known_tcp_miss | The number of ...
#                |
# un_tcp_miss    |          "
#                |
# known_udp_miss |
#                |
# un_udp_miss    |
#                |
# ---------------+-----------------------------------
my %output;

for (my $i = 0 ; $i < $num_index ; $i++)
{
	$output{$xtr_indexes[$i]} = {};
}

# An example of the key of cache: 100.00.0.0/12
my %cache;  

for (my $i = 0 ; $i < $num_index ; $i++)
{
	$cache{$xtr_indexes[$i]} = {};
}

# An example of the key of flows:
#     192.168.0.1-10.0.0.1-8808-80-16
my %flows;

for (my $i = 0 ; $i < $num_index ; $i++)
{
	$flows{$xtr_indexes[$i]} = {};
}

# --------------------------------------------------
# Userpool
# -------------+------------------------------------
my %userpool;

# --------------------------------------------------
# Prefixes
# --------------------------------------------------
my %prefixes;

for (my $i = 0 ; $i < $num_index ; $i++)
{
	$prefixes{$xtr_indexes[$i]} = {};
}

my $error;
my $input = ($stream_input eq T) ? INPUTSTREAM : $ARGV[0];

# Initialize
for (my $i = 0 ; $i < $num_index ; $i++)
{
	initOutput($xtr_indexes[$i], -1,-1);
}

if ($::FAIL_OR_RECOVER eq "recover")
{
	$patricia_int_prefixes{$xtr_indexes[$::FAILXTR]}->climb(movePrefix);
}

prnt("Running\n"); 

my $packetnum = 0;
my $linenum = 0;
my $counter = 0;

my %timestamp;
my $startTime = time;
my $startTimeOfPkt;
my $isEventHappened = F;
my $is_xTR_recovered = F;

my $inputStream;

if ($::MODE eq "text")
{
	open($inputStream, "< " . $input); # Reading from ascii formated file/stream
}
else
{
	$inputStream = Net::Pcap::open_offline($input,\$error) # Reading from pcap file (stream)
	or die "Can't read '$input': $error\n";
}

while (my ($line, %pkt_info) = getPacketInfo())
{
	last unless exists $pkt_info{'timestamp'};

	$packetnum++;

	my $xtr_index = getXTRindex($pkt_info{'src_ip'}, $pkt_info{'dst_ip'});

	next if $xtr_index == -1;

	$timestamp{$xtr_index} = $pkt_info{'timestamp'};
	$startTimeOfPkt = $pkt_info{'timestamp'} if ($packetnum == 1);

	# --------------------------------------------------
	# If a packet is incoming packet	
    # --------------------------------------------------
	my $dir = getFlowDir($xtr_index, $pkt_info{'src_ip'}, $pkt_info{'dst_ip'});
	my $key = undef;

	# --------------------------------------------------
	next unless userlimit($pkt_info{'src_ip'}, $pkt_info{'dst_ip'}, $dir) == T;

	if ($::SYMMETRIC eq "yes" || $dir == OUT)
	{
    	$key = ($dir == IN) ? 
		$patricia_bgp_prefixes->match_string($pkt_info{'src_ip'}):
		$patricia_bgp_prefixes->match_string($pkt_info{'dst_ip'});
	}

	# --------------------------------------------------
	# Patricia trie returns "undefined" when the address
	# is a multicast address
	# --------------------------------------------------
	# $key = "0.0.0.0/0" unless defined $key;
	next unless defined $key;

	# --------------------------------------------------
	# Check if this packet is the first packet of traces
	# --------------------------------------------------
	if ($output{$xtr_index}->{'slicestart'} == -1 && $output{$xtr_index}->{'sliceend'} == -1)
	{
		for (my $i = 0 ; $i < $num_index ; $i++)
		{
			initOutput($xtr_indexes[$i], $pkt_info{'timestamp'}, $pkt_info{'timestamp'} + $::GRANULARITY);
		}

		if ($::QUIET eq "no" && $linenum == 0)
		{
			printf "\r\n %06d +", ++$linenum;
		}
	}

	if ($::QUIET eq "no")
	{
		$counter++; 
		printf "-" if ($counter % 10000 == 0);
		printf "+" if ($counter % 100000 == 0);

		if ($counter % 1000000 == 0)
		{
			my $tmpTime = $timestamp{$xtr_index};
			printf " " . `date -d \@$tmpTime` . " %06d +", ++$linenum;
			$counter = 0;
		}
	}
 
	# --------------------------------------------------
	# (an artificial) Failure of a RLOCator.
	# --------------------------------------------------
	if (($pkt_info{'timestamp'} - $startTimeOfPkt) >= $::TIMEPOINT && $isEventHappened == F && $::FAIL_OR_RECOVER ne "none")
	{
		prnt("\bX");

		if ($::FAIL_OR_RECOVER eq "fail")
		{
			$patricia_int_prefixes{$xtr_indexes[$::FAILXTR]}->climb(movePrefix);
		}
		elsif ($::FAIL_OR_RECOVER eq "recover")
		{
			if ($::SHARE eq "yes")
			{
				initRecoveringXTR();
			}
			elsif ($::SHARE eq "no")
			{
				recoverXTRs();
			}
		}

		$isEventHappened = T;
	}

	if (($pkt_info{'timestamp'} - $startTimeOfPkt) >= ($::TIMEPOINT + $::TTL)
        && $::FAIL_OR_RECOVER ne "none"
		&& $isEventHappened == T
	   	&& $is_xTR_recovered == F
	   	&& $::FAIL_OR_RECOVER eq "recover"
		&& $::SHARE eq "yes")
	{
		prnt("\bR");

		recoverXTRs();	
		$is_xTR_recovered = T;
	}

	# --------------------------------------------------
	# Check if it is time to empty the output table
	# --------------------------------------------------
	if  ($pkt_info{'timestamp'} >= $output{$xtr_index}->{'sliceend'})
	{
		if ($::SYMMETRIC eq "yes" || $dir == OUT)
		{
			for (my $i = 0 ; $i < $num_index ; $i++)
			{
				my $xtr_index = $xtr_indexes[$i];
	
				finishTimeslot($xtr_index, $pkt_info{'timestamp'});
			}
		}
	}

	# --------------------------------------------------
	#
	# --------------------------------------------------
	my $flow = processFlow($xtr_index,
						   $pkt_info{'src_ip'},
                           $pkt_info{'dst_ip'},
                           $pkt_info{'src_port'},
                           $pkt_info{'dst_port'},
                           $pkt_info{'proto'});

	# --------------------------------------------------
	# 
	# --------------------------------------------------
    processPrefix($xtr_index, $key, $dir);

	# --------------------------------------------------
	# Check if the entry is expired
	# --------------------------------------------------
	if (exists $cache{$xtr_index}->{$key} and checkExpiredCache($xtr_index, $key, $pkt_info{'timestamp'}) == F)
	{	
		# if so (hit)
		if ($::SYMMETRIC eq "yes" || $dir == OUT)
		{
			# ----------------------------------------------
			# Update the cache entry
			# ----------------------------------------------
			if ($cache{$xtr_index}->{$key}->{'direction'} != BI && $cache{$xtr_index}->{$key}->{'direction'} != $dir)
			{
				$cache{$xtr_index}->{$key}->{'direction'} = BI;
				$cache{$xtr_index}->{$key}->{'ts_of_bidir'} = $pkt_info{'timestamp'};
				$cache{$xtr_index}->{$key}->{'uni_dir_pkts'} += $cache{$xtr_index}->{$key}->{'packets'};
				$cache{$xtr_index}->{$key}->{'uni_dir_byte'} += $cache{$xtr_index}->{$key}->{'bytes'};
			}

			# ----------------------------------------------
			# If SHARE is yes the cache entry will be
			# refreshed in all xTRs, otherwise only the xTR
			# which the packet passed through will be updated
			# ----------------------------------------------
			if ($::SHARE eq "no")
			{
				$cache{$xtr_index}->{$key}->{'last_update'} = $pkt_info{'timestamp'};
			}
			else
			{
				for (my $i = 0 ; $i < $num_index ; $i++)
				{
					my $tmp_xtr_index = $xtr_indexes[$i];
					
					if (exists $cache{$tmp_xtr_index}->{$key})
					{
						$cache{$tmp_xtr_index}->{$key}->{'last_update'} = $pkt_info{'timestamp'};
					}
				}
			}

			$cache{$xtr_index}->{$key}->{'packets'}++;
			$cache{$xtr_index}->{$key}->{'bytes'} += $pkt_info{'len'};

			if ($dir == IN)
			{
				$cache{$xtr_index}->{$key}->{'in-packets'}++;
				$cache{$xtr_index}->{$key}->{'in-bytes'} += $pkt_info{'len'};
			}
			elsif ($dir == OUT)
			{
				$cache{$xtr_index}->{$key}->{'out-packets'}++;
				$cache{$xtr_index}->{$key}->{'out-bytes'} += $pkt_info{'len'};
			}

			my $flowForCache = isFlowIn($xtr_index, $key, $pkt_info{'src_ip'}, $pkt_info{'dst_ip'});
			
			if (defined($flowForCache))
			{
				updateFlowForCache($xtr_index, $key, $flowForCache);
			}
			else
			{
				createFlowForCache($xtr_index, $key, $pkt_info{'src_ip'}, $pkt_info{'dst_ip'});
			}

			# ---------------------------------------------
			# 3) Update output table
			# ---------------------------------------------
			# %output->{'slicestart'}; 
			# %output->{'sliceend'};
			# %output->{'entries'}; 
			# %output->{'timeouts'};
			# %output->{'miss'}++; 
			# %output->{'inmiss'}++ if % == IN;
			# %output->{'outmiss'}++ if % == OUT;
			$output{$xtr_index}->{'hit'}++;
			$dir == IN ? $output{$xtr_index}->{'inhit'}++ : $output{$xtr_index}->{'outhit'}++;
		}
	}
	else
	{  
	   	# if not (miss)
		if ($::SYMMETRIC eq "yes" || $dir == OUT)
		{
			# ---------------------------------------------
			#  Save cache-miss-causing packets
			# ---------------------------------------------
			my $file = $FD_MISSPACKETFILE . $xtr_index;
			print $file substr($line, 0, 250) . "\n";

			# ---------------------------------------------
			# Create a new cache entry
			# ---------------------------------------------
			if ($::SHARE eq "no")
			{
				createCacheEntry($xtr_index, $key, $pkt_info{'timestamp'}, $dir, $pkt_info{'len'});
			}
			else 
			{
				for (my $i = 0 ; $i < $num_index ; $i++)
				{
					my $tmp_xtr_index = $xtr_indexes[$i];

					createCacheEntry($tmp_xtr_index, $key, $pkt_info{'timestamp'}, $dir, $pkt_info{'len'});
				}
			} 

			# ---------------------------------------------
			# Update output table
			# ---------------------------------------------
			$output{$xtr_index}->{'miss'}++; 
			$output{$xtr_index}->{'flows'}++; 
			$dir == IN ? $output{$xtr_index}->{'inmiss'}++ : $output{$xtr_index}->{'outmiss'}++;

			matchProtocol($xtr_index, $pkt_info{'proto'}, $pkt_info{'dst_port'}, MISS); 
		} 
	} 

	$output{$xtr_index}->{'pkts'}++;
	$output{$xtr_index}->{'bytes'} += $pkt_info{'len'};
	matchProtocol($xtr_index, $pkt_info{'proto'}, $pkt_info{'dst_port'}, PKTS); 

	$dir == IN ? $output{$xtr_index}->{'inpkts'}++ : $output{$xtr_index}->{'outpkts'}++;

	if ($dir == IN) 
	{
		$output{$xtr_index}->{'inbytes'} += $pkt_info{'len'};
	}
	else
	{
		$output{$xtr_index}->{'outbytes'} += $pkt_info{'len'};
	}
}
	
if ($::MODE eq "text")
{
	close($inputStream); # ASCII
}
else
{
	Net::Pcap::close($inputStream); # Pcap
}

#---------------------------------------------------------
# There are still entries in the cache. Check expiration
# every second until the cache is totally empty.
#---------------------------------------------------------

$::SHARE = "no"; # A hack which prevents a cache entries
                 # being deleted because of other cache's
				 # expirations

for (my $i = 0 ; $i < $num_index ; $i++)
{
	my $xtr_index = $xtr_indexes[$i];

	while (countCacheEntries($xtr_index) > 0)
	{
		$timestamp{$xtr_index}++;
		checkExpiredCaches($xtr_index, $timestamp{$xtr_index});

		if ($timestamp{$xtr_index} >= $output{$xtr_index}->{'sliceend'})
		{
			finishTimeslot($xtr_index, $timestamp{$xtr_index});
		}
	}

	finishTimeslot($xtr_index, $timestamp{$xtr_index});
}

prnt("\nComplete: " . (time - $startTime) . " seconds\n\n");

#---------------------------------------------------------
# Sub routines
#---------------------------------------------------------
sub createCacheEntry
{
	my $xtr_index = shift or die "Parameter is missing: createCacheEntry->\$xtr_index\n";
	my $key = shift or die "Parameter is missing: createCacheEntry->\$key\n";
	my $timestamp = shift or die "Parameter is missing: createCacheEntry->\$timestampx\n";
	my $dir = shift or NONE; # die "Parameter is missing: createCacheEntry->\$dir\n";
	my $len = shift or 0;    # die"Parameter is missing: createCacheEntry->\$len\n";

	$cache{$xtr_index}->{$key}->{'inserted'}     = $timestamp;
	$cache{$xtr_index}->{$key}->{'last_update'}  = $timestamp;
	$cache{$xtr_index}->{$key}->{'packets'}      = 0;
	$cache{$xtr_index}->{$key}->{'in-packets'}   = 0; 
	$cache{$xtr_index}->{$key}->{'out-packets'}  = 0;
	$cache{$xtr_index}->{$key}->{'bytes'}        = 0;
	$cache{$xtr_index}->{$key}->{'in-bytes'}     = 0;
	$cache{$xtr_index}->{$key}->{'out-bytes'}    = 0;
	$cache{$xtr_index}->{$key}->{'first_dir'}    = $dir;
	$cache{$xtr_index}->{$key}->{'direction'}    = $dir;
	$cache{$xtr_index}->{$key}->{'ts_of_bidir'}  = 0;
	$cache{$xtr_index}->{$key}->{'uni_dir_pkts'} = 1;
	$cache{$xtr_index}->{$key}->{'uni_dir_byte'} = $len;
	$cache{$xtr_index}->{$key}->{'flows'}        = ();
	$cache{$xtr_index}->{$key}->{'ttl_end'}      = $timestamp + $::TTL;
	$cache{$xtr_index}->{$key}->{'num_renew'}    = 0;
}

sub matchProtocol
{
	my $xtr_index = shift or die "Parameter is missing: matchProtocol->\$xtr_index\n";
	my $tran = shift or 0; # die "Parameter is missing: matchProtocol->\$tran\n";
	my $port = shift or 0; # die "Parameter is missing: matchProtocol->\$port\n";
	my $op = shift or die "Parameter is missing: matchProtocol->\$op\n";

	if ($op eq PKTS)
	{
		if ($tran eq "tcp")
		{
			$output{$xtr_index}->{'http_pkts'}++ if ($port == 80);
			$output{$xtr_index}->{'nntp_pkts'}++ if ($port == 119);
			$output{$xtr_index}->{'edtcp_pkts'}++ if ($port == 4661 || $port == 4662);
			$output{$xtr_index}->{'torrent_pkts'}++ if ($port == 6881);
			$output{$xtr_index}->{'ftp_pkts'}++ if ($port == 20 || $port == 21);
			$output{$xtr_index}->{'smtp_pkts'}++ if ($port == 25);
			$output{$xtr_index}->{'known_tcp_pkts'}++ if ($port <= 1024);
			$output{$xtr_index}->{'un_tcp_pkts'}++ if ($port > 1024);
		}
		elsif ($tran eq "udp")
		{
			$output{$xtr_index}->{'dns_pkts'}++ if ($port == 53);
			$output{$xtr_index}->{'ntp_pkts'}++ if ($port == 123);
			$output{$xtr_index}->{'edudp_pkts'}++ if ($port == 4665);
			$output{$xtr_index}->{'known_udp_pkts'}++ if ($port <= 1024);
			$output{$xtr_index}->{'un_udp_pkts'}++ if ($port > 1024);
		}
	}
	elsif ($op eq MISS)
	{
		if ($tran eq "tcp")
		{
			$output{$xtr_index}->{'http_miss'}++ if ($port == 80);
			$output{$xtr_index}->{'nntp_miss'}++ if ($port == 119);
			$output{$xtr_index}->{'edtcp_miss'}++ if ($port == 4661 || $port == 4662);
			$output{$xtr_index}->{'torrent_miss'}++ if ($port == 6881);
			$output{$xtr_index}->{'ftp_miss'}++ if ($port == 20 || $port == 21);
			$output{$xtr_index}->{'smtp_miss'}++ if ($port == 25);
			$output{$xtr_index}->{'known_tcp_miss'}++ if ($port <= 1024);
			$output{$xtr_index}->{'un_tcp_miss'}++ if ($port > 1024);
		}
		elsif ($tran eq "udp")
		{
			$output{$xtr_index}->{'dns_miss'}++ if ($port == 53);
			$output{$xtr_index}->{'ntp_miss'}++ if ($port == 123);
			$output{$xtr_index}->{'edudp_miss'}++ if ($port == 4665);
			$output{$xtr_index}->{'known_udp_miss'}++ if ($port <= 1024);
			$output{$xtr_index}->{'un_udp_miss'}++ if ($port > 1024);
		}
	}
}

sub initOutput
{
	my $xtr_index = shift or die "Parameter is missing: initOutput->\$xtr_index\n";
	my $slicestart = shift or die "Parameter is missing: initOutput->\$slicestart\n";
	my $sliceend = shift or die "Parameter is missing: initOutput->\$sliceend\n";

	$output{$xtr_index}->{'slicestart'} = $slicestart; 
	$output{$xtr_index}->{'sliceend'} = $sliceend;
	$output{$xtr_index}->{'entries'} = 0; 
	$output{$xtr_index}->{'timeouts'} = 0;
	$output{$xtr_index}->{'miss'} = 0; 
	$output{$xtr_index}->{'inmiss'} = 0;
	$output{$xtr_index}->{'outmiss'} = 0;
	$output{$xtr_index}->{'flows_total'} = 0;
	$output{$xtr_index}->{'flows_tcp_in'} = 0;
	$output{$xtr_index}->{'flows_tcp_out'} = 0;
	$output{$xtr_index}->{'flows_udp_in'} = 0;
	$output{$xtr_index}->{'flows_udp_out'} = 0;
	$output{$xtr_index}->{'flows_other_in'} = 0;
	$output{$xtr_index}->{'flows_other_out'} = 0;
	$output{$xtr_index}->{'hit'} = 0;
	$output{$xtr_index}->{'pkts'} = 0;
	$output{$xtr_index}->{'inpkts'} = 0;
	$output{$xtr_index}->{'outpkts'} = 0; 
	$output{$xtr_index}->{'inhit'} = 0;
   	$output{$xtr_index}->{'outhit'} = 0;
	$output{$xtr_index}->{'bytes'} = 0;
	$output{$xtr_index}->{'inbytes'} = 0;
	$output{$xtr_index}->{'outbytes'} = 0;
	$output{$xtr_index}->{'inpfx'} = 0;
	$output{$xtr_index}->{'outpfx'} = 0;
	$output{$xtr_index}->{'unipfx'} = 0;
	$output{$xtr_index}->{'intpfx'} = 0;
	$output{$xtr_index}->{'http_pkts'} = 0;
	$output{$xtr_index}->{'nntp_pkts'} = 0;
	$output{$xtr_index}->{'edtcp_pkts'} = 0;
	$output{$xtr_index}->{'edudp_pkts'} = 0;
	$output{$xtr_index}->{'torrent_pkts'} = 0;
	$output{$xtr_index}->{'ftp_pkts'} = 0;
	$output{$xtr_index}->{'smtp_pkts'} = 0;
	$output{$xtr_index}->{'known_tcp_pkts'} = 0;
	$output{$xtr_index}->{'un_tcp_pkts'} = 0;
	$output{$xtr_index}->{'dns_pkts'} = 0;
	$output{$xtr_index}->{'ntp_pkts'} = 0;
	$output{$xtr_index}->{'known_udp_pkts'} = 0;
	$output{$xtr_index}->{'un_udp_pkts'} = 0;
	$output{$xtr_index}->{'http_miss'} = 0;
	$output{$xtr_index}->{'nntp_miss'} = 0;
	$output{$xtr_index}->{'edtcp_miss'} = 0;
	$output{$xtr_index}->{'edudp_miss'} = 0;
	$output{$xtr_index}->{'torrent_miss'} = 0;
	$output{$xtr_index}->{'ftp_miss'} = 0;
	$output{$xtr_index}->{'smtp_miss'} = 0;
	$output{$xtr_index}->{'known_tcp_miss'} = 0;
	$output{$xtr_index}->{'un_tcp_miss'} = 0;
	$output{$xtr_index}->{'dns_miss'} = 0;
	$output{$xtr_index}->{'ntp_miss'} = 0;
	$output{$xtr_index}->{'known_udp_miss'} = 0;
	$output{$xtr_index}->{'un_udp_miss'} = 0;
	$output{$xtr_index}->{'num_renewed_caches'} = 0;
}

sub checkExpiredCache
{
	my $xtr_index = shift or die "Parameter is missing: checkExpiredCache->\$xtr_index\n";
	my $key = shift or die "Parameter is missing: checkExpiredCache->\$key\n";
	my $timeCurrPkt = shift or die "Parameter is missing: checkExpiredCache->\$timeCurrPkt\n";

	die "Given key doesn't exist\n" unless exists $cache{$xtr_index}->{$key};

	if ($timeCurrPkt >= $cache{$xtr_index}->{$key}->{'ttl_end'})
	{ 
		if ($cache{$xtr_index}->{$key}->{'ttl_end'} - $cache{$xtr_index}->{$key}->{'last_update'} > $::REFRESHTIME)
		{
		
			# -------------------------------------------------
			#  Update output table
			# -------------------------------------------------
			$output{$xtr_index}->{'timeouts'}++;

			if ($::SHARE eq "no")
			{
				# ---------------------------------------------
				#  Delete this entry 
				# ---------------------------------------------
				deleteEntry($xtr_index, $key, $timeCurrPkt);
			}
			else
			{
				for (my $i = 0 ; $i < $num_index ; $i++)
				{
					my $tmp_xtr_index = $xtr_indexes[$i];

					# -----------------------------------------
					#  Delete this entry (for all xTRs)
					# -----------------------------------------
					deleteEntry($tmp_xtr_index, $key, $timeCurrPkt);
				}
			}

			return T; # The entry expires
		}
		else
		{
			# TTL is expired, but the cache entry was used within the last one minute, so it will be renewed.

			if ($::SHARE eq "no")
			{
				# ---------------------------------------------
				#  Renew the ttl-end
				# ---------------------------------------------
				$cache{$xtr_index}->{$key}->{'ttl_end'} = $cache{$xtr_index}->{$key}->{'ttl_end'} + $::TTL;

				# ---------------------------------------------
				#  Update the number of renewals of the
				#  cache entry
				# ---------------------------------------------
				$cache{$xtr_index}->{$key}->{'num_renew'} = $cache{$xtr_index}->{$key}->{'num_renew'} + 1;


				# ---------------------------------------------
				#  Increase the number of renewed caches 
				#  within this time slot
				# ---------------------------------------------
				$output{$xtr_index}->{'num_renewed_caches'}++;
			}
			else
			{
				for (my $i = 0 ; $i < $num_index ; $i++)
				{
					my $tmp_xtr_index = $xtr_indexes[$i];

					unless (exists $cache{$tmp_xtr_index}->{$key})
					{
						# -----------------------------------------
						# Create a new entry if the cache entry is 
						# not in the cache of backup xTRs
						# -----------------------------------------
						
						createCacheEntry($tmp_xtr_index, $key, $timeCurrPkt, NONE, 0);
					}

					# -----------------------------------------
					#  Renew the ttl-end (for all xTRs)
					# -----------------------------------------
					$cache{$tmp_xtr_index}->{$key}->{'ttl_end'} = $cache{$xtr_index}->{$key}->{'ttl_end'} + $::TTL;

					# -----------------------------------------
					#  Update the number of renewals of the
					#  cache entry (for all xTRs)
					# -----------------------------------------
					$cache{$tmp_xtr_index}->{$key}->{'num_renew'} = $cache{$xtr_index}->{$key}->{'num_renew'} + 1;

					# -----------------------------------------
					#  Increase the number of renewed caches 
					#  within this time slot
					# -----------------------------------------
					$output{$tmp_xtr_index}->{'num_renewed_caches'}++;
				}
			}
		}
	}

	return F; # The entry is still alive
}

sub checkExpiredCaches
{
	my $xtr_index = shift or die "Parameter is missing: checkExpiredCaches->\$xtr_index\n";
	my $timeCurrPkt = shift or die "Parameter is missing: checkExpiredCaches->\$timeCurrPkt\n";
	my $tmpCache = $cache{$xtr_index};

	while (my($key, $val) = each(%$tmpCache))
	{
		checkExpiredCache($xtr_index, $key, $timeCurrPkt);
	}
}

sub countCacheEntries
{
	my $xtr_index = shift or die "Parameter is missing: countCacheEntries->\$xtr_index\n";
	my $tmpCache = $cache{$xtr_index};
	return scalar keys %$tmpCache;
}

sub writeout_titles
{
	my $xtr_index = shift or die "Parameter is missing: writeout->\$xtr_index\n";
	my $file = $FD_LOGFILE . $xtr_index;

	print $file 'slicestart' .
	" " . 'sliceend' .
	" " . 'entries' .
	" " . 'timeouts' .
	" " . 'pkts' .
	" " . 'inpkts' .
	" " . 'outpkts' .
	" " . 'hit' .
	" " . 'inhit' .
	" " . 'outhit' .
	" " . 'miss' .
	" " . 'inmiss' .
	" " . 'outmiss' .
	" " . 'flows_total' . 
	" " . 'flows_tcp_in' . 
	" " . 'flows_tcp_out' . 
	" " . 'flows_udp_in' . 
	" " . 'flows_udp_out' . 
	" " . 'flows_other_in' . 
	" " . 'flows_other_out' . 
	" " . "bytes" .
	" " . "inbytes" .
	" " . "outbytes" .
	" " . "total-pfx" . 
	" " . "in-pfx" .
	" " . "out-pfx" .
	" " . "bidir-pfx" .
 	" " . "http_pkts" .
 	" " . "nntp_pkts" .
 	" " . "edonkey_tcp_pkts" .
 	" " . "torrent_pkts" .
 	" " . "ftp_pkts" .
 	" " . "smtp_pkts" .
 	" " . "dns_pkts" .
 	" " . "ntp_pkts" .
 	" " . "edonkey_udp_pkts" .
 	" " . "known_tcp_pkts" .
 	" " . "un_tcp_pkts" .
 	" " . "known_udp_pkts" .
 	" " . "un_udp_pkts" .
 	" " . "http_miss" .
 	" " . "nntp_miss" .
 	" " . "edonkey_tcp_miss" .
 	" " . "torrent_miss" .
 	" " . "ftp_miss" .
 	" " . "smtp_miss" .
 	" " . "dns_miss" .
 	" " . "ntp_miss" .
 	" " . "edonkey_udp_miss" .
 	" " . "known_tcp_miss" .
 	" " . "un_tcp_miss" .
 	" " . "known_udp_miss" .
 	" " . "un_udp_miss" .
	"\n";
}

sub writeout
{
	my $xtr_index = shift or die "Parameter is missing: writeout->\$xtr_index\n";
	my $file = $FD_LOGFILE . $xtr_index;
	
	print $file $output{$xtr_index}->{'slicestart'} .   # 1
	" " . $output{$xtr_index}->{'sliceend'} .           # 2
	" " . $output{$xtr_index}->{'entries'} .            # 3
	" " . $output{$xtr_index}->{'timeouts'} .           # 4
	" " . $output{$xtr_index}->{'pkts'} .               # 5
	" " . $output{$xtr_index}->{'inpkts'} .             # 6
	" " . $output{$xtr_index}->{'outpkts'} .            # 7
	" " . $output{$xtr_index}->{'hit'} .                # 8
	" " . $output{$xtr_index}->{'inhit'} .              # 9
	" " . $output{$xtr_index}->{'outhit'} .             # 10
	" " . $output{$xtr_index}->{'miss'} .               # 11
	" " . $output{$xtr_index}->{'inmiss'} .             # 12
	" " . $output{$xtr_index}->{'outmiss'} .            # 13
	" " . $output{$xtr_index}->{'flows_total'} .        # 14
	" " . $output{$xtr_index}->{'flows_tcp_in'} .       # 15
	" " . $output{$xtr_index}->{'flows_tcp_out'} .      # 16
	" " . $output{$xtr_index}->{'flows_udp_in'} .       # 17
	" " . $output{$xtr_index}->{'flows_udp_out'} .      # 18
	" " . $output{$xtr_index}->{'flows_other_in'} .     # 19
	" " . $output{$xtr_index}->{'flows_other_out'} .    # 20
	" " . $output{$xtr_index}->{'bytes'} .              # 21
	" " . $output{$xtr_index}->{'inbytes'} .            # 22
	" " . $output{$xtr_index}->{'outbytes'} .           # 23
	" " . $output{$xtr_index}->{'unipfx'} .             # 24
	" " . $output{$xtr_index}->{'inpfx'} .              # 25
	" " . $output{$xtr_index}->{'outpfx'} .             # 26
	" " . $output{$xtr_index}->{'intpfx'} .             # 27
 	" " . $output{$xtr_index}->{'http_pkts'} .          # 28
 	" " . $output{$xtr_index}->{'nntp_pkts'} .          # 29
 	" " . $output{$xtr_index}->{'edtcp_pkts'} .         # 30
 	" " . $output{$xtr_index}->{'torrent_pkts'} .       # 31
 	" " . $output{$xtr_index}->{'ftp_pkts'} .           # 32
 	" " . $output{$xtr_index}->{'smtp_pkts'} .          # 33
 	" " . $output{$xtr_index}->{'dns_pkts'} .           # 34 
 	" " . $output{$xtr_index}->{'ntp_pkts'} .           # 35
 	" " . $output{$xtr_index}->{'edudp_pkts'} .         # 36
 	" " . $output{$xtr_index}->{'known_tcp_pkts'} .     # 37
 	" " . $output{$xtr_index}->{'un_tcp_pkts'} .        # 38
 	" " . $output{$xtr_index}->{'known_udp_pkts'} .     # 39
 	" " . $output{$xtr_index}->{'un_udp_pkts'} .        # 40
 	" " . $output{$xtr_index}->{'http_miss'} .          # 41
 	" " . $output{$xtr_index}->{'nntp_miss'} .          # 42
 	" " . $output{$xtr_index}->{'edtcp_miss'} .         # 43
 	" " . $output{$xtr_index}->{'torrent_miss'} .       # 44
 	" " . $output{$xtr_index}->{'ftp_miss'} .           # 45
 	" " . $output{$xtr_index}->{'smtp_miss'} .          # 46
 	" " . $output{$xtr_index}->{'dns_miss'} .           # 47
 	" " . $output{$xtr_index}->{'ntp_miss'} .           # 48
 	" " . $output{$xtr_index}->{'edudp_miss'} .         # 49
 	" " . $output{$xtr_index}->{'known_tcp_miss'} .     # 50
 	" " . $output{$xtr_index}->{'un_tcp_miss'} .        # 51
 	" " . $output{$xtr_index}->{'known_udp_miss'} .     # 52
 	" " . $output{$xtr_index}->{'un_udp_miss'} .        # 53
 	" " . $output{$xtr_index}->{'num_renewed_caches'} . # 54
    "\n";
}

sub userlimit
{
	my $src_ip = shift or die "Parameter is missing: userlimit->\$src_ip\n"; 
	my $dst_ip = shift or die "Parameter is missing: userlimit->\$dst_ip\n";
	my $dir = shift or die "Parameter is missing: userlimit->\$dir\n";

	return T if $::USERLIMIT == 0;

	if (exists($userpool{$src_ip}) || exists($userpool{$dst_ip}))
	{
		return T;
	}
	else
	{
		if (scalar(keys(%userpool)) < $::USERLIMIT)
		{
			if ($dir == IN)
			{
				$userpool{$dst_ip} = T;
			}
			elsif ($dir == OUT)
			{
				$userpool{$src_ip} = T;
			}

			return T;
		}
	}

	return F;
}


sub getFlowDir
{
	my $xtr_index = shift or die "Parameter is missing: getFlowDir->\$xtr_index\n";
	my $src_ip = shift or die "Parameter is missing: getFlowDir->\$src_ip\n"; 
	my $dst_ip = shift or die "Parameter is missing: getFlowDir->\$dst_ip\n";

	my $isdef_src = defined($patricia_int_prefixes{$xtr_index}->match_string($src_ip));
	my $isdef_dst = defined($patricia_int_prefixes{$xtr_index}->match_string($dst_ip));

	if ($isdef_src && $isdef_dst)
	{
		return NONE;
	}
	elsif ($isdef_src && !$isdef_dst)
	{
		return OUT;
	}
	elsif (!$isdef_src && $isdef_dst)
	{
		return IN;
	}
	elsif (!$isdef_src && !$isdef_dst)
	{
		return NONE;
	}
}

sub getXTRindex
{
	my $src_ip = shift or die "Parameter is missing: getXTRindex->\$src_ip\n";
	my $dst_ip = shift or die "Parameter is missing: getXTRindex->\$dst_ip\n";

	for (my $i = 0 ; $i < $num_index ; $i++)
	{
		if (defined($patricia_int_prefixes{$xtr_indexes[$i]}->match_string($src_ip)))
		{
			return $xtr_indexes[$i];
		}
		elsif (defined($patricia_int_prefixes{$xtr_indexes[$i]}->match_string($dst_ip)))
		{
			return $xtr_indexes[$i];
		}
	}

	return -1;
}

sub deleteEntry
{
	my $xtr_index = shift or die "Parameter is missing: deleteEntry->\$xtr_index\n";
	my $key = shift or die "Parameter is missing: deleteEntry->\$key\n";
	my $currentPktTime = shift or die "Parameter is missing: deleteEntry->\$currentPktTime\n"; 

 	# 1 prefix
 	# 2 A timestamp of the entry's creation
 	# 3 A timestamp the entry expires
 	# 4 Life time of the entry
	# 5 Direction of the first packet
	# 6 direction
 	# 7 unix timestamp that the entry becomes bi-directional
	# 8 the number of packets until the entry becomes bi-directional
	# 9 total transmitted volume until the entry becomes bi-directional
	# 10 Total packets
	# 11 In-packets
	# 12 Out-packets
	# 13 Total bytes
	# 14 in bytes
	# 15 out bytes

	my $file = $FD_CACHELOGFILE . $xtr_index;

	print $file $key .
	" " . $cache{$xtr_index}->{$key}->{'inserted'} .
	" " . $currentPktTime .
	" " . ($currentPktTime - $cache{$xtr_index}->{$key}->{'inserted'}) .
	" " . (($cache{$xtr_index}->{$key}->{'first_dir'} == IN) ? "in" : "out") .
	" " . (($cache{$xtr_index}->{$key}->{'direction'} == BI) ? "bi" : ($cache{$xtr_index}->{$key}->{'direction'} == IN ? "in" : "out")) .
	" " . $cache{$xtr_index}->{$key}->{'ts_of_bidir'} .
	" " . (($cache{$xtr_index}->{$key}->{'direction'} == BI) ? $cache{$xtr_index}->{$key}->{'uni_dir_pkts'} : $cache{$xtr_index}->{$key}->{'packets'}) .
	" " . (($cache{$xtr_index}->{$key}->{'direction'} == BI) ? $cache{$xtr_index}->{$key}->{'uni_dir_byte'} : $cache{$xtr_index}->{$key}->{'bytes'}) .
	" " . $cache{$xtr_index}->{$key}->{'packets'} .
	" " . $cache{$xtr_index}->{$key}->{'in-packets'} .
	" " . $cache{$xtr_index}->{$key}->{'out-packets'} .
	" " . $cache{$xtr_index}->{$key}->{'bytes'} .
	" " . $cache{$xtr_index}->{$key}->{'in-bytes'} .
	" " . $cache{$xtr_index}->{$key}->{'out-bytes'} .
	" " . countFlowsPerCache($xtr_index, $key) . 
	" " . $cache{$xtr_index}->{$key}->{'num_renew'} . 
	"\n";

	delete $cache{$xtr_index}->{$key};
}

sub finishTimeslot
{
	my $xtr_index = shift or die "Parameter is missing: finishTimeslot->\$xtr_index\n";
	my $timestamp = shift or die "Parameter is missing: finishTimeslot->\$timestamp\n";

	if ($output{$xtr_index}->{'sliceend'} > 0)
	{
		checkExpiredCaches($xtr_index, $output{$xtr_index}->{'sliceend'});   # check timeouts, 
		$output{$xtr_index}->{'entries'} = countCacheEntries($xtr_index);
		
		(	$output{$xtr_index}->{'flows_total'}, 
			$output{$xtr_index}->{'flows_tcp_in'}, 
			$output{$xtr_index}->{'flows_tcp_out'}, 
			$output{$xtr_index}->{'flows_udp_in'}, 
			$output{$xtr_index}->{'flows_udp_out'}, 
			$output{$xtr_index}->{'flows_other_in'},
			$output{$xtr_index}->{'flows_other_out'}
		) = countFlows($xtr_index);

		(	$output{$xtr_index}->{'unipfx'},
			$output{$xtr_index}->{'inpfx'},
			$output{$xtr_index}->{'outpfx'},
			$output{$xtr_index}->{'intpfx'}
		) = countPrefixes($xtr_index);

		writeout($xtr_index);
	}

	initOutput($xtr_index, $output{$xtr_index}->{'sliceend'}, $output{$xtr_index}->{'sliceend'} + $::GRANULARITY);
	clearFlows($xtr_index);
	clearPrefixes($xtr_index);
}

sub getPacketInfo
{
	if ($::MODE eq "text")
	{
		return getPacketInfoFromAscii();
	}
	else
	{
		return getPacketInfoFromPcap();
	}
}

sub getPacketInfoFromPcap
{
	my %pkt_info;

	my %pcapHeader;
	# --------------------------------------------------
	# %pcapHeader includes following information
	# ---------+----------------------------------------
	#  len     | the total length of the packet,
	#          |
	#  caplen  | the captured length of the packet; 
	#          | this corresponds to the $snaplen argument 
	#          | passed to the Net::Pcap::open_live method
	#          |
	#  tv_sec  | the seconds value of the packet timestamp
	#          |
	#  tv_usec | the microseconds value of the packet timestamp
	# ---------+---------------------------------------
	my $pkt = Net::Pcap::next($inputStream, \%pcapHeader);

	return F unless defined $pkt;

    # Strip ethernet encapsulation of captured packet 
    my $ether_data = NetPacket::Ethernet::strip($pkt);
	
    # get object to check if that is ip.
    my $ether_obj = NetPacket::Ethernet->decode($pkt);

	if ($ether_obj->{'type'} == 2048) # Type 2048 indicates IP packet
	{
		my $ip = NetPacket::IP->decode($ether_obj->{'data'});

		$pkt_info{'timestamp'} = $pcapHeader{'tv_sec'};
		$pkt_info{'src_port'} = 0;
		$pkt_info{'dst_port'} = 0;
		$pkt_info{'proto'} = $ip->{'proto'};
		$pkt_info{'src_ip'} = $ip->{'src_ip'};
		$pkt_info{'dst_ip'} = $ip->{'dest_ip'};
		$pkt_info{'len'} = $ip->{'len'};
		# --------------------------------------------------
		# Available infomation retrived from NetPacket::IP->decode($eth_pkt)
		# --------------------------------------------------
		# ver:     The IP version number of this packet.
		# hlen:    The IP header length of this packet.
		# flags:   The IP header flags for this packet.
		# foffset: The IP fragment offset for this packet.
		# tos:     The type-of-service for this IP packet.
		# len:     The length (including length of header) 
		#          in bytes for this packet.
		# id:      The identification (sequence) number for 
		#          this IP packet.
		# ttl:     The time-to-live value for this packet.
		# proto:   The IP protocol number for this packet.
		# cksum:   The IP checksum value for this packet.
		# src_ip:  The source IP address for this packet in 
		#          dotted-quad notation.
		# dest_ip: The destination IP address for this packet 
		#          in dotted-quad notation.
		# options: Any IP options for this packet.
		# data:    The encapsulated data (payload) for this 
		#          IP packet.
		# --------------------------------------------------
		if ($ip->{'proto'} == NetPacket::IP::IP_PROTO_TCP) 
		{	
			my $tcp = NetPacket::TCP->decode($ip->{'data'});

			# ---------------------------------------------
			# Available information retrieved from 
			# NetPacket::TCP->decode($ip-payload)
			# ---------------------------------------------
			# src_port:  The source TCP port for the packet.
			# dest_port: The destination TCP port for the packet.
			# seqnum:    The TCP sequence number for this packet.
			# acknum:    The TCP acknowledgement number for this packet.
			# hlen:      The header length for this packet.
			# reserved:  The 6-bit "reserved" space in the TCP header.
			# flags:     Contains the urg, ack, psh, rst, syn, fin, ece 
			#            and cwr flags for this packet.
			# winsize:   The TCP window size for this packet.
			# cksum:     The TCP checksum.
			# urg:       The TCP urgent pointer.
			# options:   Any TCP options for this packet in binary form.
			# data:      The encapsulated data (payload) for this packet.
			# ---------------------------------------------
		
			$pkt_info{'proto'} = "tcp";
			$pkt_info{'src_port'} = $tcp->{'src_port'};
			$pkt_info{'dst_port'} = $tcp->{'dest_port'};
		}
		elsif ($ip->{'proto'} == NetPacket::IP::IP_PROTO_UDP)
		{
			my $udp = NetPacket::UDP->decode($ip->{'data'});
	
			# ---------------------------------------------
			# Available information retrieved from 
			# NetPacket::UDP->decode($ip-payload)
			# ---------------------------------------------
			# src_port:  The source UDP port for the datagram.
			# dest_port: The destination UDP port for the datagram.
			# len:       The length (including length of header) 
			# 	         in bytes for this packet.
			# cksum:     The checksum value for this packet.
			# data:      The encapsulated data (payload) for 
			#            this packet.
			# ---------------------------------------------

			$pkt_info{'proto'} = "udp";
			$pkt_info{'src_port'} = $udp->{'src_port'};
			$pkt_info{'dst_port'} = $udp->{'dest_port'};
		}

   		# Decode contents of TCP/IP packet contained within 
   		# captured ethernet packet
		# my $ip = NetPacket::IP->decode($ether_data);
	}

	return %pkt_info;
}

sub getPacketInfoFromAscii
{
	my %pkt_info;

	my $line = <$inputStream>;
	$line =~ s/\n//;
	
	return F unless defined $line; 
	my @cols = split / /, $line; 

	$pkt_info{'timestamp'} = $cols[0];
	$pkt_info{'src_ip'} = $cols[1];
	$pkt_info{'dst_ip'} = $cols[2];
	$pkt_info{'src_port'} = $cols[3];
	$pkt_info{'dst_port'} = $cols[4];
	$pkt_info{'proto'} = $cols[5];
	$pkt_info{'len'} = $cols[6];

	return $line, %pkt_info;
}

sub printUsage
{
	print "lispcache-emulator Ver, 3.0 ttl.mod\n\n";
	print "usage: " . $::PROGRAM . " [options] [file]\n";
	print "<file>\t\t\t\t\t| read from a trace file, or from the stdin\n";
	print " -m| --mode <text|pcap>\t\t\t| read in <text|pcap> format\n";
	print " -t| --ttl <num>\t\t\t| TTL\n";
	print " -g| --granularity <num|default=60>\t| set a aggregation granularity in seconds\n";
	print " -y| --symmetric <yes|no>\t\t| emulate symmetric LISP (yes) or original LISP (no)\n";
	print " -s| --suffix <suffix>\t\t\t| append given suffix to the name of log files\n";
	print " -u| --userlimit <num>\t\t\t| set a maximum number of end-users. 0 for no user limit\n";
	print " -h| --share <yes|no>\t\t\t| all xTRs will share a single LISP-Cache (yes), default=no\n";
    print " -r| --failrecover <fail|recover>\t| is this a failure scenario? or a recovery scenario?\n";
	print " -f| --timepoint <num>\t\t\t| a timepoint of artificial failure/recovery. 0 for no failure/recovery.\n";
    print " -a| --failxtr <0|1|...>\t\t| an index of the xTR which fails in the middle of the emulation.\n";
	print " -b| --nonfailxtr <0|1|...>\t\t| an index of the xTR which runs without failure/recovery.\n";
	print " -q| --quiet <yes|no>\t\t\t| no output when yes\n";
	print "\n";
	print "example: " . $::PROGRAM . " -m pcap -t 60 -g 60 -y no -q no -u 10000 -h no -f 300 -a 0 -b 1 -s test-simulation  test-trace.pcap \n";
	print "\n";
	exit;
}

sub processFlow
{
	my $xtr_index = shift or die "Parameter is missing: processFlow->\$xtr_index\n";
	my $srcip = shift or 0; #die "Parameter is missing: processFlow->\$srcip\n";
	my $dstip = shift or 0; #die "Parameter is missing: processFlow->\$dstip\n";
	my $srcport = shift or 0; #die "Parameter is missing: processFlow->\$srcport\n";
	my $dstport = shift or 0; #die "Parameter is missing: processFlow->\$dstport\n";
	my $protocol = shift or 0; #die "Parameter is missing: processFlow->\$protocol\n";
	my $flow = $srcip . "-" . $dstip . "-" . $srcport . "-" . $dstport . "-" . $protocol;

	createFlow($xtr_index, $flow) unless (defined $flows{$xtr_index}->{$flow});

	return $flow;
}

sub createFlow
{
	my $xtr_index = shift or die "Parameter is missing: createFlow->\$xtr_index\n";
	my $flow = shift or die "Parameter is missing: createFlow->\$flow\n";
	my ($srcip,$dstip,$srcport,$dstport,$protocol) = split /-/, $flow;
	my $flowDir = getFlowDir($xtr_index, $srcip, $dstip);

	if ($flowDir != NONE)
	{
		$flows{$xtr_index}->{$flow}->{'srcip'} = $srcip;
		$flows{$xtr_index}->{$flow}->{'dstip'} = $dstip;
		$flows{$xtr_index}->{$flow}->{'srcport'} = $srcport;
		$flows{$xtr_index}->{$flow}->{'dstport'} = $dstport;
		$flows{$xtr_index}->{$flow}->{'protocol'} = $protocol;
		$flows{$xtr_index}->{$flow}->{'dir'} = $flowDir;
	}
}

sub processPrefix
{
	my $xtr_index = shift or die "Parameter is missing: processPrefix->\$xtr_index\n";
	my $prefix = shift or die "Parameter is missing: processPrefix->\$prefix\n";
	my $dir = shift or die "Parameter is missing: processPrefix->\$dir\n";

	if (defined $prefixes{$xtr_index}->{$prefix})
	{
		updatePrefix($xtr_index, $prefix, $dir);
	}
	else
	{
		createPrefix($xtr_index, $prefix, $dir);
	}
}

sub createPrefix
{
	my $xtr_index = shift or die "Parameter is missing: createPrefix->\$xtr_index\n";
	my $prefix = shift or die "Parameter is missing: createPrefix->\$prefix\n";
	my $dir = shift or die "Parameter is missing: createPrefix->\$dir\n";

	$prefixes{$xtr_index}->{$prefix} = $dir;
}

sub updatePrefix
{
	my $xtr_index = shift or die "Parameter is missing: updatePrefix->\$xtr_index\n";
	my $prefix = shift or die "Parameter is missing: updatePrefix->\$prefix\n";
	my $dir = shift or die "Parameter is missing: updatePrefix->\$dir\n";

	if ($prefixes{$prefix} != BI && $prefixes{$prefix} != $dir)
	{
		$prefixes{$prefix} = BI;
	}
}

sub countFlows
{
	my $xtr_index = shift or die "Parameter is missing: countFlows->\$xtr_index\n";
	my $tmpFlows = $flows{$xtr_index};
	my $flowsTotal = scalar keys %$tmpFlows;
	my $flowsTCPIn = 0;
	my $flowsTCPOut = 0;
	my $flowsUDPIn = 0;
	my $flowsUDPOut = 0;
	my $flowsOtherIn = 0;
	my $flowsOtherOut = 0;
	
	while (my($key, %value) = each(%$tmpFlows))
	{
		if ($flows{$xtr_index}->{$key}->{'protocol'} eq "tcp")
		{
			if ($flows{$xtr_index}->{$key}->{'dir'} == IN)
			{
				$flowsTCPIn++;
			}
			else
			{
				$flowsTCPOut++;
			}
		}	
		elsif ($flows{$xtr_index}->{$key}->{'protocol'} eq "udp")
		{
			if ($flows{$xtr_index}->{$key}->{'dir'} == IN)
			{
				$flowsUDPIn++;
			}
			else
			{
				$flowsUDPOut++;
			}
		}
		else
		{
			if ($flows{$xtr_index}->{$key}->{'dir'} == IN)
			{
				$flowsOtherIn++;
			}
			else
			{
				$flowsOtherOut++;
			}
		}
	}

	return ($flowsTotal, $flowsTCPIn, $flowsTCPOut, $flowsUDPIn, $flowsUDPOut, $flowsOtherIn, $flowsOtherOut);
}

sub countPrefixes
{
	my $xtr_index = shift or die "Parameter is missing: countPrefixes->\$xtr_index\n";
	my $tmpPrefixes = $prefixes{$xtr_index};
	my $prefixesTotal = scalar keys %$tmpPrefixes;
	my $prefixesIn = 0;
	my $prefixesOut = 0;
	my $prefixesIntersect = 0;

	while (my($key, $value) = each(%$tmpPrefixes))
	{
		if ($prefixes{$xtr_index}->{$key} == BI)
		{
			$prefixesIntersect++;
		}
		elsif ($prefixes{$xtr_index}->{$key} == IN)
		{
			$prefixesIn++;
		}
		elsif ($prefixes{$xtr_index}->{$key} == OUT)
		{
			$prefixesOut++;
		}
	}

	return ($prefixesTotal, $prefixesIn, $prefixesOut, $prefixesIntersect);
}

sub clearFlows
{
	my $xtr_index = shift or die "Parameter is missing: clearFlows->\$xtr_index\n";
	my $tmpFlows = $flows{$xtr_index};

	while (my($key, $value) = each(%$tmpFlows))
	{
		delete $flows{$xtr_index}->{$key};
	}
}

sub clearPrefixes
{
	my $xtr_index = shift or die "Parameter is missing: clearprefixes->\$xtr_index\n";
	my $tmpPrefixes = $prefixes{$xtr_index};

	while (my($key, $value) = each(%$tmpPrefixes))
	{
		delete $prefixes{$xtr_index}->{$key};
	}
}

sub createFlowForCache
{
	my $xtr_index = shift or die "Parameter is missing: createFlowForCache->\$xtr_index\n";
	my $prefix = shift or die "Parameter is missing: createFlowForCache->\$prefix\n";
	my $ip1 = shift or die "Parameter is missing: createFlowForCache->\$ip1\n";
	my $ip2 = shift or die "Parameter is missing: createFlowForCache->\$ip2\n";
	
	$cache{$xtr_index}->{$prefix}->{'flows'}->{$ip1 . "-" . $ip2} = 1;
}

sub updateFlowForCache
{
	my $xtr_index = shift or die "Parameter is missing: createFlowForCache->\$xtr_index\n";
	my $prefix = shift or die "Parameter is missing: createFlowForCache->\$prefix\n";
	my $flow = shift or die "Parameter is missing: createFlowForCache->\$flow\n";
	
	$cache{$xtr_index}->{$prefix}->{'flows'}->{$flow}++;
}

sub isFlowIn
{
	my $xtr_index = shift or die "Parameter is missing: isFlowIn->\$xtr_index\n";
	my $prefix = shift or die "Parameter is missing: isFlowIn->\$prefix\n";
	my $ip1 = shift or die "Parameter is missing: isFlowIn->\$ip1\n";
	my $ip2 = shift or die "Parameter is missing: isFlowIn->\$ip2\n";
	
	if (defined($cache{$xtr_index}->{$prefix}->{'flows'}->{$ip1 . "-" . $ip2}))
	{
		return $ip1 . "-" . $ip2;
	}	
	elsif(defined($cache{$xtr_index}->{$prefix}->{'flows'}->{$ip2 . "-" . $ip1}))
	{
		return $ip2 . "-" . $ip1;
	}
	
	return undef;
}

sub countFlowsPerCache
{
	my $xtr_index = shift or die "Parameter is missing: countFlowsPerCache->\$xtr_index\n";
	my $prefix = shift or die "Parameter is missing: countFlowsPerCache->\$prefix\n";
	my $flows_ref = $cache{$xtr_index}->{$prefix}->{'flows'};
	return scalar keys %$flows_ref;
}

# -----------------------------------------------------
# This sub routine moves a prefix from failed xTR to
# the next xTR. (Currently, only from the first xTR to
# the second xTR)
# -----------------------------------------------------
sub movePrefix
{
	my $prefix = shift or die "Parameter is missing: movePrefix->\$prefix\n";
	my $from_xtr = $xtr_indexes[$::FAILXTR]; 
	my $to_xtr = $xtr_indexes[$::NONFAILXTR];

	$patricia_int_prefixes{$from_xtr}->remove_string($prefix);
	$patricia_int_prefixes{$to_xtr}->add_string($prefix);
}

sub initRecoveringXTR()
{
	my $xtr_index = $xtr_indexes[$::FAILXTR];
	my $tmpCache = $cache{$xtr_index};

	while (my($key, $value) = each(%$tmpCache))
	{
		delete $cache{$xtr_index}->{$key};
	}
}

sub recoverXTRs
{
	my $xtr_index_fail = $xtr_indexes[$::FAILXTR];
	my $xtr_index_nonfail = $xtr_indexes[$::NONFAILXTR];

	for (my $i = 0 ; $i < $num_index ; $i++)
	{
		my $xtr_index = $xtr_indexes[$i];

		$patricia_int_prefixes_backup{$xtr_index}->climb(
			sub 
			{ 
				$patricia_int_prefixes{$xtr_index_fail}->remove_string($_[0]);
				$patricia_int_prefixes{$xtr_index_nonfail}->remove_string($_[0]);
			}
		);

		$patricia_int_prefixes_backup{$xtr_index}->climb(
			sub 
			{ 
				$patricia_int_prefixes{$xtr_index}->add_string($_[0]); 
			}
		);
	}
}

sub prnt
{
	print shift if $::QUIET eq "no";
}

for (my $i = 0 ; $i < $num_index ; $i++)
{
	my $logfileref = $FD_LOGFILE . $xtr_indexes[$i];
	my $cachelogfileref = $FD_CACHELOGFILE . $xtr_indexes[$i];
	my $misspacketfileref = $FD_MISSPACKETFILE . $xtr_indexes[$i];

	close($logfileref);
	close($cachelogfileref);
	close($misspacketfileref);
}
