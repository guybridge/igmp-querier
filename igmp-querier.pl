#! /usr/bin/perl -w

# Adapted from    : http://code.google.com/p/perl-igmp-querier/
# Original author : http://code.google.com/u/jayshoo/

use strict;
use lib '/usr/local/hsw/libs';
use POSIX;

sub forgepkt {

  my $src_host = shift;
  my $dst_host = shift;

  my $zero_cksum        = 0;
  my $igmp_proto        = 2;
  my $igmp_type         = '11';
  my $igmp_mrt          = '64';
  my $igmp_pay          = 0;
  my $igmp_chk          = 0;
  my $igmp_len          = 0;

  my ($igmp_pseudo) = pack('H2H2vN',$igmp_type,$igmp_mrt,$igmp_chk,$igmp_pay);
  $igmp_chk = &checksum($igmp_pseudo);
  $igmp_pseudo = pack('H2H2vN',$igmp_type,$igmp_mrt,$igmp_chk,$igmp_pay);
  $igmp_len = length($igmp_pseudo);

  my $ip_ver            = 4;
  my $ip_len            = 6;
  my $ip_ver_len        = $ip_ver . $ip_len;
  my $ip_tos            = 00;
  my ($ip_tot_len)      = $igmp_len + 20 + 4;
  my $ip_frag_id        = 11243;
  my $ip_frag_flag      = "010";
  my $ip_frag_oset      = "0000000000000";
  my $ip_fl_fr          = $ip_frag_flag . $ip_frag_oset;
  my $ip_ttl            = 1;
  my $ip_opts			= '94040000'; # router alert
  
  my ($head) = pack('H2H2nnB16C2n',
    $ip_ver_len,$ip_tos,$ip_tot_len,$ip_frag_id,
    $ip_fl_fr,$ip_ttl,$igmp_proto);
  my ($addresses) = pack('a4a4',$src_host,$dst_host);
  my ($pkt) = pack('a*a*H8a*',$head,$addresses,$ip_opts,$igmp_pseudo);

  return $pkt;
}

sub checksum {
 my ($msg) = @_;
 my ($len_msg,$num_short,$short,$chk);
 $len_msg = length($msg);
 $num_short = $len_msg / 2;
 $chk = 0;
 foreach $short (unpack("S$num_short", $msg)) {
  $chk += $short;
 }
 $chk += unpack("C", substr($msg, $len_msg - 1, 1)) if $len_msg % 2;
 $chk = ($chk >> 16) + ($chk & 0xffff);
 return(~(($chk >> 16) + $chk) & 0xffff);
}

MAIN:
{
    # Initialization
	use Socket;

	my $src = "172.16.7.2"; # arbitary source
	my $dst = "224.0.0.1";  # igmp all-hosts
	
	socket(RAW, AF_INET, SOCK_RAW, 255) || die $!;
	setsockopt(RAW, 0, 1, 1);

	my $src_host = (gethostbyname($src))[4]; 
	my $dst_host = (gethostbyname($dst))[4];
	my ($packet) = forgepkt($src_host,$dst_host);
	my ($dest) = pack('Sna4x8', AF_INET, 0, $dst_host);

	# Send general query packet twice for reliability
	send(RAW,$packet,0,$dest);
	send(RAW,$packet,0,$dest);
	
	# Do some logging
	print "Sending querier packet\n";
	my $logFile = "/var/log/igmp.log";
	open(FH, '>>', $logFile) or die $!;
	print FH "Sending querier packet to 224.0.0.1\n";
	close(FH);
}

