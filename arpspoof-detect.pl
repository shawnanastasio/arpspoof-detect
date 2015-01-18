#!/usr/bin/perl -w

# Arpspoof-detect
# Detects changes in router mac address to detect common ARP poisoning techniques.
# Shawn Anastasio 2014
# Licensed under the LGPL Version 2.0

# Let's get the number of arguments provided
$num_args = $#ARGV + 1;

if ($num_args == 0) {
  print("Warning: Router MAC not provided; assuming that your current ARP tables are sane\n");

  #Get router IP
  my $router = qx(/sbin/ip route | awk '/default/ { print \$3 }');
  chomp $router;

  #Get current router mac
  my $routermac = qx(arp |grep -w $router |grep -oi '[0-9A-F]\\{2\\}\\(:[0-9A-F]\\{2\\}\\)\\{5\\}');
  chomp $routermac;


  while (1) {
    #Check mac to make sure it matches up
    my $checkedroutermac = qx(arp |grep -w $router |grep -oi '[0-9A-F]\\{2\\}\\(:[0-9A-F]\\{2\\}\\)\\{5\\}');
    chomp $checkedroutermac;

    #If not the same; die with error
    if ($checkedroutermac ne $routermac) {
      die("ERROR: Your arp tables have been modified. You are most likely being ARP Spoofed.\n")
    } else {
      sleep(1);
    }

  }


}
