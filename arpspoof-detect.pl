#!/usr/bin/perl

# arpspoof-detect
# Detects changes in router mac address to detect common ARP poisoning techniques.
# Shawn Anastasio 2014-2016
# Licensed under the LGPL Version 2.0

# Amount of time to wait between ARP table checks (in seconds)
$delay = 5;

main();
sub main() {
  # Let's get the number of arguments provided
  my $num_args = $#ARGV + 1;
  if ($num_args == 0) {
    print("Watching ARP tables.\n");
    print("Warning: Router MAC not provided; assuming that your current ARP tables are sane\n");
    watch_arp_spoof(undef);
  } else {
    # Check arguments
    for($i=0;$i<$num_args-1;$i++) {
      if ($ARGV[$i] eq "-m" && $num_args == 2) { # -m <mac> argument provided
        print("Watching ARP tables.\n");
        print("Known-good router MAC address: " . $ARGV[$i+1] . "\n");
        watch_arp_spoof($ARGV[$i+1]); # Pass user-specified mac to watch_arp_spoof
      }
    }

    # Invalid arguments
    show_help();
  }
}

sub watch_arp_spoof {
  my ($routermac) = @_;

  #Get router IP
  my $router = qx(/sbin/ip route | awk '/default/ { print \$3 }');
  chomp $router;

  if (defined($routermac) == 0) { # No mac address provided; assume current is correct
    #Get current router mac
    $routermac = qx(arp -n |grep -w $router |grep -oi '[0-9A-F]\\{2\\}\\(:[0-9A-F]\\{2\\}\\)\\{5\\}');
    chomp $routermac;
  }

  while (1) {
    #Check mac to make sure it matches up
    my $checkedroutermac = qx(arp -n |grep -w $router |grep -oi '[0-9A-F]\\{2\\}\\(:[0-9A-F]\\{2\\}\\)\\{5\\}');
    chomp $checkedroutermac;

    #If not the same; die with error
    if ($checkedroutermac ne $routermac) {
      arp_error();
    } else {
      sleep($delay);
    }
  }
}

# Runs when arp spoof is detected
# You can modify this to make it do something more useful than printing out error
sub arp_error {
  die("ERROR: Your arp tables have been modified. You are most likely being ARP Spoofed.\n");
}

sub show_help {
  print("Usage: arpspoof-detect [-m <MAC address>]\n");
  print("  -m <MAC address>   Supply expected MAC address of router\n");
  exit();
}
