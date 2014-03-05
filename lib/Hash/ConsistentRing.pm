package Hash::ConsistentRing;

use 5.008008;
our $VERSION = '0.01';

require XSLoader;
XSLoader::load('Hash::ConsistentRing', $VERSION);

1;
__END__
=head1 NAME

Hash::ConsistentRing - Consistent Ring Hashing used in Graphite

=head1 SYNOPSIS

  use Hash::ConsistentRing;
  
  my $ring = Hash::ConsistentRing->new(
    nodes => [
      ['node0host','port'],
      ['node1host','port'],
    ]
  );
  my $node = $ring->get("key");

=head1 DESCRIPTION



=head1 SEE ALSO

https://github.com/graphite-project/carbon/blob/master/lib/carbon/hashing.py

=head1 AUTHOR

Mons Anderson <mons@cpan.org>

md5 code was completely derived from Gisle Aas' L<Digest::MD5>

=head1 COPYRIGHT AND LICENSE

Copyright (c) 2014 by Mons Anderson

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.10.1 or,
at your option, any later version of Perl 5 you may have available.

=cut