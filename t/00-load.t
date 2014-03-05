#!/usr/bin/evn perl

use Test::More tests => 7;
BEGIN { use_ok('Hash::ConsistentRing') };
#use Data::Dumper;

my @nodes = map { ["192.168.10.".(10+$_),20+$_] } 0..2;

my $ring = Hash::ConsistentRing->new(
	replica_count => 2,
	nodes => \@nodes,
);
is_deeply $nodes[0], $ring->get("test"),  '2x3: test - node0';
is_deeply $nodes[1], $ring->get("test5"), '2x3: test5 - node1';
is_deeply $nodes[2], $ring->get("test2"), '2x3: test2 - node2';

@nodes = map { ["127.0.0.".(10+$_),"$_"] } 1..10;

$ring = Hash::ConsistentRing->new(
	replica_count => 100,
	nodes => \@nodes,
);
is_deeply $nodes[3],  $ring->get("test1"), '100x10: test1 - node3';
is_deeply $nodes[2],  $ring->get("test2"), '100x10: test2 - node2';
is_deeply $nodes[7],  $ring->get("test5"), '100x10: test3 - node7';

