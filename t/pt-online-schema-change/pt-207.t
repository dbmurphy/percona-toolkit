#!/usr/bin/env perl

BEGIN {
   die "The PERCONA_TOOLKIT_BRANCH environment variable is not set.\n"
      unless $ENV{PERCONA_TOOLKIT_BRANCH} && -d $ENV{PERCONA_TOOLKIT_BRANCH};
   unshift @INC, "$ENV{PERCONA_TOOLKIT_BRANCH}/lib";
};

use strict;
use warnings FATAL => 'all';
use threads;

use English qw(-no_match_vars);
use Test::More;

use Data::Dumper;
use PerconaTest;
use Sandbox;
use SqlModes;
use File::Temp qw/ tempdir /;

require "$trunk/bin/pt-online-schema-change";

my $dp = new DSNParser(opts=>$dsn_opts);
my $sb = new Sandbox(basedir => '/tmp', DSNParser => $dp);
my $source_dbh = $sb->get_dbh_for('source');
my $source_dsn = 'h=127.1,P=12345,u=msandbox,p=msandbox';

if ( !$source_dbh ) {
   plan skip_all => 'Cannot connect to sandbox source';
}

if ($sandbox_version lt '5.7') {
   plan skip_all => "RocksDB is only available on Percona Server 5.7.19+";
}

my $rows = $source_dbh->selectall_arrayref('SHOW ENGINES', {Slice=>{}});
my $rocksdb_enabled;
for my $row (@$rows) {
    if ($row->{engine} eq 'ROCKSDB') {
        $rocksdb_enabled = 1;
        last;
    }
}

if (!$rocksdb_enabled) {
   plan skip_all => "RocksDB engine is not available";
}

plan tests => 3;

# The sandbox servers run with lock_wait_timeout=3 and it's not dynamic
# so we need to specify --set-vars innodb_lock_wait_timeout=3 else the
# tool will die.
my @args       = (qw(--set-vars innodb_lock_wait_timeout=3));
my $output;
my $exit_status;

$sb->load_file('source', "t/pt-online-schema-change/samples/pt-207.sql");

($output, $exit_status) = full_output(
   sub { pt_online_schema_change::main(@args, "$source_dsn,D=test,t=t1",
         '--execute', 
         '--alter', "ADD INDEX (f3)",
         ),
      },
);

isnt(
      $exit_status,
      0,
      "PT-207 Altering RocksDB table adding index with invalid collation, exit status != 0",
);

like(
      $output,
      qr/`test`.`t1` was not altered/s,
      "PT-207 Message cannot add index with invalid collation to a RocksDB table",
);

$source_dbh->do("DROP DATABASE IF EXISTS test");

# #############################################################################
# Done.
# #############################################################################
$sb->wipe_clean($source_dbh);
ok($sb->ok(), "Sandbox servers") or BAIL_OUT(__FILE__ . " broke the sandbox");
done_testing;
