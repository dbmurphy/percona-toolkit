STOP REPLICA;
CHANGE REPLICATION FILTER REPLICATE_IGNORE_DB = ();
CHANGE REPLICATION FILTER REPLICATE_IGNORE_TABLE = ();
CHANGE REPLICATION FILTER REPLICATE_WILD_IGNORE_TABLE = ();
RESET REPLICA;
START REPLICA;
