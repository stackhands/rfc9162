`rfc9162-log`: A seal or compaction retried after its manifest append failed, or after a crash between storing the run file and logging the manifest, logs the run.
It found its own run file and refused every retry with "a run for that entry range is already stored"; a run file with other bytes for the range is still refused.
