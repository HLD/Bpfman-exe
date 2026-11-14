SET s3_endpoint='look.int.exe.xyz';
SET s3_url_style='path';
SET TimeZone='UTC';
CREATE OR REPLACE VIEW http_requests AS
  FROM iceberg_scan('s3://look/http_requests', allow_moved_paths = true);
CREATE OR REPLACE VIEW vm_metrics AS
  FROM iceberg_scan('s3://look/vm_metrics', allow_moved_paths = true);
CREATE OR REPLACE MACRO increase(cur, prev) AS
  CASE WHEN cur < prev THEN cur ELSE cur - prev END;
