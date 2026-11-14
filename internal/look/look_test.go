package look

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strings"
	"testing"

	"github.com/exedev/warden/internal/config"
)

// fixtures builds local tables with the Look In schema, seeded with one
// example of each detection plus benign background rows.
const fixtures = `
SET TimeZone='UTC';
CREATE MACRO increase(cur, prev) AS CASE WHEN cur < prev THEN cur ELSE cur - prev END;

CREATE TABLE http_requests (timestamp TIMESTAMPTZ, user_id VARCHAR, team_id VARCHAR,
  login_user_id VARCHAR, vm_name VARCHAR, method VARCHAR, host VARCHAR, path VARCHAR,
  status INTEGER, duration_ms BIGINT, response_bytes BIGINT, source_ip VARCHAR, user_agent VARCHAR);
-- benign: owner using their private app, with history
INSERT INTO http_requests SELECT now() - INTERVAL (i) HOUR, '', 'tm_1', 'usr_a', 'app', 'GET',
  'app.exe.xyz', '/', 200, 5, 100, '198.51.100.1', 'Mozilla/5.0' FROM range(1, 72) t(i);
-- LK-001 anonymous 200
INSERT INTO http_requests VALUES (now() - INTERVAL 5 MINUTE, '', 'tm_1', '', 'pub', 'GET',
  'pub.exe.xyz', '/index.html', 200, 3, 512, '203.0.113.9', 'Mozilla/5.0');
-- LK-002 secrets probe that got through
INSERT INTO http_requests VALUES (now() - INTERVAL 5 MINUTE, '', 'tm_1', '', 'pub', 'GET',
  'pub.exe.xyz', '/.env', 200, 3, 80, '203.0.113.10', 'curl/8.0');
-- LK-003 scanner
INSERT INTO http_requests VALUES (now() - INTERVAL 5 MINUTE, '', 'tm_1', '', 'app', 'GET',
  'app.exe.xyz', '/', 307, 1, 0, '203.0.113.11', 'Mozilla/5.0 zgrab/0.x');
-- LK-004 burst of login redirects from one IP
INSERT INTO http_requests SELECT now() - INTERVAL 10 MINUTE, '', 'tm_1', '', 'app', 'GET',
  'app.exe.xyz', '/login' || i, 307, 1, 0, '203.0.113.12', 'python-requests' FROM range(60) t(i);
-- LK-010 known user from a new IP
INSERT INTO http_requests VALUES (now() - INTERVAL 5 MINUTE, '', 'tm_1', 'usr_a', 'app', 'GET',
  'app.exe.xyz', '/', 200, 5, 100, '192.0.2.77', 'Mozilla/5.0');

CREATE TABLE ssh_access (timestamp TIMESTAMPTZ, user_id VARCHAR, team_id VARCHAR,
  login_user_id VARCHAR, vm_name VARCHAR, via VARCHAR, key_fingerprint VARCHAR, ssh_user VARCHAR);
-- benign: long-used key
INSERT INTO ssh_access SELECT now() - INTERVAL (i) DAY, '', 'tm_1', 'usr_a', 'app', 'ssh',
  'SHA256:old', 'exedev' FROM range(1, 30) t(i);
INSERT INTO ssh_access VALUES
  (now() - INTERVAL 5 MINUTE, '', 'tm_1', 'usr_b', 'app', 'ssh', 'SHA256:new', 'exedev'),     -- LK-011
  (now() - INTERVAL 5 MINUTE, '', 'tm_1', 'usr_sup', 'app', 'support', 'SHA256:sup', 'root'), -- LK-012, LK-013
  (now() - INTERVAL 5 MINUTE, '', 'tm_1', 'usr_a', 'app', 'api_ssh', '', 'exedev');           -- LK-014

CREATE TABLE vm_metrics (timestamp TIMESTAMPTZ, user_id VARCHAR, team_id VARCHAR, vm_name VARCHAR,
  cpus INTEGER, cpu_usec BIGINT, net_rx_bytes BIGINT, net_tx_bytes BIGINT,
  fs_used_bytes BIGINT, fs_size_bytes BIGINT);
-- LK-020 'exfil': ~10 MB/h for 3 days, then 600 MB within the last hour
INSERT INTO vm_metrics SELECT now() - INTERVAL 1 HOUR * 72 + INTERVAL 1 MINUTE * i, '', 'tm_1', 'exfil', 2,
  i * 1000000, i * 100000, i * 170000, 0, 0 FROM range(0, 4318) t(i);
INSERT INTO vm_metrics VALUES (now() - INTERVAL 1 MINUTE, '', 'tm_1', 'exfil', 2,
  4320000000, 432000000, 4318 * 170000 + 600000000, 0, 0);
-- LK-021 'miner': 30 minutes at 2 of 2 vCPUs
INSERT INTO vm_metrics SELECT now() - INTERVAL 31 MINUTE + INTERVAL 1 MINUTE * i, '', 'tm_1', 'miner', 2,
  i * 120000000, i * 1000, i * 1000, 0, 0 FROM range(0, 31) t(i);
-- LK-022 'reboot': network counter starts over
INSERT INTO vm_metrics VALUES
  (now() - INTERVAL 20 MINUTE, '', 'tm_1', 'reboot', 2, 5000000, 9000000, 9000000, 0, 0),
  (now() - INTERVAL 19 MINUTE, '', 'tm_1', 'reboot', 2, 1000, 1000, 1000, 0, 0);
`

func TestRulesAgainstFixtures(t *testing.T) {
	duck, err := exec.LookPath("duckdb")
	if err != nil {
		t.Skip("duckdb CLI not installed")
	}
	rs, err := ParseRules(config.DefaultLookRules)
	if err != nil {
		t.Fatal(err)
	}
	fired := map[string]int{}
	got := map[string][]string{} // rule -> sorted key values, for exact checks
	for _, r := range rs {
		sql := strings.ReplaceAll(r.SQL, "{since}", "(now() - INTERVAL 1 HOUR)")
		cmd := exec.Command(duck, "-json")
		cmd.Env = append(os.Environ(), "HOME="+t.TempDir())
		cmd.Stdin = strings.NewReader(fixtures + strings.TrimRight(strings.TrimSpace(sql), ";") + ";\n")
		var out, errb bytes.Buffer
		cmd.Stdout, cmd.Stderr = &out, &errb
		if err := cmd.Run(); err != nil || strings.Contains(errb.String(), "Error") {
			t.Fatalf("%s: %v: %s", r.ID, err, errb.String())
		}
		rows, err := lastResult(out.Bytes())
		if err != nil {
			t.Fatalf("%s: %v", r.ID, err)
		}
		fired[r.ID] = len(rows)
		for _, row := range rows {
			if v, ok := row[r.Key[0]]; ok {
				got[r.ID] = append(got[r.ID], fmt.Sprint(v))
			}
			for _, k := range r.Key {
				if _, ok := row[k]; !ok {
					t.Errorf("%s: key column %q missing from result", r.ID, k)
				}
			}
		}
	}
	var ids []string
	for id := range fired {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		t.Logf("%s rows=%d", id, fired[id])
		if fired[id] == 0 {
			t.Errorf("%s did not fire on its fixture", id)
		}
	}
	// Exactly the seeded examples fire; benign background rows don't.
	for id, want := range map[string]string{
		"LK-010": "usr_a",                  // keyed by login_user_id (new IP only)
		"LK-011": "SHA256:new,SHA256:sup", // the long-used key stays quiet
		"LK-020": "exfil",
		"LK-021": "miner",
		"LK-022": "reboot",
	} {
		sort.Strings(got[id])
		if g := strings.Join(got[id], ","); g != want {
			t.Errorf("%s: got %q, want %q", id, g, want)
		}
	}
}

func TestParseRulesRequiresSince(t *testing.T) {
	if _, err := ParseRules([]byte("- {id: X, key: [a], sql: 'SELECT 1'}")); err == nil {
		t.Fatal("expected error for sql without {since}")
	}
}
