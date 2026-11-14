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

-- LK-031 anonymous write accepted
INSERT INTO http_requests VALUES (now() - INTERVAL 5 MINUTE, '', 'tm_1', '', 'pub', 'POST',
  'pub.exe.xyz', '/api/upload', 201, 9, 40, '203.0.113.13', 'curl/8.0');
-- LK-032 one IP sweeping four VMs
INSERT INTO http_requests SELECT now() - INTERVAL 8 MINUTE, '', 'tm_1', '', 'sweep' || i, 'GET',
  'sweep' || i || '.exe.xyz', '/', 307, 1, 0, '203.0.113.14', 'Go-http-client/1.1' FROM range(4) t(i);
-- LK-033 content discovery: 40 distinct 404 paths
INSERT INTO http_requests SELECT now() - INTERVAL 8 MINUTE, '', 'tm_1', '', 'pub', 'GET',
  'pub.exe.xyz', '/dir' || i, 404, 1, 10, '203.0.113.15', 'gobuster-ish' FROM range(40) t(i);
-- LK-034 same recon path from six IPs (all 404, so LK-002 stays quiet)
INSERT INTO http_requests SELECT now() - INTERVAL 7 MINUTE, '', 'tm_1', '', 'camp', 'GET',
  'camp.exe.xyz', '/boaform/admin/formLogin', 404, 1, 10, '198.18.0.' || i, 'Mozilla/5.0' FROM range(6) t(i);
-- LK-035 five 500s to one anonymous IP
INSERT INTO http_requests SELECT now() - INTERVAL 6 MINUTE, '', 'tm_1', '', 'pub', 'GET',
  'pub.exe.xyz', '/render?x=' || i, 500, 1, 10, '203.0.113.16', 'python-requests' FROM range(5) t(i);
-- negatives: 2 VMs swept, 29 distinct 404s, 4 500s, authenticated POST
INSERT INTO http_requests SELECT now() - INTERVAL 8 MINUTE, '', 'tm_1', '', 'two' || (i % 2), 'GET',
  'two.exe.xyz', '/', 307, 1, 0, '203.0.113.50', 'x' FROM range(4) t(i);
INSERT INTO http_requests SELECT now() - INTERVAL 8 MINUTE, '', 'tm_1', '', 'pub', 'GET',
  'pub.exe.xyz', '/n' || i, 404, 1, 10, '203.0.113.51', 'x' FROM range(29) t(i);
INSERT INTO http_requests SELECT now() - INTERVAL 6 MINUTE, '', 'tm_1', '', 'pub', 'GET',
  'pub.exe.xyz', '/e' || i, 500, 1, 10, '203.0.113.52', 'x' FROM range(4) t(i);
INSERT INTO http_requests VALUES (now() - INTERVAL 5 MINUTE, '', 'tm_1', 'usr_a', 'app', 'POST',
  'app.exe.xyz', '/api/save', 200, 9, 40, '198.51.100.1', 'Mozilla/5.0');
-- LK-030: 'fresh' has history behind a login, then goes public
INSERT INTO http_requests SELECT now() - INTERVAL (i) HOUR, '', 'tm_1', 'usr_a', 'fresh', 'GET',
  'fresh.exe.xyz', '/', 200, 5, 100, '198.51.100.1', 'Mozilla/5.0' FROM range(3, 72) t(i);
INSERT INTO http_requests VALUES (now() - INTERVAL 4 MINUTE, '', 'tm_1', '', 'fresh', 'GET',
  'fresh.exe.xyz', '/', 200, 5, 100, '203.0.113.17', 'Mozilla/5.0');

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
-- LK-036: the 'exfil' VM also serves anonymous visitors
INSERT INTO http_requests VALUES (now() - INTERVAL 30 MINUTE, '', 'tm_1', '', 'exfil', 'GET',
  'exfil.exe.xyz', '/', 200, 3, 512, '203.0.113.18', 'Mozilla/5.0');
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
		"LK-030": "fresh",
		"LK-032": "203.0.113.14",
		"LK-031": "pub",
		"LK-033": "pub",
		"LK-034": "/boaform/admin/formlogin",
		"LK-035": "pub",
		"LK-036": "exfil",
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
