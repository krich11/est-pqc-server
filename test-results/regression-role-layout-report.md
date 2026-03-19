# Regression Test Report

- EST base URL: `https://192.168.200.120:8443`
- WebUI URL: `http://192.168.200.120:9443`
- SSH host: `krich@192.168.200.120`
- Report generated: `Wed Mar 18 20:47:50 CDT 2026`

## Summary

- Passed: 8
- Failed: 0
- Skipped: 0

## Results

| Category | ID | Status | Description | Log |
|---|---|---|---|---|
| webui-config | WC-01 | PASS | configuration GET returns expected fields | test-results/regression.1WMztq/WC-01.log |
| webui-config | WC-02 | PASS | configuration POST persists a temporary change and restore | test-results/regression.1WMztq/WC-02.log |
| webui-users | WU-01 | PASS | user listing, create, role, enable, password, own-password, and delete flow | test-results/regression.1WMztq/WU-01.log |
| webui-certs | WCERT-01 | PASS | certificate store load, validate, view, list, and cleanup flow | test-results/regression.1WMztq/WCERT-01.log |
| webui-systemd | WS-01 | PASS | systemd status endpoint returns est-server details | test-results/regression.1WMztq/WS-01.log |
| webui-systemd | WS-02 | PASS | invalid systemd action returns 400 | test-results/regression.1WMztq/WS-02.log |
| webui-systemd | WS-03 | PASS | systemd restart action succeeds through WebUI API | test-results/regression.1WMztq/WS-03.log |
| webui-gui | WG-01 | PASS | browser navigation and GUI view coverage | test-results/regression.1WMztq/WG-01.log |

## Notes

- QA WebUI on port 9443 is currently reachable over plain HTTP at http://192.168.200.120:9443.
- QA service restart method is systemctl via sudo systemctl restart est-server.
- QA WebUI credentials in active use for regression are admin/*** and krich/***.
