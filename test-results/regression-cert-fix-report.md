# Regression Test Report

- EST base URL: `https://192.168.200.120:8443`
- WebUI URL: `http://192.168.200.120:9443`
- SSH host: `krich@192.168.200.120`
- Report generated: `Wed Mar 18 21:30:42 CDT 2026`

## Summary

- Passed: 1
- Failed: 0
- Skipped: 0

## Results

| Category | ID | Status | Description | Log |
|---|---|---|---|---|
| webui-certs | WCERT-01 | PASS | certificate store load, validate, view, list, and cleanup flow | test-results/regression.ICPkFn/WCERT-01.log |

## Notes

- QA WebUI on port 9443 is currently reachable over plain HTTP at http://192.168.200.120:9443.
- QA service restart method is systemctl via sudo systemctl restart est-server.
- QA WebUI credentials in active use for regression are admin/*** and krich/***.
