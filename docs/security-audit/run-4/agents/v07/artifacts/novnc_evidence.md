# v07 verification evidence - extract-novnc-unauthenticated-no-single-flight

Source: src-audited @ 9805d91 (api.py:100,355-362; sandbox_desktop.py:146-169; deploy/Caddyfile:4-5;
web.py registers only /static/htmx.min.js). All runs in tools/sbx.py v07 (no network, no docker socket),
docker.from_env patched to an in-process fake that counts containers.create and serves a fixed tar.

Measured (novnc_repro.py, Python 3.12.3):
- fresh tree, 1 unauth GET  -> 200, creates=1, removes=1, marker published
- second GET                -> 200, creates=0 (marker hit)
- 6 concurrent unauth GETs (directory-complete tar) -> 6 x 200, creates=6, no exception
- 3 x GET /static/novnc/does-not-exist.js, tree deleted before each -> 404, creates=1 each
- truncated tar, 3 sequential GETs -> 500 ReadError x3, creates=3, marker never published

Measured (novnc_variant.py):
- tar WITHOUT directory members, 6 concurrent -> 1 x 200 + 5 x 500 FileExistsError
  "[Errno 17] File exists: '<home>/novnc/core'", creates=6 (tarfile._extract_member's
  unguarded os.makedirs(upperdirs) at line 163-166; the 3.12 source was dumped and inspected)
- directory-complete tar, 12 concurrent -> 12 x 200, creates=12, no exception
- truncated tar, 4 concurrent -> 4 x 500 ReadError, creates=4, no partial tree left

Conclusion: unauthenticated per-request docker create + full tar extraction with no single-flight is
confirmed and duplicates under concurrency in every archive shape; the concurrent FileExistsError
500s are fixture-dependent, not universal.
