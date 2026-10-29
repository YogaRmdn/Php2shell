"""advisory.py — daftar advisori CVE + catatan pasca-rilis. Data murni, tanpa jaringan."""

from __future__ import annotations

ADVISORIES = (
    {
        "cve": "CVE-2026-109619",
        "class": "stale global state -> UAF",
        "trigger": ("session.upload_progress multipart callbacks run BEFORE RINIT; "
                    "OOM leaves PS(http_session_vars)/PS(id) dangling -> next request "
                    "on the same worker calls zval_ptr_dtor on freed memory"),
        "requests": "2 (producer + consumer)",
        "status": "implemented",
    },
    {
        "cve": "CVE-2026-109618",
        "class": "OOM bailout corruption -> longjmp",
        "trigger": ("zend_bailout() mid-allocation leaves half-built structures "
                    "in global state"),
        "requests": "1",
        "status": "detect-only",
    },
)

# Catatan pasca-rilis (diverifikasi 2026-10-24, sumber primer).
NOTES = (
    "advisory.patched_rebuilt",
    "advisory.cve_115560",
    "advisory.memory_limit_note",
    "advisory.upload_progress_note",
    "advisory.in_wild",
)
