#!/usr/bin/env python3
"""Run unchanged coreutils shell tests with cpcopy installed as cp.

Usage: run-upstream.py COREUTILS_SOURCE CPCOPY_BINARY [TEST_NAME ...]
The source must include tests/init.sh (the GNU release tarball does).
Other utilities come from PATH; cp is always the supplied binary.
"""
import os
from pathlib import Path
import subprocess
import shutil
import sys
import tempfile


def main():
    source, binary = (Path(arg).resolve(strict=True) for arg in sys.argv[1:3])
    tests = sys.argv[3:] or [path.name for path in sorted((source / "tests/cp").glob("*.sh"))]
    failed = False
    header = os.environ.get("CONFIG_HEADER")
    if header is None and (source / "lib/config.h").is_file():
        header = str(source / "lib/config.h")
    for name in tests:
        test = source / "tests/cp" / name
        if test.parent != source / "tests/cp" or not test.is_file():
            raise ValueError(f"invalid test name: {name}")
        if "CONFIG_HEADER" in test.read_text() and (not header or not Path(header).is_file()):
            print(f"INFRA {name}: supply CONFIG_HEADER from a configured coreutils build", flush=True)
            failed = True
            continue
        with tempfile.TemporaryDirectory(prefix="cpcopy-upstream-") as directory:
            work = Path(directory)
            (work / "src").mkdir()
            (work / "src/cp").symlink_to(binary)
            programs = {"cp"}
            for line in test.read_text().splitlines():
                if line.startswith("print_ver_ "):
                    programs.update(program for program in line.split()[1:]
                                    if shutil.which(program))
            env = dict(os.environ, srcdir=str(source), abs_srcdir=str(source),
                       LC_ALL="C", PATH_SEPARATOR=":",
                       built_programs=" ".join(sorted(programs)))
            env["PATH"] = str(work / "src") + os.pathsep + env["PATH"]
            if shutil.which("perl"):
                env["PERL"] = shutil.which("perl")
            if shutil.which("awk"):
                env["AWK"] = shutil.which("awk")
            if header:
                env["CONFIG_HEADER"] = str(Path(header).resolve())
            result = subprocess.run(["sh", "-c", 'exec 9>&2; . "$0"; exit "${fail:-0}"', str(test)], cwd=work, env=env,
                                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                    timeout=120)
            output = result.stdout.decode(errors="replace")
            status = {0: "PASS", 77: "SKIP"}.get(result.returncode, "FAIL")
            # Some upstream tests misspell framework_failure_. Do not accept
            # a zero exit code after that broken setup failure path.
            if (("framework-failure" in output and "not found" in output)
                    or "unary operator expected" in output):
                status = "INFRA"
            print(f"{status} {name}\n{output}", flush=True)
            failed |= status in {"FAIL", "INFRA"}
    return int(failed)


if __name__ == "__main__":
    sys.exit(main())
