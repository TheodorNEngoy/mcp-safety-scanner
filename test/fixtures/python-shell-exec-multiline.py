import subprocess


def do_not_run_in_prod():
    # Multi-line call: scanner should still flag shell=True usage.
    subprocess.run(
        "echo hello",
        shell=True,
    )

