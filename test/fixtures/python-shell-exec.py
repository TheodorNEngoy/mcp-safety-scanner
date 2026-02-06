import subprocess


def run(user_input: str):
    # This should be flagged.
    subprocess.run(user_input, shell=True)

