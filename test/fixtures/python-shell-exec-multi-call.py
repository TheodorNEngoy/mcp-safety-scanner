import subprocess


def f(url: str) -> None:
    subprocess.run(["open", url], check=False)
    subprocess.run(["start", url], shell=True, check=False)

