import subprocess


def _archive(filename):
    subprocess.run(f"tar czf /tmp/{filename}.tgz /srv/reports", shell=True)


def export(name):
    cleaned = name.strip()
    _archive(cleaned)
    return {"ok": True}
