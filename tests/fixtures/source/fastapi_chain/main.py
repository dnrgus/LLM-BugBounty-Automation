import os

import requests
from fastapi import Depends, FastAPI

app = FastAPI()


def current_user():
    return {"id": 1}


def fetch_preview(target):
    return requests.get(target)


def recurse(value, n):
    if n > 0:
        return recurse(value, n - 1)
    os.system(value)


class Repo:
    def run(self, sql):
        return self.conn.execute(sql)


@app.get("/preview")
def preview(url: str, user=Depends(current_user)):
    return fetch_preview(url)


@app.get("/loop")
def loop(cmd: str):
    return recurse(cmd, 3)


@app.get("/method-call")
def method_call(q: str):
    return Repo().run(q)


@app.get("/depends-only")
def depends_only(user=Depends(current_user)):
    return fetch_preview(user)
