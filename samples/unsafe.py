import pickle
import yaml
import subprocess
import hashlib
import requests
import os as operating_system


def unsafe_function(data):

    eval(data)

    exec(data)

    pickle.loads(data)

    yaml.load(data)

    subprocess.run(data, shell=True)

    hashlib.md5(data)

    requests.get(
        "https://example.com",
        verify=False
    )

    operating_system.system(data)


def safe_function(data):

    yaml.safe_load(data)

    subprocess.run(
        ["echo", data],
        shell=False
    )

    requests.get(
        "https://example.com",
        verify=True
    )