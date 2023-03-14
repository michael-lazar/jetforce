#!/usr/bin/env python3
import json
import os

print("20 application/json")
print(json.dumps(dict(os.environ)))
