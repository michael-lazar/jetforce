#!/usr/bin/env python
import json
import os

print("20 application/json")
print(json.dumps(dict(os.environ)))
