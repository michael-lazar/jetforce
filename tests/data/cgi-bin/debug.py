#!/usr/bin/env python
import os
import json

print("20 application/json")
print(json.dumps(dict(os.environ)))
