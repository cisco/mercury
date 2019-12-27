# run as: python3 package_test.py
#
# return value will be 0 (success) only if all needed packages are available

import sys

try:
    import jsonschema
except ModuleNotFoundError:
    print ("error: python3 jsonschema module not found")
    sys.exit(-1)
    
print ("found python package jsonschema")
