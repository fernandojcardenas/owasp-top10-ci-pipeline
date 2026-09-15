# Insecure YAML deserialization

**OWASP category:** A08:2021 Software and Data Integrity Failures
**CWE:** CWE-502 Deserialization of Untrusted Data
**Location:** `app/config_loader.py`

## The vulnerability

The app's config file was parsed with PyYAML's full loader instead of the safe one:

```python
return yaml.load(f, Loader=yaml.Loader)
```

`yaml.Loader` can construct arbitrary Python objects from tags embedded in the YAML
document, including tags that call functions like `os.system` at load time. `yaml.load`
does not distinguish "data" from "code to run while parsing the data" unless it's told to
with a restricted loader. This app's own `config.yaml` is a static file today, but the
same call is what a lot of real-world incidents trace back to: a config file, a cache
entry, or an uploaded file gets parsed this way, and whoever can influence its contents,
through a compromised dependency, a writable shared volume, or a future feature that lets
a config be uploaded or fetched, gets code execution the moment it's loaded.

## Exploit

This reproduces the exact call `config_loader.py` makes, against a crafted YAML string:

```
$ python3 -c "
import yaml
malicious_yaml = '''
app_name: !!python/object/apply:os.system [\"touch /tmp/pwned_via_yaml\"]
debug: true
'''
result = yaml.load(malicious_yaml, Loader=yaml.Loader)
import os
print('marker file created:', os.path.exists('/tmp/pwned_via_yaml'))
"
marker file created: True
```

Just parsing the document (`app_name`'s value is never even used) ran `os.system(...)` as
a side effect of building the `app_name` value, proving that loading this file is enough
to execute arbitrary shell commands if its contents are ever attacker-influenced.

## Fix

Use `yaml.safe_load`, which only builds plain Python types (str, int, float, bool, list,
dict) and refuses any tag that would construct an arbitrary object:

```python
return yaml.safe_load(f)
```

## Verification

The identical payload against the fixed call:

```
$ python3 -c "
import yaml
malicious_yaml = '''
app_name: !!python/object/apply:os.system [\"touch /tmp/pwned_via_yaml\"]
debug: true
'''
result = yaml.safe_load(malicious_yaml)
"
Traceback (most recent call last):
  ...
yaml.constructor.ConstructorError: could not determine a constructor for the tag
'tag:yaml.org,2002:python/object/apply:os.system'
```

`safe_load` refuses to build the object at all and raises instead of running anything, so
the same file that previously executed a shell command now just fails to parse.
