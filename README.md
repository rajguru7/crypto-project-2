# Piptuf



## Demo workflow

For this demo we will show how a developer (us) can upload a package
(piptuf-demo) to PyPI with TUF metadata maintained on localhost (in real world,
there will be a single TUF repository accessible to public internet for
uploading package metadata). The download step will compare the hash of the
package downloaded from pypi with the hash of the package from the TUF repo to
make sure that the package integrity has been maintained.

### install dependencies

```bash
pip install -r requirements.txt
```

### Deploy TUF repo

First deploy TUF repository that will hold the metadata

```bash
./tuf/repository/repo
```

### Add the delegation for piptuf-demo package 

This must be run by the user who is the owner of the package `piptuf-demo` on
pypi

```bash
./tuf/uploader/uploader tofu
./tuf/uploader/uploader add-delegation piptuf-demo
```

### Use piptuf to upload the python package

```
./piptuf upload piptuf-demo piptuf-demo/dist/piptuf_demo-0.3-py3-none-any.whl
```

### Use piptuf to download the python package

```bash
./piptuf download piptuf-demo
# Collecting piptuf-demo
# Using cached piptuf_demo-0.3-py3-none-any.whl.metadata (870 bytes)
# Using cached piptuf_demo-0.3-py3-none-any.whl (1.7 kB)
# Saved ./piptuf_demo-0.3-py3-none-any.whl
# Successfully downloaded piptuf-demo
# Trust-on-First-Use: Initialized new root in
# /home/killua/.local/share/tuf-example/d412c05c
# Expected hash: e2752789730f96541ac63dca8b487ef6f4747733f10a3144e56282a3ca605c6c
# Downloaded file piptuf_demo-0.3-py3-none-any.whl is secure
```

The output will show that the downloaded package is secure if the hash on the
TUF repo for that package matches the hash of the downloaded package.
