from setuptools import setup

# Read the package signature
with open("piptuf_demo/package_name.sig", "rb") as sig_file:
    package_signature = sig_file.read().hex()

setup(
    name="piptuf-demo",
    version="0.3",
    description=f"A demo project.",
    long_description=f"TUF Signature for verification: {package_signature}",
    long_description_content_type="text/plain",
    author="LV",
    author_email="lv@example.com",
    packages=["piptuf_demo"],
    include_package_data=True,
    package_data={
        "piptuf_demo": [],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.6",
)
