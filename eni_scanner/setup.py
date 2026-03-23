from setuptools import setup, find_packages

setup(
    name="eni-scanner",
    version="6.3",
    packages=find_packages(),
    include_package_data=True,
    install_requires=[
        "aiohttp",
        "beautifulsoup4",
        "paramiko",
        "pysocks",
        "pysnmp",
        "aiosnmp",
        "zeroconf",
        "scapy",
        "tqdm",
        "pyyaml",
        "cryptography",
        "openpyxl",
        "requests",
    ],
    entry_points={
        "console_scripts": [
            "eni-scanner = scanner.__main__:main",
        ]
    },
    python_requires=">=3.7",
    author="Your Name",
    description="Asynchronous IoT scanner and exploitation framework",
    license="MIT",
)
