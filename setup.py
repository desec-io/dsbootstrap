from setuptools import setup
import dsbootstrap

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name=dsbootstrap.__name__,
    version=dsbootstrap.__version__,
    description=dsbootstrap.__doc__,
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="",
    author="Peter Thomassen",
    author_email="peter@desec.io",
    packages=["dsbootstrap"],
    setup_requires=["pytest-runner"],
    python_requires=">=3.7",
    install_requires=["dnspython", "cryptography", "click"],
    tests_require=["pytest"],
    entry_points={
        "console_scripts": [
            "dsbootstrap = dsbootstrap.__main__:main",
        ],
    },
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Environment :: Console",
        "Intended Audience :: System Administrators",
        "Operating System :: POSIX :: Linux",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3 :: Only",
        "Topic :: System :: Systems Administration",
    ],
)
