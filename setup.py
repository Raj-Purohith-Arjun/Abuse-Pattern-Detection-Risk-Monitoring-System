from setuptools import setup, find_packages

with open("README.md", encoding="utf-8") as fh:
    long_description = fh.read()

with open("requirements.txt") as fh:
    install_requires = [
        line.strip() for line in fh if line.strip() and not line.startswith("#")
    ]

setup(
    name="abuse-pattern-detection",
    version="1.0.0",
    author="Abuse Pattern Detection Team",
    description="Abuse Pattern Detection & Risk Monitoring System",
    long_description=long_description,
    long_description_content_type="text/markdown",
    packages=find_packages(where=".", include=["src", "src.*"]),
    package_dir={"": "."},
    python_requires=">=3.11",
    install_requires=install_requires,
    classifiers=[
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.11",
        "Operating System :: OS Independent",
        "Intended Audience :: Developers",
        "Topic :: Security",
        "Topic :: Scientific/Engineering :: Artificial Intelligence",
    ],
    entry_points={
        "console_scripts": [
            "abuse-detection=src.__init__:main",
        ],
    },
)
