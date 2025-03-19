from setuptools import setup, find_packages

setup(
    name="pwnai",
    version="0.1.0",
    packages=find_packages(),
    install_requires=[
        "pwntools",
        "r2pipe",
        "openai>=1.0.0",
        "python-dotenv",
        "numpy",
        "colorlog",
        "pyyaml",
        "requests",
        "capstone",
        "ropgadget",
        "pwndbg",
    ],
    extras_require={
        "dev": [
            "pytest",
            "pytest-cov",
            "black",
            "isort",
            "pylint",
            "mypy",
        ],
    },
    entry_points={
        "console_scripts": [
            "pwnai=pwnai.cli:main",
            "pwnai-config=pwnai.sample_config:main",
        ],
    },
    python_requires=">=3.8",
    author="PwnAI Contributors",
    author_email="",
    description="LLM-Based CTF Exploitation Solver",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    url="https://github.com/username/pwnai",
    include_package_data=True,
    package_data={
        "pwnai": ["models.yaml"],
    },
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Education",
        "Topic :: Security",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
    ],
) 