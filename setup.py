from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="raven-secure-messenger",
    version="2.0.0",
    author="Your Name",
    author_email="your.email@example.com",
    description="Decentralized secure messenger with military-grade encryption",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/yourusername/raven-secure-messenger",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Topic :: Communications :: Chat",
        "Topic :: Security :: Cryptography",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.8",
    install_requires=[
        "cryptography>=41.0.0",
        "pynacl>=1.5.0",
        "argon2-cffi>=23.1.0",
        "Pillow>=10.0.0",
        "requests>=2.31.0",
        "beautifulsoup4>=4.12.0",
    ],
    entry_points={
        "console_scripts": [
            "raven-messenger=raven_messenger:main",
        ],
    },
    keywords="p2p, messenger, encryption, secure, cryptography, osint",
)
