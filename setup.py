from setuptools import setup, find_packages

setup(
    name="supply-chain-guard",
    version="1.0.0",
    description="Real-Time Supply Chain Malware Detection",
    packages=find_packages(),
    install_requires=[
        "flask>=3.0.0",
        "flask-cors>=4.0.0",
        "requests>=2.31.0",
        "python-Levenshtein>=0.23.0",
        "networkx>=3.2.1",
        "scikit-learn>=1.3.2",
        "numpy>=1.26.2",
        "pyyaml>=6.0.1",
    ],
    entry_points={
        "console_scripts": [
            "scg=cli.installer:main",
            "scg-hooks=cli.setup_hooks:install_hooks",
        ],
    },
    python_requires=">=3.9",
)