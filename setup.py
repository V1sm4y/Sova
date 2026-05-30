from setuptools import find_packages, setup


setup(
    name="sova",
    version="0.1.0",
    description="Interactive CLI network diagnostic and service auditing tool.",
    author="V1sm4y",
    packages=find_packages(),
    include_package_data=True,
    package_data={"sova": ["wordlists/*.txt"]},
    install_requires=[
        "httpx>=0.27.0",
        "rich>=13.7.0",
    ],
    extras_require={
        "dev": [
            "pytest>=8.0.0",
            "pytest-asyncio>=0.23.0",
        ]
    },
    entry_points={
        "console_scripts": [
            "sova=sova.cli:main",
        ],
    },
    python_requires=">=3.9",
)
