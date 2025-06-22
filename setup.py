import setuptools

# Read the contents of your README file
with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

# Read dependencies from requirements.txt
with open("requirements.txt", "r", encoding="utf-8") as f_req:
    install_requires = [line.strip() for line in f_req if line.strip() and not line.startswith('#')]

setuptools.setup(
    name="autobb",
    version="0.5.0", # Updated version
    author="AI (Jules for AutoBugBounty)",
    author_email="ai@example.com", # Placeholder, user should update
    description="A CLI toolkit to assist with bug bounty hunting workflows.",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/CodyJacobs974/autobb", # Updated URL
    project_urls={
        "Bug Tracker": "https://github.com/CodyJacobs974/autobb/issues", # Updated URL
        "Source Code": "https://github.com/CodyJacobs974/autobb", # Added Source Code URL
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "License :: OSI Approved :: MIT License", # Assuming MIT, can be changed
        "Operating System :: POSIX :: Linux",
        "Environment :: Console",
        "Intended Audience :: Developers", # And security professionals
        "Topic :: Security",
        "Topic :: Utilities",
    ],
    package_dir={"": "."}, # Tells setuptools that packages are under the root dir
    packages=setuptools.find_packages(where="."), # Finds the 'autobb' package
    python_requires=">=3.8", # From .python-version and general good practice
    install_requires=install_requires, # Read from requirements.txt
    entry_points={
        "console_scripts": [
            "autobb=autobb.main:main", # This creates the 'autobb' command
        ],
    },
)
