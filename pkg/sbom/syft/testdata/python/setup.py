from setuptools import setup, find_packages

setup(
    name="test-python-package",
    version="1.0.0",
    author="Test Author",
    author_email="test@example.com",
    description="A test Python package for SBOM scanning",
    packages=find_packages(),
    install_requires=[
        "requests==2.31.0",
        "flask==3.0.0",
        "numpy==1.26.0",
        "pandas==2.1.1",
    ],
    python_requires=">=3.7",
)