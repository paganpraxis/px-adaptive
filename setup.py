from setuptools import find_packages, setup

setup(
    name="pxadaptive",
    version="0.1.0",
    packages=find_packages(),
    python_requires=">=3.9",
    install_requires=["numpy>=1.24,<3", "pandas>=2.0,<3", "scikit-learn>=1.3,<2", "scipy>=1.10,<2", "duckdb>=1.1,<2"],
    extras_require={"test": ["pytest>=7,<9"]},
    entry_points={"console_scripts": ["pxadaptive=pxadaptive.cli:main"]},
)
