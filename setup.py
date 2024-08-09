from setuptools import setup, find_packages

setup(
    name='getNmapAndCensysToTable',
    version='1.0.0',
    description='Private package to getNmapAndCensysToTable, a tool to convert Nmap and Censys scans to a table',
    url='git@github.com:JavaliMZ/getNmapAndCensysToTable.git',
    author='Sylvain Júlio',
    author_email='syjulio123@gmail.com',
    license='unlicense',
    packages=find_packages(),  # Automatically finds all packages in the directory
    zip_safe=False,
    install_requires=[
        'tabulate',  # Ensures that the tabulate library is installed
    ],
    entry_points={
        'console_scripts': [
            'getNmapAndCensysToTable=getNmapAndCensysToTable:main'
        ]
    }
)
