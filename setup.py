from setuptools import setup, find_packages

setup(
    name='catNmapAndCensysToTable',
    version='0.0.1',
    description='Private package to catNmapAndCensysToTable, a tool to convert Nmap and Censys scans to a table',
    url='git@github.com:JavaliMZ/catNmapAndCensysToTable.git',
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
            'catNmapAndCensysToTable=catNmapAndCensysToTable:main'
        ]
    }
)
