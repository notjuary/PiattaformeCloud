from setuptools import setup, find_packages

setup(
    name="ai-security-advisor",
    version="0.1.0",
    packages=find_packages(),
    install_requires=[
        'pandas>=1.5.0',
        'numpy>=1.23.0',
        'scikit-learn>=1.2.0',
        'PyYAML>=6.0',
        'watchdog>=3.0.0',
        'python-keystoneclient>=5.0.0',
        'keystoneauth1>=5.0.0',
    ],
    entry_points={
        'console_scripts': [
            'ai-security-advisor=ai_security_advisor.main:main',
        ],
    },
    author="OpenStack Security Team",
    description="AI Security Advisor per OpenStack Keystone",
    python_requires='>=3.8',
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: Apache Software License",
        "Programming Language :: Python :: 3.8",
        "Topic :: Security",
        "Topic :: System :: Logging",
    ],
)