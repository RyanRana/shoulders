"""
Setup script for AI Security Orchestrator
Production-ready, enterprise-grade AI security package
"""
from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="ai-security-orchestrator",
    version="2.0.0",
    author="Security Team",
    author_email="security@example.com",
    description="Enterprise-grade AI security orchestrator with dynamic threat detection and rerouting",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/yourusername/ai-security-orchestrator",
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Topic :: Security",
        "Topic :: Software Development :: Libraries :: Python Modules",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
    ],
    python_requires=">=3.8",
    install_requires=[
        "fastapi>=0.104.0",
        "uvicorn>=0.24.0",
        "numpy>=1.24.0",
        "scikit-learn>=1.3.0",
        "pydantic>=2.0.0",
        "python-multipart>=0.0.6",
        "httpx>=0.25.0",
        "redis>=5.0.0",  # For distributed monitoring
        "prometheus-client>=0.19.0",  # For metrics
        "colorlog>=6.8.0",  # For beautiful logging
    ],
    extras_require={
        "dev": [
            "pytest>=7.4.0",
            "pytest-asyncio>=0.21.0",
            "pytest-cov>=4.1.0",
            "black>=23.10.0",
            "flake8>=6.1.0",
            "mypy>=1.6.0",
        ],
        "monitoring": [
            "grafana-client>=3.5.0",
            "elasticsearch>=8.10.0",
        ],
        "ml": [
            "transformers>=4.35.0",
            "sentence-transformers>=2.2.0",
            "torch>=2.1.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "ai-security=ai_security_orchestrator.cli:main",
        ],
    },
    include_package_data=True,
    zip_safe=False,
)
