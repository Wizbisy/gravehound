# Contributing to Gravehound 🐾

First off, thank you for considering contributing to Gravehound! Every contribution helps make this tool better for the security community.

## 🚀 How to Contribute

### Reporting Bugs

1. Open an issue on GitHub
2. Include your Python version, OS, and the full error traceback
3. Describe what you expected vs. what happened

### Suggesting Features

1. Open an issue with the `[Feature Request]` tag
2. Describe the feature and why it would be useful
3. If possible, include examples of expected output

### Submitting Code

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/my-new-module`
3. Write your code and tests
4. Ensure your code follows the existing style
5. Submit a Pull Request

## 📦 Adding a New Module

Gravehound is designed to be modular. To add a new recon module:

1. Create a new file in `gravehound/modules/your_module.py`
2. Implement a `run(target: str) -> dict` function
3. Return results in the standard format:

   ```python
   {
       "module": "Your Module Name",
       "target": target,
       "data": {},  # your results
       "errors": [],
   }
   ```

4. Register it in `gravehound/scanner.py` in the `MODULES` dict
5. Add a printer function in `gravehound/reporting/console.py`
6. Add a renderer in `gravehound/reporting/html_report.py`

## ⚖️ Code of Conduct

- Be respectful and constructive
- This tool is for **authorized security testing only**
- Never use Gravehound against targets without permission
- Follow responsible disclosure practices

## 📝 License

By contributing, you agree that your contributions will be licensed under the MIT License.
