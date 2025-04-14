# Web Application Penetration Testing MCP

A comprehensive tool for analyzing web applications with a focus on business logic security vulnerabilities. This Master Control Program (MCP) systematically crawls, analyzes, and identifies potential security issues beyond what standard scanners detect.

## Overview

Web Application Penetration Testing MCP helps you understand the business context of web applications by building a complete map of the application structure and identifying potential security weak points, particularly in business logic implementation.

## Key Features

### Comprehensive Discovery
- Automatically builds a tree structure of the entire web application
- Maps all links, forms, and interactive elements
- Identifies input fields with their types and expected values

### Authentication Handling
- Automatically detects login/logout pages
- Can authenticate using credentials to access protected areas
- Supports both cookie-based and bearer token authentication

### Business Logic Analysis
- Identifies potential IDOR (Insecure Direct Object Reference) vulnerabilities
- Detects mathematical/calculation edge cases
- Maps multi-step workflows that could be manipulated
- Discovers permission and access control issues

### Advanced Input Analysis
- Identifies input field types (even when not explicitly defined)
- Generates appropriate test values based on field type
- Detects hidden fields that might contain sensitive values

### Visualization Support
- Creates a visual sitemap using DOT format (viewable with Graphviz)
- Highlights complex pages requiring more attention

## Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/web-app-penetration-testing-mcp.git

# Navigate to the directory
cd web-app-penetration-testing-mcp

# Install dependencies
pip install -r requirements.txt
```

## Usage

### Basic Operation

```bash
# Basic usage
python web_app_mcp.py https://example.com

# With authentication
python web_app_mcp.py https://example.com --username user@example.com --password mysecretpassword

# Create visual sitemap
python web_app_mcp.py https://example.com --visual

# Control crawl speed and depth
python web_app_mcp.py https://example.com --delay 1.0 --max-pages 200
```

### Command Line Arguments

| Argument | Description |
|----------|-------------|
| `url` | Target web application URL (required) |
| `--username` | Username for authenticated scanning |
| `--password` | Password for authenticated scanning |
| `--visual` | Generate visual sitemap in DOT format |
| `--delay` | Delay between requests in seconds (default: 0.5) |
| `--max-pages` | Maximum number of pages to scan (default: 100) |
| `--output` | Output file name (default: mcp_results.json) |
| `--cookies` | Cookie string for authenticated scanning |
| `--headers` | Additional headers in JSON format |

## Output

The tool generates a `mcp_results.json` file containing:

- Complete application structure
- Identified input fields and their types
- Detected authentication mechanisms
- Multi-step workflows
- Potential edge cases and vulnerabilities
- Business logic analysis results

## Workflow for Testing

1. Review the generated `mcp_results.json` file to understand the application structure
2. Focus on the "potential_edge_cases" section for high-value test targets
3. Use the visual sitemap to identify complex areas of the application
4. Leverage the generated test cases to find business logic vulnerabilities

## Example Output

```json
{
  "application_map": {
    "https://example.com/": {
      "type": "page",
      "links": ["https://example.com/login", "https://example.com/about"],
      "forms": []
    },
    "https://example.com/login": {
      "type": "authentication",
      "links": [],
      "forms": [
        {
          "action": "/process-login",
          "method": "POST",
          "inputs": [
            {"name": "username", "type": "email"},
            {"name": "password", "type": "password"}
          ]
        }
      ]
    }
  },
  "potential_edge_cases": [
    {
      "url": "https://example.com/user/profile",
      "type": "IDOR",
      "description": "User ID parameter may allow access to other profiles"
    }
  ]
}
```

## Visualization

When using the `--visual` flag, the tool generates a `sitemap.dot` file that can be converted to an image using Graphviz:

```bash
dot -Tpng sitemap.dot -o sitemap.png
```

## Advanced Usage

### Scanning with Custom Headers

```bash
python web_app_mcp.py https://example.com --headers '{"X-API-Key": "your-api-key"}'
```

### Rate Limited Scanning

```bash
python web_app_mcp.py https://example.com --delay 2.0 --max-pages 50
```

### Focusing on Specific Areas

```bash
python web_app_mcp.py https://example.com/admin --max-depth 3
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details.