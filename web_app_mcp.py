

from bs4 import BeautifulSoup
import re
import json
import argparse
import logging
from urllib.parse import urlparse, urljoin, parse_qs
import time
from typing import Dict, List, Set, Tuple, Any, Optional
import datetime
import uuid
import sys
from dataclasses import dataclass
from enum import Enum
import requests
import os

# Define enums and data classes
class SecurityContext(Enum):
    SQL = "SQL"
    XSS = "XSS"
    CSRF = "CSRF"
    FILE = "FILE"
    AUTH = "AUTH"
    GENERIC = "GENERIC"

@dataclass
class Parameter:
    name: str
    value: str
    type: str
    context: SecurityContext

class WebAppMCP:
    def __init__(self, target_url: str, output_file: str = "mcp_results.json", delay: float = 0.5):
        self.config = {
            "target_url": target_url,
            "output_file": output_file,
            "delay": delay,
            "max_retries": 3,
            "timeout": 30,
            "headers": {
                "User-Agent": "ModelContextProtocol/1.0",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.5",
                "Accept-Encoding": "gzip, deflate"
            }
        }
        
        self.session = requests.Session()
        self.session.headers.update(self.config["headers"])
        
        # Initialize core components
        self.visited_urls: Set[str] = set()
        self.context_tree: Dict[str, Dict] = {}
        self.parameter_contexts: Dict[str, SecurityContext] = {}
        self.security_findings: List[Dict] = []
        self.forms_data: List[Dict] = []
        
        # Setup logging
        self._setup_logging()

    def _setup_logging(self):
        """Initialize logging configuration"""
        self.logger = logging.getLogger("WebAppMCP")
        self.logger.setLevel(logging.INFO)
        
        handler = logging.StreamHandler()
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)

    def crawl(self, max_pages: int = 100):
        """Main crawling method"""
        self.logger.info(f"Starting crawl of {self.config['target_url']}")
        queue = [self.config["target_url"]]
        
        while queue and len(self.visited_urls) < max_pages:
            current_url = queue.pop(0)
            
            if current_url in self.visited_urls:
                continue
                
            self.logger.info(f"Analyzing {current_url}")
            
            try:
                # Analyze current URL
                context_info = self.analyze_context(current_url)
                self.context_tree[current_url] = context_info
                
                # Make request and extract links
                response = self.session.get(current_url, timeout=self.config["timeout"])
                soup = BeautifulSoup(response.text, 'html.parser')
                
                # Extract forms
                self._extract_forms(soup, current_url)
                
                # Extract and queue new URLs
                for link in soup.find_all('a', href=True):
                    href = urljoin(current_url, link['href'])
                    if self._should_crawl(href):
                        queue.append(href)
                        
                self.visited_urls.add(current_url)
                time.sleep(self.config["delay"])
                
            except Exception as e:
                self.logger.error(f"Error analyzing {current_url}: {str(e)}")

    def _should_crawl(self, url: str) -> bool:
        """Determine if URL should be crawled"""
        parsed = urlparse(url)
        target_parsed = urlparse(self.config["target_url"])
        
        return (
            parsed.netloc == target_parsed.netloc and
            url not in self.visited_urls and
            not url.endswith(('.png', '.jpg', '.gif', '.pdf', '.js', '.css'))
        )

    def _extract_forms(self, soup: BeautifulSoup, url: str):
        """Extract and analyze forms from page"""
        for form in soup.find_all('form'):
            form_data = {
                "action": urljoin(url, form.get('action', '')),
                "method": form.get('method', 'get').upper(),
                "inputs": []
            }
            
            for input_tag in form.find_all(['input', 'textarea', 'select']):
                input_data = {
                    "name": input_tag.get('name', ''),
                    "type": input_tag.get('type', 'text'),
                    "value": input_tag.get('value', ''),
                    "required": input_tag.has_attr('required')
                }
                form_data["inputs"].append(input_data)
            
            self.forms_data.append({
                "page_url": url,
                "form_data": form_data
            })

    def analyze_context(self, url: str, params: Dict = None) -> Dict:
        """Analyze security context of URL and parameters"""
        context_info = {
            "url": url,
            "parameters": [],
            "security_contexts": set(),
            "risks": []
        }

        parsed_url = urlparse(url)
        
        # Analyze path context
        path_context = self._analyze_path_context(parsed_url.path)
        context_info["path_context"] = path_context

        # Analyze query parameters
        if parsed_url.query:
            query_params = parse_qs(parsed_url.query)
            for param_name, param_values in query_params.items():
                param_context = self._analyze_parameter_context(param_name, param_values[0])
                context_info["parameters"].append({
                    "name": param_name,
                    "value": param_values[0],
                    "context": param_context.value,
                    "risks": self._analyze_parameter_risks(param_name, param_values[0], param_context)
                })
                context_info["security_contexts"].add(param_context.value)

        return context_info

    def _analyze_path_context(self, path: str) -> str:
        """Analyze context of URL path"""
        admin_patterns = ['/admin', '/manage', '/dashboard', '/control']
        auth_patterns = ['/login', '/auth', '/signin', '/register']
        data_patterns = ['/api', '/data', '/query', '/search']
        
        path_lower = path.lower()
        
        if any(pattern in path_lower for pattern in admin_patterns):
            return "ADMIN_CONTEXT"
        elif any(pattern in path_lower for pattern in auth_patterns):
            return "AUTH_CONTEXT"
        elif any(pattern in path_lower for pattern in data_patterns):
            return "DATA_CONTEXT"
        
        return "GENERIC_CONTEXT"

    def _analyze_parameter_context(self, name: str, value: str) -> SecurityContext:
        """Analyze security context of parameter"""
        name_lower = name.lower()
        
        if any(pattern in name_lower for pattern in ['id', 'query', 'filter', 'where']):
            return SecurityContext.SQL
        elif any(pattern in value for pattern in ['<', '>', 'script', 'onerror', 'onload']):
            return SecurityContext.XSS
        elif any(pattern in name_lower for pattern in ['file', 'path', 'upload']):
            return SecurityContext.FILE
        elif any(pattern in name_lower for pattern in ['token', 'auth', 'session']):
            return SecurityContext.AUTH
            
        return SecurityContext.GENERIC

    def _analyze_parameter_risks(self, name: str, value: str, context: SecurityContext) -> List[str]:
        """Analyze security risks for parameter"""
        risks = []
        
        if context == SecurityContext.SQL:
            if any(char in value for char in "';\""):
                risks.append("Potential SQL injection")
        elif context == SecurityContext.XSS:
            if any(char in value for char in "<>"):
                risks.append("Potential XSS")
        elif context == SecurityContext.FILE:
            if '../' in value or '..\\' in value:
                risks.append("Potential path traversal")
        elif context == SecurityContext.AUTH:
            if len(value) < 8:
                risks.append("Weak authentication token")
                
        return risks

    def save_results(self):
        """Save analysis results to file"""
        def set_to_list(obj):
            """Convert sets to lists in nested dictionaries"""
            if isinstance(obj, dict):
                return {key: set_to_list(value) for key, value in obj.items()}
            elif isinstance(obj, list):
                return [set_to_list(item) for item in obj]
            elif isinstance(obj, set):
                return list(obj)
            return obj

        results = {
            "target_url": self.config["target_url"],
            "scan_date": datetime.datetime.now().isoformat(),
            "context_tree": set_to_list(self.context_tree),
            "forms_analyzed": self.forms_data,
            "security_findings": self.security_findings,
            "statistics": {
                "urls_visited": len(self.visited_urls),
                "forms_found": len(self.forms_data),
                "security_findings": len(self.security_findings)
            }
        }
    
        with open(self.config["output_file"], 'w') as f:
            json.dump(results, f, indent=2)

    def summarize_findings(self) -> Dict:
        """Generate summary of findings"""
        return {
            "target_url": self.config["target_url"],
            "pages_visited": len(self.visited_urls),
            "forms_found": len(self.forms_data),
            "inputs_analyzed": sum(len(form["form_data"]["inputs"]) for form in self.forms_data),
            "authentication": self._get_auth_info(),
            "potential_edge_cases": self.security_findings,
            "complex_pages": self._get_complex_pages()
        }

    def _get_auth_info(self) -> Dict:
        """Extract authentication information"""
        auth_forms = [f for f in self.forms_data 
                        if any(input_data["type"] == "password" 
                            for input_data in f["form_data"]["inputs"])]
        
        if auth_forms:
            return {
                "login_url": auth_forms[0]["page_url"],
                "auth_type": "form_based"
            }
        return {
            "login_url": None,
            "auth_type": "unknown"
        }

    def _get_complex_pages(self) -> List[Dict]:
        """Identify complex pages based on form count and parameter count"""
        complex_pages = []
        
        for url in self.visited_urls:
            if url in self.context_tree:
                complexity = len(self.context_tree[url]["parameters"])
                if complexity > 5:  # Arbitrary threshold
                    complex_pages.append({
                        "url": url,
                        "complexity": complexity
                    })
        
        return sorted(complex_pages, key=lambda x: x["complexity"], reverse=True)[:5]

def main():
    """Main execution"""
    parser = argparse.ArgumentParser(description="Model Context Protocol Analyzer")
    parser.add_argument("url", help="Target URL to analyze")
    parser.add_argument("--output", "-o", default="mcp_results.json", help="Output file path")
    parser.add_argument("--max-pages", "-m", type=int, default=100, help="Maximum pages to crawl")
    parser.add_argument("--delay", "-d", type=float, default=0.5, help="Delay between requests")
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable verbose logging")
    
    args = parser.parse_args()
    
    try:
        mcp = WebAppMCP(
            target_url=args.url,
            output_file=args.output,
            delay=args.delay
        )
        
        if args.verbose:
            mcp.logger.setLevel(logging.DEBUG)
        
        print(f"\nStarting analysis of {args.url}")
        print("=" * 50)
        
        # Execute crawl and analysis
        mcp.crawl(max_pages=args.max_pages)
        
        # Save and summarize results
        mcp.save_results()
        summary = mcp.summarize_findings()
        
        # Display summary
        print("\n=== Analysis Summary ===")
        print(f"Pages analyzed: {summary['pages_visited']}")
        print(f"Forms discovered: {summary['forms_found']}")
        print(f"Inputs analyzed: {summary['inputs_analyzed']}")
        print(f"Security findings: {len(summary['potential_edge_cases'])}")
        print(f"\nResults saved to: {args.output}")
        
    except KeyboardInterrupt:
        print("\nAnalysis interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\nError during analysis: {str(e)}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()