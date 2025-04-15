from flask import Flask, request, jsonify
import requests
from bs4 import BeautifulSoup
import json
import logging
from urllib.parse import urljoin
from typing import Dict, List, Set, Optional
import datetime
import uuid
# server.py
from fastmcp import FastMCP

# Create an MCP server
mcp = FastMCP("Demo")

# # MCP Tool Decorator
# def mcp_tool(func):
#     """Decorator to register a function as an MCP tool"""
#     def wrapper(*args, **kwargs):
#         print(f"Executing tool: {func.__name__}")
#         return func(*args, **kwargs)
#     return wrapper

class WebAppMCP:
    def __init__(self, target_url: str, output_file: str = "mcp_results.json", delay: float = 0.5):
        """
        Initialize WebAppMCP with FastMCP integration
        """
        self.target_url = target_url
        self.output_file = output_file
        self.delay = delay

        # Initialize FastMCP components
        # self.param_analyzer = ParameterAnalyzer()
        # self.test_gen = TestCaseGenerator()
        # self.context_handler = ContextHandler()

        # Setup logging
        self._setup_logging()

        # Initialize visited URLs and results
        self.visited_urls = set()
        self.results = []

    def _setup_logging(self):
        """Initialize logging configuration"""
        self.logger = logging.getLogger("WebAppMCP")
        self.logger.setLevel(logging.INFO)
        
        handler = logging.StreamHandler()
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)

    @mcp.tool()
    def crawl(self, max_pages: int = 100):
        """Custom crawling logic using requests and BeautifulSoup"""
        self.logger.info(f"Starting crawl of {self.target_url}")
        queue = [self.target_url]

        while queue and len(self.visited_urls) < max_pages:
            current_url = queue.pop(0)

            if current_url in self.visited_urls:
                continue

            self.logger.info(f"Visiting: {current_url}")
            try:
                response = requests.get(current_url, timeout=10)
                soup = BeautifulSoup(response.text, 'html.parser')

                # Analyze the page
                self.analyze_page(current_url, response.text)

                # Extract links and add them to the queue
                for link in soup.find_all('a', href=True):
                    href = urljoin(current_url, link['href'])
                    if href not in self.visited_urls and href.startswith(self.target_url):
                        queue.append(href)

                self.visited_urls.add(current_url)
            except Exception as e:
                self.logger.error(f"Error visiting {current_url}: {e}")

    @mcp.tool()
    def analyze_page(self, url: str, html_content: str):
        """Analyze a page"""
        self.logger.info(f"Analyzing page: {url}")
        params = self.param_analyzer.extract_url_parameters(url)
        test_cases = []

        for param in params:
            context = self.context_handler.detect_context(param.name, param.value)
            test_cases.extend(self.test_gen.generate_for_parameter(
                param_name=param.name,
                param_type=param.type,
                security_context=context
            ))

        self.results.append({
            "url": url,
            "parameters": params,
            "test_cases": test_cases
        })

    @mcp.tool()
    def authenticate(self, username: str, password: str) -> bool:
        """Authenticate with the application"""
        self.logger.info(f"Authenticating with username: {username}")
        # Add authentication logic here
        return True

    @mcp.tool()
    def generate_test_cases(self):
        """Generate test cases"""
        self.logger.info("Generating test cases")
        # Add test case generation logic here
        return {"test_cases": "Generated test cases"}

    @mcp.tool()
    def save_results(self):
        """Save results to a file"""
        self.logger.info(f"Saving results to {self.output_file}")
        with open(self.output_file, 'w') as f:
            json.dump(self.results, f, indent=2)

    @mcp.tool()
    def get_results(self):
        """Retrieve the results"""
        return self.results

# Flask app setup
app = Flask(__name__)
mcp_instance = None

@app.route('/start', methods=['POST'])
def start_crawl():
    """Start the crawling process"""
    global mcp_instance
    data = request.json
    target_url = data.get('target_url')
    output_file = data.get('output_file', 'mcp_results.json')
    max_pages = data.get('max_pages', 100)
    delay = data.get('delay', 0.5)

    if not target_url:
        return jsonify({"error": "target_url is required"}), 400

    # Initialize WebAppMCP
    mcp_instance = WebAppMCP(target_url=target_url, output_file=output_file, delay=delay)
    mcp_instance.crawl(max_pages=max_pages)
    mcp_instance.save_results()

    return jsonify({"message": "Crawling completed", "output_file": output_file})

@app.route('/analyze', methods=['POST'])
def analyze_url():
    """Analyze a specific URL dynamically"""
    global mcp_instance
    if not mcp_instance:
        return jsonify({"error": "MCP instance is not initialized"}), 400

    data = request.json
    url = data.get('url')
    if not url:
        return jsonify({"error": "URL is required"}), 400

    try:
        response = requests.get(url, timeout=10)
        mcp_instance.analyze_page(url, response.text)
        return jsonify({"message": f"URL {url} analyzed successfully"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/results', methods=['GET'])
def get_results():
    """Retrieve the results of the analysis"""
    global mcp_instance
    if not mcp_instance:
        return jsonify({"error": "No analysis has been performed yet"}), 400

    results = mcp_instance.get_results()
    return jsonify(results)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)