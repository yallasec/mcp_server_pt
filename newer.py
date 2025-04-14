from flask import Flask, request, jsonify
from fastmcp import FastMCP
import requests
from bs4 import BeautifulSoup
import json
import logging
import datetime
from urllib.parse import urljoin

class WebAppMCP:
    def __init__(self, target_url: str, output_file: str = "mcp_results.json", delay: float = 0.5):
        """
        Initialize WebAppMCP with FastMCP integration
        """
        self.target_url = target_url
        self.output_file = output_file
        self.delay = delay

        # Initialize FastMCP
        self.fastmcp = FastMCP(target_url=target_url, delay=delay)

        # Setup logging
        self._setup_logging()

        # Initialize visited URLs
        self.visited_urls = set()

        # Initialize results storage
        self.results = []

    def _setup_logging(self):
        """Initialize logging configuration"""
        self.logger = logging.getLogger("WebAppMCP")
        self.logger.setLevel(logging.INFO)
        
        handler = logging.StreamHandler()
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)

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

                # Pass the page content to FastMCP for analysis
                analysis_result = self.fastmcp.analyze_page(current_url, response.text)
                self.results.append(analysis_result)

                # Extract links and add them to the queue
                for link in soup.find_all('a', href=True):
                    href = urljoin(current_url, link['href'])
                    if href not in self.visited_urls and href.startswith(self.target_url):
                        queue.append(href)

                self.visited_urls.add(current_url)
            except Exception as e:
                self.logger.error(f"Error visiting {current_url}: {e}")

    def save_results(self):
        """Save FastMCP results to a file"""
        self.logger.info(f"Saving results to {self.output_file}")
        with open(self.output_file, 'w') as f:
            json.dump(self.results, f, indent=2)

    def get_results(self):
        """Retrieve the results from FastMCP"""
        return self.results

# Flask app setup
app = Flask(__name__)
mcp_instance = None

@app.route('/start', methods=['POST'])
def start_crawl():
    """Start the crawling process using WebAppMCP"""
    global mcp_instance
    data = request.json
    target_url = data.get('target_url')
    output_file = data.get('output_file', 'mcp_results.json')
    max_pages = data.get('max_pages', 100)
    delay = data.get('delay', 0.5)

    if not target_url:
        return jsonify({"error": "target_url is required"}), 400

    # Initialize WebAppMCP with FastMCP
    mcp_instance = WebAppMCP(target_url=target_url, output_file=output_file, delay=delay)
    mcp_instance.crawl(max_pages=max_pages)
    mcp_instance.save_results()

    return jsonify({"message": "Crawling completed", "output_file": output_file})

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