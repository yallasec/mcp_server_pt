import requests
from bs4 import BeautifulSoup
import json
import logging
from urllib.parse import urljoin
from typing import Dict, List, Set, Optional, Tuple
import datetime
import uuid
# server.py
from fastmcp import FastMCP
from urllib.parse import urlparse, parse_qs
import time
import re

# Create an MCP server
mcp = FastMCP("Demo1")

class ContextHandler:
    """
    A class for detecting input contexts, possible values, and potential misuse.
    """

    def detect_context(self, param_name: str, param_value: str) -> str:
        """
        Detect the security context of a parameter based on its name and value.

        Args:
            param_name (str): The name of the parameter.
            param_value (str): The value of the parameter.

        Returns:
            str: The detected security context (e.g., "SQL", "XSS", "PATH_TRAVERSAL").
        """
        param_name_lower = param_name.lower()
        param_value_lower = param_value.lower()

        # Detect SQL context
        if any(keyword in param_name_lower for keyword in ["id", "query", "filter", "search"]):
            return "SQL"
        if any(keyword in param_value_lower for keyword in ["'", ";", "--", "select", "union"]):
            return "SQL"

        # Detect XSS context
        if any(keyword in param_name_lower for keyword in ["html", "script", "content"]):
            return "XSS"
        if any(keyword in param_value_lower for keyword in ["<", ">", "script", "onerror", "onload"]):
            return "XSS"

        # Detect Path Traversal context
        if any(keyword in param_name_lower for keyword in ["path", "file", "dir"]):
            return "PATH_TRAVERSAL"
        if "../" in param_value_lower or "..\\" in param_value_lower:
            return "PATH_TRAVERSAL"

        # Detect Command Injection context
        if any(keyword in param_name_lower for keyword in ["cmd", "exec", "run"]):
            return "COMMAND_INJECTION"
        if any(keyword in param_value_lower for keyword in ["|", "&", ";", "$", "`"]):
            return "COMMAND_INJECTION"

        # Default to GENERIC context
        return "GENERIC"

    def detect_possible_values(self, param_name: str) -> List[str]:
        """
        Suggest possible valid values for a parameter based on its name.

        Args:
            param_name (str): The name of the parameter.

        Returns:
            List[str]: A list of possible valid values.
        """
        param_name_lower = param_name.lower()

        # Suggest values for common parameter types
        if "email" in param_name_lower:
            return ["user@example.com", "test@example.com"]
        if "password" in param_name_lower:
            return ["Password123!", "SecurePass!"]
        if "username" in param_name_lower or "user" in param_name_lower:
            return ["admin", "testuser", "guest"]
        if "date" in param_name_lower:
            return [datetime.datetime.now().strftime("%Y-%m-%d")]
        if "id" in param_name_lower:
            return ["1", "123", "456"]
        if "search" in param_name_lower or "query" in param_name_lower:
            return ["test", "example", "sample"]
        if "path" in param_name_lower or "file" in param_name_lower:
            return ["/etc/passwd", "C:\\Windows\\System32\\cmd.exe"]

        # Default to generic values
        return ["test", "example", "123"]

    def detect_misuse(self, param_name: str, param_value: str) -> List[str]:
        """
        Detect potential misuse of a parameter based on its name and value.

        Args:
            param_name (str): The name of the parameter.
            param_value (str): The value of the parameter.

        Returns:
            List[str]: A list of potential misuse scenarios.
        """
        misuse_scenarios = []

        # Check for SQL Injection
        if any(char in param_value for char in ["'", ";", "--", "\""]):
            misuse_scenarios.append("Potential SQL Injection")

        # Check for XSS
        if any(char in param_value for char in ["<", ">", "script", "onerror", "onload"]):
            misuse_scenarios.append("Potential XSS")

        # Check for Path Traversal
        if "../" in param_value or "..\\" in param_value:
            misuse_scenarios.append("Potential Path Traversal")

        # Check for Command Injection
        if any(char in param_value for char in ["|", "&", ";", "$", "`"]):
            misuse_scenarios.append("Potential Command Injection")

        return misuse_scenarios

class TestCaseGenerator:
    """
    A class for generating test cases for various security vulnerabilities.
    """

    def generate_for_parameter(self, param_name: str, param_type: str, security_context: str) -> List[Dict]:
        """
        Generate test cases for a specific parameter based on its type and security context.

        Args:
            param_name (str): The name of the parameter.
            param_type (str): The type of the parameter (e.g., "text", "number").
            security_context (str): The security context (e.g., "SQL", "XSS").

        Returns:
            List[Dict]: A list of test cases.
        """
        test_cases = []

        if security_context == "SQL":
            test_cases.extend(self._generate_sql_injection_tests(param_name))
        elif security_context == "XSS":
            test_cases.extend(self._generate_xss_tests(param_name))
        elif security_context == "COMMAND_INJECTION":
            test_cases.extend(self._generate_command_injection_tests(param_name))
        elif security_context == "PATH_TRAVERSAL":
            test_cases.extend(self._generate_path_traversal_tests(param_name))

        return test_cases

    def _generate_sql_injection_tests(self, param_name: str) -> List[Dict]:
        """
        Generate SQL injection test cases.

        Args:
            param_name (str): The name of the parameter.

        Returns:
            List[Dict]: A list of SQL injection test cases.
        """
        payloads = [
            "' OR 1=1 --",
            "'; DROP TABLE users; --",
            "' UNION SELECT null, null, null --",
            "' AND 'a'='a",
            "' AND 'a'='b"
        ]
        return [{"parameter": param_name, "payload": payload, "type": "SQL Injection"} for payload in payloads]

    def _generate_xss_tests(self, param_name: str) -> List[Dict]:
        """
        Generate XSS test cases.

        Args:
            param_name (str): The name of the parameter.

        Returns:
            List[Dict]: A list of XSS test cases.
        """
        payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "'><script>alert('XSS')</script>",
            "<iframe src=javascript:alert('XSS')>"
        ]
        return [{"parameter": param_name, "payload": payload, "type": "XSS"} for payload in payloads]

    def _generate_command_injection_tests(self, param_name: str) -> List[Dict]:
        """
        Generate command injection test cases.

        Args:
            param_name (str): The name of the parameter.

        Returns:
            List[Dict]: A list of command injection test cases.
        """
        payloads = [
            "ls; cat /etc/passwd",
            "`ls`",
            "$(ls)",
            "| ls",
            "& ls"
        ]
        return [{"parameter": param_name, "payload": payload, "type": "Command Injection"} for payload in payloads]

    def _generate_path_traversal_tests(self, param_name: str) -> List[Dict]:
        """
        Generate path traversal test cases.

        Args:
            param_name (str): The name of the parameter.

        Returns:
            List[Dict]: A list of path traversal test cases.
        """
        payloads = [
            "../etc/passwd",
            "../../etc/passwd",
            "/etc/passwd",
            "..\\..\\windows\\system32\\cmd.exe",
            "..%2f..%2f..%2fetc%2fpasswd"
        ]
        return [{"parameter": param_name, "payload": payload, "type": "Path Traversal"} for payload in payloads]

    def get_generic_test_cases(self) -> List[Dict]:
        """
        Generate generic test cases for common vulnerabilities.

        Returns:
            List[Dict]: A list of generic test cases.
        """
        return [
            {"payload": "<script>alert('XSS')</script>", "type": "XSS"},
            {"payload": "' OR 1=1 --", "type": "SQL Injection"},
            {"payload": "../etc/passwd", "type": "Path Traversal"},
            {"payload": "ls; cat /etc/passwd", "type": "Command Injection"}
        ]

class ParameterAnalyzer:
    """
    A class for analyzing URL and form parameters.
    """

    def extract_url_parameters(self, url: str) -> List[Dict]:
        """
        Extract parameters from a URL query string.

        Args:
            url (str): The URL to analyze.

        Returns:
            List[Dict]: A list of parameter dictionaries with name and value.
        """
        parsed_url = urlparse(url)
        query_params = parse_qs(parsed_url.query)
        parameters = []

        for name, values in query_params.items():
            for value in values:
                parameters.append({
                    "name": name,
                    "value": value
                })

        return parameters

    def extract_form_parameters(self, form_data: Dict) -> List[Dict]:
        """
        Extract parameters from a form's input fields.

        Args:
            form_data (Dict): The form data dictionary.

        Returns:
            List[Dict]: A list of parameter dictionaries with name and value.
        """
        parameters = []

        for input_field in form_data.get("inputs", []):
            name = input_field.get("name")
            value = input_field.get("value", "")
            if name:
                parameters.append({
                    "name": name,
                    "value": value
                })

        return parameters

    def detect_vulnerabilities(self, parameters: List[Dict]) -> List[Dict]:
        """
        Detect potential vulnerabilities in parameters.

        Args:
            parameters (List[Dict]): A list of parameters to analyze.

        Returns:
            List[Dict]: A list of detected vulnerabilities.
        """
        vulnerabilities = []

        for param in parameters:
            name = param["name"]
            value = param["value"]

            # Check for SQL injection patterns
            if any(char in value for char in ["'", ";", "--", "\""]):
                vulnerabilities.append({
                    "parameter": name,
                    "value": value,
                    "vulnerability": "SQL Injection"
                })

            # Check for XSS patterns
            if any(char in value for char in ["<", ">", "script", "onerror", "onload"]):
                vulnerabilities.append({
                    "parameter": name,
                    "value": value,
                    "vulnerability": "XSS"
                })

            # Check for path traversal
            if "../" in value or "..\\" in value:
                vulnerabilities.append({
                    "parameter": name,
                    "value": value,
                    "vulnerability": "Path Traversal"
                })

            # Check for command injection
            if any(char in value for char in ["|", "&", ";", "$", "`"]):
                vulnerabilities.append({
                    "parameter": name,
                    "value": value,
                    "vulnerability": "Command Injection"
                })

        return vulnerabilities

target_url = 'https://example.com'
output_file = 'mcp_results.json'
delay = 0.5
"""
Enhanced initialization with better configuration management
"""
config = {
    "target_url": target_url,
    "output_file": output_file,
    "delay": delay,
    "max_retries": 3,
    "timeout": 30,
    "user_agent": "WebAppMCP/1.0",
    "headers": {
        "User-Agent": "WebAppMCP/1.0",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Accept-Encoding": "gzip, deflate",
        "Connection": "keep-alive",
        "DNT": "1"
    }
}

session = requests.Session()
session.headers.update(config["headers"])

# Initialize fastmcp components
param_analyzer = ParameterAnalyzer()
test_gen = TestCaseGenerator()
context_handler = ContextHandler()

# # Enhanced logging setup
# _setup_logging()
"""
Initialize the Master Control Program for web application testing

Args:
    target_url: The base URL of the target web application
    output_file: File to save the results
    delay: Delay between requests in seconds to avoid overwhelming the server
"""
target_url = target_url
output_file = output_file
delay = delay
session = requests.Session()
visited_urls: Set[str] = set()
pages_tree = {}
forms_data = []
inputs_data = []
auth_info = {
    "login_url": None,
    "logout_url": None,
    "authenticated": False,
    "auth_type": None,  # "cookie" or "bearer"
    "auth_data": None
}
potential_edge_cases = []

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("mcp_log.txt"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("WebAppMCP")

# Common input patterns for detection
input_patterns = {
    "email": r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
    "phone": r'\d{10,15}',
    "date": r'\d{4}-\d{2}-\d{2}',
    "credit_card": r'\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}',
    "uuid": r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',
    "username": r'^[a-zA-Z0-9_]{3,20}$',
    "password": r'.{8,}',
    "zip_code": r'\d{5}(?:-\d{4})?',
    "ip_address": r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
}

# Sample values for different input types
input_samples = {
    "text": "Sample Text",
    "email": "user@example.com",
    "password": "SecurePassword123!",
    "number": "12345",
    "tel": "1234567890",
    "date": datetime.datetime.now().strftime("%Y-%m-%d"),
    "datetime-local": datetime.datetime.now().strftime("%Y-%m-%dT%H:%M"),
    "month": datetime.datetime.now().strftime("%Y-%m"),
    "week": datetime.datetime.now().strftime("%Y-W%W"),
    "time": datetime.datetime.now().strftime("%H:%M"),
    "url": "https://example.com",
    "search": "search query",
    "uuid": str(uuid.uuid4()),
    "file": None,  # Will be handled separately
    "hidden": "hidden_value",
    "checkbox": "on",
    "radio": "option1",
    "select": None  # Will be determined from options
}

def _make_request( url: str, method: str = "GET", data: Dict = None, headers: Dict = None) -> Tuple[requests.Response, Optional[BeautifulSoup]]:
    """
    Enhanced request handling with retry logic and better error handling
    """
    if headers:
        request_headers = {**config["headers"], **headers}
    else:
        request_headers = config["headers"]

    for attempt in range(config["max_retries"]):
        try:
            time.sleep(delay)
            
            if method.upper() == "GET":
                response = session.get(
                    url, 
                    headers=request_headers,
                    timeout=config["timeout"],
                    allow_redirects=True
                )
            elif method.upper() == "POST":
                response = session.post(
                    url, 
                    data=data,
                    headers=request_headers,
                    timeout=config["timeout"],
                    allow_redirects=True
                )
            else:
                logger.error(f"Unsupported HTTP method: {method}")
                return None, None

            # Check response validity
            response.raise_for_status()
            
            # Process response
            if 'text/html' in response.headers.get('Content-Type', ''):
                soup = BeautifulSoup(response.text, 'html.parser')
                return response, soup
            else:
                return response, None

        except requests.exceptions.RequestException as e:
            logger.warning(f"Request attempt {attempt + 1} failed for {url}: {str(e)}")
            if attempt == config["max_retries"] - 1:
                logger.error(f"All retry attempts failed for {url}")
                return None, None
            time.sleep(2 ** attempt)  # Exponential backoff

def normalize_url( url: str) -> str:
    """
    Normalize URL to prevent visiting the same page with different parameters
    """
    parsed = urlparse(url)
    return f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

def is_same_domain(target_url,url: str) -> bool:
    target_domain = urlparse(target_url).netloc
    url_domain = urlparse(url).netloc
    return url_domain == target_domain or url_domain.endswith('.' + target_domain)

@mcp.tool()
def crawl(max_pages: int = 100, url: str = None) -> str:
    """
    Crawl the web application to discover pages and build the tree.
    """
    target_url = url or config["target_url"]
    logger.info(f"Starting crawl of {target_url}")
    queue = [target_url]

    while queue and len(visited_urls) < max_pages:
        current_url = queue.pop(0)
        normalized_url = normalize_url(current_url)

        if normalized_url in visited_urls:
            logger.info(f"Skipping already visited URL: {normalized_url}")
            continue

        logger.info(f"Crawling {current_url}")
        response, soup = _make_request(current_url)

        if not soup:
            logger.warning(f"No valid HTML content at {current_url}")
            continue

        visited_urls.add(normalized_url)

        # Extract page details
        title = soup.title.text.strip() if soup.title else "No Title"
        pages_tree[normalized_url] = {
            "title": title,
            "links": [],
            "forms": [],
            "buttons": []
        }

        # Extract links
        for link in soup.find_all('a', href=True):
            href = link.get('href')
            if not href or href.startswith('#') or href.startswith('javascript:'):
                continue

            absolute_url = urljoin(current_url, href)
            if is_same_domain(target_url,absolute_url) and absolute_url not in visited_urls:
                logger.info(f"Adding URL to queue: {absolute_url}")
                queue.append(absolute_url)
                pages_tree[normalized_url]["links"].append({
                    "url": absolute_url,
                    "text": link.text.strip() or "No Text"
                })

        # Extract forms
        _extract_forms(soup, current_url)

        # Extract buttons (that aren't in forms)
        for button in soup.find_all('button'):
            if not button.find_parent('form'):
                button_text = button.text.strip() or "No Text"
                button_id = button.get('id', '')
                button_class = button.get('class', '')
                pages_tree[normalized_url]["buttons"].append({
                    "text": button_text,
                    "id": button_id,
                    "class": button_class
                })

    logger.info(f"Crawl completed. Visited {len(visited_urls)} pages.")
    return str(visited_urls)

@mcp.tool()
def _extract_forms(soup, page_url: str) -> str:
    """
    Extract form details from a page
    """
    if soup is None:
        response, soup = _make_request(page_url)
    forms = soup.find_all('form')
    page_forms = []

    for form in forms:
        form_action = form.get('action', '')
        form_method = form.get('method', 'get').lower()
        form_id = form.get('id', '')
        form_name = form.get('name', '')
        
        # Determine the absolute form submission URL
        form_url = urljoin(page_url, form_action) if form_action else page_url
        
        # Extract form inputs
        inputs = []
        for input_tag in form.find_all(['input', 'textarea', 'select']):
            input_data = _analyze_input(input_tag)
            if input_data:
                inputs.append(input_data)
                inputs_data.append({
                    "page_url": page_url,
                    "form_url": form_url,
                    "form_id": form_id,
                    "input_data": input_data
                })
        
        # Add buttons within the form
        for button in form.find_all('button'):
            button_type = button.get('type', 'submit')
            button_name = button.get('name', '')
            button_value = button.get('value', '')
            button_text = button.text.strip() or "No Text"
            
            inputs.append({
                "type": "button",
                "html_type": button_type,
                "name": button_name,
                "value": button_value,
                "text": button_text
            })
        
        form_data = {
            "action": form_url,
            "method": form_method,
            "id": form_id,
            "name": form_name,
            "inputs": inputs
        }
        
        page_forms.append(form_data)
        forms_data.append({
            "page_url": page_url,
            "form_data": form_data
        })
        
        # Add to page tree
        normalized_url = normalize_url(page_url)
        if normalized_url in pages_tree:
            pages_tree[normalized_url]["forms"].append(form_data)
        
    return str(pages_tree[normalized_url]["forms"])

def _analyze_input( input_tag) -> Dict:
    """
    Analyze an input element and determine its type and properties
    """
    tag_type = input_tag.name

    if tag_type == 'input':
        input_type = input_tag.get('type', 'text')
        input_name = input_tag.get('name', '')
        input_id = input_tag.get('id', '')
        input_placeholder = input_tag.get('placeholder', '')
        input_required = input_tag.has_attr('required')
        input_pattern = input_tag.get('pattern', '')
        input_min = input_tag.get('min', '')
        input_max = input_tag.get('max', '')
        
        return {
            "name": input_name,
            "id": input_id,
            "type": "input",
            "html_type": input_type,
            "placeholder": input_placeholder,
            "required": input_required,
            "pattern": input_pattern,
            "min": input_min,
            "max": input_max,
            "inferred_type": _infer_input_type(input_name, input_type, input_placeholder, input_pattern)
        }
        
    elif tag_type == 'textarea':
        input_name = input_tag.get('name', '')
        input_id = input_tag.get('id', '')
        input_placeholder = input_tag.get('placeholder', '')
        input_required = input_tag.has_attr('required')
        
        return {
            "name": input_name,
            "id": input_id,
            "type": "textarea",
            "html_type": "textarea",
            "placeholder": input_placeholder,
            "required": input_required,
            "inferred_type": "text"
        }
        
    elif tag_type == 'select':
        input_name = input_tag.get('name', '')
        input_id = input_tag.get('id', '')
        input_required = input_tag.has_attr('required')
        options = []
        
        for option in input_tag.find_all('option'):
            option_value = option.get('value', '')
            option_text = option.text.strip()
            options.append({
                "value": option_value,
                "text": option_text
            })
        
        return {
            "name": input_name,
            "id": input_id,
            "type": "select",
            "html_type": "select",
            "required": input_required,
            "options": options,
            "inferred_type": "choice"
        }

    return None

def _analyze_parameters( url: str, form_data: Optional[Dict] = None) -> Dict:
    """
    Enhanced parameter analysis with context detection and vulnerability patterns
    """
    results = {
        "url_parameters": [],
        "form_parameters": [],
        "contexts": set(),
        "potential_vulnerabilities": []
    }

    # Analyze URL parameters
    if '?' in url:
        params = param_analyzer.extract_url_parameters(url)
        for param in params:
            context = context_handler.detect_context(param.name, param.value)
            vuln_patterns = _check_vulnerability_patterns(param.name, param.value)
            
            results["url_parameters"].append({
                "name": param.name,
                "value": param.value,
                "type": param.type.value,
                "context": context.value,
                "potential_vulnerabilities": vuln_patterns
            })
            results["contexts"].add(context.value)

    # Analyze form parameters if provided
    if form_data:
        form_params = param_analyzer.extract_form_parameters(form_data)
        for param in form_params:
            context = context_handler.detect_context(param.name, param.value)
            vuln_patterns = _check_vulnerability_patterns(param.name, param.value)
            
            results["form_parameters"].append({
                "name": param.name,
                "value": param.value,
                "type": param.type.value,
                "context": context.value,
                "potential_vulnerabilities": vuln_patterns
            })
            results["contexts"].add(context.value)

    return results

def _check_vulnerability_patterns( param_name: str, param_value: str) -> List[str]:
    """
    Check parameters for common vulnerability patterns
    """
    patterns = []

    # SQL Injection patterns
    if any(char in param_value for char in "';\""):
        patterns.append("SQL_INJECTION")

    # XSS patterns
    if any(char in param_value for char in "<>"):
        patterns.append("XSS")

    # Path traversal
    if "../" in param_value or "..\\\\" in param_value:
        patterns.append("PATH_TRAVERSAL")

    # Command injection
    if any(char in param_value for char in "|;&$"):
        patterns.append("COMMAND_INJECTION")

    return patterns

def _infer_input_type( name: str, html_type: str, placeholder: str, pattern: str) -> str:
    """
    Infer the semantic type of an input field based on its attributes
    """
    name_lower = name.lower()
    placeholder_lower = placeholder.lower()

    # First check HTML type which is the most reliable
    if html_type in ['email', 'password', 'number', 'tel', 'date', 'datetime-local', 
                        'month', 'week', 'time', 'url', 'file', 'hidden', 'checkbox', 'radio']:
        return html_type

    # Check for common field name patterns
    if any(word in name_lower for word in ['email', 'e-mail']):
        return 'email'
    elif any(word in name_lower for word in ['password', 'passwd', 'pwd']):
        return 'password'
    elif any(word in name_lower for word in ['phone', 'tel', 'mobile', 'cell']):
        return 'tel'
    elif any(word in name_lower for word in ['date', 'dob', 'birthday']):
        return 'date'
    elif any(word in name_lower for word in ['time']):
        return 'time'
    elif any(word in name_lower for word in ['url', 'website', 'link']):
        return 'url'
    elif any(word in name_lower for word in ['file', 'upload', 'attachment']):
        return 'file'
    elif any(word in name_lower for word in ['price', 'cost', 'amount', 'quantity', 'qty', 'num']):
        return 'number'
    elif any(word in name_lower for word in ['username', 'user', 'login']):
        return 'username'
    elif any(word in name_lower for word in ['zip', 'postal']):
        return 'zip_code'
    elif any(word in name_lower for word in ['uuid', 'guid']):
        return 'uuid'
    elif any(word in name_lower for word in ['search', 'query']):
        return 'search'
    elif any(word in name_lower for word in ['cc', 'creditcard', 'credit-card', 'card']):
        return 'credit_card'

    # Check placeholder text for clues
    if placeholder:
        if any(word in placeholder_lower for word in ['email', 'e-mail']):
            return 'email'
        elif any(word in placeholder_lower for word in ['password']):
            return 'password'
        elif any(word in placeholder_lower for word in ['phone', 'tel']):
            return 'tel'
        elif re.search(r'\d{1,2}[-/]\d{1,2}[-/]\d{2,4}', placeholder_lower):
            return 'date'
        elif re.search(r'\d+', placeholder_lower) and any(word in placeholder_lower for word in ['price', 'cost', 'amount']):
            return 'number'

    # Check if pattern attribute gives any clues
    if pattern:
        for type_name, regex in input_patterns.items():
            if re.search(regex, pattern):
                return type_name

    # Default to text if we can't determine the type
    return 'text'

def _is_login_page( soup: BeautifulSoup, url: str) -> bool:
    """
    Determine if a page might be a login page
    """
    # Check URL for login indicators
    url_lower = url.lower()
    if any(word in url_lower for word in ['login', 'signin', 'sign-in', 'auth']):
        return True

    # Check for login form indicators
    forms = soup.find_all('form')
    for form in forms:
        form_action = form.get('action', '').lower()
        if any(word in form_action for word in ['login', 'signin', 'auth']):
            return True
        
        # Check if form contains password input
        has_password = False
        has_username = False
        
        for input_tag in form.find_all('input'):
            input_type = input_tag.get('type', '').lower()
            input_name = input_tag.get('name', '').lower()
            
            if input_type == 'password':
                has_password = True
            elif any(word in input_name for word in ['user', 'email', 'login', 'username']):
                has_username = True
        
        if has_password and has_username:
            return True

    # Check for common login page text
    page_text = soup.get_text().lower()
    login_phrases = ['log in', 'sign in', 'login', 'signin', 'username', 'password']
    if any(phrase in page_text for phrase in login_phrases):
        form_count = len(forms)
        password_inputs = len(soup.find_all('input', {'type': 'password'}))
        if form_count > 0 and password_inputs > 0:
            return True

    return False

def _is_logout_page( soup: BeautifulSoup, url: str) -> bool:
    """
    Determine if a page or link might be related to logout functionality
    """
    # Check URL for logout indicators
    url_lower = url.lower()
    if any(word in url_lower for word in ['logout', 'signout', 'sign-out']):
        return True

    # Check for logout links
    for link in soup.find_all('a', href=True):
        href = link.get('href', '').lower()
        link_text = link.text.strip().lower()
        
        if any(word in href for word in ['logout', 'signout', 'sign-out']):
            return True
        if any(word in link_text for word in ['logout', 'log out', 'sign out', 'signout']):
            return True

    # Check for logout buttons
    for button in soup.find_all('button'):
        button_text = button.text.strip().lower()
        if any(word in button_text for word in ['logout', 'log out', 'sign out', 'signout']):
            return True

    return False

def authenticate( username: str, password: str) -> bool:
    """
    Attempt to authenticate with the application
    """
    if not auth_info["login_url"]:
        logger.error("No login URL found. Run crawl() first.")
        return False

    login_url = auth_info["login_url"]
    logger.info(f"Attempting to authenticate at {login_url}")

    # Get the login page to analyze the form
    response, soup = _make_request(login_url)
    if not soup:
        logger.error("Could not access login page")
        return False

    # Find the login form
    login_form = None
    for form in soup.find_all('form'):
        has_password = False
        for input_tag in form.find_all('input'):
            if input_tag.get('type') == 'password':
                has_password = True
                break
        
        if has_password:
            login_form = form
            break

    if not login_form:
        logger.error("Could not find login form")
        return False

    # Prepare login data
    login_data = {}
    username_field = None
    password_field = None

    for input_tag in login_form.find_all('input'):
        input_type = input_tag.get('type', '')
        input_name = input_tag.get('name', '')
        
        if input_type == 'password' and input_name:
            password_field = input_name
        elif input_type == 'text' or input_type == 'email':
            if input_name:
                username_field = input_name
        
        # Include all hidden fields
        if input_type == 'hidden' and input_name:
            login_data[input_name] = input_tag.get('value', '')

    if not username_field or not password_field:
        logger.error("Could not identify username or password fields")
        return False

    login_data[username_field] = username
    login_data[password_field] = password

    # Submit the login form
    form_action = login_form.get('action', '')
    form_method = login_form.get('method', 'post').lower()
    form_url = urljoin(login_url, form_action) if form_action else login_url

    response, _ = _make_request(form_url, method=form_method, data=login_data)
    if not response:
        logger.error("Login request failed")
        return False

    # Check if authentication was successful
    if response.url != login_url and response.status_code == 200:
        auth_info["authenticated"] = True
        
        # Determine authentication type
        if 'Authorization' in session.headers and 'Bearer' in session.headers['Authorization']:
            auth_info["auth_type"] = "bearer"
            auth_info["auth_data"] = session.headers['Authorization']
        else:
            auth_info["auth_type"] = "cookie"
            auth_info["auth_data"] = dict(session.cookies)
        
        logger.info(f"Authentication successful using {auth_info['auth_type']}")
        return True
    else:
        logger.error("Authentication failed")
        return False

def _analyze_test_coverage( test_suites: Dict) -> Dict:
    """
    Analyze test coverage metrics
    """
    coverage = {
        "total_test_cases": sum(len(suite) for suite in test_suites.values()),
        "coverage_by_category": {},
        "untested_components": [],
        "risk_areas": []
    }

    # Calculate coverage metrics
    for category, suite in test_suites.items():
        coverage["coverage_by_category"][category] = {
            "test_count": len(suite),
            "coverage_percentage": _calculate_coverage_percentage(category, suite)
        }

    return coverage

def _handle_security_context(self, context_type: str, data: Dict) -> Dict:
    """
    Enhanced security context handling with advanced detection and validation
    """
    context_handlers = {
        "SQL": _handle_sql_context,
        "XSS": _handle_xss_context,
        "CSRF": _handle_csrf_context,
        "FILE": _handle_file_context,
        "AUTH": _handle_auth_context
    }

    handler = context_handlers.get(context_type.upper())
    if handler:
        return handler(data)

    return _handle_generic_context(data)

def _handle_sql_context(self, data: Dict) -> Dict:
    """
    Handle SQL injection context
    """
    return {
        "context": "SQL",
        "risk_level": "HIGH",
        "validation_required": True,
        "sanitization_rules": [
            "Parameterize queries",
            "Escape special characters",
            "Use prepared statements"
        ],
        "test_cases": _generate_sql_injection_tests(data)
    }


def generate_test_cases(self):
    """
    Enhanced test case generation with broader coverage and smarter analysis
    """
    logger.info("Generating comprehensive test cases")

    test_suites = {
        "authentication": _generate_auth_test_cases(),
        "authorization": _generate_permission_test_cases(),
        "input_validation": _generate_input_validation_cases(),
        "business_logic": _generate_business_logic_cases(),
        "session_management": _generate_session_test_cases(),
        "api_security": _generate_api_test_cases()
    }

    # Analyze test coverage
    coverage_metrics = _analyze_test_coverage(test_suites)

    # Generate test execution plan
    execution_plan = _create_test_execution_plan(test_suites)

    return {
        "test_suites": test_suites,
        "coverage_metrics": coverage_metrics,
        "execution_plan": execution_plan
    }


def _generate_idor_test_cases(self):
    """
    Generate test cases for Insecure Direct Object References
    """
    # Look for URLs with numeric IDs
    id_patterns = [
        r'/(\d+)/?$',  # /123/
        r'/[^/]+/(\d+)/?$',  # /resource/123/
        r'[?&]id=(\d+)',  # ?id=123
        r'[?&][^=]+=(\d+)',  # ?user_id=123
        r'/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})/?$'  # UUIDs
    ]

    idor_opportunities = []

    for url in visited_urls:
        for pattern in id_patterns:
            matches = re.findall(pattern, url)
            if matches:
                for match in matches:
                    idor_opportunities.append({
                        "url": url,
                        "id_value": match,
                        "pattern": pattern
                    })

    if idor_opportunities:
        potential_edge_cases.append({
            "category": "IDOR (Insecure Direct Object References)",
            "description": "These URLs contain IDs that might be manipulated to access unauthorized resources",
            "opportunities": idor_opportunities,
            "test_suggestions": [
                "Change numeric IDs to access other users' data",
                "Try sequential IDs (increment/decrement)",
                "Use completely different UUIDs",
                "Test with IDs belonging to other roles"
            ]
        })

def _generate_math_test_cases(self):
    """
    Generate test cases for mathematical or calculation bugs
    """
    calculation_forms = []

    # Look for forms with multiple number
    # IDOR test cases
    _generate_idor_test_cases()

    # Mathematical/Calculation bugs
    _generate_math_test_cases()

    # Workflow/State test cases
    _generate_workflow_test_cases()

    # Permission test cases
    _generate_permission_test_cases()

    # # Parameter manipulation test cases
    # _generate_parameter_ inputs and possible calculations

    for form_data in forms_data:
        number_inputs = 0
        price_inputs = 0
        quantity_inputs = 0
        
        for input_data in form_data["form_data"]["inputs"]:
            if input_data.get("html_type") == "number" or input_data.get("inferred_type") == "number":
                number_inputs += 1
                
                input_name = input_data.get("name", "").lower()
                if any(term in input_name for term in ["price", "cost", "amount"]):
                    price_inputs += 1
                if any(term in input_name for term in ["qty", "quantity", "count"]):
                    quantity_inputs += 1
        
        if number_inputs >= 2 or (price_inputs > 0 and quantity_inputs > 0):
            calculation_forms.append({
                "page_url": form_data["page_url"],
                "form_action": form_data["form_data"]["action"],
                "inputs": [input_data for input_data in form_data["form_data"]["inputs"] 
                            if input_data.get("html_type") == "number" or input_data.get("inferred_type") == "number"]
            })

    if calculation_forms:
        potential_edge_cases.append({
            "category": "Mathematical/Calculation Bugs",
            "description": "These forms may involve calculations that could be manipulated",
            "opportunities": calculation_forms,
            "test_suggestions": [
                "Test with negative numbers",
                "Test with extremely large numbers",
                "Test with zero values",
                "Test with fractional values (e.g., 0.1)",
                "Test with multiple decimal places (e.g., 10.99999)",
                "Test discount/promotion code logic",
                "Check if calculations are properly rounded",
                "Verify tax calculations"
            ]
        })

def _generate_workflow_test_cases(self):
    """
    Generate test cases for workflow and state manipulation
    """
    # Identify multi-step processes
    potential_workflows = []

    # Look for numbered steps in URLs or page titles
    step_patterns = [
        r'step[_-]?(\d+)',
        r'page[_-]?(\d+)',
        r'/wizard/',
        r'/checkout/',
        r'/registration/',
        r'/onboarding/'
    ]

    workflow_pages = {}

    for url, page_data in pages_tree.items():
        for pattern in step_patterns:
            if re.search(pattern, url, re.IGNORECASE) or re.search(pattern, page_data["title"], re.IGNORECASE):
                # Extract workflow name - try to get the part before step/page indicator
                url_parts = url.split('/')
                workflow_name = "unknown"
                
                for part in url_parts:
                    if re.search(r'checkout|wizard|registration|onboarding', part, re.IGNORECASE):
                        workflow_name = part
                        break
                
                if workflow_name not in workflow_pages:
                    workflow_pages[workflow_name] = []
                
                workflow_pages[workflow_name].append({
                    "url": url,
                    "title": page_data["title"]
                })

    # Add multi-step workflows to test cases
    for workflow_name, pages in workflow_pages.items():
        if len(pages) > 1:
            potential_workflows.append({
                "workflow_name": workflow_name,
                "pages": pages
            })

    if potential_workflows:
        potential_edge_cases.append({
            "category": "Workflow/State Manipulation",
            "description": "These appear to be multi-step processes that could have state manipulation issues",
            "opportunities": potential_workflows,
            "test_suggestions": [
                "Skip steps by directly accessing later URLs",
                "Go back and modify previous inputs",
                "Submit forms out of sequence",
                "Use browser back button and resubmit with changes",
                "Test parallel sessions with the same user",
                "Modify hidden state parameters",
                "Complete process with missing required fields"
            ]
        })

def _generate_permission_test_cases(self):
    """
    Generate test cases for permission and access control issues
    """
    admin_pages = []
    sensitive_actions = []

    # Look for admin or management pages
    admin_patterns = [
        r'/admin',
        r'/manage',
        r'/dashboard',
        r'/settings',
        r'/control',
        r'/profile',
        r'/account'
    ]

    for url in visited_urls:
        for pattern in admin_patterns:
            if re.search(pattern, url, re.IGNORECASE):
                admin_pages.append(url)
                break

    # Look for sensitive actions in forms
    sensitive_actions_keywords = ['delete', 'remove', 'update', 'edit', 'modify', 'change', 'add', 'create', 'grant']

    for form_data in forms_data:
        form_action = form_data["form_data"]["action"].lower()
        
        for keyword in sensitive_actions_keywords:
            if keyword in form_action:
                sensitive_actions.append({
                    "page_url": form_data["page_url"],
                    "form_action": form_data["form_data"]["action"],
                    "method": form_data["form_data"]["method"]
                })
                break

    if admin_pages or sensitive_actions:
        potential_edge_cases.append({
            "category": "Permission and Access Control Issues",
            "description": "These pages and actions should be tested for proper access control",
            "opportunities": {
                "admin_pages": admin_pages,
                "sensitive_actions": sensitive_actions
            },
            "test_suggestions": [
                "Access admin pages as a regular user",
                "Modify admin parameters in request URLs",
                "Access sensitive functions directly via URLs",
                "Test horizontal access control (accessing other users' data)",
                "Test vertical access control (accessing higher privilege actions)",
                "Test with session tokens of different user roles"
            ]
        })

def _generate_parameter_manipulation_test_cases(self):
    """
    Generate test cases for parameter manipulation using fastmcp
    """
    # Initialize fastmcp components
    param_analyzer = ParameterAnalyzer()
    test_gen = TestCaseGenerator()
    context_handler = ContextHandler()

    analyzed_params = []

    # Analyze URL parameters
    for url in visited_urls:
        if '?' in url:
            params = param_analyzer.extract_url_parameters(url)
            for param in params:
                context = context_handler.detect_context(param.name, param.value)
                test_cases = test_gen.generate_for_parameter(
                    param_name=param.name,
                    param_type=param.type,
                    security_context=context
                )
                analyzed_params.append({
                    "url": url,
                    "parameter": param.name,
                    "type": param.type.value,
                    "context": context.value,
                    "test_cases": test_cases
                })

    # Analyze form parameters
    for form_data in forms_data:
        form_params = param_analyzer.extract_form_parameters(form_data["form_data"])
        for param in form_params:
            context = context_handler.detect_context(param.name, param.value)
            test_cases = test_gen.generate_for_parameter(
                param_name=param.name,
                param_type=param.type,
                security_context=context
            )
            analyzed_params.append({
                "page_url": form_data["page_url"],
                "form_action": form_data["form_data"]["action"],
                "parameter": param.name,
                "type": param.type.value,
                "context": context.value,
                "test_cases": test_cases
            })

    # Group findings by security context
    context_groups = {}
    for param in analyzed_params:
        context = param["context"]
        if context not in context_groups:
            context_groups[context] = []
        context_groups[context].append(param)

    # Add findings to potential edge cases
    potential_edge_cases.append({
        "category": "Parameter Manipulation",
        "description": "Parameters analyzed using fastmcp for potential security issues",
        "opportunities": {
            "analyzed_parameters": analyzed_params,
            "context_groups": context_groups
        },
        "test_suggestions": test_gen.get_generic_test_cases(),
        "metadata": {
            "total_params": len(analyzed_params),
            "contexts_found": list(context_groups.keys()),
            "analysis_timestamp": datetime.datetime.now().isoformat()
        }
    })

    logger.info(f"Generated test cases for {len(analyzed_params)} parameters across {len(context_groups)} security contexts")

def _generate_replay_attack_test_cases(self):
    """
    Generate test cases for replay attacks
    """
    sensitive_forms = []

    # Look for forms that might involve sensitive operations
    sensitive_keywords = ['payment', 'transfer', 'checkout', 'purchase', 'order', 'delete', 'update', 'submit']

    for form_data in forms_data:
        form_action = form_data["form_data"]["action"].lower()
        page_url = form_data["page_url"].lower()
        
        if any(keyword in form_action for keyword in sensitive_keywords) or any(keyword in page_url for keyword in sensitive_keywords):
            sensitive_forms.append({
                "page_url": form_data["page_url"],
                "form_action": form_data["form_data"]["action"],
                "method": form_data["form_data"]["method"]
            })

    if sensitive_forms:
        potential_edge_cases.append({
            "category": "Replay Attacks",
            "description": "These forms handle sensitive operations and should be tested for replay vulnerabilities",
            "opportunities": sensitive_forms,
            "test_suggestions": [
                "Capture and replay form submissions",
                "Check for missing CSRF tokens",
                "Submit the same form multiple times",
                "Submit stale/expired forms",
                "Test if transaction IDs or nonces are validated",
                "Replay authenticated requests after logout"
            ]
        })

def generate_valid_inputs(self, form_data):
    """
    Generate valid inputs for a form based on input types
    """
    input_values = {}

    for input_field in form_data["inputs"]:
        field_name = input_field.get("name", "")
        html_type = input_field.get("html_type", "text")
        inferred_type = input_field.get("inferred_type", "text")
        
        if not field_name:
            continue
            
        # Skip submit buttons
        if html_type == "submit" or html_type == "button":
            continue
        
        # Handle checkbox and radio differently
        if html_type == "checkbox":
            input_values[field_name] = "on"
            continue
            
        if html_type == "radio":
            input_values[field_name] = input_field.get("value", "on")
            continue
        
        # For select, use the first option value
        if input_field.get("type") == "select" and "options" in input_field and input_field["options"]:
            input_values[field_name] = input_field["options"][0]["value"]
            continue
        
        # For other types, use sample values
        if inferred_type in input_samples:
            input_values[field_name] = input_samples[inferred_type]
        else:
            input_values[field_name] = input_samples["text"]

    return input_values



def create_user_flows(self):
    """
    Identify potential user flows through the application
    """
    logger.info("Creating potential user flows")

    # Start with the base page or login if available
    starting_points = []

    if auth_info["login_url"]:
        starting_points.append(auth_info["login_url"])
    else:
        starting_points.append(target_url)

    flows = []

    for start_point in starting_points:
        # Simple flow: just follow links in levels
        # Level 1: Start -> Any page directly linked
        level1_links = []
        
        start_normalized = normalize_url(start_point)
        if start_normalized in pages_tree:
            for link in pages_tree[start_normalized]["links"]:
                level1_links.append({
                    "from": start_point,
                    "to": link["url"],
                    "text": link["text"]
                })
        
        # Level 2: Follow links from level 1
        level2_links = []
        
        for l1_link in level1_links:
            l1_normalized = normalize_url(l1_link["to"])
            if l1_normalized in pages_tree:
                for link in pages_tree[l1_normalized]["links"]:
                    level2_links.append({
                        "from": l1_link["to"],
                        "to": link["url"],
                        "text": link["text"]
                    })
        
        flows.append({
            "start": start_point,
            "level1_links": level1_links,
            "level2_links": level2_links
        })

    # Identify forms completion flows
    form_flows = []

    for form_data in forms_data:
        page_url = form_data["page_url"]
        form = form_data["form_data"]
        
        # Generate valid inputs for this form
        inputs = generate_valid_inputs(form)
        
        form_flows.append({
            "page_url": page_url,
            "form_action": form["action"],
            "method": form["method"],
            "inputs": inputs
        })

    return {
        "navigation_flows": flows,
        "form_flows": form_flows
    }

def summarize_findings(self):
    """
    Create a summary of the application structure and potential vulnerabilities
    """
    summary = {
        "target_url": target_url,
        "pages_visited": len(visited_urls),
        "forms_found": len(forms_data),
        "inputs_analyzed": len(inputs_data),
        "authentication": {
            "login_url": auth_info["login_url"],
            "logout_url": auth_info["logout_url"],
            "auth_type": auth_info["auth_type"]
        },
        "potential_edge_cases": potential_edge_cases
    }

    # Add top 5 pages by complexity (number of forms + links)
    pages_complexity = []

    for url, page_data in pages_tree.items():
        complexity = len(page_data.get("forms", [])) + len(page_data.get("links", []))
        pages_complexity.append({
            "url": url,
            "title": page_data.get("title", "No Title"),
            "complexity": complexity
        })

    # Sort by complexity
    pages_complexity.sort(key=lambda x: x["complexity"], reverse=True)

    summary["complex_pages"] = pages_complexity[:5]  # Top 5 most complex pages

    return summary

def save_results(self):
    """
    Save all collected data to a JSON file
    """
    results = {
        "target_url": target_url,
        "pages_tree": pages_tree,
        "forms_data": forms_data,
        "inputs_data": inputs_data,
        "auth_info": auth_info,
        "potential_edge_cases": potential_edge_cases,
        "summary": summarize_findings()
    }

    with open(output_file, 'w') as f:
        json.dump(results, f, indent=2)

    logger.info(f"Results saved to {output_file}")

def create_visual_sitemap(self, output_file="sitemap.dot"):
    """
    Create a visual sitemap in DOT format (for Graphviz)
    """
    with open(output_file, 'w') as f:
        f.write("digraph sitemap {\n")
        f.write('  rankdir="LR";\n')
        f.write('  node [shape=box, style=filled, fillcolor=lightblue];\n')
        
        # Add nodes for each page
        for url in visited_urls:
            normalized = normalize_url(url)
            node_id = str(hash(normalized) % 100000000)
            
            if normalized in pages_tree:
                title = pages_tree[normalized].get("title", "No Title")
                title = title.replace('"', '\\"')  # Escape quotes in title
                f.write(f'  {node_id} [label="{title}\\n{normalized}"];\n')
            else:
                f.write(f'  {node_id} [label="{normalized}"];\n')
        
        # Add edges for links
        for url, page_data in pages_tree.items():
            from_id = str(hash(url) % 100000000)
            
            for link in page_data.get("links", []):
                to_url = link["url"]
                to_normalized = normalize_url(to_url)
                to_id = str(hash(to_normalized) % 100000000)
                
                link_text = link["text"].replace('"', '\\"')
                if len(link_text) > 20:
                    link_text = link_text[:17] + "..."
                
                f.write(f'  {from_id} -> {to_id} [label="{link_text}"];\n')
        
        f.write("}\n")

    logger.info(f"Visual sitemap saved to {output_file}")
    logger.info("Visualize with: $ dot -Tpng sitemap.dot -o sitemap.png")
