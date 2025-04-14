import requests
from bs4 import BeautifulSoup
import re
import json
import argparse
import logging
from urllib.parse import urlparse, urljoin
import time
from typing import Dict, List, Set, Tuple, Any, Optional
import random
import datetime
import uuid

class WebAppMCP:
    def __init__(self, target_url: str, output_file: str = "mcp_results.json", delay: float = 0.5):
        """
        Initialize the Master Control Program for web application testing
        
        Args:
            target_url: The base URL of the target web application
            output_file: File to save the results
            delay: Delay between requests in seconds to avoid overwhelming the server
        """
        self.target_url = target_url
        self.output_file = output_file
        self.delay = delay
        self.session = requests.Session()
        self.visited_urls: Set[str] = set()
        self.pages_tree = {}
        self.forms_data = []
        self.inputs_data = []
        self.auth_info = {
            "login_url": None,
            "logout_url": None,
            "authenticated": False,
            "auth_type": None,  # "cookie" or "bearer"
            "auth_data": None
        }
        self.potential_edge_cases = []
        
        # Configure logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler("mcp_log.txt"),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger("WebAppMCP")
        
        # Common input patterns for detection
        self.input_patterns = {
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
        self.input_samples = {
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
    
    def _make_request(self, url: str, method: str = "GET", data: Dict = None, headers: Dict = None) -> Tuple[requests.Response, Optional[BeautifulSoup]]:
        """
        Make HTTP requests with proper error handling and delay
        """
        if headers is None:
            headers = {}
        
        try:
            time.sleep(self.delay)  # Delay to be respectful to the server
            
            if method.upper() == "GET":
                response = self.session.get(url, headers=headers, timeout=10)
            elif method.upper() == "POST":
                response = self.session.post(url, data=data, headers=headers, timeout=10)
            else:
                self.logger.error(f"Unsupported method: {method}")
                return None, None
            
            if response.status_code == 200:
                soup = BeautifulSoup(response.text, 'html.parser')
                return response, soup
            else:
                self.logger.warning(f"Received status code {response.status_code} for URL: {url}")
                return response, None
                
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Request error for {url}: {str(e)}")
            return None, None
    
    def normalize_url(self, url: str) -> str:
        """
        Normalize URL to prevent visiting the same page with different parameters
        """
        parsed = urlparse(url)
        return f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
    
    def is_same_domain(self, url: str) -> bool:
        """
        Check if URL belongs to the same domain as the target
        """
        target_domain = urlparse(self.target_url).netloc
        url_domain = urlparse(url).netloc
        return url_domain == target_domain or url_domain.endswith('.' + target_domain)
    
    def crawl(self, max_pages: int = 100):
        """
        Crawl the web application to discover pages and build the tree
        """
        self.logger.info(f"Starting crawl of {self.target_url}")
        queue = [self.target_url]
        
        while queue and len(self.visited_urls) < max_pages:
            current_url = queue.pop(0)
            normalized_url = self.normalize_url(current_url)
            
            if normalized_url in self.visited_urls:
                continue
                
            self.logger.info(f"Crawling {current_url}")
            response, soup = self._make_request(current_url)
            
            if not soup:
                continue
                
            self.visited_urls.add(normalized_url)
            
            # Extract page details
            title = soup.title.text.strip() if soup.title else "No Title"
            self.pages_tree[normalized_url] = {
                "title": title,
                "links": [],
                "forms": [],
                "buttons": []
            }
            
            # Check if this might be a login page
            if self._is_login_page(soup, current_url):
                self.auth_info["login_url"] = current_url
                self.logger.info(f"Potential login page found: {current_url}")
            
            # Check if this might be a logout page/link
            if self._is_logout_page(soup, current_url):
                self.auth_info["logout_url"] = current_url
                self.logger.info(f"Potential logout page/link found: {current_url}")
            
            # Extract links
            for link in soup.find_all('a', href=True):
                href = link.get('href')
                if not href or href.startswith('#') or href.startswith('javascript:'):
                    continue
                    
                absolute_url = urljoin(current_url, href)
                if self.is_same_domain(absolute_url):
                    link_text = link.text.strip() or "No Text"
                    self.pages_tree[normalized_url]["links"].append({
                        "url": absolute_url,
                        "text": link_text
                    })
                    queue.append(absolute_url)
            
            # Extract forms
            self._extract_forms(soup, current_url)
            
            # Extract buttons (that aren't in forms)
            for button in soup.find_all('button'):
                if not button.find_parent('form'):
                    button_text = button.text.strip() or "No Text"
                    button_id = button.get('id', '')
                    button_class = button.get('class', '')
                    self.pages_tree[normalized_url]["buttons"].append({
                        "text": button_text,
                        "id": button_id,
                        "class": button_class
                    })
            
        self.logger.info(f"Crawl completed. Visited {len(self.visited_urls)} pages.")
    
    def _extract_forms(self, soup: BeautifulSoup, page_url: str):
        """
        Extract form details from a page
        """
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
                input_data = self._analyze_input(input_tag)
                if input_data:
                    inputs.append(input_data)
                    self.inputs_data.append({
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
            self.forms_data.append({
                "page_url": page_url,
                "form_data": form_data
            })
            
            # Add to page tree
            normalized_url = self.normalize_url(page_url)
            if normalized_url in self.pages_tree:
                self.pages_tree[normalized_url]["forms"].append(form_data)
    
    def _analyze_input(self, input_tag) -> Dict:
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
                "inferred_type": self._infer_input_type(input_name, input_type, input_placeholder, input_pattern)
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
    
    def _infer_input_type(self, name: str, html_type: str, placeholder: str, pattern: str) -> str:
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
            for type_name, regex in self.input_patterns.items():
                if re.search(regex, pattern):
                    return type_name
        
        # Default to text if we can't determine the type
        return 'text'
    
    def _is_login_page(self, soup: BeautifulSoup, url: str) -> bool:
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
    
    def _is_logout_page(self, soup: BeautifulSoup, url: str) -> bool:
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
    
    def authenticate(self, username: str, password: str) -> bool:
        """
        Attempt to authenticate with the application
        """
        if not self.auth_info["login_url"]:
            self.logger.error("No login URL found. Run crawl() first.")
            return False
        
        login_url = self.auth_info["login_url"]
        self.logger.info(f"Attempting to authenticate at {login_url}")
        
        # Get the login page to analyze the form
        response, soup = self._make_request(login_url)
        if not soup:
            self.logger.error("Could not access login page")
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
            self.logger.error("Could not find login form")
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
            self.logger.error("Could not identify username or password fields")
            return False
        
        login_data[username_field] = username
        login_data[password_field] = password
        
        # Submit the login form
        form_action = login_form.get('action', '')
        form_method = login_form.get('method', 'post').lower()
        form_url = urljoin(login_url, form_action) if form_action else login_url
        
        response, _ = self._make_request(form_url, method=form_method, data=login_data)
        if not response:
            self.logger.error("Login request failed")
            return False
        
        # Check if authentication was successful
        if response.url != login_url and response.status_code == 200:
            self.auth_info["authenticated"] = True
            
            # Determine authentication type
            if 'Authorization' in self.session.headers and 'Bearer' in self.session.headers['Authorization']:
                self.auth_info["auth_type"] = "bearer"
                self.auth_info["auth_data"] = self.session.headers['Authorization']
            else:
                self.auth_info["auth_type"] = "cookie"
                self.auth_info["auth_data"] = dict(self.session.cookies)
            
            self.logger.info(f"Authentication successful using {self.auth_info['auth_type']}")
            return True
        else:
            self.logger.error("Authentication failed")
            return False
    
    def generate_test_cases(self):
        """
        Generate potential test cases for business logic testing
        """
        self.logger.info("Generating potential test cases and edge cases")
        
        # IDOR test cases
        self._generate_idor_test_cases()
        
        # Mathematical/Calculation bugs
        self._generate_math_test_cases()
        
        # Workflow/State test cases
        self._generate_workflow_test_cases()
        
        # Permission test cases
        self._generate_permission_test_cases()
        
        # Parameter manipulation test cases
        self._generate_parameter_manipulation_test_cases()
        
        # Replay attack test cases
        self._generate_replay_attack_test_cases()
        
        self.logger.info(f"Generated {len(self.potential_edge_cases)} potential test cases")
    
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
        
        for url in self.visited_urls:
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
            self.potential_edge_cases.append({
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
        
        # Look for forms with multiple number inputs and possible calculations
        for form_data in self.forms_data:
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
            self.potential_edge_cases.append({
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
        
        for url, page_data in self.pages_tree.items():
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
            self.potential_edge_cases.append({
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
        
        for url in self.visited_urls:
            for pattern in admin_patterns:
                if re.search(pattern, url, re.IGNORECASE):
                    admin_pages.append(url)
                    break
        
        # Look for sensitive actions in forms
        sensitive_actions_keywords = ['delete', 'remove', 'update', 'edit', 'modify', 'change', 'add', 'create', 'grant']
        
        for form_data in self.forms_data:
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
            self.potential_edge_cases.append({
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
        Generate test cases for parameter manipulation
        """
        query_param_urls = []
        hidden_inputs = []
        
        # Look for URLs with query parameters
        for url in self.visited_urls:
            if '?' in url:
                query_param_urls.append(url)
        
        # Look for hidden inputs in forms
        for form_data in self.forms_data:
            for input_data in form_data["form_data"]["inputs"]:
                if input_data.get("html_type") == "hidden":
                    hidden_inputs.append({
                        "page_url": form_data["page_url"],
                        "form_action": form_data["form_data"]["action"],
                        "input_name": input_data.get("name", ""),
                        "input_value": input_data.get("value", "")
                    })
        
        if query_param_urls or hidden_inputs:
            self.potential_edge_cases.append({
                "category": "Parameter Manipulation",
                "description": "These URLs and inputs could be manipulated to test application logic",
                "opportunities": {
                    "query_param_urls": query_param_urls,
                    "hidden_inputs": hidden_inputs
                },
                "test_suggestions": [
                    "Modify query string parameters (e.g., price, quantity, discount)",
                    "Tamper with hidden form fields",
                    "Test boolean parameters (change true/false, 0/1, yes/no)",
                    "Try SQL injection in parameters",
                    "Test with empty parameter values",
                    "Add unexpected parameters",
                    "Remove required parameters",
                    "Test with extremely large values"
                ]
            })
    
    def _generate_replay_attack_test_cases(self):
        """
        Generate test cases for replay attacks
        """
        sensitive_forms = []
        
        # Look for forms that might involve sensitive operations
        sensitive_keywords = ['payment', 'transfer', 'checkout', 'purchase', 'order', 'delete', 'update', 'submit']
        
        for form_data in self.forms_data:
            form_action = form_data["form_data"]["action"].lower()
            page_url = form_data["page_url"].lower()
            
            if any(keyword in form_action for keyword in sensitive_keywords) or any(keyword in page_url for keyword in sensitive_keywords):
                sensitive_forms.append({
                    "page_url": form_data["page_url"],
                    "form_action": form_data["form_data"]["action"],
                    "method": form_data["form_data"]["method"]
                })
        
        if sensitive_forms:
            self.potential_edge_cases.append({
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
            if inferred_type in self.input_samples:
                input_values[field_name] = self.input_samples[inferred_type]
            else:
                input_values[field_name] = self.input_samples["text"]
        
        return input_values
    
    def create_user_flows(self):
        """
        Identify potential user flows through the application
        """
        self.logger.info("Creating potential user flows")
        
        # Start with the base page or login if available
        starting_points = []
        
        if self.auth_info["login_url"]:
            starting_points.append(self.auth_info["login_url"])
        else:
            starting_points.append(self.target_url)
        
        flows = []
        
        for start_point in starting_points:
            # Simple flow: just follow links in levels
            # Level 1: Start -> Any page directly linked
            level1_links = []
            
            start_normalized = self.normalize_url(start_point)
            if start_normalized in self.pages_tree:
                for link in self.pages_tree[start_normalized]["links"]:
                    level1_links.append({
                        "from": start_point,
                        "to": link["url"],
                        "text": link["text"]
                    })
            
            # Level 2: Follow links from level 1
            level2_links = []
            
            for l1_link in level1_links:
                l1_normalized = self.normalize_url(l1_link["to"])
                if l1_normalized in self.pages_tree:
                    for link in self.pages_tree[l1_normalized]["links"]:
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
        
        for form_data in self.forms_data:
            page_url = form_data["page_url"]
            form = form_data["form_data"]
            
            # Generate valid inputs for this form
            inputs = self.generate_valid_inputs(form)
            
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
            "target_url": self.target_url,
            "pages_visited": len(self.visited_urls),
            "forms_found": len(self.forms_data),
            "inputs_analyzed": len(self.inputs_data),
            "authentication": {
                "login_url": self.auth_info["login_url"],
                "logout_url": self.auth_info["logout_url"],
                "auth_type": self.auth_info["auth_type"]
            },
            "potential_edge_cases": self.potential_edge_cases
        }
        
        # Add top 5 pages by complexity (number of forms + links)
        pages_complexity = []
        
        for url, page_data in self.pages_tree.items():
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
            "target_url": self.target_url,
            "pages_tree": self.pages_tree,
            "forms_data": self.forms_data,
            "inputs_data": self.inputs_data,
            "auth_info": self.auth_info,
            "potential_edge_cases": self.potential_edge_cases,
            "summary": self.summarize_findings()
        }
        
        with open(self.output_file, 'w') as f:
            json.dump(results, f, indent=2)
        
        self.logger.info(f"Results saved to {self.output_file}")
    
    def create_visual_sitemap(self, output_file="sitemap.dot"):
        """
        Create a visual sitemap in DOT format (for Graphviz)
        """
        with open(output_file, 'w') as f:
            f.write("digraph sitemap {\n")
            f.write('  rankdir="LR";\n')
            f.write('  node [shape=box, style=filled, fillcolor=lightblue];\n')
            
            # Add nodes for each page
            for url in self.visited_urls:
                normalized = self.normalize_url(url)
                node_id = str(hash(normalized) % 100000000)
                
                if normalized in self.pages_tree:
                    title = self.pages_tree[normalized].get("title", "No Title")
                    title = title.replace('"', '\\"')  # Escape quotes in title
                    f.write(f'  {node_id} [label="{title}\\n{normalized}"];\n')
                else:
                    f.write(f'  {node_id} [label="{normalized}"];\n')
            
            # Add edges for links
            for url, page_data in self.pages_tree.items():
                from_id = str(hash(url) % 100000000)
                
                for link in page_data.get("links", []):
                    to_url = link["url"]
                    to_normalized = self.normalize_url(to_url)
                    to_id = str(hash(to_normalized) % 100000000)
                    
                    link_text = link["text"].replace('"', '\\"')
                    if len(link_text) > 20:
                        link_text = link_text[:17] + "..."
                    
                    f.write(f'  {from_id} -> {to_id} [label="{link_text}"];\n')
            
            f.write("}\n")
        
        self.logger.info(f"Visual sitemap saved to {output_file}")
        self.logger.info("Visualize with: $ dot -Tpng sitemap.dot -o sitemap.png")


def main():
    """
    Main function to run the MCP from command line
    """
    parser = argparse.ArgumentParser(description="Web Application MCP for Penetration Testing")
    parser.add_argument("url", help="Target URL of the web application")
    parser.add_argument("--output", "-o", default="mcp_results.json", help="Output file for results")
    parser.add_argument("--max-pages", "-m", type=int, default=100, help="Maximum number of pages to crawl")
    parser.add_argument("--delay", "-d", type=float, default=0.5, help="Delay between requests in seconds")
    parser.add_argument("--username", "-u", help="Username for authentication")
    parser.add_argument("--password", "-p", help="Password for authentication")
    parser.add_argument("--visual", "-v", action="store_true", help="Create visual sitemap")
    
    args = parser.parse_args()
    
    # Initialize and run the MCP
    mcp = WebAppMCP(args.url, args.output, args.delay)
    
    # Crawl the application
    mcp.crawl(max_pages=args.max_pages)
    
    # Authenticate if credentials are provided
    if args.username and args.password:
        mcp.authenticate(args.username, args.password)
    
    # Generate test cases
    mcp.generate_test_cases()
    
    # Create user flows
    flows = mcp.create_user_flows()
    
    # Create visual sitemap if requested
    if args.visual:
        mcp.create_visual_sitemap()
    
    # Save results
    mcp.save_results()
    
    # Display summary
    summary = mcp.summarize_findings()
    print("\n=== MCP Analysis Summary ===")
    print(f"Target URL: {summary['target_url']}")
    print(f"Pages visited: {summary['pages_visited']}")
    print(f"Forms found: {summary['forms_found']}")
    print(f"Inputs analyzed: {summary['inputs_analyzed']}")
    print(f"Login page: {summary['authentication']['login_url']}")
    print(f"Potential edge cases identified: {len(summary['potential_edge_cases'])}")
    print(f"Results saved to: {args.output}")


if __name__ == "__main__":
    main()