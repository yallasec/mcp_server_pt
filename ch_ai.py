from transformers import pipeline
from typing import List, Dict

class ContextHandlerAI:
    """
    A class for detecting input contexts, possible values, and potential misuse using AI.
    """

    def __init__(self):
        # Load a pre-trained NLP model for text classification
        self.nlp_model = pipeline("text-classification", model="distilbert-base-uncased")

    def detect_context(self, param_name: str, param_value: str) -> str:
        """
        Detect the security context of a parameter using AI.

        Args:
            param_name (str): The name of the parameter.
            param_value (str): The value of the parameter.

        Returns:
            str: The detected security context (e.g., "SQL", "XSS", "PATH_TRAVERSAL").
        """
        input_text = f"Parameter name: {param_name}, Parameter value: {param_value}"
        prediction = self.nlp_model(input_text)
        label = prediction[0]["label"]

        # Map AI labels to security contexts
        context_mapping = {
            "LABEL_0": "SQL",
            "LABEL_1": "XSS",
            "LABEL_2": "PATH_TRAVERSAL",
            "LABEL_3": "COMMAND_INJECTION",
            "LABEL_4": "GENERIC"
        }

        return context_mapping.get(label, "GENERIC")

    def detect_possible_values(self, param_name: str) -> List[str]:
        """
        Suggest possible valid values for a parameter using AI.

        Args:
            param_name (str): The name of the parameter.

        Returns:
            List[str]: A list of possible valid values.
        """
        # Use AI to suggest possible values based on the parameter name
        input_text = f"Suggest valid values for parameter: {param_name}"
        suggestions = self.nlp_model(input_text)
        return [suggestion["label"] for suggestion in suggestions]

    def detect_misuse(self, param_name: str, param_value: str) -> List[str]:
        """
        Detect potential misuse of a parameter using AI.

        Args:
            param_name (str): The name of the parameter.
            param_value (str): The value of the parameter.

        Returns:
            List[str]: A list of potential misuse scenarios.
        """
        input_text = f"Parameter name: {param_name}, Parameter value: {param_value}"
        prediction = self.nlp_model(input_text)
        label = prediction[0]["label"]

        # Map AI labels to misuse scenarios
        misuse_mapping = {
            "LABEL_0": "Potential SQL Injection",
            "LABEL_1": "Potential XSS",
            "LABEL_2": "Potential Path Traversal",
            "LABEL_3": "Potential Command Injection",
            "LABEL_4": "No misuse detected"
        }

        return [misuse_mapping.get(label, "No misuse detected")]