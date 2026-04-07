"""
CLEAN PACKAGE SAMPLE - FOR TESTING BASELINE
This simulates a normal, legitimate package.
"""


def greet(name):
    """Return a greeting string"""
    return f"Hello, {name}!"


def add(a, b):
    """Add two numbers"""
    return a + b


def fibonacci(n):
    """Calculate nth fibonacci number"""
    if n <= 1:
        return n
    return fibonacci(n - 1) + fibonacci(n - 2)


class Calculator:
    """Simple calculator class"""

    def __init__(self):
        self.history = []

    def calculate(self, operation, a, b):
        if operation == "add":
            result = a + b
        elif operation == "subtract":
            result = a - b
        elif operation == "multiply":
            result = a * b
        elif operation == "divide":
            if b == 0:
                raise ValueError("Cannot divide by zero")
            result = a / b
        else:
            raise ValueError(f"Unknown operation: {operation}")

        self.history.append({"op": operation, "a": a, "b": b, "result": result})
        return result

    def get_history(self):
        return self.history


if __name__ == "__main__":
    print(greet("World"))
    calc = Calculator()
    print(calc.calculate("add", 10, 20))