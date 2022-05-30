from enum import Enum

class VulnerableResource(Enum):
    NOT_VULNERABLE = 0
    SEEMS_VULNERABLE = 1
    VULNERABLE = 2