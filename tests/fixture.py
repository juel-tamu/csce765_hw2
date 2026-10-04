import pytest 
import sys
import os

parent_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if parent_dir not in sys.path:
    sys.path.append(parent_dir)

from handshake import *

@pytest.fixture
def create_handshake():
    print(main())
    return main()