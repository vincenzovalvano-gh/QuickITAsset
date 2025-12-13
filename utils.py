import sys
import os

def get_app_path():
    """
    Returns the directory where the application executable or script resides.
    This is where persistent configuration files should be stored.
    """
    if getattr(sys, 'frozen', False):
        # If the application is run as a bundle (PyInstaller)
        return os.path.dirname(sys.executable)
    else:
        # If running as a script
        return os.path.dirname(os.path.abspath(__file__))

def get_config_path(filename):
    """
    Returns the absolute path for a configuration file in the app directory.
    """
    return os.path.join(get_app_path(), filename)

def resource_path(relative_path):
    """ Get absolute path to resource, works for dev and for PyInstaller """
    try:
        # PyInstaller creates a temp folder and stores path in _MEIPASS
        base_path = sys._MEIPASS
    except Exception:
        base_path = os.path.abspath(".")

    return os.path.join(base_path, relative_path)
