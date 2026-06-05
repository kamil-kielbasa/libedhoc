# Configuration file for the Sphinx documentation builder.
#
# For the full list of built-in configuration values, see the documentation:
# https://www.sphinx-doc.org/en/master/usage/configuration.html

import os
import subprocess
from pathlib import Path

# -- Project information -----------------------------------------------------

project = "libedhoc"
copyright = "2026, Kamil Kielbasa"
author = "Kamil Kielbasa"
version = "v1.10.3"
release = version

# -- General configuration ---------------------------------------------------

extensions = [
    "breathe",
    "myst_parser",
    "sphinx.ext.intersphinx",
]

source_suffix = {
    ".rst": "restructuredtext",
    ".md": "markdown",
}
master_doc = "index"

templates_path = ["_templates"]
exclude_patterns = ["build", "_build", "Thumbs.db", ".DS_Store"]

# -- Options for HTML output -------------------------------------------------

html_theme = "furo"
html_static_path = ["_static"]
html_css_files = ["custom.css"]

html_theme_options = {
    "source_repository": "https://github.com/kamil-kielbasa/libedhoc/",
    "source_branch": "main",
    "source_directory": "doc/",
    "navigation_with_keys": True,
    "top_of_page_buttons": ["view", "edit"],
}

# -- Breathe / Doxygen -------------------------------------------------------

_buildoc_path = Path("../build/doc/doxygen")
os.makedirs(_buildoc_path, exist_ok=True)

subprocess.call("doxygen", shell=True)

breathe_projects = {"libedhoc": str(_buildoc_path) + "/xml"}
breathe_default_project = "libedhoc"
# Only show members for directives that explicitly opt in via :members:.
breathe_default_members = ()
