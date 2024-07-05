# Configuration file for the Sphinx documentation builder.
#
# For the full list of built-in configuration values, see the documentation:
# https://www.sphinx-doc.org/en/master/usage/configuration.html

# -- Version setup -----------------------------------------------------------

import os
from pathlib import Path
import subprocess

#project = u'Read the Docs Sphinx Theme'
#slug = re.sub(r'\W+', '-', project.lower())

# -- Project information -----------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#project-information

project = 'libedhoc'
copyright = '2024, Kamil Kielbasa'
author = 'Kamil Kielbasa'
version = 'v0.4.0'

# -- General configuration ---------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#general-configuration

extensions = [
              'sphinx.ext.autodoc',
              'breathe',
              'myst_parser',
              'sphinx.ext.intersphinx',
              'sphinx.ext.autodoc',
              'sphinx.ext.autosummary',
              'sphinx.ext.mathjax',
              'sphinx.ext.viewcode',
              'sphinx_rtd_theme',
             ]

source_suffix = [".rst", ".md"]
master_doc = "index"

templates_path = ['_templates']
exclude_patterns = ['build', 'Thumbs.db', '.DS_Store']



# -- Options for HTML output -------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#options-for-html-output

import sphinx_rtd_theme
html_theme = 'sphinx_rtd_theme'
html_theme_path = [sphinx_rtd_theme.get_html_theme_path()]

# Breathe options --------------------------------------------------------------

_buildoc_path = Path("../build/doc/doxygen")
os.makedirs(_buildoc_path, exist_ok=True)

subprocess.call('doxygen', shell=True)

# Tell Breathe where to find the Doxygen output
breathe_projects = { "libedhoc": str(_buildoc_path) + "/xml" }

breathe_default_project = "libedhoc"
