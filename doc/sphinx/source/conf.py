# Configuration file for the Sphinx documentation builder.
#
# For the full list of built-in configuration values, see the documentation:
# https://www.sphinx-doc.org/en/master/usage/configuration.html

# -- Project information -----------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#project-information

project = 'mercury'
copyright = '2023, Cisco Systems'
author = 'Cisco Systems'
with open('../../../VERSION') as VERSION:
    release = VERSION.read()

# -- General configuration ---------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#general-configuration

import os
import sys
sys.path.append("./docproj/ext/breathe/")
sys.path.append(os.path.abspath('../../../src/cython/'))

extensions = [
    'breathe',
    'sphinx.ext.autodoc',
    'sphinx.ext.viewcode',
    'sphinx_autodoc_typehints'
]

breathe_default_project = "mercury"

templates_path = ['_templates']
exclude_patterns = []

# -- Options for HTML output -------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#options-for-html-output

html_theme = 'sphinx_rtd_theme' # 'alabaster'
#html_static_path = ['_static']

###################################

breathe_projects = {
    "mercury": "./doxyxml/xml/",
}

breathe_projects_source = {
    "mercury" : ( "../../../", ["src/libmerc/datum.h"])
}
