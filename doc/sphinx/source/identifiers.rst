.. Mercury documentation master file, created by
   sphinx-quickstart on Mon Aug 14 16:13:10 2023.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

Domain Names and Addresses
========================================

Internet Protocol (IP) Addresses
---------------------------------

.. doxygenclass:: ipv4_address
   :project: mercury
   :members:

.. doxygenstruct:: ipv6_address
   :project: mercury
   :members:

.. doxygenclass:: ipv4_address_string
   :project: mercury
   :members:

.. doxygenclass:: ipv6_address_string
   :project: mercury
   :members:

.. doxygenfunction:: normalize_ip_address
   :project: mercury

.. doxygennamespace:: normalized
   :project: mercury
   :members:


Host and Server Identifiers
----------------------------

.. doxygentypedef:: dns_name_t
   :project: mercury

.. doxygentypedef:: host_identifier
   :project: mercury

.. doxygenclass:: server_identifier
   :project: mercury
   :members:
