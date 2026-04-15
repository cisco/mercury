# mk/doc.mk -- documentation targets (doxygen, sphinx)
#
# Included by Makefile2.  Provides targets for building API reference
# (Doxygen) and user documentation (Sphinx).
#
# When to edit:
#   - Adding a new documentation format or tool: add a new .PHONY
#     target and recipe below, and update the Documentation section
#     in Makefile2 'make help'.

.PHONY: doc
doc: doc/mercury.pdf sphinx

doc/mercury.pdf:
ifeq ($(HAVE_DOXYGEN),yes)
	doxygen
	cd doc/latex && $(MAKE) && mv refman.pdf ../mercury.pdf
else
	@echo '$(COLOR_YELLOW)  warning: doxygen not found; skipping doc/mercury.pdf$(COLOR_OFF)'
endif

.PHONY: sphinx
sphinx:
ifeq ($(CAN_BUILD_DOCS),yes)
	cd doc/sphinx && $(MAKE) html
else
	@echo '$(COLOR_YELLOW)  warning: sphinx prerequisites not found; skipping sphinx docs$(COLOR_OFF)'
endif

.PHONY: clean-sphinx
clean-sphinx:
	cd doc/sphinx && $(MAKE) clean
