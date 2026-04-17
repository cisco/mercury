# mk/install.mk -- install, uninstall, and packaging targets
#
# Included by Makefile2.  Provides targets for installing mercury and
# certtools, managing the systemd service, and building .deb/.rpm
# packages.
#
# When to edit:
#   - Adding a new installable binary: add an install-<name> target
#     and include it in the appropriate install umbrella target.  Update
#     the Install/package section in Makefile2 'make help'.
#   - Changing package layout: edit the package-deb / package-rpm
#     recipes.
#
# Provides:
#   install            -- install mercury binary, config, create service user
#   install-nonroot    -- install binary + config without user/group creation
#   install-nosystemd  -- alias for install (no systemd activation)
#   install-systemd    -- install + deploy + activate systemd service
#   install-certtools  -- install cert_analyze, tls_scanner, batch_gcd
#   uninstall          -- remove everything, stop systemd, delete user
#   uninstall-mercury  -- remove mercury binary, library, config
#   uninstall-systemd  -- stop/disable systemd service, remove service file, delete user
#   uninstall-certtools -- remove certtools binaries
#   package-deb        -- build Debian package
#   package-rpm        -- build RPM package

INSTALL      = /usr/bin/install -c
INSTALLDATA  = /usr/bin/install -c -m 644
MERCURY_CFG  = mercury.cfg

# --- install ----------------------------------------------------------

.PHONY: install install-nosystemd
install: install-mercury install-etc-config
install-nosystemd: install-mercury install-etc-config

.PHONY: install-mercury
install-mercury: $(BIN)/mercury
	mkdir -p $(DESTDIR)$(bindir)
	$(INSTALL) $(BIN)/mercury $(DESTDIR)$(bindir)/mercury
	$(INSTALLDATA) mercury $(DESTDIR)/usr/share/bash-completion/completions/ 2>/dev/null || true
	PATH=$(PATH):/sbin ldconfig 2>/dev/null || true
	-useradd --system --no-create-home --user-group mercury 2>/dev/null || true
	mkdir -p $(DESTDIR)$(localstatedir)
	$(INSTALL) -d $(DESTDIR)$(localstatedir) -o mercury -g mercury 2>/dev/null || true

.PHONY: install-etc-config
install-etc-config:
	$(INSTALL) -d $(DESTDIR)/etc/mercury
	$(INSTALLDATA) $(MERCURY_CFG) $(DESTDIR)/etc/mercury/mercury.cfg

# --- install-nonroot --------------------------------------------------

.PHONY: install-nonroot
install-nonroot: $(BIN)/mercury install-etc-config
	mkdir -p $(DESTDIR)$(bindir)
	$(INSTALL) $(BIN)/mercury $(DESTDIR)$(bindir)/mercury
	mkdir -p $(DESTDIR)$(localstatedir)
	$(INSTALL) -d $(DESTDIR)$(localstatedir)

# --- install-systemd --------------------------------------------------

.PHONY: install-systemd
install-systemd: install-mercury install-etc-config
	$(INSTALLDATA) install_mercury/mercury.service $(DESTDIR)/etc/systemd/system/
	systemctl daemon-reload
	systemctl start mercury
	systemctl enable mercury

# --- install-certtools ------------------------------------------------

.PHONY: install-certtools
install-certtools: $(CERTTOOLS)
	$(INSTALL) -d $(DESTDIR)$(bindir)
	$(INSTALL) $(BIN)/cert_analyze $(DESTDIR)$(bindir)/cert_analyze
ifeq ($(HAVE_GMP),yes)
	$(INSTALL) $(BIN)/batch_gcd $(DESTDIR)$(bindir)/batch_gcd
endif
ifneq ($(IS_MACOS),yes)
	$(INSTALL) $(BIN)/tls_scanner $(DESTDIR)$(bindir)/tls_scanner
endif

# --- install-intercept ------------------------------------------------
# Installs the LD_PRELOAD TLS interception library.
# Note: intercept.so cannot currently be built successfully (missing
# nspr4/gnutls deps on most hosts), so this target exists for
# completeness and will fail at the dependency step until that is fixed.
#
# FIXME: chmod o+w makes interceptdir world-writable, and the .so is
# installed into libdir rather than interceptdir.  Both are inherited
# from the old Makefile.  Preserving existing behavior for now since
# intercept.so can't be built or tested; revisit when it is.

.PHONY: install-intercept
install-intercept: $(LIB)/intercept.so
	mkdir -p $(DESTDIR)$(interceptdir)
	chmod o+w $(DESTDIR)$(interceptdir)
	mkdir -p $(DESTDIR)$(libdir)
	$(INSTALL) $(LIB)/intercept.so $(DESTDIR)$(libdir)
	@echo "install complete; run 'export LD_PRELOAD=$(libdir)/intercept.so' to perform interception"

# --- uninstall --------------------------------------------------------

.PHONY: uninstall
uninstall: uninstall-mercury uninstall-systemd uninstall-certtools

.PHONY: uninstall-mercury
uninstall-mercury:
	rm -f  $(DESTDIR)/etc/mercury/mercury.cfg
	rm -rf $(DESTDIR)/etc/mercury
	rm -f  $(DESTDIR)$(bindir)/mercury
	rm -f  $(DESTDIR)$(libdir)/libmerc.so
	PATH=$(PATH):/sbin ldconfig 2>/dev/null || true
	@echo "local captures not removed; to do that, run 'rm -rf $(localstatedir)'"

.PHONY: uninstall-systemd
uninstall-systemd:
	-systemctl stop mercury 2>/dev/null || true
	-systemctl disable mercury 2>/dev/null || true
	rm -f $(DESTDIR)/etc/systemd/system/mercury.service
	-userdel mercury 2>/dev/null || true

.PHONY: uninstall-certtools
uninstall-certtools:
	rm -f $(DESTDIR)$(bindir)/batch_gcd
	rm -f $(DESTDIR)$(bindir)/cert_analyze
	rm -f $(DESTDIR)$(bindir)/tls_scanner

# --- packaging --------------------------------------------------------

PKGDIR := build/$(_variant)/pkg

.PHONY: package-deb
package-deb: $(BIN)/mercury
	MERCURY_BIN=$(BIN)/mercury ./build_pkg.sh -t deb -o $(PKGDIR)

.PHONY: package-rpm
package-rpm: $(BIN)/mercury
	MERCURY_BIN=$(BIN)/mercury ./build_pkg.sh -t rpm -o $(PKGDIR)
