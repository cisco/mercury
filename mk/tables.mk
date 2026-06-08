# mk/tables.mk -- source code regeneration targets
#
# Included by the top-level Makefile.  Regenerates checked-in source files from
# declarative inputs:
#
#   - IANA CSV registries -> protocol enum headers (src/libmerc/*.h)
#   - ASN.1 OID definitions -> oid.cc / oid.h (src/libmerc/asn1/)
#
# NOTE: Unlike the main build, generator tools are built IN-SOURCE
# (e.g. src/tables/csv, src/libmerc/asn1/oidc).  They are developer
# tools not shipped in packages and not part of 'make all'.
#
# When to edit:
#   - Adding a new IANA registry: add the CSV filename to the
#     appropriate *_CSV variable and add a name:enum_type entry to
#     the corresponding *_CMD variable.
#   - Adding a new .asn1 file: just place it in src/libmerc/asn1/
#     (auto-discovered by wildcard) and run 'make regen-oid'.
#   - Adding a new top-level target: update the Tables section in
#     'make help'.
#
# Provides:
#   download-tables       -- fetch latest IANA CSVs into src/tables/source/
#   regen-tables          -- download + regenerate all protocol headers
#   regen-tables-offline  -- regenerate from cached CSVs (no download)
#   regen-oid             -- regenerate oid.cc/oid.h from .asn1 files
#   clean-tables          -- remove built table-generator binaries
#   clean-oidc            -- remove built oidc tool

# ===================================================================
# Variables
# ===================================================================

# --- ASN.1 OID paths --------------------------------------------------

ASN1_DIR       := src/libmerc/asn1
ASN1_SRCS      := $(wildcard $(ASN1_DIR)/*.asn1)

# --- IANA CSV paths and registry lists --------------------------------

TABLES_DIR     := src/tables
TABLES_OUTDIR  := src/libmerc

IKEV2_CSV := ikev2-parameters-1.csv ikev2-parameters-2.csv \
  ikev2-parameters-3.csv ikev2-parameters-4.csv ikev2-parameters-5.csv \
  ikev2-parameters-6.csv ikev2-parameters-7.csv ikev2-parameters-8.csv \
  ikev2-parameters-9.csv ikev2-parameters-10.csv ikev2-parameters-11.csv \
  ikev2-parameters-12.csv ikev2-parameters-14.csv ikev2-parameters-16.csv \
  ikev2-parameters-17.csv ikev2-parameters-18.csv ikev2-parameters-19.csv \
  ikev2-parameters-20.csv ikev2-parameters-21.csv ikev2-parameters-22.csv \
  ikev2-parameters-23.csv secure-password-methods.csv hash-algorithms.csv \
  ikev2-post-quantum-preshared-key-id-types.csv

IKEV2_CMD := ikev2-parameters-1.csv:exchange_type \
  ikev2-parameters-2.csv:payload_type ikev2-parameters-3.csv:transform_type \
  ikev2-parameters-4.csv:transform_attribute_type \
  ikev2-parameters-5.csv:encryption_transform_type \
  ikev2-parameters-6.csv:pseudorandom_function_type \
  ikev2-parameters-7.csv:integrity_transform_type \
  ikev2-parameters-8.csv:diffie_hellman_group_type \
  ikev2-parameters-9.csv:extended_sequence_numbers_type \
  ikev2-parameters-10.csv:identification_payload_type \
  ikev2-parameters-11.csv:certificate_encoding_type \
  ikev2-parameters-12.csv:authentication_method_type \
  ikev2-parameters-14.csv:notify_message_error_type \
  ikev2-parameters-16.csv:notify_message_status_type \
  ikev2-parameters-17.csv:notification_ipcomp_type \
  ikev2-parameters-18.csv:security_protocol_type \
  ikev2-parameters-19.csv:traffic_selector_type \
  ikev2-parameters-20.csv:configuration_payload_type \
  ikev2-parameters-21.csv:configuration_payload_attribute_type \
  ikev2-parameters-22.csv:gateway_identity_type \
  ikev2-parameters-23.csv:rohc_attribute_type \
  secure-password-methods.csv:secure_password_type \
  hash-algorithms.csv:hash_algorithm_type \
  ikev2-post-quantum-preshared-key-id-types.csv:postquantum_preshared_key_type

STUN_CSV := stun-parameters-2.csv stun-parameters-4.csv \
  stun-parameters-6.csv turn-channel.csv \
  stun-security-features.csv stun-password-algorithm.csv

STUN_CMD := stun-parameters-2.csv:method \
  local-stun-attributes.csv,stun-parameters-4.csv:attribute_type:type \
  stun-parameters-6.csv:error_codes \
  stun-security-features.csv:security_features \
  stun-password-algorithm.csv:password_algorithms

TLS_CSV := tls-extensiontype-values-1.csv
TLS_CMD := include_extensions=local_include_extension.txt \
  tls-extensiontype-values-1.csv:tls_extensions_assign

HPKE_CSV := hpke-kem-ids.csv hpke-aead-ids.csv hpke-kdf-ids.csv
HPKE_CMD := hpke-kem-ids.csv:kem hpke-aead-ids.csv:aead hpke-kdf-ids.csv:kdf

KRB5_CSV := kerberos-parameters-1.csv kerberos-parameters-2.csv \
  pre-authentication.csv
KRB5_CMD := kerberos-parameters-1.csv:encryption_type \
  kerberos-parameters-2.csv:checksum_type \
  pre-authentication.csv:pa_data_type

TACPLUS_CMD := tac_plus_authen_action.csv:authen_action \
  tac_plus_authen_type.csv:authen_type \
  tac_plus_authen_service.csv:authen_service \
  tac_plus_authen_status.csv:authen_status \
  tac_plus_authen_meth.csv:authen_meth \
  tac_plus_author_status.csv:author_status \
  tac_plus_acct_status.csv:acct_status \
  tac_plus_priv_lvl.csv:privilege_level

# ===================================================================
# Build rules + targets
# ===================================================================

# --- IANA CSV-to-header generators ------------------------------------

$(TABLES_DIR)/csv: $(TABLES_DIR)/csv.cc
	$(CXX_LINK)

$(TABLES_DIR)/tls_csv: $(TABLES_DIR)/tls_extension_generator.cc
	$(CXX_LINK)

# --- IANA registry download + header regeneration ---------------------

.PHONY: download-tables
download-tables:
	cd $(TABLES_DIR) && wget -N -P source/ \
	  $(addprefix https://www.iana.org/assignments/ikev2-parameters/,$(IKEV2_CSV))
	cd $(TABLES_DIR) && wget -N -P source/ \
	  $(addprefix https://www.iana.org/assignments/stun-parameters/,$(STUN_CSV))
	cd $(TABLES_DIR) && wget -N -P source/ \
	  https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values-1.csv
	cd $(TABLES_DIR) && wget -N -P source/ \
	  $(addprefix https://www.iana.org/assignments/hpke/,$(HPKE_CSV))
	cd $(TABLES_DIR) && wget -N -P source/ \
	  $(addprefix https://www.iana.org/assignments/kerberos-parameters/,$(KRB5_CSV))

.PHONY: regen-tables regen-tables-offline
regen-tables: download-tables regen-tables-offline

# Relative path from $(TABLES_DIR) to $(TABLES_OUTDIR), used by
# outfile= so the csv generators derive sane include-guard names
# (basename only, not an absolute path).
_tables_relout := ../libmerc

regen-tables-offline: $(TABLES_DIR)/csv $(TABLES_DIR)/tls_csv
	cd $(TABLES_DIR) && ./csv outfile=ikev2_params.h \
	  verbose=true dir=source $(IKEV2_CMD) && mv ikev2_params.h $(_tables_relout)/
	cd $(TABLES_DIR) && ./csv outfile=stun_params.h \
	  verbose=true dir=source $(STUN_CMD) && mv stun_params.h $(_tables_relout)/
	cd $(TABLES_DIR) && ./tls_csv outfile=tls_extensions.h \
	  verbose=true dir=source $(TLS_CMD) && mv tls_extensions.h $(_tables_relout)/
	cd $(TABLES_DIR) && ./csv outfile=hpke_params.h \
	  verbose=true dir=source $(HPKE_CMD) && mv hpke_params.h $(_tables_relout)/
	cd $(TABLES_DIR) && ./csv outfile=tacacs_plus_params.hpp \
	  verbose=true dir=local $(TACPLUS_CMD) && mv tacacs_plus_params.hpp $(_tables_relout)/
	cd $(TABLES_DIR) && ./csv outfile=krb5_params.hpp \
	  verbose=true dir=source $(KRB5_CMD) && mv krb5_params.hpp $(_tables_relout)/
	@printf '$(COLOR_GREEN)  regenerated all IANA table headers in src/libmerc/$(COLOR_OFF)\n'

# --- ASN.1 OID regeneration --------------------------------------------
#
# Tip: pass OPTFLAGS=-DASN1_DEBUG=1 to enable debug output during OID
# compilation (e.g. 'make regen-oid OPTFLAGS=-DASN1_DEBUG=1').

.PHONY: regen-oid
regen-oid: $(ASN1_DIR)/oidc
	cd $(ASN1_DIR) && ./oidc $(sort $(notdir $(ASN1_SRCS)))
	@printf '$(COLOR_GREEN)  regenerated oid.cc and oid.h from %d .asn1 files$(COLOR_OFF)\n' \
	  $(words $(ASN1_SRCS))
	@echo '  Review: git diff src/libmerc/asn1/'

$(ASN1_DIR)/oidc: $(ASN1_DIR)/oidc.cc
	$(CXX_LINK)

# --- clean -----------------------------------------------------------

.PHONY: clean-tables
clean-tables:
	rm -f $(TABLES_DIR)/csv $(TABLES_DIR)/tls_csv \
	  $(TABLES_DIR)/csv.d $(TABLES_DIR)/tls_csv.d

.PHONY: clean-oidc
clean-oidc:
	rm -f $(ASN1_DIR)/oidc $(ASN1_DIR)/oidc.d
