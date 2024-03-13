# Makefile for csv utility and table generation
#

protocol_libs += ikev2_params.h
protocol_libs += stun_params.h
protocol_libs += hpke_params.h

.PHONY: all
all: csv tls $(protocol_libs)

.PHONY: tls
tls: tls_csv tls_extensions.h

# build csv processing utility
#
csv: csv.cc tls_extension_generator.cc csv.h
	$(CXX) -Wall csv.cc -o csv

tls_csv: tls_extension_generator.cc csv.h
	$(CXX) -Wall tls_extension_generator.cc -o tls_csv

# IKEv2 table generation
#
# wget -O - https://www.iana.org/assignments/ikev2-parameters/ikev2-parameters.xhtml 2> /dev/null | grep "[^\"]*\.csv" -o
#
#
IKEV2 += ikev2-parameters-1.csv
IKEV2 += ikev2-parameters-2.csv
IKEV2 += ikev2-parameters-3.csv
IKEV2 += ikev2-parameters-4.csv
IKEV2 += ikev2-parameters-5.csv
IKEV2 += ikev2-parameters-6.csv
IKEV2 += ikev2-parameters-7.csv
IKEV2 += ikev2-parameters-8.csv
IKEV2 += ikev2-parameters-9.csv
IKEV2 += ikev2-parameters-10.csv
IKEV2 += ikev2-parameters-11.csv
IKEV2 += ikev2-parameters-12.csv
IKEV2 += ikev2-parameters-14.csv
IKEV2 += ikev2-parameters-16.csv
IKEV2 += ikev2-parameters-17.csv
IKEV2 += ikev2-parameters-18.csv
IKEV2 += ikev2-parameters-19.csv
IKEV2 += ikev2-parameters-20.csv
IKEV2 += ikev2-parameters-21.csv
IKEV2 += ikev2-parameters-22.csv
IKEV2 += ikev2-parameters-23.csv
IKEV2 += secure-password-methods.csv
IKEV2 += hash-algorithms.csv
IKEV2 += ikev2-post-quantum-preshared-key-id-types.csv

IKEV2_CMD += ikev2-parameters-1.csv:exchange_type
IKEV2_CMD += ikev2-parameters-2.csv:payload_type
IKEV2_CMD += ikev2-parameters-3.csv:transform_type
IKEV2_CMD += ikev2-parameters-4.csv:transform_attribute_type
IKEV2_CMD += ikev2-parameters-5.csv:encryption_transform_type
IKEV2_CMD += ikev2-parameters-6.csv:pseudorandom_function_type
IKEV2_CMD += ikev2-parameters-7.csv:integrity_transform_type
IKEV2_CMD += ikev2-parameters-8.csv:diffie_hellman_group_type
IKEV2_CMD += ikev2-parameters-9.csv:extended_sequence_numbers_type
IKEV2_CMD += ikev2-parameters-10.csv:identification_payload_type
IKEV2_CMD += ikev2-parameters-11.csv:certificate_encoding_type
IKEV2_CMD += ikev2-parameters-12.csv:authentication_method_type
IKEV2_CMD += ikev2-parameters-14.csv:notify_message_error_type
IKEV2_CMD += ikev2-parameters-16.csv:notify_message_status_type
IKEV2_CMD += ikev2-parameters-17.csv:notification_ipcomp_type
IKEV2_CMD += ikev2-parameters-18.csv:security_protocol_type
IKEV2_CMD += ikev2-parameters-19.csv:traffic_selector_type
IKEV2_CMD += ikev2-parameters-20.csv:configuration_payload_type
IKEV2_CMD += ikev2-parameters-21.csv:configuration_payload_attribute_type
IKEV2_CMD += ikev2-parameters-22.csv:gateway_identity_type
IKEV2_CMD += ikev2-parameters-23.csv:rohc_attribute_type
IKEV2_CMD += secure-password-methods.csv:secure_password_type
IKEV2_CMD += hash-algorithms.csv:hash_algorithm_type
IKEV2_CMD += ikev2-post-quantum-preshared-key-id-types.csv:postquantum_preshared_key_type

# rules to fetch IKEv2 CSV files
#
.PHONY: $(IKEV2)
$(IKEV2):
	wget -N -P source/ https://www.iana.org/assignments/ikev2-parameters/$@

# build IKEv2 tables
#
ikev2_params.h: $(IKEV2)
	./csv outfile=$@ verbose=true dir=source $(IKEV2_CMD)


# STUN
#
STUN += stun-parameters-2.csv
STUN += stun-parameters-4.csv
STUN += stun-parameters-6.csv
STUN += turn-channel.csv
STUN += stun-security-features.csv
STUN += stun-password-algorithm.csv

STUN_CMD += stun-parameters-2.csv:method
STUN_CMD += local-stun-attributes.csv,stun-parameters-4.csv:attribute_type:type
STUN_CMD += stun-parameters-6.csv:error_codes
# STUN_CMD += turn-channel.csv
STUN_CMD += stun-security-features.csv:security_features
STUN_CMD += stun-password-algorithm.csv:password_algorithms

# rules to fetch STUN CSV files
#
.PHONY: $(STUN)
$(STUN):
	wget -N -P source/ https://www.iana.org/assignments/stun-parameters/$@

stun_params.h: $(STUN) csv
	./csv outfile=$@ verbose=true dir=source $(STUN_CMD)

TLS += tls-extensiontype-values-1.csv
TLS_CMD += include_extensions=local_include_extension.txt tls-extensiontype-values-1.csv:tls_extensions_assign

.PHONY: $(TLS)
$(TLS):
	wget -N -P source/ https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values-1.csv

tls_extensions.h: $(TLS) tls_csv
	./tls_csv outfile=$@ verbose=true dir=source $(TLS_CMD)

# HPKE
#
HPKE += hpke-kem-ids.csv
HPKE += hpke-aead-ids.csv
HPKE += hpke-kdf-ids.csv

HPKE_CMD += hpke-kem-ids.csv:kem
HPKE_CMD += hpke-aead-ids.csv:aead
HPKE_CMD += hpke-kdf-ids.csv:kdf

.PHONY: $(HPKE)
$(HPKE):
	wget -N -P source/ https://www.iana.org/assignments/hpke/$@

hpke_params.h: $(HPKE) csv
	./csv outfile=$@ verbose=true dir=source $(HPKE_CMD)

# housekeeping
#
clean:
	rm -f csv tls_csv Makefile~ csv.h~ csv.cc~
	find source/ -type f ! -name 'local*' -delete

distclean: clean
	rm -f $(protocol_libs)

# EOF
