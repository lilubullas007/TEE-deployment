global-incdirs-y += include ../../adp_relic/ta/include
srcs-y += adp1_ta.c

srcs-y += afgh/encoding.c afgh/encryption.c afgh/keygen.c afgh/test.c afgh/utils.c
srcs-y += adp_internals.c adp_crypto.c adp_metadata.c adp_export.c

srcs-y += $(wildcard ../../adp_relic/ta/src/low/easy/*.c)
srcs-y += $(wildcard ../../adp_relic/ta/src/*/*.c)
srcs-y += $(wildcard ../../adp_relic/ta/src/*.c)

srcs-y += $(wildcard ../../adp_relic/ta/bak/bc/*.c)
