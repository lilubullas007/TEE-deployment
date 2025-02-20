global-incdirs-y += include
srcs-y += $(wildcard src/low/easy/*.c)
srcs-y += $(wildcard src/*/*.c)
srcs-y += $(wildcard src/*.c)

srcs-y += bak/bc/relic_bc_aes.c
