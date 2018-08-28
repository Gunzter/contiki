

In apps/tinydtls:
autoreconf
./configure --with-contiki --without-debug --without-ecc

Make sure that RPL-Border-Router and smart-lock-server uses the same RDC and MAC drivers. nullmac and nullrdc has caused WDT to reset when used in smart-lock-server
