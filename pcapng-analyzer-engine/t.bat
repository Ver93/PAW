gcc tests/test_ipv4_reassembly.c ^
src/fragmentation/ipv4_reassembly.c ^
src/validation/ipv4_reassembly_validation.c ^
-Isrc ^
-Isrc/core ^
-Isrc/parsing ^
-Isrc/pcapng ^
-Isrc/validation ^
-Isrc/protocols ^
-Isrc/packets ^
-Isrc/analysis ^
-Isrc/utils ^
-Isrc/fragmentation ^
-Wall -Wextra -Wpedantic ^
-o bin/test_ipv4_reassembly.exe