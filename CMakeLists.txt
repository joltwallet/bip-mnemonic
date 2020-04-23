idf_component_register(
        SRCS
            "src/mnemonic.c"
            "src/tree.c"
        INCLUDE_DIRS
            "include"
        REQUIRES
            "jolt-types"
        PRIV_REQUIRES
            "libsodium"
            "jolt-crypto"
)

