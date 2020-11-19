###This is an attempt to write undetectable ransomware by using no crypto libraries. All agorithms are custom implementations.
#####The following algorithms are implemented:
    ECC
    RSA with no padding(for now)
    AES in CFB mode
    XOR
    RC4

#####Features I'm planning to add:
    Server communication
    OAEP padding
    Automatic encryption of the whole filesystem
    Buffering of files
    Parallelization/concurrency where possible
    Multiprocessing for encrypting different files
