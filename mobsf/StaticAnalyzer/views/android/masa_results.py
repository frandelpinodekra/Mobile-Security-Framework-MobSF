MASA_NOT_ANALYSIS = {
    'dekra-storage-2': {
        'files': None,
        'metadata': {
            'title': 'Permission "android.permission.WRITE_EXTERNAL_STORAGE"',
            'info': 'Does not read/modify/delete external storage contents.',
            'description': 'Does not allow an application to write to external storage.',
            'masvs': 'storage_2',
            'severity': 'good'
        }

    },
    'dekra-crypto-1': {
        'files': None,
        'metadata': {
            'title': 'Harcoded keys',
            'info': 'Does not contains hardcoded encryption keys.',
            'description': 'Does not allow accessing to the key to anyone who can access to the code.',
            'masvs': 'crypto_1',
            'severity': 'good'
        }

    },
    'dekra-crypto-3': {
        'files': None,
        'metadata': {
            'title': 'Insecure cryptographic algorithms',
            'info': 'Does not use vulnerable cryptographic algorithms as DES, 3DES or ECB.',
            'description': 'Does not allow cryptographic attacks which may result in recovery of the plaintext.',
            'masvs': 'crypto_3',
            'severity': 'good'
        }

    },
    'dekra-platform-2': {
        'files': None,
        'metadata': {
            'title': 'SQL injection',
            'info': 'There is not SQL injection.',
            'description': 'Does not allow manipulating database information.',
            'masvs': 'platform_2',
            'severity': 'good'
        }

    },
    # 'dekra-platform-3': {
    #     'files': None,
    #     'metadata': {
    #         'title': 'Custom URL schemes',
    #         'info': 'Does not use custom URL not verified by the OS.',
    #         'description': 'Does not allow potential attach vector into the app.',
    #         'masvs': 'platform_3',
    #         'severity': 'good'
    #     }

    # },
    # 'dekra-network-1': {
    #     'files': None,
    #     'metadata': {
    #         'title': 'TLS encryption',
    #         'info': 'Does not use URL without TLS encryption.',
    #         'description': 'Provide encryption and integrity of the transferred data.',
    #         'masvs': 'network_1',
    #         'severity': 'good'
    #     }
    # },
    'dekra-network-2': {
        'files': None,
        'metadata': {
            'title': 'TLS protocol version',
            'info': 'Does not use legacy TLS version that have have cryptographic weaknesses.',
            'description': 'Does not allow cryptographic attacks which may result in recovery the data.',
            'masvs': 'network_2',
            'severity': 'good'
        }
    },
    # 'dekra-network-3': {
    #     'files': None,
    #     'metadata': {
    #         'title': 'X.509 certificate',
    #         'info': 'Uses X.509 certification trusted.',
    #         'description': 'The site is secure.',
    #         'masvs': 'network_3',
    #         'severity': 'good'
    #     }
    # },
    'dekra-code-1': {
        'files': None,
        'metadata': {
            'title': 'App certificate',
            'info': 'App is signed with a valid certificate.',
            'description': 'Does not allow being tampered with or modified to include malicious code.',
            'masvs': 'code_1',
            'severity': 'good'
        }

    },
    'dekra-code-2': {
        'files': None,
        'metadata': {
            'title': 'App release mode',
            'info': 'App has not been built in debug mode.',
            'description': 'Does not display debug information.',
            'masvs': 'code_2',
            'severity': 'good'
        }

    },
}

MASA_ANALYSIS = {
    'dekra-storage-2': {
        'files': None,
        'metadata': {
            'title': 'Permission "android.permission.WRITE_EXTERNAL_STORAGE"',
            'info': 'Read/modify/delete external storage contents.',
            'description': 'Allows an application to write to external storage.',
            'masvs': 'storage_2',
            'severity': 'warning'
        }

    },
    'dekra-crypto-1': {
        'files': None,
        'metadata': {
            'title': 'Harcoded keys',
            'info': 'Contains hardcoded encryption keys.',
            'description': 'Allows accessing to the key to anyone who can access to the code.',
            'masvs': 'crypto_1',
            'severity': 'dangerous'
        }

    },
    'dekra-crypto-3': {
        'files': None,
        'metadata': {
            'title': 'Insecure cryptographic algorithms',
            'info': 'Uses vulnerable cryptographic algorithms as DES, 3DES or ECB.',
            'description': 'Allows cryptographic attacks which may result in recovery of the plaintext.',
            'masvs': 'crypto_3',
            'severity': 'dangerous'
        }

    },
    'dekra-platform-2': {
        'files': None,
        'metadata': {
            'title': 'SQL injection',
            'info': 'There is SQL injection.',
            'description': 'Allows manipulating database information.',
            'masvs': 'platform_2',
            'severity': 'dangerous'
        }

    },
    # 'dekra-platform-3': {
    #     'files': None,
    #     'metadata': {
    #         'title': 'Custom URL schemes',
    #         'info': 'Uses custom URL not verified by the OS.',
    #         'description': 'Allows potential attach vector into the app.',
    #         'masvs': 'platform_3',
    #         'severity': 'warning'
    #     }

    # },
    # 'dekra-network-1': {
    #     'files': None,
    #     'metadata': {
    #         'title': 'TLS encryption',
    #         'info': 'Uses URL without TLS encryption.',
    #         'description': 'Does not provide encryption and integrity of the transferred data.',
    #         'masvs': 'network_1',
    #         'severity': 'dangerous'
    #     }
    # },
    'dekra-network-2': {
        'files': None,
        'metadata': {
            'title': 'TLS protocol version',
            'info': 'Uses legacy TLS version that have have cryptographic weaknesses.',
            'description': 'Allows cryptographic attacks which may result in recovery the data.',
            'masvs': 'network_2',
            'severity': 'dangerous'
        }
    },
    # 'dekra-network-3': {
    #     'files': None,
    #     'metadata': {
    #         'title': 'X.509 certificate',
    #         'info': 'Uses X.509 certification not trusted.',
    #         'description': 'The site may be not secure.',
    #         'masvs': 'network_3',
    #         'severity': 'dangerous'
    #     }
    # },
    'dekra-code-1': {
        'files': None,
        'metadata': {
            'title': 'App certificate',
            'info': 'App is signed with an invalid certificate.',
            'description': 'Allows being tampered with or modified to include malicious code.',
            'masvs': 'code_1',
            'severity': 'dangerous'
        }

    },
    'dekra-code-2': {
        'files': None,
        'metadata': {
            'title': 'App release mode',
            'info': 'App has been built in debug mode.',
            'description': 'Displays debug information.',
            'masvs': 'code_2',
            'severity': 'dangerous'
        }

    },
}