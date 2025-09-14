from Crypt import CryptEpix


class TestCryptEpix:
    def testSign(self, crypt_epix_lib):
        privatekey = "5K9S6dVpufGnroRgFrT6wsKiz2mJRYsC73eWDmajaHserAp3F1C"
        privatekey_bad = "5Jbm9rrusXyApAoM8YoM4Rja337zMMoBUMRJ1uijiguU2aZRnwC"

        # Get address by privatekey
        address = crypt_epix_lib.privatekeyToAddress(privatekey)
        assert address.startswith("epix1")

        address_bad = crypt_epix_lib.privatekeyToAddress(privatekey_bad)
        assert address_bad != address

        # Sign message
        sign = crypt_epix_lib.sign("hello", privatekey)
        assert len(sign) > 0

        # Verify signature
        assert crypt_epix_lib.verify("hello", address, sign)
        assert not crypt_epix_lib.verify("hello", address_bad, sign)
        assert not crypt_epix_lib.verify("hello2", address, sign)

        # Verify with invalid signature
        assert not crypt_epix_lib.verify("hello", address, "invalid")

    def testVerify(self, crypt_epix_lib):
        # Test with known values
        privatekey = "5K9S6dVpufGnroRgFrT6wsKiz2mJRYsC73eWDmajaHserAp3F1C"
        address = crypt_epix_lib.privatekeyToAddress(privatekey)
        
        # Sign a test message
        message = "test message for verification"
        sign = crypt_epix_lib.sign(message, privatekey)
        
        # Verify the signature
        assert crypt_epix_lib.verify(message, address, sign)

    def testNewPrivatekey(self):
        assert CryptEpix.newPrivatekey() != CryptEpix.newPrivatekey()
        assert CryptEpix.privatekeyToAddress(CryptEpix.newPrivatekey())

    def testAddressValidation(self):
        # Test valid Epix addresses - generate them dynamically to ensure they're valid
        privatekey1 = "5K9S6dVpufGnroRgFrT6wsKiz2mJRYsC73eWDmajaHserAp3F1C"
        privatekey2 = "5Jbm9rrusXyApAoM8YoM4Rja337zMMoBUMRJ1uijiguU2aZRnwC"

        valid_addresses = [
            CryptEpix.privatekeyToAddress(privatekey1),
            CryptEpix.privatekeyToAddress(privatekey2),
        ]

        for addr in valid_addresses:
            assert CryptEpix.isValidAddress(addr), f"Address {addr} should be valid"
        
        # Test invalid addresses
        invalid_addresses = [
            "1MpDMxFeDUkiHohxx9tbGLeEGEuR4ZNsJz",  # Bitcoin address
            "epix1invalid",  # Too short
            "invalid1s0wq3fwmsruhm922dq3flwn8kz6qdrpsjeusyy",  # Wrong prefix
            "",  # Empty
            "epix1",  # Too short
        ]
        
        for addr in invalid_addresses:
            assert not CryptEpix.isValidAddress(addr), f"Address {addr} should be invalid"

    def testAddressConversion(self):
        # Test address to hash160 conversion
        address = "epix1dashuu6pvsut7aw9dx44f543mv7xt9zlydsj9t"
        hash160 = CryptEpix.addressToHash160(address)
        assert hash160 is not None
        assert len(hash160) == 20
        
        # Test hash160 to address conversion
        converted_address = CryptEpix.hash160ToAddress(hash160)
        assert converted_address == address
        
        # Test with invalid address
        invalid_hash160 = CryptEpix.addressToHash160("invalid_address")
        assert invalid_hash160 is None

    def testPublicKeyToAddress(self):
        # Generate a private key and get the corresponding public key
        privatekey = CryptEpix.newPrivatekey()
        address = CryptEpix.privatekeyToAddress(privatekey)
        
        # Verify the address is valid
        assert CryptEpix.isValidAddress(address)
        assert address.startswith("epix1")
