from Crypt import CryptEpix


class TestCryptEpix:
    def testSign(self, crypt_bitcoin_lib):
        privatekey = "5K9S6dVpufGnroRgFrT6wsKiz2mJRYsC73eWDmajaHserAp3F1C"
        privatekey_bad = "5Jbm9rrusXyApAoM8YoM4Rja337zMMoBUMRJ1uijiguU2aZRnwC"

        # Get address by privatekey
        address = crypt_bitcoin_lib.privatekeyToAddress(privatekey)
        assert address.startswith("epix1")

        address_bad = crypt_bitcoin_lib.privatekeyToAddress(privatekey_bad)
        assert address_bad != address

        # Text signing
        data_len_list = list(range(0, 300, 10))
        data_len_list += [1024, 2048, 1024 * 128, 1024 * 1024, 1024 * 2048]
        for data_len in data_len_list:
            data = data_len * "!"
            sign = crypt_bitcoin_lib.sign(data, privatekey)

            assert crypt_bitcoin_lib.verify(data, address, sign)
            assert not crypt_bitcoin_lib.verify("invalid" + data, address, sign)

        # Signed by bad privatekey
        sign_bad = crypt_bitcoin_lib.sign("hello", privatekey_bad)
        assert not crypt_bitcoin_lib.verify("hello", address, sign_bad)

    def testVerify(self, crypt_bitcoin_lib):
        # Test with fresh signatures for Epix addresses
        privatekey = "5K9S6dVpufGnroRgFrT6wsKiz2mJRYsC73eWDmajaHserAp3F1C"
        address = crypt_bitcoin_lib.privatekeyToAddress(privatekey)
        message = "test message for verification"
        sign = crypt_bitcoin_lib.sign(message, privatekey)

        assert crypt_bitcoin_lib.verify(message, address, sign)

    def testNewPrivatekey(self):
        assert CryptEpix.newPrivatekey() != CryptEpix.newPrivatekey()
        assert CryptEpix.privatekeyToAddress(CryptEpix.newPrivatekey())

    def testNewSeed(self):
        assert CryptEpix.newSeed() != CryptEpix.newSeed()
        assert CryptEpix.privatekeyToAddress(
            CryptEpix.hdPrivatekey(CryptEpix.newSeed(), 0)
        )
        assert CryptEpix.privatekeyToAddress(
            CryptEpix.hdPrivatekey(CryptEpix.newSeed(), 2**256)
        )
