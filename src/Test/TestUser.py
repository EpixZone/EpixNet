import pytest

from Crypt import CryptEpix


@pytest.mark.usefixtures("resetSettings")
class TestUser:
    def testAddress(self, user):
        assert user.master_address == "epix16jha5q3qvr7fgldrgem4x5ju8vwd78d3lwawtn"
        address_index = 14199856986777972317416200829214867103927393370315628508069949862373673319704318642080835749710491251822
        assert user.getAddressAuthIndex("epix16jha5q3qvr7fgldrgem4x5ju8vwd78d3lwawtn") == address_index

    # Re-generate privatekey based on address_index
    def testNewSite(self, user):
        address, address_index, site_data = user.getNewSiteData()  # Create a new random site
        assert CryptEpix.hdPrivatekey(user.master_seed, address_index) == site_data["privatekey"]

        user.sites = {}  # Reset user data

        # Site address and auth address is different
        assert user.getSiteData(address)["auth_address"] != address
        # Re-generate auth_privatekey for site
        assert user.getSiteData(address)["auth_privatekey"] == site_data["auth_privatekey"]

    def testAuthAddress(self, user):
        # Auth address without Cert
        test_site_address = "epix1test0000000000000000000000000000000000"
        auth_address = user.getAuthAddress(test_site_address)
        assert auth_address == "epix19mqssu8uf40xfuzfczlxrxauus9k8r5jaznrgf"
        auth_privatekey = user.getAuthPrivatekey(test_site_address)
        assert CryptEpix.privatekeyToAddress(auth_privatekey) == auth_address

    def testCert(self, user):
        cert_site_address = "epix1xauthduuyn63k6kj54jzgp4l8nnjlhrsyaku8c"
        test_site_address = "epix1test0000000000000000000000000000000000"

        cert_auth_address = user.getAuthAddress(cert_site_address)  # Add site to user's registry
        assert cert_auth_address == "epix1lxfgsrns0uex5gtlvn3ta74adnam2cwjvpet4q"

        # Add cert
        user.addCert(cert_auth_address, "zeroid.bit", "faketype", "fakeuser", "fakesign")
        user.setCert(test_site_address, "zeroid.bit")

        # By using certificate the auth address should be same as the certificate provider
        assert user.getAuthAddress(test_site_address) == cert_auth_address
        auth_privatekey = user.getAuthPrivatekey(test_site_address)
        assert CryptEpix.privatekeyToAddress(auth_privatekey) == cert_auth_address

        # Test delete site data
        assert test_site_address in user.sites
        user.deleteSiteData(test_site_address)
        assert test_site_address not in user.sites

        # Re-create add site should generate normal, unique auth_address
        assert not user.getAuthAddress(test_site_address) == cert_auth_address
        assert user.getAuthAddress(test_site_address) == "epix19mqssu8uf40xfuzfczlxrxauus9k8r5jaznrgf"
