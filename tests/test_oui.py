from iknowurhere.oui import lookup_vendor


def test_lookup_vendor_from_ieee_style_csv(tmp_path):
    registry = tmp_path / "oui.csv"
    registry.write_text(
        "Registry,Assignment,Organization Name\nMA-L,AABBCC,Example Networks\nMA-M,AABBCC1,Small Block Vendor\nMA-S,AABBCC12A,Very Small Block\n",
        encoding="utf-8",
    )
    assert lookup_vendor("aa:bb:cc:dd:ee:ff", path=registry) == "Example Networks"
    assert lookup_vendor("aa:bb:cc:1d:ee:ff", path=registry) == "Small Block Vendor"
    assert lookup_vendor("aa:bb:cc:12:a1:ff", path=registry) == "Very Small Block"
    assert lookup_vendor("00:11:22:33:44:55", path=registry) is None
