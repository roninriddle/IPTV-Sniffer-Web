"""Behavior regressions found while integrating PRs 7, 8, 10 and 11."""
import pytest
from services.rtp2httpd_config import parse_config, effective_config


def test_uci_comments_and_quoted_url_fragment():
    parsed = effective_config(parse_config("""config rtp2httpd 'main'
option upstream_interface 'eth1' # IPTV
option external_m3u 'https://example.test/list?a=1#fragment' # comment
list listen '[::]:5140' # bind
"""))
    assert parsed['values']['upstream-interface'] == 'eth1'
    assert parsed['values']['external-m3u'] == 'https://example.test/list?a=1#fragment'
    assert parsed['bind'] == ['[::]:5140']


def test_uci_effective_instance_and_simple_mode():
    parsed = effective_config(parse_config("""config rtp2httpd 'off'
option disabled '1'
option upstream_interface 'wrong0'
list listen '127.0.0.1:5141'
config rtp2httpd 'main'
option upstream_interface 'eth1'
option advanced_interface_settings '0'
option upstream_interface_multicast 'old0'
list listen '[::]:5140'
"""))
    assert parsed['values']['upstream-interface'] == 'eth1'
    assert 'upstream-interface-multicast' not in parsed['values']
    assert parsed['bind'] == ['[::]:5140']


@pytest.mark.parametrize('text', [
    "config rtp2httpd 'a'\nconfig rtp2httpd 'b'",
    "config rtp2httpd\noption disabled '1'",
    "config rtp2httpd\noption use_config_file '1'",
    "config rtp2httpd\noption disabled 'invalid'",
])
def test_uci_uncertain_config_is_not_reported_as_effective(text):
    with pytest.raises(ValueError):
        effective_config(parse_config(text))


def test_uci_advanced_mode_does_not_fall_back_to_inactive_default():
    parsed = effective_config(parse_config("""config rtp2httpd
option upstream_interface 'old0'
option advanced_interface_settings '1'
option upstream_interface_fcc 'eth1'
"""))
    assert 'upstream-interface' not in parsed['values']
    assert parsed['values']['upstream-interface-fcc'] == 'eth1'
