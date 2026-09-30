'use strict';
'require form';
'require view';

return view.extend({
	render() {
		let m, s, o;

		m = new form.Map('komari-agent-c', _('Komari Agent Configuration'),
			_('Configuration for Komari Agent - a lightweight monitoring agent for OpenWrt.'));

		/* Basic Settings */
		s = m.section(form.NamedSection, 'main', 'komari-agent-c', _('Basic Settings'));

		o = s.option(form.Value, 'endpoint', _('Panel Server URL'),
			_('URL of the Komari Monitor panel server (e.g., https://panel.example.com)'));
		o.rmempty = false;
		o.validate = function(section_id, value) {
			if (!value)
				return _('Endpoint URL is required');

			if (!value.match(/^https?:\/\//))
				return _('URL must start with http:// or https://');

			return true;
		};

		o = s.option(form.Value, 'token', _('Authentication Token'),
			_('Token for authentication with the panel server'));
		o.password = true;
		o.rmempty = false;
		o.validate = function(section_id, value) {
			if (!value)
				return _('Token is required');

			if (value.length < 8)
				return _('Token must be at least 8 characters');

			if (value.length > 256)
				return _('Token must not exceed 256 characters');

			return true;
		};

		o = s.option(form.Value, 'interval', _('Report Interval (seconds)'),
			_('Interval between status reports (1 - 300 seconds)'));
		o.default = '3';
		o.validate = function(section_id, value) {
			let num = parseFloat(value);

			if (isNaN(num))
				return _('Must be a number');

			if (num < 1)
				return _('Minimum interval is 1 second');

			if (num > 300)
				return _('Maximum interval is 300 seconds');

			return true;
		};

		/* Connection Settings */
		s = m.section(form.NamedSection, 'main', 'komari-agent-c', _('Connection Settings'));

		o = s.option(form.Value, 'custom_dns', _('Custom DNS Server'),
			_('Custom DNS server for resolving panel hostname (optional)'));
		o.datatype = 'ipaddr';

		o = s.option(form.Flag, 'ignore_unsafe_cert', _('Ignore Certificate Errors'),
			_('Ignore SSL certificate validation errors (not recommended for production)'));
		o.default = '0';

		o = s.option(form.Value, 'auto_discovery_key', _('Auto Discovery Key'),
			_('Auto-discovery key for auto-registration to the panel (optional)'));
		o.password = true;
		o.rmempty = true;

		o = s.option(form.ListValue, 'prefer_ip_version', _('Preferred IP Version'),
			_('Preferred IP version for connecting to the panel (empty = system default)'));
		o.value('', _('System default'));
		o.value('4', _('IPv4'));
		o.value('6', _('IPv6'));
		o.default = '';

		o = s.option(form.Value, 'max_retries', _('Maximum Retries'),
			_('Maximum number of connection retry attempts'));
		o.default = '3';
		o.validate = function(section_id, value) {
			let num = parseInt(value);

			if (isNaN(num))
				return _('Must be a number');

			if (num < 1)
				return _('Minimum value is %d').format(1);

			if (num > 100)
				return _('Maximum value is %d').format(100);

			return true;
		};

		o = s.option(form.Value, 'reconnect_interval', _('Reconnect Interval (seconds)'),
			_('Seconds to wait between reconnection attempts'));
		o.default = '5';
		o.validate = function(section_id, value) {
			let num = parseInt(value);

			if (isNaN(num))
				return _('Must be a number');

			if (num < 5)
				return _('Minimum value is %d').format(5);

			if (num > 600)
				return _('Maximum value is %d').format(600);

			return true;
		};

		o = s.option(form.Value, 'info_report_interval', _('Info Report Interval (minutes)'),
			_('Minutes between full system information reports'));
		o.default = '5';
		o.validate = function(section_id, value) {
			let num = parseInt(value);

			if (isNaN(num))
				return _('Must be a number');

			if (num < 1)
				return _('Minimum value is %d').format(1);

			if (num > 60)
				return _('Maximum value is %d').format(60);

			return true;
		};

		/* Web SSH Settings */
		s = m.section(form.NamedSection, 'main', 'komari-agent-c', _('Web SSH Settings'));

		o = s.option(form.Flag, 'disable_web_ssh', _('Disable Web SSH'),
			_('Disable the Web SSH terminal feature for security'));
		o.default = '0';

		/* Network Interface Settings */
		s = m.section(form.NamedSection, 'main', 'komari-agent-c', _('Network Interface Settings'));

		o = s.option(form.Value, 'include_nics', _('Include Network Interfaces'),
			_('Comma-separated list of network interfaces to monitor; wildcards such as eth* are supported (empty = all non-virtual interfaces)'));
		o.rmempty = true;

		o = s.option(form.Value, 'exclude_nics', _('Exclude Network Interfaces'),
			_('Comma-separated list of network interfaces to exclude from monitoring; wildcards are supported'));
		o.rmempty = true;

		/* Disk Settings */
		s = m.section(form.NamedSection, 'main', 'komari-agent-c', _('Disk Settings'));

		o = s.option(form.Value, 'include_mountpoints', _('Include Mount Points'),
			_('Semicolon-separated list of mount points to monitor (empty = all physical filesystems)'));
		o.rmempty = true;

		/* Traffic Statistics */
		s = m.section(form.NamedSection, 'main', 'komari-agent-c', _('Traffic Statistics'));

		o = s.option(form.Value, 'month_rotate', _('Month Rotate Day'),
			_('Day of month for traffic statistics rotation (0 = disabled, 1-28)'));
		o.default = '0';
		o.validate = function(section_id, value) {
			let num = parseInt(value);

			if (isNaN(num))
				return _('Must be a number');

			if (num < 0)
				return _('Minimum value is %d').format(0);

			if (num > 28)
				return _('Maximum value is %d').format(28);

			return true;
		};

		/* Custom IP Addresses */
		s = m.section(form.NamedSection, 'main', 'komari-agent-c', _('Custom IP Addresses'));

		o = s.option(form.Value, 'custom_ipv4', _('Custom IPv4 Address'),
			_('Override detected IPv4 address (optional)'));
		o.datatype = 'ip4addr';
		o.rmempty = true;

		o = s.option(form.Value, 'custom_ipv6', _('Custom IPv6 Address'),
			_('Override detected IPv6 address (optional)'));
		o.datatype = 'ip6addr';
		o.rmempty = true;

		/* Advanced Settings */
		s = m.section(form.NamedSection, 'main', 'komari-agent-c', _('Advanced Settings'));

		o = s.option(form.Flag, 'memory_include_cache', _('Memory Includes Cache'),
			_('Report memory usage including cache/buffer (used = total - free)'));
		o.default = '0';

		o = s.option(form.Flag, 'memory_report_raw_used', _('Raw Memory Calculation'),
			_('Compatibility alias kept for Go flag parity; on Linux this behaves like the default calculation'));
		o.default = '0';

		o = s.option(form.Flag, 'disable_compression', _('Disable Compression'),
			_('Disable WebSocket permessage-deflate and HTTP gzip compression'));
		o.default = '0';

		o = s.option(form.Flag, 'disable_auto_update', _('Disable Auto Update Check'),
			_('Disable automatic update checking on startup'));
		o.default = '0';

		return m.render();
	}
});
