'use strict';
'require view';
'require rpc';
'require ui';
'require poll';

const callStatus = rpc.declare({
	object: 'luci.komari-agent-c',
	method: 'status',
	expect: {}
});

const callStart = rpc.declare({
	object: 'luci.komari-agent-c',
	method: 'start',
	expect: {}
});

const callStop = rpc.declare({
	object: 'luci.komari-agent-c',
	method: 'stop',
	expect: {}
});

const callRestart = rpc.declare({
	object: 'luci.komari-agent-c',
	method: 'restart',
	expect: {}
});

const callTestConnection = rpc.declare({
	object: 'luci.komari-agent-c',
	method: 'test_connection',
	expect: {}
});

function formatUptime(seconds) {
	let days = Math.floor(seconds / 86400),
	    hours = Math.floor((seconds % 86400) / 3600),
	    minutes = Math.floor((seconds % 3600) / 60),
	    result = '';

	if (days > 0)
		result += days + ' ' + _('d') + ' ';

	if (hours > 0)
		result += hours + ' ' + _('h') + ' ';

	result += minutes + ' ' + _('min');

	return result;
}

function formatSpeed(bytes) {
	if (bytes >= 1048576)
		return (bytes / 1048576).toFixed(2) + ' MB/s';

	if (bytes >= 1024)
		return (bytes / 1024).toFixed(2) + ' KB/s';

	return bytes + ' B/s';
}

function indicator(color, text) {
	return '<span style="color:%s;">●</span> %s'.format(color, text);
}

return view.extend({
	load() {
		return L.resolveDefault(callStatus(), {});
	},

	updateStatus() {
		return L.resolveDefault(callStatus(), {}).then((status) => {
			status = status || {};

			const setText = (id, text) => {
				let el = document.getElementById(id);
				if (el)
					el.innerHTML = text;
			};

			if (status.running) {
				setText('service-status', indicator('green', _('Running')));
				setText('agent-uptime', formatUptime(status.uptime || 0));
			}
			else {
				setText('service-status', indicator('red', _('Not Running')));
				setText('agent-uptime', '-');
			}

			setText('enabled-status', status.enabled
				? indicator('green', _('Enabled'))
				: indicator('red', _('Disabled')));

			if (status.running && status.data) {
				setText('connection-status', status.data.connected
					? indicator('green', _('Connected'))
					: indicator('red', _('Disconnected')));
				setText('endpoint', status.data.endpoint || '-');
				setText('cpu-usage', (status.data.cpu_usage || 0).toFixed(1) + '%');
				setText('memory-usage', (status.data.memory_usage || 0).toFixed(1) + '%');
				setText('disk-usage', (status.data.disk_usage || 0).toFixed(1) + '%');
				setText('rx-speed', formatSpeed(status.data.rx_speed || 0));
				setText('tx-speed', formatSpeed(status.data.tx_speed || 0));
			}
			else {
				setText('connection-status', '-');
				setText('endpoint', '-');
				setText('cpu-usage', '-');
				setText('memory-usage', '-');
				setText('disk-usage', '-');
				setText('rx-speed', '-');
				setText('tx-speed', '-');
			}
		});
	},

	runAction(call, successMsg, failureMsg) {
		return L.resolveDefault(call(), {}).then((res) => {
			if (res && res.code === 0)
				ui.addNotification(null, E('p', {}, successMsg), 'info');
			else
				ui.addNotification(null, E('p', {}, failureMsg), 'error');

			return this.updateStatus();
		});
	},

	handleStart() {
		return this.runAction(callStart, _('Service started'), _('Failed to start service'));
	},

	handleStop() {
		return this.runAction(callStop, _('Service stopped'), _('Failed to stop service'));
	},

	handleRestart() {
		return this.runAction(callRestart, _('Service restarted'), _('Failed to restart service'));
	},

	handleTestConnection() {
		return L.resolveDefault(callTestConnection(), {}).then((res) => {
			if (res && res.code === 0)
				ui.addNotification(null, E('p', {}, _('Connection successful')), 'info');
			else if (res && res.reason === 'not_configured')
				ui.addNotification(null, E('p', {}, _('Endpoint not configured')), 'error');
			else if (res && res.reason === 'invalid_url')
				ui.addNotification(null, E('p', {}, _('Endpoint must start with http:// or https://')), 'error');
			else
				ui.addNotification(null, E('p', {}, _('Connection failed')), 'error');
		});
	},

	render(status) {
		const table = (headers, ids) => E('div', { 'class': 'cbi-section' }, [
			E('div', { 'class': 'cbi-section-node' }, [
				E('table', { 'class': 'table' }, [
					E('tr', { 'class': 'tr table-titles' }, headers.map((h) => E('th', { 'class': 'th' }, h))),
					E('tr', { 'class': 'tr' }, ids.map((id) => E('td', { 'class': 'td', 'id': id }, '-')))
				])
			])
		]);

		const view = E('div', {}, [
			E('h2', {}, _('Komari Agent Status')),
			E('h3', {}, _('Service Status')),
			table([_('Status'), _('Auto Start'), _('System Uptime')],
				['service-status', 'enabled-status', 'agent-uptime']),
			E('h3', {}, _('Connection Status')),
			table([_('Connection Status'), _('Panel Server')],
				['connection-status', 'endpoint']),
			E('h3', {}, _('System Metrics')),
			table([_('CPU Usage'), _('Memory Usage'), _('Disk Usage'), _('Download Speed'), _('Upload Speed')],
				['cpu-usage', 'memory-usage', 'disk-usage', 'rx-speed', 'tx-speed']),
			E('h3', {}, _('Actions')),
			E('div', { 'class': 'cbi-section' }, [
				E('div', { 'class': 'cbi-section-node' }, [
					E('div', { 'class': 'cbi-value-field' }, [
						E('button', {
							'class': 'cbi-button cbi-button-positive',
							'click': ui.createHandlerFn(this, 'handleStart')
						}, _('Start')),
						' ',
						E('button', {
							'class': 'cbi-button cbi-button-negative',
							'click': ui.createHandlerFn(this, 'handleStop')
						}, _('Stop')),
						' ',
						E('button', {
							'class': 'cbi-button cbi-button-reload',
							'click': ui.createHandlerFn(this, 'handleRestart')
						}, _('Restart')),
						' ',
						E('button', {
							'class': 'cbi-button cbi-button-action',
							'click': ui.createHandlerFn(this, 'handleTestConnection')
						}, _('Test Connection'))
					])
				])
			])
		]);

		this.updateStatus();

		poll.add(L.bind(this.updateStatus, this), 5);

		return view;
	}
});
