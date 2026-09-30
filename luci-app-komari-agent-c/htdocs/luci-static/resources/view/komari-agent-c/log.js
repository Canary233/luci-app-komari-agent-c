'use strict';
'require view';
'require rpc';
'require ui';

const callLog = rpc.declare({
	object: 'luci.komari-agent-c',
	method: 'log',
	params: ['lines'],
	expect: {}
});

return view.extend({
	load() {
		return L.resolveDefault(callLog(100), {});
	},

	render(data) {
		this.autoRefreshInterval = null;
		this.currentLines = 100;

		const logEl = E('div', {
			'id': 'log-content',
			'style': 'background:#fff;color:#000;padding:10px;max-height:600px;overflow-y:auto;font-family:monospace;border:1px solid #ccc;border-radius:4px;'
		});

		const renderLog = (res) => {
			res = res || {};

			if (res.code === 0 && res.log && res.log.trim() !== '')
				logEl.innerHTML = '<pre style="background:transparent;color:#000;margin:0;white-space:pre-wrap;word-break:break-word;">' +
					res.log.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;') + '</pre>';
			else
				logEl.innerHTML = '<p>' + _('No log entries found') + '</p>';
		};

		const loadLog = () => L.resolveDefault(callLog(this.currentLines), {}).then(renderLog);

		const autoRefreshBtn = E('button', {
			'class': 'cbi-button cbi-button-action',
			'click': ui.createHandlerFn(this, function() {
				if (this.autoRefreshInterval) {
					clearInterval(this.autoRefreshInterval);
					this.autoRefreshInterval = null;
					autoRefreshBtn.textContent = _('Auto Refresh');
				}
				else {
					this.autoRefreshInterval = setInterval(loadLog, 5000);
					autoRefreshBtn.textContent = _('Stop Auto Refresh');
				}
			})
		}, _('Auto Refresh'));

		const linesSelect = E('select', {
			'id': 'log-lines',
			'change': ui.createHandlerFn(this, function(ev) {
				this.currentLines = parseInt(ev.target.value) || 100;
				return loadLog();
			})
		}, [50, 100, 200, 500, 1000].map((n) => E('option', { 'value': n, 'selected': n === 100 ? '' : null }, n)));

		const view = E('div', {}, [
			E('h2', {}, _('Komari Agent Log')),
			E('div', { 'class': 'cbi-section' }, [
				E('h3', {}, _('Log Settings')),
				E('div', { 'class': 'cbi-section-node' }, [
					E('div', { 'class': 'cbi-value' }, [
						E('label', { 'class': 'cbi-value-title' }, _('Log Lines') + ':'),
						E('div', { 'class': 'cbi-value-field' }, [
							linesSelect,
							' ',
							E('button', {
								'class': 'cbi-button cbi-button-action',
								'click': ui.createHandlerFn(this, function() { return loadLog(); })
							}, _('Refresh')),
							' ',
							autoRefreshBtn
						])
					])
				])
			]),
			E('div', { 'class': 'cbi-section' }, [
				E('h3', {}, _('Log Content')),
				E('div', { 'class': 'cbi-section-node' }, logEl)
			])
		]);

		renderLog(data);

		return view;
	}
});
