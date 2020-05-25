// Cronicle API Layer
// Copyright (c) 2015 Joseph Huckaby
// Released under the MIT License

var fs = require('fs');
var assert = require("assert");
var async = require('async');

var Class = require("pixl-class");
var Tools = require("pixl-tools");

module.exports = Class.create({
	
	__mixins: [
		require('./api/config.js'),
		require('./api/category.js'),
		require('./api/group.js'),
		require('./api/plugin.js'),
		require('./api/event.js'),
		require('./api/job.js'),
		require('./api/admin.js'),
		require('./api/apikey.js')
	],
	
	api_ping: function(args, callback) {
		// hello
		callback({ code: 0 });
	},

	api_crontab: function(args, callback) {

		var parsed = parse_crontab(args.query.crontab, "DEFAULT");
		callback({
			timing:parsed || {}
		});
	},
	
	api_echo: function(args, callback) {
		// for testing: adds 1 second delay, echoes everything back
		setTimeout( function() {
			callback({
				code: 0,
				query: args.query || {},
				params: args.params || {},
				files: args.files || {}
			});
		}, 1000 );
	},
	
	api_check_user_exists: function(args, callback) {
		// checks if username is taken (used for showing green checkmark on form)
		var self = this;
		var query = args.query;
		var path = 'users/' + this.usermgr.normalizeUsername(query.username);
		
		if (!this.requireParams(query, {
			username: this.usermgr.usernameMatch
		}, callback)) return;
		
		// do not cache this API response
		this.forceNoCacheResponse(args);
		
		this.storage.get(path, function(err, user) {
			callback({ code: 0, user_exists: !!user });
		} );
	},
	
	api_status: function(args, callback) {
		// simple status, used by monitoring tools
		var tick_age = 0;
		var now = Tools.timeNow();
		if (this.lastTick) tick_age = now - this.lastTick;
		
		// do not cache this API response
		this.forceNoCacheResponse(args);
		
		var data = {
			code: 0,
			version: this.server.__version,
			node: process.version,
			hostname: this.server.hostname,
			ip: this.server.ip,
			pid: process.pid,
			now: now,
			uptime: Math.floor( now - (this.server.started || now) ),
			last_tick: this.lastTick || now,
			tick_age: tick_age,
			cpu: process.cpuUsage(),
			mem: process.memoryUsage()
		};
		
		callback(data);
		
		// self-check: if tick_age is over 60 seconds, log a level 1 debug alert
		if (tick_age > 60) {
			var msg = "EMERGENCY: Tick age is over 60 seconds (" + Math.floor(tick_age) + "s) -- Server should be restarted immediately.";
			this.logDebug(1, msg, data);
			
			// JH 2018-08-28 Commenting this out for now, because an unsecured API should not have the power to cause an internal restart.
			// This kind of thing should be handled by external monitoring tools.
			// this.restartLocalServer({ reason: msg });
		}
	},

	api_health: function(args, callback) {

		var status = "200 OK";
		var headers = {};

		if (this.multi.master){
			 callback( { code: 'master', description: "Master server!" }, status, headers );
			 return true;
		}else{

			status = "502 Bad Gateway";

			callback( { code: 'no-master', description: "Not the master server!" }, status, headers );
			return false;
		}
	},
	
	forceNoCacheResponse: function(args) {
		// make sure this response isn't cached, ever
		args.response.setHeader( 'Cache-Control', 'no-cache, no-store, must-revalidate, proxy-revalidate' );
		args.response.setHeader( 'Expires', 'Thu, 01 Jan 1970 00:00:00 GMT' );
	},
	
	getServerBaseAPIURL: function(hostname, ip) {
		// construct fully-qualified URL to API on specified hostname
		// use proper protocol and ports as needed
		var api_url = '';
		
		if (ip && !this.server.config.get('server_comm_use_hostnames')) hostname = ip;
		
		if (this.web.config.get('https') && this.web.config.get('https_force')) {
			api_url = 'https://' + hostname;
			if (this.web.config.get('https_port') != 443) api_url += ':' + this.web.config.get('https_port');
		}
		else {
			api_url = 'http://' + hostname;
			if (this.web.config.get('http_port') != 80) api_url += ':' + this.web.config.get('http_port');
		}
		api_url += this.api.config.get('base_uri');
		
		return api_url;
	},
	
	validateOptionalParams: function(params, rules, callback) {
		// vaildate optional params given rule set
		assert( arguments.length == 3, "Wrong number of arguments to validateOptionalParams" );
		
		for (var key in rules) {
			if (key in params) {
				var rule = rules[key];
				var type_regexp = rule[0];
				var value_regexp = rule[1];
				var value = params[key];
				var type_value = typeof(value);
				
				if (!type_value.match(type_regexp)) {
					this.doError('api', "Malformed parameter type: " + key + " (" + type_value + ")", callback);
					return false;
				}
				else if (!value.toString().match(value_regexp)) {
					this.doError('api', "Malformed parameter value: " + key, callback);
					return false;
				}
			}
		}
		
		return true;
	},
	
	requireValidEventData: function(event, callback) {
		// make sure params contains valid event data (optional params)
		// otherwise throw an API error and return false
		// used by create_event, update_event, run_event and update_job APIs
		var RE_TYPE_STRING = /^(string)$/,
			RE_TYPE_BOOL = /^(boolean|number)$/,
			RE_TYPE_NUM = /^(number)$/,
			RE_ALPHANUM = /^\w+$/, 
			RE_POS_INT = /^\d+$/, 
			RE_BOOL = /^(\d+|true|false)$/;
		
		var rules = {
			algo: [RE_TYPE_STRING, RE_ALPHANUM],
			api_key: [RE_TYPE_STRING, RE_ALPHANUM],
			catch_up: [RE_TYPE_BOOL, RE_BOOL],
			category: [RE_TYPE_STRING, RE_ALPHANUM],
			chain: [RE_TYPE_STRING, /^\w*$/],
			chain_error: [RE_TYPE_STRING, /^\w*$/],
			cpu_limit: [RE_TYPE_NUM, RE_POS_INT],
			cpu_sustain: [RE_TYPE_NUM, RE_POS_INT],
			created: [RE_TYPE_NUM, RE_POS_INT],
			detached: [RE_TYPE_BOOL, RE_BOOL],
			enabled: [RE_TYPE_BOOL, RE_BOOL],
			id: [RE_TYPE_STRING, RE_ALPHANUM],
			log_max_size: [RE_TYPE_NUM, RE_POS_INT],
			max_children: [RE_TYPE_NUM, RE_POS_INT],
			memory_limit: [RE_TYPE_NUM, RE_POS_INT],
			memory_sustain: [RE_TYPE_NUM, RE_POS_INT],
			modified: [RE_TYPE_NUM, RE_POS_INT],
			multiplex: [RE_TYPE_BOOL, RE_BOOL],
			notes: [RE_TYPE_STRING, /.*/],
			notify_fail: [RE_TYPE_STRING, /.*/],
			notify_success: [RE_TYPE_STRING, /.*/],
			plugin: [RE_TYPE_STRING, RE_ALPHANUM],
			queue: [RE_TYPE_BOOL, RE_BOOL],
			queue_max: [RE_TYPE_NUM, RE_POS_INT],
			retries: [RE_TYPE_NUM, RE_POS_INT],
			retry_delay: [RE_TYPE_NUM, RE_POS_INT],
			stagger: [RE_TYPE_NUM, RE_POS_INT],
			target: [RE_TYPE_STRING, /^[\w\-\.]+$/],
			timeout: [RE_TYPE_NUM, RE_POS_INT],
			timezone: [RE_TYPE_STRING, /.*/],
			title: [RE_TYPE_STRING, /\S/],
			username: [RE_TYPE_STRING, /^[\w\-\.]+$/],
			web_hook: [RE_TYPE_STRING, /(^$|https?\:\/\/\S+$)/i]
		};
		if (!this.validateOptionalParams(event, rules, callback)) return false;
		
		// params
		if (("params" in event) && (typeof(event.params) != 'object')) {
			this.doError('api', "Malformed event parameter: params (must be object)", callback);
			return false;
		}
		
		// timing (can be falsey, or object)
		if (event.timing) {
			if (typeof(event.timing) != 'object') {
				this.doError('api', "Malformed event parameter: timing (must be object)", callback);
				return false;
			}
			
			// check timing keys, should all be arrays of ints
			var timing = event.timing;
			for (var key in timing) {
				if (!key.match(/^(years|months|days|weekdays|hours|minutes)$/)) {
					this.doError('api', "Unknown event timing parameter: " + key, callback);
					return false;
				}
				var values = timing[key];
				if (!Tools.isaArray(values)) {
					this.doError('api', "Malformed event timing parameter: " + key + " (must be array)", callback);
					return false;
				}
				for (var idx = 0, len = values.length; idx < len; idx++) {
					var value = values[idx];
					if (typeof(value) != 'number') {
						this.doError('api', "Malformed event timing parameter: " + key + " (must be array of numbers)", callback);
						return false;
					}
					if ((key == 'years') && (value < 1)) {
						this.doError('api', "Malformed event timing parameter: " + key + " (value out of range: " + value + ")", callback);
						return false;
					}
					if ((key == 'months') && ((value < 1) || (value > 12))) {
						this.doError('api', "Malformed event timing parameter: " + key + " (value out of range: " + value + ")", callback);
						return false;
					}
					if ((key == 'days') && ((value < 1) || (value > 31))) {
						this.doError('api', "Malformed event timing parameter: " + key + " (value out of range: " + value + ")", callback);
						return false;
					}
					if ((key == 'weekdays') && ((value < 0) || (value > 6))) {
						this.doError('api', "Malformed event timing parameter: " + key + " (value out of range: " + value + ")", callback);
						return false;
					}
					if ((key == 'hours') && ((value < 0) || (value > 23))) {
						this.doError('api', "Malformed event timing parameter: " + key + " (value out of range: " + value + ")", callback);
						return false;
					}
					if ((key == 'minutes') && ((value < 0) || (value > 59))) {
						this.doError('api', "Malformed event timing parameter: " + key + " (value out of range: " + value + ")", callback);
						return false;
					}
				}
			}
		} // timing
		
		return true;
	},
	
	requireValidUser: function(session, user, callback) {
		// make sure user and session are valid
		// otherwise throw an API error and return false
		
		if (session && (session.type == 'api')) {
			// session is simulated, created by API key
			if (!user) {
				return this.doError('api', "Invalid API Key: " + session.api_key, callback);
			}
			if (!user.active) {
				return this.doError('api', "API Key is disabled: " + session.api_key, callback);
			}
			return true;
		} // api key
		
		if (!session) {
			return this.doError('session', "Session has expired or is invalid.", callback);
		}
		if (!user) {
			return this.doError('user', "User not found: " + session.username, callback);
		}
		if (!user.active) {
			return this.doError('user', "User account is disabled: " + session.username, callback);
		}
		return true;
	},
	
	requireAdmin: function(session, user, callback) {
		// make sure user and session are valid, and user is an admin
		// otherwise throw an API error and return false
		if (!this.requireValidUser(session, user, callback)) return false;
		
		if (session.type == 'api') {
			// API Keys cannot be admins
			return this.doError('api', "API Key cannot use administrator features", callback);
		}
		
		if (!user.privileges.admin) {
			return this.doError('user', "User is not an administrator: " + session.username, callback);
		}
		
		return true;
	},
	
	requirePrivilege: function(user, priv_id, callback) {
		// make sure user has the specified privilege
		// otherwise throw an API error and return false
		if (user.privileges.admin) return true; // admins can do everything
		if (user.privileges[priv_id]) return true;
		
		if (user.key) {
			return this.doError('api', "API Key ('"+user.title+"') does not have the required privileges to perform this action ("+priv_id+").", callback);
		}
		else {
			return this.doError('user', "User '"+user.username+"' does not have the required account privileges to perform this action ("+priv_id+").", callback);
		}
	},
	
	requireCategoryPrivilege: function(user, cat_id, callback) {
		// make sure user has the specified category privilege
		// otherwise throw an API error and return false
		if (user.privileges.admin) return true; // admins can do everything
		if (!user.privileges.cat_limit) return true; // user is not limited to categories
		
		var priv_id = 'cat_' + cat_id;
		return this.requirePrivilege(user, priv_id, callback);
	},
	
	requireMaster: function(args, callback) {
		// make sure we are the master server
		// otherwise throw an API error and return false
		if (this.multi.master) return true;
		
		var status = "200 OK";
		var headers = {};
		
		if (this.multi.masterHostname) {
			// we know who master is, so let's give the client a hint
			status = "302 Found";
			
			var url = '';
			if (this.web.config.get('https') && this.web.config.get('https_force')) {
				url = 'https://' + (this.server.config.get('server_comm_use_hostnames') ? this.multi.masterHostname : this.multi.masterIP);
				if (this.web.config.get('https_port') != 443) url += ':' + this.web.config.get('https_port');
			}
			else {
				url = 'http://' + (this.server.config.get('server_comm_use_hostnames') ? this.multi.masterHostname : this.multi.masterIP);
				if (this.web.config.get('http_port') != 80) url += ':' + this.web.config.get('http_port');
			}
			url += args.request.url;
			
			headers['Location'] = url;
		}
		
		var msg = "This API call can only be invoked on the master server.";
		// this.logError( 'master', msg );
		callback( { code: 'master', description: msg }, status, headers );
		return false;
	},
	
	getClientInfo: function(args, params) {
		// proxy over to user module
		// var info = this.usermgr.getClientInfo(args, params);
		var info = null;
		if (params) info = Tools.copyHash(params, true);
		else info = {};
		
		info.ip = args.ip;
		info.headers = args.request.headers;
		
		// augment with our own additions
		if (args.admin_user) info.username = args.admin_user.username;
		else if (args.user) {
			if (args.user.key) {
				// API Key
				info.api_key = args.user.key;
				info.api_title = args.user.title;
			}
			else {
				info.username = args.user.username;
			}
		}
		
		return info;
	},
	
	loadSession: function(args, callback) {
		// Load user session or validate API Key
		var self = this;
		var session_id = args.cookies['session_id'] || args.request.headers['x-session-id'] || args.params.session_id || args.query.session_id;
		
		if (session_id) {
			this.storage.get('sessions/' + session_id, function(err, session) {
				if (err) return callback(err, null, null);
				
				// also load user
				self.storage.get('users/' + self.usermgr.normalizeUsername(session.username), function(err, user) {
					if (err) return callback(err, null, null);
					
					// set type to discern this from API Key sessions
					session.type = 'user';
					
					// get session_id out of args.params, so it doesn't interfere with API calls
					delete args.params.session_id;
					
					// pass both session and user to callback
					callback(null, session, user);
				} );
			} );
			return;
		}
		
		// no session found, look for API Key
		var api_key = args.request.headers['x-api-key'] || args.params.api_key || args.query.api_key;
		if (!api_key) return callback( new Error("No Session ID or API Key could be found"), null, null );
		
		this.storage.listFind( 'global/api_keys', { key: api_key }, function(err, item) {
			if (err) return callback(new Error("API Key is invalid: " + api_key), null, null);
			
			// create simulated session and user objects
			var session = {
				type: 'api',
				api_key: api_key
			};
			var user = item;
			
			// get api_key out of args.params, so it doesn't interfere with API calls
			delete args.params.api_key;
			
			// pass both "session" and "user" to callback
			callback(null, session, user);
		} );
		return;
	},
	
	requireParams: function(params, rules, callback) {
		// proxy over to user module
		assert( arguments.length == 3, "Wrong number of arguments to requireParams" );
		return this.usermgr.requireParams(params, rules, callback);
	},
	
	doError: function(code, msg, callback) {
		// proxy over to user module
		assert( arguments.length == 3, "Wrong number of arguments to doError" );
		return this.usermgr.doError( code, msg, callback );
	}
	
});

// Crontab Parsing Tools
// by Joseph Huckaby, (c) 2015, MIT License

var cron_aliases = {
	jan: 1,
	feb: 2,
	mar: 3,
	apr: 4,
	may: 5,
	jun: 6,
	jul: 7,
	aug: 8,
	sep: 9,
	oct: 10,
	nov: 11,
	dec: 12,
	
	sun: 0,
	mon: 1,
	tue: 2,
	wed: 3,
	thu: 4,
	fri: 5,
	sat: 6
};

function hash_keys_to_array(hash) {
	// convert hash keys to array (discard values)
	var array = [];
	for (var key in hash) array_push(array, key);
	return array;
}

var cron_alias_re = new RegExp("\\b(" + hash_keys_to_array(cron_aliases).join('|') + ")\\b", "g");

function parse_crontab_part(timing, raw, key, min, max, rand_seed) {
	// parse one crontab part, e.g. 1,2,3,5,20-25,30-35,59
	// can contain single number, and/or list and/or ranges and/or these things: */5 or 10-50/5
	if (raw == '*') { return; } // wildcard
	if (raw == 'h') {
		// unique value over accepted range, but locked to random seed
		// https://github.com/jhuckaby/Cronicle/issues/6
		raw = min + (parseInt( hex_md5(rand_seed), 16 ) % ((max - min) + 1));
		raw = '' + raw;
	}
	if (!raw.match(/^[\w\-\,\/\*]+$/)) { throw new Error("Invalid crontab format: " + raw); }
	var values = {};
	var bits = raw.split(/\,/);
	
	for (var idx = 0, len = bits.length; idx < len; idx++) {
		var bit = bits[idx];
		if (bit.match(/^\d+$/)) {
			// simple number, easy
			values[bit] = 1;
		}
		else if (bit.match(/^(\d+)\-(\d+)$/)) {
			// simple range, e.g. 25-30
			var start = parseInt( RegExp.$1 );
			var end = parseInt( RegExp.$2 );
			for (var idy = start; idy <= end; idy++) { values[idy] = 1; }
		}
		else if (bit.match(/^\*\/(\d+)$/)) {
			// simple step interval, e.g. */5
			var step = parseInt( RegExp.$1 );
			var start = min;
			var end = max;
			for (var idy = start; idy <= end; idy += step) { values[idy] = 1; }
		}
		else if (bit.match(/^(\d+)\-(\d+)\/(\d+)$/)) {
			// range step inverval, e.g. 1-31/5
			var start = parseInt( RegExp.$1 );
			var end = parseInt( RegExp.$2 );
			var step = parseInt( RegExp.$3 );
			for (var idy = start; idy <= end; idy += step) { values[idy] = 1; }
		}
		else {
			throw new Error("Invalid crontab format: " + bit + " (" + raw + ")");
		}
	}
	
	// min max
	var to_add = {};
	var to_del = {};
	for (var value in values) {
		value = parseInt( value );
		if (value < min) {
			to_del[value] = 1;
			to_add[min] = 1;
		}
		else if (value > max) {
			to_del[value] = 1;
			value -= min;
			value = value % ((max - min) + 1); // max is inclusive
			value += min;
			to_add[value] = 1;
		}
	}
	for (var value in to_del) delete values[value];
	for (var value in to_add) values[value] = 1;
	
	// convert to sorted array
	var list = hash_keys_to_array(values);
	for (var idx = 0, len = list.length; idx < len; idx++) {
		list[idx] = parseInt( list[idx] );
	}
	list = list.sort( function(a, b) { return a - b; } );
	if (list.length) timing[key] = list;
};

function parse_crontab(raw, rand_seed) {
	// parse standard crontab syntax, return timing object
	// e.g. 1,2,3,5,20-25,30-35,59 23 31 12 * *
	// optional 6th element == years
	if (!rand_seed) rand_seed = get_unique_id();
	var timing = {};
	
	// resolve all @shortcuts
	raw = trim(raw).toLowerCase();
	if (raw.match(/\@(yearly|annually)/)) raw = '0 0 1 1 *';
	else if (raw == '@monthly') raw = '0 0 1 * *';
	else if (raw == '@weekly') raw = '0 0 * * 0';
	else if (raw == '@daily') raw = '0 0 * * *';
	else if (raw == '@hourly') raw = '0 * * * *';
	
	// expand all month/wday aliases
	raw = raw.replace(cron_alias_re, function(m_all, m_g1) {
		return cron_aliases[m_g1];
	} );
	
	// at this point string should not contain any alpha characters or '@', except for 'h'
	if (raw.match(/([a-gi-z\@]+)/i)) throw new Error("Invalid crontab keyword: " + RegExp.$1);
	
	// split into parts
	var parts = raw.split(/\s+/);
	if (parts.length > 6) throw new Error("Invalid crontab format: " + parts.slice(6).join(' '));
	if (!parts[0].length) throw new Error("Invalid crontab format");
	
	// parse each part
	if ((parts.length > 0) && parts[0].length) parse_crontab_part( timing, parts[0], 'minutes', 0, 59, rand_seed );
	if ((parts.length > 1) && parts[1].length) parse_crontab_part( timing, parts[1], 'hours', 0, 23, rand_seed );
	if ((parts.length > 2) && parts[2].length) parse_crontab_part( timing, parts[2], 'days', 1, 31, rand_seed );
	if ((parts.length > 3) && parts[3].length) parse_crontab_part( timing, parts[3], 'months', 1, 12, rand_seed );
	if ((parts.length > 4) && parts[4].length) parse_crontab_part( timing, parts[4], 'weekdays', 0, 6, rand_seed );
	if ((parts.length > 5) && parts[5].length) parse_crontab_part( timing, parts[5], 'years', 1970, 3000, rand_seed );
	
	return timing;
};

// TAB handling code from http://www.webdeveloper.com/forum/showthread.php?t=32317
// Hacked to do my bidding - JH 2008-09-15
function setSelectionRange(input, selectionStart, selectionEnd) {
  if (input.setSelectionRange) {
    input.focus();
    input.setSelectionRange(selectionStart, selectionEnd);
  }
  else if (input.createTextRange) {
    var range = input.createTextRange();
    range.collapse(true);
    range.moveEnd('character', selectionEnd);
    range.moveStart('character', selectionStart);
    range.select();
  }
};

function replaceSelection (input, replaceString) {
	var oldScroll = input.scrollTop;
	if (input.setSelectionRange) {
		var selectionStart = input.selectionStart;
		var selectionEnd = input.selectionEnd;
		input.value = input.value.substring(0, selectionStart)+ replaceString + input.value.substring(selectionEnd);

		if (selectionStart != selectionEnd){ 
			setSelectionRange(input, selectionStart, selectionStart + 	replaceString.length);
		}else{
			setSelectionRange(input, selectionStart + replaceString.length, selectionStart + replaceString.length);
		}

	}else if (document.selection) {
		var range = document.selection.createRange();

		if (range.parentElement() == input) {
			var isCollapsed = range.text == '';
			range.text = replaceString;

			 if (!isCollapsed)  {
				range.moveStart('character', -replaceString.length);
				range.select();
			}
		}
	}
	input.scrollTop = oldScroll;
};

function catchTab(item,e){
	var c = e.which ? e.which : e.keyCode;

	if (c == 9){
		replaceSelection(item,String.fromCharCode(9));
		setTimeout("document.getElementById('"+item.id+"').focus();",0);	
		return false;
	}
};

function get_text_from_seconds_round_custom(sec, abbrev) {
	// convert raw seconds to human-readable relative time
	// round to nearest instead of floor, but allow one decimal point if under 10 units
	var neg = '';
	if (sec < 0) { sec =- sec; neg = '-'; }
	
	var text = abbrev ? "sec" : "second";
	var amt = sec;
	
	if (sec > 59) {
		var min = sec / 60;
		text = abbrev ? "min" : "minute"; 
		amt = min;
		
		if (min > 59) {
			var hour = min / 60;
			text = abbrev ? "hr" : "hour"; 
			amt = hour;
			
			if (hour > 23) {
				var day = hour / 24;
				text = "day"; 
				amt = day;
			} // hour>23
		} // min>59
	} // sec>59
	
	if (amt < 10) amt = Math.round(amt * 10) / 10;
	else amt = Math.round(amt);
	
	var text = "" + amt + " " + text;
	if ((amt != 1) && !abbrev) text += "s";
	
	return(neg + text);
};

function array_push(array, item) {
	// push item onto end of array
	array[ array.length ] = item;
}

function trim(text) {
	// strip whitespace from beginning and end of string
	if (text == null) return '';
	
	if (text && text.replace) {
		text = text.replace(/^\s+/, "");
		text = text.replace(/\s+$/, "");
	}
	
	return text;
}
